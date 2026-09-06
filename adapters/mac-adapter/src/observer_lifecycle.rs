//! macOS 观察器的代际、取消与停止排空契约。

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::Thread;
use std::time::{Duration, Instant};

/// 一次观察器启动的不可复用标识。`0` 永远表示“没有活动代际”。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObserverGeneration(u64);

impl ObserverGeneration {
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ObserverGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// 一次有界停止的真实结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopOutcome {
    /// 该代际的所有 worker 都已退出，且没有 panic。
    Drained,
    /// worker 已退出，但退出路径发生过 panic。
    Panicked,
    /// 截止期限内仍有 worker；generation 已取消，但不能声称已经排空。
    TimedOut { remaining: usize },
}

#[derive(Default)]
struct WorkerState {
    running: usize,
    panicked: bool,
    threads: Vec<Thread>,
}

#[derive(Default)]
struct DrainState {
    workers: HashMap<ObserverGeneration, WorkerState>,
}

struct Inner {
    next: AtomicU64,
    active: AtomicU64,
    /// 提交锁把“仍是当前代际吗”与共享状态写入变成一个原子区间。
    /// `begin` 也经过它，所以新代际不会越过一个已经开始提交的旧回调。
    commit: Mutex<()>,
    drain: Mutex<DrainState>,
    drained: Condvar,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(0),
            active: AtomicU64::new(0),
            commit: Mutex::new(()),
            drain: Mutex::new(DrainState::default()),
            drained: Condvar::new(),
        }
    }
}

/// 可克隆的观察器生命周期控制器。
///
/// `cancel` 只做原子失效与 `unpark`，不会等待系统 API，因此可安全地从 UI 路径发出；真正的
/// `wait` 必须放到 blocking worker。采集可在锁外进行，只有最终写 App 状态时调用 [`commit`]。
#[derive(Clone, Default)]
pub struct ObserverLifecycle {
    inner: Arc<Inner>,
}

impl ObserverLifecycle {
    pub fn new() -> Self {
        Self::default()
    }

    /// 分配并激活一个从不复用的代际。
    ///
    /// 可能等待一个已经进入提交区的旧回调，因此调用方应在 blocking worker 中执行。
    pub fn begin(&self) -> ObserverGeneration {
        let _commit = lock_unpoisoned(&self.inner.commit);
        self.allocate_generation()
    }

    /// 仅在旧 worker 已全部退出时激活新代际。
    ///
    /// 生产 start/stop 控制路径使用这个入口：一次 stop timeout 会先让旧代际不能提交，
    /// 但在其 worker 真正退出前仍拒绝 start。返回值是仍在运行的 worker 数；活动代际尚未
    /// 登记 worker 时也按一个未排空单元计。
    pub fn begin_if_drained(&self) -> Result<ObserverGeneration, usize> {
        let _commit = lock_unpoisoned(&self.inner.commit);
        let mut drain = lock_unpoisoned(&self.inner.drain);
        drain.workers.retain(|_, worker| worker.running > 0);
        let running = drain
            .workers
            .values()
            .map(|worker| worker.running)
            .sum::<usize>();
        let active = self.inner.active.load(Ordering::SeqCst);
        if active != 0 || running > 0 {
            return Err(running.max(1));
        }
        drop(drain);
        Ok(self.allocate_generation())
    }

    fn allocate_generation(&self) -> ObserverGeneration {
        let generation = loop {
            let next = self
                .inner
                .next
                .fetch_add(1, Ordering::SeqCst)
                .wrapping_add(1);
            if next != 0 {
                break ObserverGeneration(next);
            }
        };
        self.inner.active.store(generation.0, Ordering::SeqCst);
        generation
    }

    /// 激活后运行原生启动；启动失败会立即撤销该代际。
    pub fn begin_with<E>(
        &self,
        start: impl FnOnce(ObserverGeneration) -> Result<(), E>,
    ) -> Result<ObserverGeneration, E> {
        let generation = self.begin();
        match start(generation) {
            Ok(()) => Ok(generation),
            Err(error) => {
                self.cancel(generation);
                Err(error)
            }
        }
    }

    pub fn active(&self) -> Option<ObserverGeneration> {
        let generation = self.inner.active.load(Ordering::SeqCst);
        (generation != 0).then_some(ObserverGeneration(generation))
    }

    pub fn is_current(&self, generation: ObserverGeneration) -> bool {
        self.inner.active.load(Ordering::SeqCst) == generation.0
    }

    /// 使指定代际失效并唤醒其休眠 worker。不会等待 worker。
    pub fn cancel(&self, generation: ObserverGeneration) -> bool {
        let cancelled = self
            .inner
            .active
            .compare_exchange(generation.0, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if cancelled {
            let threads = lock_unpoisoned(&self.inner.drain)
                .workers
                .get(&generation)
                .map(|state| state.threads.clone())
                .unwrap_or_default();
            for thread in threads {
                thread.unpark();
            }
        }
        cancelled
    }

    pub fn cancel_active(&self) -> Option<ObserverGeneration> {
        let generation = self.active()?;
        self.cancel(generation).then_some(generation)
    }

    /// 取消当前代际；若前一次取消已经发生但 worker 尚未排空，则返回最近的待排空代际。
    ///
    /// 有界 stop 超时会先把 `active` 清零，第二次 stop 不能因此谎报 `Drained`。生产停止
    /// 路径应使用此方法，并继续对同一代际调用 [`wait`](Self::wait)。
    pub fn cancel_active_or_draining(&self) -> Option<ObserverGeneration> {
        if let Some(generation) = self.cancel_active() {
            return Some(generation);
        }

        lock_unpoisoned(&self.inner.drain)
            .workers
            .keys()
            .copied()
            .max_by_key(|generation| generation.0)
    }

    /// 只有仍为当前代际时才执行最终状态写入。
    ///
    /// 回调的慢采集、OCR 或系统调用必须放在这个闭包外；这里仅容纳短小提交。取消后已经排队但
    /// 尚未进入的 callback 会返回 `None`。已经进入提交区的 callback 会先完成；下一次 `begin`
    /// 会等待它，因而它也不可能写进新代际。
    pub fn commit<T>(
        &self,
        generation: ObserverGeneration,
        write: impl FnOnce() -> T,
    ) -> Option<T> {
        if !self.is_current(generation) {
            return None;
        }
        let _commit = lock_unpoisoned(&self.inner.commit);
        if !self.is_current(generation) {
            return None;
        }
        Some(write())
    }

    /// 为该代际登记一个 worker。返回 `None` 表示启动完成前代际已被取消。
    pub fn worker(&self, generation: ObserverGeneration) -> Option<ObserverWorker> {
        if !self.is_current(generation) {
            return None;
        }
        let mut drain = lock_unpoisoned(&self.inner.drain);
        if !self.is_current(generation) {
            return None;
        }
        drain.workers.entry(generation).or_default().running += 1;
        Some(ObserverWorker {
            lifecycle: self.clone(),
            generation,
            attached: false,
        })
    }

    /// 等指定代际退出；调用方负责先取消。必须在 blocking worker 中调用。
    pub fn wait(&self, generation: ObserverGeneration, timeout: Duration) -> StopOutcome {
        let started = Instant::now();
        let mut drain = lock_unpoisoned(&self.inner.drain);
        loop {
            let Some(worker) = drain.workers.get(&generation) else {
                return StopOutcome::Drained;
            };
            if worker.running == 0 {
                let panicked = worker.panicked;
                drain.workers.remove(&generation);
                return if panicked {
                    StopOutcome::Panicked
                } else {
                    StopOutcome::Drained
                };
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return StopOutcome::TimedOut {
                    remaining: worker.running,
                };
            }
            let (next, wait) = self
                .inner
                .drained
                .wait_timeout(drain, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            drain = next;
            if wait.timed_out() {
                let running = drain
                    .workers
                    .get(&generation)
                    .map(|worker| worker.running)
                    .unwrap_or(0);
                if running > 0 {
                    return StopOutcome::TimedOut { remaining: running };
                }
            }
        }
    }

    pub fn stop_and_wait(&self, generation: ObserverGeneration, timeout: Duration) -> StopOutcome {
        self.cancel(generation);
        self.wait(generation, timeout)
    }
}
/// 登记中的 worker；无论正常返回还是 unwind，Drop 都会通知等待方。
pub struct ObserverWorker {
    lifecycle: ObserverLifecycle,
    generation: ObserverGeneration,
    attached: bool,
}

impl ObserverWorker {
    /// 保存线程句柄，让取消可以 `unpark`，避免必须等完整轮询周期。
    pub fn attach_current_thread(mut self) -> Self {
        let mut drain = lock_unpoisoned(&self.lifecycle.inner.drain);
        if let Some(worker) = drain.workers.get_mut(&self.generation) {
            worker.threads.push(std::thread::current());
            self.attached = true;
        }
        drop(drain);
        self
    }
}

impl Drop for ObserverWorker {
    fn drop(&mut self) {
        let mut drain = lock_unpoisoned(&self.lifecycle.inner.drain);
        if let Some(worker) = drain.workers.get_mut(&self.generation) {
            worker.running = worker.running.saturating_sub(1);
            worker.panicked |= std::thread::panicking();
            if self.attached {
                let current = std::thread::current().id();
                worker.threads.retain(|thread| thread.id() != current);
            }
        }
        self.lifecycle.inner.drained.notify_all();
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    #[test]
    fn fake_poller反复一千次开始结束再开始_旧代际不能写新状态() {
        let lifecycle = ObserverLifecycle::new();
        let writes = Arc::new(AtomicUsize::new(0));

        for _ in 0..1_000 {
            let old = lifecycle.begin();
            let worker = lifecycle.worker(old).unwrap();
            let queued_writes = writes.clone();
            let queued_lifecycle = lifecycle.clone();
            let (ready_tx, ready_rx) = mpsc::sync_channel(0);
            let (release_tx, release_rx) = mpsc::sync_channel(0);
            let handle = std::thread::spawn(move || {
                let _worker = worker.attach_current_thread();
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                let _ =
                    queued_lifecycle.commit(old, || queued_writes.fetch_add(1, Ordering::SeqCst));
            });
            ready_rx.recv().unwrap();
            lifecycle.cancel(old);
            let current = lifecycle.begin();
            release_tx.send(()).unwrap();
            handle.join().unwrap();
            assert_eq!(
                lifecycle.wait(old, Duration::from_secs(1)),
                StopOutcome::Drained
            );
            assert!(lifecycle
                .commit(current, || writes.fetch_add(1, Ordering::SeqCst))
                .is_some());
            lifecycle.cancel(current);
        }

        assert_eq!(writes.load(Ordering::SeqCst), 1_000);
    }

    #[test]
    fn 启动失败会撤销刚分配的代际() {
        let lifecycle = ObserverLifecycle::new();
        let error = lifecycle
            .begin_with::<&str>(|_| Err("native start failed"))
            .unwrap_err();
        assert_eq!(error, "native start failed");
        assert_eq!(lifecycle.active(), None);
    }

    #[test]
    fn worker_panic仍能被停止排空观察到() {
        let lifecycle = ObserverLifecycle::new();
        let generation = lifecycle.begin();
        let worker = lifecycle.worker(generation).unwrap();
        std::thread::spawn(move || {
            let _worker = worker.attach_current_thread();
            panic!("fake poller panic");
        });

        assert_eq!(
            lifecycle.stop_and_wait(generation, Duration::from_secs(1)),
            StopOutcome::Panicked
        );
    }

    #[test]
    fn 停止超时不冒充已经排空() {
        let lifecycle = ObserverLifecycle::new();
        let generation = lifecycle.begin();
        let worker = lifecycle.worker(generation).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _worker = worker.attach_current_thread();
            release_rx.recv().unwrap();
        });

        assert!(matches!(
            lifecycle.stop_and_wait(generation, Duration::from_millis(1)),
            StopOutcome::TimedOut { remaining: 1 }
        ));
        assert_eq!(lifecycle.begin_if_drained(), Err(1));
        release_tx.send(()).unwrap();
        assert_eq!(
            lifecycle.wait(generation, Duration::from_secs(1)),
            StopOutcome::Drained
        );
        assert!(lifecycle.begin_if_drained().is_ok());
    }

    #[test]
    fn 连续停止在worker释放前仍超时_释放后才排空() {
        let lifecycle = ObserverLifecycle::new();
        let generation = lifecycle.begin();
        let worker = lifecycle.worker(generation).unwrap();
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        std::thread::spawn(move || {
            let _worker = worker.attach_current_thread();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        ready_rx.recv().unwrap();

        let first = lifecycle.cancel_active_or_draining().unwrap();
        assert_eq!(first, generation);
        assert_eq!(
            lifecycle.wait(first, Duration::ZERO),
            StopOutcome::TimedOut { remaining: 1 }
        );

        let second = lifecycle.cancel_active_or_draining().unwrap();
        assert_eq!(second, generation);
        assert_eq!(
            lifecycle.wait(second, Duration::ZERO),
            StopOutcome::TimedOut { remaining: 1 }
        );

        release_tx.send(()).unwrap();
        let third = lifecycle.cancel_active_or_draining().unwrap();
        assert_eq!(third, generation);
        assert_eq!(
            lifecycle.wait(third, Duration::from_secs(1)),
            StopOutcome::Drained
        );
        assert!(lifecycle.cancel_active_or_draining().is_none());
        assert!(lifecycle.begin_if_drained().is_ok());
    }

    #[test]
    fn 已排队callback在取消后提交会被丢弃() {
        let lifecycle = ObserverLifecycle::new();
        let generation = lifecycle.begin();
        let writes = AtomicUsize::new(0);
        lifecycle.cancel(generation);

        assert!(lifecycle
            .commit(generation, || writes.fetch_add(1, Ordering::SeqCst))
            .is_none());
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}
