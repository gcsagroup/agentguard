//! AX 原生调用的单飞与墙钟超时隔离。
//!
//! macOS 的 AX IPC 最终会进入 Mach 消息等待。即使目标应用失去响应，调用方也不能把
//! `AppState.adapter`、规则引擎或待确认队列的锁一起带进系统调用。这个 gate 只保护 AX
//! 原生桥自身的全局状态，并把调用放到独立线程；超时只放弃结果，不假装杀掉系统线程。
//! 尚未真正返回的调用会一直占着单飞槽，因此后续 tick 只会收到 `Busy`，不会继续堆线程。

use crate::{ObserverGeneration, ObserverLifecycle, ObserverWorker};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
struct InFlight {
    call_id: u64,
    generation: Option<ObserverGeneration>,
    operation: &'static str,
}

#[derive(Default)]
struct Inner {
    next_call_id: AtomicU64,
    in_flight: Mutex<Option<InFlight>>,
}

/// 所有 AX FFI 的进程内单飞入口。
#[derive(Clone, Default)]
pub struct AxNativeGate {
    inner: Arc<Inner>,
}

/// AX 原生调用在进入桥之前、桥内或等待结果时的失败。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AxNativeCallFailure {
    Busy {
        call_id: u64,
        generation: Option<ObserverGeneration>,
        operation: &'static str,
    },
    StaleGeneration(ObserverGeneration),
    Spawn(String),
    TimedOut {
        call_id: u64,
        operation: &'static str,
        timeout_ms: u128,
    },
    Disconnected {
        call_id: u64,
        operation: &'static str,
    },
    Native(String),
}

impl AxNativeCallFailure {
    /// 普通桥错误（例如某个应用不支持 AXObserver）可由调用方降级到兜底轮询；
    /// Busy/超时/线程故障则表示原生执行面不再可靠，必须停掉当前观察代际。
    pub fn is_native_error(&self) -> bool {
        matches!(self, Self::Native(_))
    }
}

impl fmt::Display for AxNativeCallFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy {
                call_id,
                generation,
                operation,
            } => write!(
                f,
                "AX native call busy: {operation} call {call_id} (generation {generation:?}) is still running; restart may be required"
            ),
            Self::StaleGeneration(generation) => {
                write!(f, "AX generation {generation} was cancelled before native call")
            }
            Self::Spawn(error) => write!(f, "spawn AX native worker: {error}"),
            Self::TimedOut {
                call_id,
                operation,
                timeout_ms,
            } => write!(
                f,
                "AX native {operation} timed out after {timeout_ms} ms (call {call_id}); observation degraded and restart may be required"
            ),
            Self::Disconnected { call_id, operation } => write!(
                f,
                "AX native {operation} worker disconnected (call {call_id}); observation degraded"
            ),
            Self::Native(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for AxNativeCallFailure {}

struct Permit {
    gate: AxNativeGate,
    call_id: u64,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.finish(self.call_id);
    }
}

impl AxNativeGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_busy(&self) -> bool {
        lock_unpoisoned(&self.inner.in_flight).is_some()
    }

    /// 在独立线程执行一个可能阻塞的 AX 调用，并给调用方一个墙钟上限。
    ///
    /// `lifecycle` 存在时，原生子线程也登记为同一观察代际的 worker。这样外层超时后，
    /// stop 会如实报告尚未排空，新代际也会在旧系统调用真正返回前被拒绝。
    pub fn call<T, F>(
        &self,
        generation: Option<ObserverGeneration>,
        lifecycle: Option<&ObserverLifecycle>,
        operation: &'static str,
        timeout: Duration,
        native: F,
    ) -> Result<T, AxNativeCallFailure>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, String> + Send + 'static,
    {
        let permit = self.acquire(generation, operation)?;
        let call_id = permit.call_id;
        let worker = match (generation, lifecycle) {
            (Some(generation), Some(lifecycle)) => Some(
                lifecycle
                    .worker(generation)
                    .ok_or(AxNativeCallFailure::StaleGeneration(generation))?,
            ),
            _ => None,
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let thread_name = format!("agentguard-ax-native-{call_id}");
        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let _worker = worker.map(ObserverWorker::attach_current_thread);
                let result = native().map_err(AxNativeCallFailure::Native);
                // 原生桥已经返回，先释放单飞槽；下一次调用无需等接收线程被调度。
                drop(permit);
                let _ = tx.send(result);
            })
            .map_err(|error| AxNativeCallFailure::Spawn(error.to_string()))?;

        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(AxNativeCallFailure::TimedOut {
                call_id,
                operation,
                timeout_ms: timeout.as_millis(),
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(AxNativeCallFailure::Disconnected { call_id, operation })
            }
        }
    }

    /// 只给不进入目标进程 IPC 的常数时间桥操作使用（当前仅通知计数提取）。
    /// 它仍经过同一个槽，避免与 start/stop/snapshot 的 Objective-C 全局状态并发。
    pub fn call_inline<T>(
        &self,
        generation: Option<ObserverGeneration>,
        operation: &'static str,
        native: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, AxNativeCallFailure> {
        let _permit = self.acquire(generation, operation)?;
        native().map_err(AxNativeCallFailure::Native)
    }

    fn acquire(
        &self,
        generation: Option<ObserverGeneration>,
        operation: &'static str,
    ) -> Result<Permit, AxNativeCallFailure> {
        let mut slot = lock_unpoisoned(&self.inner.in_flight);
        if let Some(active) = slot.as_ref() {
            return Err(AxNativeCallFailure::Busy {
                call_id: active.call_id,
                generation: active.generation,
                operation: active.operation,
            });
        }
        let call_id = loop {
            let next = self
                .inner
                .next_call_id
                .fetch_add(1, Ordering::SeqCst)
                .wrapping_add(1);
            if next != 0 {
                break next;
            }
        };
        *slot = Some(InFlight {
            call_id,
            generation,
            operation,
        });
        Ok(Permit {
            gate: self.clone(),
            call_id,
        })
    }

    fn finish(&self, call_id: u64) {
        let mut slot = lock_unpoisoned(&self.inner.in_flight);
        if slot
            .as_ref()
            .is_some_and(|active| active.call_id == call_id)
        {
            *slot = None;
        }
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
    use crate::StopOutcome;
    use std::sync::mpsc;

    #[test]
    fn 超时调用保持单飞且计入旧代际排空() {
        let gate = AxNativeGate::new();
        let lifecycle = ObserverLifecycle::new();
        let generation = lifecycle.begin();
        let caller_gate = gate.clone();
        let caller_lifecycle = lifecycle.clone();
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let caller = std::thread::spawn(move || {
            let result = caller_gate.call(
                Some(generation),
                Some(&caller_lifecycle),
                "snapshot",
                Duration::from_millis(25),
                move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(7_u8)
                },
            );
            if matches!(result, Err(AxNativeCallFailure::TimedOut { .. })) {
                caller_lifecycle.cancel(generation);
            }
            result
        });

        entered_rx.recv().unwrap();
        assert!(gate.is_busy());
        assert!(matches!(
            gate.call_inline(Some(generation), "take", || Ok(())),
            Err(AxNativeCallFailure::Busy { .. })
        ));
        assert!(matches!(
            caller.join().unwrap(),
            Err(AxNativeCallFailure::TimedOut { .. })
        ));
        assert_eq!(lifecycle.active(), None);
        assert_eq!(
            lifecycle.wait(generation, Duration::ZERO),
            StopOutcome::TimedOut { remaining: 1 }
        );
        assert_eq!(lifecycle.begin_if_drained(), Err(1));

        release_tx.send(()).unwrap();
        assert_eq!(
            lifecycle.wait(generation, Duration::from_secs(1)),
            StopOutcome::Drained
        );
        assert!(!gate.is_busy());
        assert!(lifecycle.begin_if_drained().is_ok());
    }

    #[test]
    fn 迟到的旧call_id不能清掉新槽位() {
        let gate = AxNativeGate::new();
        let first = gate.acquire(None, "first").unwrap();
        let old_call_id = first.call_id;
        drop(first);
        let second = gate.acquire(None, "second").unwrap();
        assert_ne!(second.call_id, old_call_id);

        gate.finish(old_call_id);
        assert!(gate.is_busy(), "旧调用的完成信号不得清除新调用槽位");
        drop(second);
        assert!(!gate.is_busy());
    }
}
