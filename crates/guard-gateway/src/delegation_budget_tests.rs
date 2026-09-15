//! 原子预算的实际多线程竞争与确定性单调时钟负例，不替代网关／Docker 验收。
use super::*;
use std::sync::Barrier;

fn limits() -> BudgetLimits {
    BudgetLimits {
        max_depth: 3,
        max_calls: 64,
        max_output_bytes: 4096,
        max_elapsed_ms: 1000,
    }
}
fn child(tree: &BudgetTree, parent: &str, id: &str, bounds: &BudgetLimits, now: Instant) {
    let mut permit = tree.reserve(parent, 1, now).unwrap();
    permit.mark_started(now).unwrap();
    permit.create_child(id, bounds, now).unwrap();
    permit.finish(0, now).unwrap();
}
fn node(tree: &BudgetTree, id: &str, now: Instant) -> NodeStatus {
    tree.status(now)
        .unwrap()
        .nodes
        .into_iter()
        .find(|n| n.grant_id == id)
        .unwrap()
}

#[test]
fn 最小回执额度不足时不消费调用也不部分预留() {
    let now = Instant::now();
    let tree = BudgetTree::new("A", limits(), now).unwrap();
    let permit = tree.reserve_at_least("A", 4096, 1024, now).unwrap();
    permit.finish(3500, now).unwrap();
    assert!(tree.reserve_at_least("A", 4096, 1024, now).is_err());
    let state = node(&tree, "A", now);
    assert_eq!(state.used_calls, 1);
    assert_eq!(state.used_output_bytes, 3500);
    assert_eq!(state.reserved_output_bytes, 0);
}

#[test]
fn 审计失败与撤销均不提前释放输出预留() {
    let now = Instant::now();
    for revoke in [false, true] {
        let tree = BudgetTree::new("A", limits(), now).unwrap();
        let permit = tree.reserve("A", 4096, now).unwrap();
        if revoke {
            tree.revoke("A").unwrap();
        }
        let mut recorded = false;
        let result = permit.finish_recorded(100, now, |allowed| {
            recorded = true;
            assert_eq!(allowed, !revoke);
            if revoke {
                Ok(())
            } else {
                anyhow::bail!("合成审计写入故障")
            }
        });
        assert!(result.is_err());
        assert!(recorded);
        let state = node(&tree, "A", now);
        assert_eq!(state.used_output_bytes, 4096);
        assert_eq!(state.reserved_output_bytes, 0);
        assert!(tree.reserve("A", 1, now).is_err());
    }
}

#[test]
fn 多线程兄弟分支共享祖先调用预算不能透支() {
    let now = Instant::now();
    let mut bound = limits();
    bound.max_calls = 32;
    let tree = BudgetTree::new("A", bound.clone(), now).unwrap();
    for index in 0..8 {
        child(&tree, "A", &format!("B{index}"), &bound, now);
    }
    let barrier = Arc::new(Barrier::new(8));
    let threads = (0..8)
        .map(|index| {
            let tree = tree.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut count = 0;
                for _ in 0..16 {
                    if let Ok(mut permit) = tree.reserve(&format!("B{index}"), 1, now) {
                        permit.mark_started(now).unwrap();
                        permit.finish(0, now).unwrap();
                        count += 1;
                    }
                }
                count
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        threads.into_iter().map(|t| t.join().unwrap()).sum::<u64>(),
        24
    );
    let root = node(&tree, "A", now);
    assert_eq!((root.used_calls, root.remaining_calls), (32, 0));
    assert_eq!(
        tree.status(now)
            .unwrap()
            .nodes
            .iter()
            .filter(|n| n.grant_id != "A")
            .map(|n| n.used_calls)
            .sum::<u64>(),
        24
    );
}

#[test]
fn 并发预留输出在结束前已经约束其它分支() {
    let now = Instant::now();
    let mut bound = limits();
    bound.max_output_bytes = 100;
    let tree = BudgetTree::new("A", bound.clone(), now).unwrap();
    for index in 0..8 {
        child(&tree, "A", &format!("B{index}"), &bound, now);
    }
    let barrier = Arc::new(Barrier::new(9));
    let (sender, receiver) = std::sync::mpsc::channel();
    let threads = (0..8)
        .map(|index| {
            let tree = tree.clone();
            let barrier = barrier.clone();
            let sender = sender.clone();
            std::thread::spawn(move || {
                let permit = tree.reserve(&format!("B{index}"), 80, now).ok();
                let bytes = permit.as_ref().map_or(0, BudgetPermit::output_limit);
                sender.send(bytes).unwrap();
                barrier.wait();
                if let Some(permit) = permit {
                    permit.finish(bytes, now).unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    let total = (0..8).map(|_| receiver.recv().unwrap()).sum::<u64>();
    assert_eq!(total, 100);
    assert_eq!(node(&tree, "A", now).reserved_output_bytes, 100);
    assert!(tree.reserve("A", 1, now).is_err());
    barrier.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    let root = node(&tree, "A", now);
    assert_eq!(
        (
            root.used_output_bytes,
            root.reserved_output_bytes,
            root.remaining_output_bytes
        ),
        (100, 0, 0)
    );
}

#[test]
fn 失去许可消费全部预留而已知短输出只消费实际字节() {
    let now = Instant::now();
    let tree = BudgetTree::new("A", limits(), now).unwrap();
    let permit = tree.reserve("A", 50, now).unwrap();
    drop(permit);
    let permit = tree.reserve("A", 50, now).unwrap();
    permit.finish(7, now).unwrap();
    let root = node(&tree, "A", now);
    assert_eq!(
        (
            root.used_calls,
            root.used_output_bytes,
            root.reserved_output_bytes
        ),
        (2, 57, 0)
    );
    assert_eq!(root.remaining_output_bytes, 4096 - 57);
}

#[test]
fn 子深度递减且一次许可不能制造多个子节点() {
    let now = Instant::now();
    let mut bound = limits();
    bound.max_depth = 1;
    let tree = BudgetTree::new("A", bound, now).unwrap();
    let mut permit = tree.reserve("A", 40, now).unwrap();
    assert!(permit.create_child("B", &limits(), now).is_err());
    permit.mark_started(now).unwrap();
    assert!(permit.mark_started(now).is_err());
    let actual = permit.create_child("B", &limits(), now).unwrap();
    assert_eq!(actual.max_depth, 0);
    assert!(permit.create_child("C", &limits(), now).is_err());
    permit.finish(1, now).unwrap();
    let mut child_permit = tree.reserve("B", 40, now).unwrap();
    child_permit.mark_started(now).unwrap();
    assert!(child_permit.create_child("C", &limits(), now).is_err());
    assert_eq!(tree.status(now).unwrap().nodes.len(), 2);
}

#[test]
fn 父撤销阻止后代尚未开始许可且不误伤兄弟() {
    let now = Instant::now();
    let tree = BudgetTree::new("A", limits(), now).unwrap();
    child(&tree, "A", "B", &limits(), now);
    child(&tree, "B", "C", &limits(), now);
    child(&tree, "A", "D", &limits(), now);
    let mut waiting = tree.reserve("C", 40, now).unwrap();
    let mut sibling = tree.reserve("D", 40, now).unwrap();
    assert_eq!(tree.revoke("B").unwrap(), 2);
    assert_eq!(tree.revoke("B").unwrap(), 0);
    assert!(waiting.check(now).is_err());
    assert!(waiting.mark_started(now).is_err());
    assert!(waiting.finish(1, now).is_err());
    assert!(tree.reserve("C", 1, now).is_err());
    sibling.mark_started(now).unwrap();
    sibling.finish(5, now).unwrap();
    assert_eq!(node(&tree, "C", now).used_output_bytes, 40);
    assert_eq!(node(&tree, "D", now).used_output_bytes, 5);
    assert!(!node(&tree, "D", now).revoked);
}

#[test]
fn 父期限不因迟建子节点而延长且过期结果不得公开() {
    let now = Instant::now();
    let tree = BudgetTree::new("A", limits(), now).unwrap();
    let late = now + Duration::from_millis(900);
    child(&tree, "A", "B", &limits(), late);
    assert_eq!(node(&tree, "B", late).remaining_ms, 100);
    let mut permit = tree.reserve("B", 40, late).unwrap();
    permit.mark_started(late).unwrap();
    let expired = now + Duration::from_millis(1000);
    assert!(permit.finish(4, expired).is_err());
    assert!(tree.reserve("B", 1, expired).is_err());
    assert!(tree
        .reserve("A", 1, now - Duration::from_millis(1))
        .is_err());
    assert_eq!(node(&tree, "B", expired).used_output_bytes, 40);
}

#[test]
fn 超出输出预留不能公开或恢复预算且关闭使所有旧许可失效() {
    let now = Instant::now();
    let tree = BudgetTree::new("A", limits(), now).unwrap();
    let permit = tree.reserve("A", 10, now).unwrap();
    assert!(permit.finish(11, now).is_err());
    assert_eq!(node(&tree, "A", now).used_output_bytes, 10);
    let mut old = tree.reserve("A", 15, now).unwrap();
    tree.close().unwrap();
    assert!(old.mark_started(now).is_err());
    assert!(old.finish(0, now).is_err());
    assert!(tree.reserve("A", 1, now).is_err());
    assert_eq!(node(&tree, "A", now).used_output_bytes, 25);
    assert!(tree.status(now).unwrap().closed);
}

#[test]
fn 预算失败不部分扣减祖先并拒绝无效上限与锁故障() {
    let now = Instant::now();
    let tree = BudgetTree::new("A", limits(), now).unwrap();
    let mut small = limits();
    small.max_calls = 1;
    child(&tree, "A", "B", &small, now);
    tree.reserve("B", 1, now).unwrap().finish(0, now).unwrap();
    let before = node(&tree, "A", now).used_calls;
    assert!(tree.reserve("B", 1, now).is_err());
    assert_eq!(node(&tree, "A", now).used_calls, before);
    for field in ["max_calls", "max_output_bytes", "max_elapsed_ms"] {
        let mut value = serde_json::to_value(limits()).unwrap();
        value[field] = serde_json::json!(0);
        assert!(serde_json::from_value::<BudgetLimits>(value)
            .unwrap()
            .validate()
            .is_err());
    }
    let clone = tree.clone();
    assert!(std::thread::spawn(move || {
        let _lock = clone.0.lock().unwrap();
        panic!("合成预算锁故障");
    })
    .join()
    .is_err());
    assert!(tree.reserve("A", 1, now).is_err());
    assert!(tree.status(now).is_err());
}
