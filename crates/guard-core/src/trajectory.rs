//! Executed-trajectory state and per-action conformance (Aura §4.3.2).
//!
//! The trajectory is `T = {(I_user, A₁…Aₜ)}`: the declared task, plus every step
//! actually taken. Each candidate step is checked against the task's
//! [`guard_schema::TaskPlan`] **and** against the steps already executed — the
//! second half is what the previous label comparison had no way to do.
//!
//! # Drift latches until a human re-anchors
//!
//! Aura calls the recovery step "re-anchoring": the guard re-presents the original
//! instruction and the user decides. Here, once a step is refused the trajectory is
//! **off-plan** and stays off-plan, so every subsequent plan step is refused too.
//!
//! That is not extra strictness for its own sake. Twice now a check in this codebase
//! fired once and then let the next identical attempt through — an impersonation
//! verdict, and a declassification — which means the attacker pays one prompt and
//! proceeds. A drift verdict has exactly the same shape, so it gets the same
//! treatment: only [`Trajectory::reanchor`] clears it, and only the confirm gate
//! calls that.

use guard_schema::{StepKind, TaskPlan};

/// One executed step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub kind: StepKind,
    /// App the step acted on, for the message.
    pub app: String,
    /// Whether this step conformed to the plan.
    pub justified: bool,
}

/// Why a step does not belong to the declared task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftKind {
    /// The plan does not list this step kind at all.
    OutOfPlan { kind: StepKind },
    /// The plan lists it, but this occurrence exceeds the allowance. The label is
    /// right and the *count* is wrong — a second payment in a one-payment task.
    OverBudget {
        kind: StepKind,
        limit: u32,
        seen: u32,
    },
    /// The plan lists it, the count is fine, and it came too early: a prerequisite
    /// step has not happened. Same task label, wrong sequence.
    OutOfOrder { kind: StepKind, missing: StepKind },
    /// The task's terminal step has already run, so the task is finished and this
    /// step was not asked for.
    AfterTerminal { kind: StepKind, terminal: StepKind },
    /// The trajectory is already off-plan and has not been re-anchored.
    Unanchored { kind: StepKind, first: String },
    /// The session declared a task profile with no plan in the library, and the
    /// library requires one.
    NoPlan { profile: String },
}

impl DriftKind {
    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::OutOfPlan { .. } => "PLAN-OUT-OF-SCOPE",
            Self::OverBudget { .. } => "PLAN-OVER-BUDGET",
            Self::OutOfOrder { .. } => "PLAN-OUT-OF-ORDER",
            Self::AfterTerminal { .. } => "PLAN-AFTER-COMPLETION",
            Self::Unanchored { .. } => "PLAN-UNANCHORED",
            Self::NoPlan { .. } => "PLAN-MISSING",
        }
    }

    pub fn explain(&self, goal: &str) -> String {
        let goal = if goal.is_empty() {
            String::new()
        } else {
            format!(" (task: {goal})")
        };
        match self {
            Self::OutOfPlan { kind } => format!(
                "'{}' is not a step this task performs{goal}",
                kind.label()
            ),
            Self::OverBudget { kind, limit, seen } => format!(
                "'{}' has already happened {limit} time(s), which is all this task allows; this is #{seen}{goal}",
                kind.label()
            ),
            Self::OutOfOrder { kind, missing } => format!(
                "'{}' came before '{}', which this task requires first{goal}",
                kind.label(),
                missing.label()
            ),
            Self::AfterTerminal { kind, terminal } => format!(
                "the task completed at '{}', so '{}' was not part of it{goal}",
                terminal.label(),
                kind.label()
            ),
            Self::Unanchored { kind, first } => format!(
                "the agent left this task's plan earlier ({first}) and has not been re-anchored, so '{}' cannot be justified{goal}",
                kind.label()
            ),
            Self::NoPlan { profile } => format!(
                "no plan on record for task '{profile}', and this deployment requires one"
            ),
        }
    }
}

/// The executed trajectory for one session.
#[derive(Debug)]
pub struct Trajectory {
    /// The declared task (`I_user`, as far as we can observe it).
    profile: Option<String>,
    plan: Option<TaskPlan>,
    /// Set when the named profile had no plan and the library permits that. Steps
    /// are then recorded but not judged — and the *reason* is reported once, so a
    /// missing plan is visible rather than silently permissive.
    unplanned: bool,
    steps: Vec<Step>,
    counts: std::collections::BTreeMap<StepKind, u32>,
    terminal_reached: bool,
    /// First drift, if any. Non-`None` means off-plan until re-anchored.
    off_plan: Option<String>,
}

impl Default for Trajectory {
    /// An engine that has seen no `agent_session_start` has nothing to align
    /// against, so its steps are recorded and **not judged**.
    ///
    /// `unplanned: true` is load-bearing: with the field defaulting to `false`,
    /// every event outside a declared session produced `PLAN-MISSING`, which turned
    /// "we were never told the task" into an accusation against the agent.
    fn default() -> Self {
        Self {
            profile: None,
            plan: None,
            unplanned: true,
            steps: Vec::new(),
            counts: std::collections::BTreeMap::new(),
            terminal_reached: false,
            off_plan: None,
        }
    }
}

impl Trajectory {
    /// Begin a new trajectory. Clears everything: a new session is a new `I_user`,
    /// and a pin or a drift latch that outlived its session would be judging one
    /// task by another's plan.
    pub fn start(&mut self, profile: Option<String>, plan: Option<TaskPlan>, unplanned: bool) {
        *self = Self {
            profile,
            plan,
            unplanned,
            ..Self::default()
        };
    }

    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    pub fn plan(&self) -> Option<&TaskPlan> {
        self.plan.as_ref()
    }

    pub fn is_off_plan(&self) -> bool {
        self.off_plan.is_some()
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Fraction of non-observation steps that did not conform. Aura's
    /// self-consistency pass in the only form a deterministic corpus can support.
    ///
    /// `None` when no judged step has run — reported as "not measured" rather than
    /// as a perfect 0.0, because a score of zero drift over zero steps is exactly
    /// the kind of unearned number this project has had to correct before.
    pub fn drift_score(&self) -> Option<f32> {
        let judged: Vec<&Step> = self
            .steps
            .iter()
            .filter(|s| !s.kind.is_observation())
            .collect();
        if judged.is_empty() {
            return None;
        }
        let bad = judged.iter().filter(|s| !s.justified).count();
        Some(bad as f32 / judged.len() as f32)
    }

    /// The last recorded step was refused by the guard and then approved by the user,
    /// so it executed after all: charge it to the budget and completion state.
    ///
    /// Without this, an approved payment cost nothing — the user could confirm the
    /// same one-payment task indefinitely, each time being told it was fine.
    pub fn recommit_last_as_executed(&mut self) {
        let Some(last) = self.steps.last() else {
            return;
        };
        if !last.justified || last.kind.is_observation() {
            return;
        }
        let kind = last.kind;
        *self.counts.entry(kind).or_insert(0) += 1;
        if self.plan.as_ref().and_then(|p| p.terminal) == Some(kind) {
            self.terminal_reached = true;
        }
    }

    /// Human re-anchoring: the user has re-confirmed the task, so the latch clears
    /// and the budget/order state is rebuilt from the steps that *did* conform.
    ///
    /// Only a confirmed human decision may call this. Clearing the latch on the
    /// agent's word would make the latch decorative.
    pub fn reanchor(&mut self) {
        self.off_plan = None;
        self.steps.retain(|s| s.justified);
        self.counts.clear();
        self.terminal_reached = false;
        let kinds: Vec<StepKind> = self.steps.iter().map(|s| s.kind).collect();
        let terminal = self.plan.as_ref().and_then(|p| p.terminal);
        for k in kinds {
            *self.counts.entry(k).or_insert(0) += 1;
            if Some(k) == terminal {
                self.terminal_reached = true;
            }
        }
    }

    /// Judge a candidate step **without recording it**, then let the caller commit
    /// once the final decision is known.
    ///
    /// Splitting judge from commit is not tidiness. Recording at judge time counted
    /// steps that never happened: a payment the guard *blocked* burned the task's
    /// one-payment budget, so the user's real payment afterwards reported "this is
    /// #2"; and a payment the **user denied** set `terminal_reached`, after which
    /// every legitimate step was `PLAN-AFTER-COMPLETION`. A refused step is an
    /// attempt, not an execution.
    pub fn judge_only(&self, kind: StepKind) -> Option<DriftKind> {
        if kind.is_observation() {
            return None;
        }
        self.judge(kind)
    }

    /// Record a step that actually executed (or was attempted and refused).
    ///
    /// `executed` false records the attempt for the drift score and the latch but
    /// leaves budgets and the terminal flag untouched — the step did not happen.
    pub fn commit(&mut self, kind: StepKind, app: &str, drift: Option<&DriftKind>, executed: bool) {
        let justified = drift.is_none();
        if let Some(d) = drift {
            if self.off_plan.is_none() {
                self.off_plan = Some(d.explain(self.goal()));
            }
        } else if executed {
            *self.counts.entry(kind).or_insert(0) += 1;
            if self.plan.as_ref().and_then(|p| p.terminal) == Some(kind) {
                self.terminal_reached = true;
            }
        }
        self.steps.push(Step {
            kind,
            app: app.to_string(),
            justified,
        });
    }

    /// Judge and record in one call, treating the step as executed. Convenience for
    /// tests and for callers that already know the step went through.
    pub fn evaluate(&mut self, kind: StepKind, app: &str) -> Option<DriftKind> {
        // Observation is not an action: it is recorded for context and never judged.
        // Counting it would make every plan a list of everything the agent might
        // happen to see on screen.
        if kind.is_observation() {
            self.steps.push(Step {
                kind,
                app: app.to_string(),
                justified: true,
            });
            return None;
        }

        let drift = self.judge(kind);
        let justified = drift.is_none();
        if let Some(d) = &drift {
            if self.off_plan.is_none() {
                self.off_plan = Some(d.explain(self.goal()));
            }
        } else {
            *self.counts.entry(kind).or_insert(0) += 1;
            if self.plan.as_ref().and_then(|p| p.terminal) == Some(kind) {
                self.terminal_reached = true;
            }
        }
        self.steps.push(Step {
            kind,
            app: app.to_string(),
            justified,
        });
        drift
    }

    fn goal(&self) -> &str {
        self.plan.as_ref().map(|p| p.goal.as_str()).unwrap_or("")
    }

    fn judge(&self, kind: StepKind) -> Option<DriftKind> {
        // Already off-plan: everything after the first unjustified step is
        // unjustified until a human re-anchors.
        if let Some(first) = &self.off_plan {
            return Some(DriftKind::Unanchored {
                kind,
                first: first.clone(),
            });
        }

        let Some(plan) = &self.plan else {
            // No plan. `NoPlan` is only a finding when a task *was* declared and the
            // library requires one; with nothing declared there is no claim to check
            // against, and reporting drift there would blame the agent for the
            // host's omission.
            return match (&self.profile, self.unplanned) {
                (Some(profile), false) => Some(DriftKind::NoPlan {
                    profile: profile.clone(),
                }),
                _ => None,
            };
        };

        if !plan.permits(kind) {
            return Some(DriftKind::OutOfPlan { kind });
        }
        let seen = self.counts.get(&kind).copied().unwrap_or(0);
        if let Some(limit) = plan.limit(kind) {
            if seen >= limit {
                return Some(DriftKind::OverBudget {
                    kind,
                    limit,
                    seen: seen + 1,
                });
            }
        }
        // Ordering: every entry before this one in `order` must already have run.
        if let Some(pos) = plan.order.iter().position(|k| *k == kind) {
            for earlier in &plan.order[..pos] {
                if self.counts.get(earlier).copied().unwrap_or(0) == 0 {
                    return Some(DriftKind::OutOfOrder {
                        kind,
                        missing: *earlier,
                    });
                }
            }
        }
        if self.terminal_reached {
            if let Some(t) = plan.terminal {
                return Some(DriftKind::AfterTerminal { kind, terminal: t });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_schema::TaskPlanLibrary;

    fn plan(yaml: &str) -> TaskPlan {
        TaskPlanLibrary::from_yaml_str(yaml)
            .unwrap()
            .plans
            .into_iter()
            .next()
            .unwrap()
    }

    fn booking() -> Trajectory {
        let p = plan(
            "plans:\n  - task_profile: book_hotel\n    goal: \"Reserve a room and pay once\"\n    allow: [disclose_low, disclose_high, confirm_payment]\n    max:\n      confirm_payment: 1\n      network_egress: 0\n    order: [disclose_low, confirm_payment]\n    terminal: confirm_payment\n",
        );
        let mut t = Trajectory::default();
        t.start(Some("book_hotel".into()), Some(p), false);
        t
    }

    #[test]
    fn a_conforming_trajectory_is_silent() {
        let mut t = booking();
        assert!(t.evaluate(StepKind::Observe, "Chrome").is_none());
        assert!(t.evaluate(StepKind::DiscloseLow, "Booking").is_none());
        assert!(t.evaluate(StepKind::DiscloseHigh, "Booking").is_none());
        assert!(t.evaluate(StepKind::ConfirmPayment, "Booking").is_none());
        assert!(!t.is_off_plan());
        assert_eq!(t.drift_score(), Some(0.0));
    }

    #[test]
    fn a_step_the_plan_does_not_list_is_out_of_scope() {
        let mut t = booking();
        let d = t.evaluate(StepKind::RunShell, "Terminal").unwrap();
        assert_eq!(d.rule_id(), "PLAN-OUT-OF-SCOPE");
        assert!(d.explain("Reserve a room").contains("run_shell"));
    }

    /// The label-preserving drift the string comparison could not see: the right
    /// step kind, the right task label, one time too many.
    #[test]
    fn a_second_payment_is_over_budget() {
        let mut t = booking();
        t.evaluate(StepKind::DiscloseLow, "Booking");
        assert!(t.evaluate(StepKind::ConfirmPayment, "Booking").is_none());
        // The budget check runs before the terminal check, deliberately: "you have
        // already paid once and this is payment #2" is a more specific and more
        // actionable statement than "the task was already over".
        let d = t.evaluate(StepKind::ConfirmPayment, "Booking").unwrap();
        assert_eq!(d.rule_id(), "PLAN-OVER-BUDGET");
        assert!(d.explain("").contains("this is #2"), "{}", d.explain(""));
    }

    #[test]
    fn over_budget_fires_without_a_terminal_step() {
        let p = plan(
            "plans:\n  - task_profile: t\n    allow: [persist_memory]\n    max:\n      persist_memory: 2\n",
        );
        let mut t = Trajectory::default();
        t.start(Some("t".into()), Some(p), false);
        assert!(t.evaluate(StepKind::PersistMemory, "a").is_none());
        assert!(t.evaluate(StepKind::PersistMemory, "a").is_none());
        let d = t.evaluate(StepKind::PersistMemory, "a").unwrap();
        assert_eq!(d.rule_id(), "PLAN-OVER-BUDGET");
        assert!(d.explain("").contains("#3"), "{}", d.explain(""));
    }

    /// Same two step kinds, same task label, wrong order.
    #[test]
    fn a_payment_before_any_disclosure_is_out_of_order() {
        let mut t = booking();
        let d = t.evaluate(StepKind::ConfirmPayment, "Booking").unwrap();
        assert_eq!(d.rule_id(), "PLAN-OUT-OF-ORDER");
        assert!(d.explain("").contains("disclose_low"));
    }

    #[test]
    fn plan_steps_after_the_terminal_step_are_drift() {
        let mut t = booking();
        t.evaluate(StepKind::DiscloseLow, "Booking");
        t.evaluate(StepKind::ConfirmPayment, "Booking");
        let d = t.evaluate(StepKind::DiscloseHigh, "Booking").unwrap();
        assert_eq!(d.rule_id(), "PLAN-AFTER-COMPLETION");
        // Observation after completion is still fine.
        let mut t2 = booking();
        t2.evaluate(StepKind::DiscloseLow, "Booking");
        t2.evaluate(StepKind::ConfirmPayment, "Booking");
        assert!(t2.evaluate(StepKind::Observe, "Booking").is_none());
    }

    /// Two earlier checks in this codebase fired once and let the next attempt
    /// through. A drift verdict has the same shape, so it latches.
    #[test]
    fn drift_latches_until_a_human_reanchors() {
        let mut t = booking();
        t.evaluate(StepKind::DiscloseLow, "Booking");
        assert_eq!(
            t.evaluate(StepKind::RunShell, "Terminal")
                .unwrap()
                .rule_id(),
            "PLAN-OUT-OF-SCOPE"
        );
        // Retrying something the plan *does* allow is still refused.
        let d = t.evaluate(StepKind::DiscloseHigh, "Booking").unwrap();
        assert_eq!(d.rule_id(), "PLAN-UNANCHORED");
        assert!(d.explain("").contains("run_shell"), "names the first drift");

        t.reanchor();
        assert!(!t.is_off_plan());
        // The conforming prefix survives, so ordering still holds…
        assert!(t.evaluate(StepKind::ConfirmPayment, "Booking").is_none());
        // …and the unjustified steps are gone from the record.
        assert!(t.steps().iter().all(|s| s.justified));
    }

    /// Re-anchoring must not hand back a spent budget.
    #[test]
    fn reanchoring_preserves_counts_of_conforming_steps() {
        let mut t = booking();
        t.evaluate(StepKind::DiscloseLow, "Booking");
        t.evaluate(StepKind::ConfirmPayment, "Booking");
        t.evaluate(StepKind::RunShell, "Terminal");
        t.reanchor();
        // The payment already happened and the task already completed.
        assert_eq!(
            t.evaluate(StepKind::ConfirmPayment, "Booking")
                .unwrap()
                .rule_id(),
            "PLAN-OVER-BUDGET"
        );
    }

    #[test]
    fn drift_score_is_none_before_any_judged_step() {
        let mut t = booking();
        assert_eq!(t.drift_score(), None);
        t.evaluate(StepKind::Observe, "Chrome");
        assert_eq!(
            t.drift_score(),
            None,
            "observation is not a judged step, so it must not produce a 0.0"
        );
        t.evaluate(StepKind::RunShell, "Terminal");
        assert_eq!(t.drift_score(), Some(1.0));
    }

    #[test]
    fn an_unplanned_task_is_recorded_but_not_judged() {
        let mut t = Trajectory::default();
        t.start(Some("unknown_task".into()), None, true);
        assert!(t.evaluate(StepKind::RunShell, "Terminal").is_none());
        assert!(!t.is_off_plan());
        // …unless the library requires a plan.
        let mut t = Trajectory::default();
        t.start(Some("unknown_task".into()), None, false);
        let d = t.evaluate(StepKind::RunShell, "Terminal").unwrap();
        assert_eq!(d.rule_id(), "PLAN-MISSING");
    }

    #[test]
    fn starting_a_new_trajectory_clears_the_latch() {
        let mut t = booking();
        t.evaluate(StepKind::RunShell, "Terminal");
        assert!(t.is_off_plan());
        t.start(Some("book_hotel".into()), t.plan().cloned(), false);
        assert!(!t.is_off_plan());
        assert!(t.steps().is_empty());
        assert_eq!(t.drift_score(), None);
    }
}
