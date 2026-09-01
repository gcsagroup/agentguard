//! Scenario evaluation: load YAML fixtures and drive the Engine offline.

mod acceptance;
mod capability_claims;
mod coverage;
mod leaderboard;
mod runner;
mod scenario;
mod scoreboard;

pub use acceptance::{
    default_scenarios_dir, write_acceptance_json, write_acceptance_markdown, AcceptanceManifest,
    AcceptanceReport, MacCapabilitiesSummary,
};
pub use capability_claims::{
    to_markdown as claims_markdown, verify as verify_claims, CapabilityClaim, ClaimProblem,
    ClaimSource, ClaimsRegistry, ClaimsReport, ProvingTest,
};
pub use coverage::{
    to_markdown as coverage_markdown, verify as verify_coverage, CoverageMatrix, CoverageProblem,
    CoverageReport, CoverageStatus, ScenarioFacts, Surface, ENGINE_EMITTED_RULE_IDS,
};
pub use leaderboard::{
    build_leaderboard, comparability_errors, load_agent_dir, score_agent, synthesize_suite_events,
    verify_comparable, write_leaderboard_html, write_leaderboard_json, AgentProfile, AgentScore,
    LeaderboardReport, ProbeDimension, ProbeResponse, ProbeSuite, SuiteProbe, REQUIRED_DIMENSIONS,
};
pub use runner::{EvalReport, EvalRunner, ScenarioResult};
pub use scenario::*;
pub use scoreboard::{write_scoreboard_html, write_scoreboard_json, ScoreboardReport};
