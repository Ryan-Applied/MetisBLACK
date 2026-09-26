//! Small, inspectable belief-state planner used before each assessment action.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Belief {
    pub probability: f64,
    pub observations: u32,
    pub receipts: Vec<String>,
}
impl Default for Belief {
    fn default() -> Self {
        Self {
            probability: 0.5,
            observations: 0,
            receipts: vec![],
        }
    }
}
impl Belief {
    pub fn entropy(&self) -> f64 {
        let p = self.probability.clamp(0.000_001, 0.999_999);
        -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
    }
    pub fn observe(&mut self, positive: bool, reliability: f64, receipt: &str) -> Result<()> {
        ensure!(
            (0.5..1.0).contains(&reliability),
            "reliability must be 0.5..1"
        );
        ensure!(!receipt.is_empty(), "observation requires receipt");
        if self.receipts.iter().any(|r| r == receipt) {
            return Ok(());
        }
        let likelihood = if positive {
            reliability
        } else {
            1.0 - reliability
        };
        let p = self.probability;
        self.probability = (p * likelihood / (p * likelihood + (1.0 - p) * (1.0 - likelihood)))
            .clamp(0.000_001, 0.999_999);
        self.observations += 1;
        self.receipts.push(receipt.into());
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorldModel {
    pub assets: BTreeMap<String, Belief>,
    pub hypotheses: BTreeMap<String, Belief>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Recon,
    Reproduce,
    Assess,
    Stop,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub action: DecisionKind,
    pub subject: String,
    pub value_of_information: f64,
    pub expected_value: f64,
    pub reason: String,
    pub alternatives: Vec<ActionValue>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionValue {
    pub action: DecisionKind,
    pub expected_reward: f64,
    pub information_gain: f64,
    pub cost: f64,
    pub risk: f64,
    pub utility: f64,
    pub admissible: bool,
}
impl WorldModel {
    pub fn decide(&self, subject: &str, remaining: u64) -> Decision {
        let belief = self
            .hypotheses
            .get(subject)
            .or_else(|| self.assets.get(subject))
            .cloned()
            .unwrap_or_default();
        // One-step lookahead over a Bayesian belief state. This is explicitly
        // a small finite action policy, not a learned long-horizon POMDP solver.
        let voi = belief.entropy() * 0.75;
        let mut alternatives = vec![
            ActionValue {
                action: DecisionKind::Recon,
                expected_reward: 0.0,
                information_gain: voi,
                cost: 0.10 + f64::from(belief.observations) * 0.08,
                risk: 0.01,
                utility: 0.0,
                admissible: remaining > 0,
            },
            ActionValue {
                action: DecisionKind::Assess,
                expected_reward: belief.probability * 0.8,
                information_gain: voi * 0.15,
                cost: 0.18,
                risk: 0.05,
                utility: 0.0,
                admissible: remaining > 0
                    && belief.observations > 0
                    && !self.hypotheses.contains_key(subject),
            },
            ActionValue {
                action: DecisionKind::Reproduce,
                expected_reward: belief.probability,
                information_gain: voi * 0.25,
                cost: 0.15,
                risk: 0.03,
                utility: 0.0,
                admissible: remaining > 0
                    && belief.observations > 0
                    && self.hypotheses.contains_key(subject),
            },
            ActionValue {
                action: DecisionKind::Stop,
                expected_reward: 0.0,
                information_gain: 0.0,
                cost: 0.0,
                risk: 0.0,
                utility: 0.0,
                admissible: true,
            },
        ];
        for a in &mut alternatives {
            a.utility = a.expected_reward + a.information_gain - a.cost - a.risk;
        }
        let selected = alternatives
            .iter()
            .filter(|a| a.admissible)
            .max_by(|a, b| a.utility.total_cmp(&b.utility))
            .expect("stop is always available");
        let action = selected.action.clone();
        let ev = selected.utility;
        let reason = if remaining == 0 {
            "Budget exhausted; stop is the only admissible action."
        } else {
            "Selected highest expected reward plus information gain minus cost and risk."
        };
        Decision {
            action,
            subject: subject.into(),
            value_of_information: voi,
            expected_value: ev,
            reason: reason.into(),
            alternatives,
        }
    }
    pub fn observe_asset(&mut self, target: &str, positive: bool, receipt: &str) -> Result<()> {
        self.assets
            .entry(target.into())
            .or_default()
            .observe(positive, 0.9, receipt)
    }
    pub fn observe_hypothesis(&mut self, id: &str, positive: bool, receipt: &str) -> Result<()> {
        self.hypotheses
            .entry(id.into())
            .or_default()
            .observe(positive, 0.9, receipt)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observations_change_runtime_decision() -> Result<()> {
        let mut w = WorldModel::default();
        assert_eq!(w.decide("f", 5).action, DecisionKind::Recon);
        w.observe_hypothesis("f", true, "receipt-1")?;
        assert_eq!(w.decide("f", 5).action, DecisionKind::Reproduce);
        assert_eq!(w.decide("f", 0).action, DecisionKind::Stop);
        Ok(())
    }
    #[test]
    fn duplicate_receipts_do_not_increase_belief() -> Result<()> {
        let mut b = Belief::default();
        b.observe(true, 0.9, "r")?;
        let p = b.probability;
        b.observe(true, 0.9, "r")?;
        assert_eq!(b.probability, p);
        Ok(())
    }
}
