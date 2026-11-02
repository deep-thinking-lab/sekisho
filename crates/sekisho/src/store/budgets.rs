use super::{StoreError, Tx};
use rusqlite::{OptionalExtension, params};
use sekisho_core::{AgentId, Budget, Timestamp};

fn window_start(budget: Budget, now: Timestamp) -> Result<i64, StoreError> {
    let period = i64::from(budget.per_seconds);
    if period == 0 {
        return Err(StoreError::InvalidBudget);
    }
    Ok(now.as_secs() - now.as_secs().rem_euclid(period))
}

impl Tx<'_> {
    pub fn budget_used(
        &self,
        agent: &AgentId,
        rule: &str,
        budget: Budget,
        now: Timestamp,
    ) -> Result<u32, StoreError> {
        self.checked(|| {
            let start = window_start(budget, now)?;
            let used = self
                .sql
                .query_row(
                    "SELECT used FROM budget_counters WHERE agent_id=? AND rule_name=? AND window_start=?",
                    params![agent.as_str(), rule, start],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .unwrap_or(0);
            u32::try_from(used).map_err(|_| StoreError::InvalidBudgetCounter)
        })
    }

    pub fn record_budget_use(
        &self,
        agent: &AgentId,
        rule: &str,
        budget: Budget,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        self.checked(|| {
            let start = window_start(budget, now)?;
            self.sql.execute(
                "INSERT INTO budget_counters(agent_id,rule_name,window_start,used) VALUES (?,?,?,1)
                 ON CONFLICT(agent_id,rule_name,window_start) DO UPDATE SET used=used+1",
                params![agent.as_str(), rule, start],
            )?;
            Ok(())
        })
    }
}
