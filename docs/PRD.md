# PRD: Real-Time Fraud Prevention & Velocity Check Rule Engine (V1)

**Status:** In Development (MVP)  
**Author:** Japapedia  
**Last Updated:** November 17th, 2026  

---

## 1. Context and Business Problem

In high-volume payment operations and digital platforms, fraud prevention faces an ongoing trade-off between **security** and **conversion**:

1. **False Negatives (Fraud):** Letting automated attacks (*Card Testing*, *Account Takeover*, promo abuse) slip through results in direct financial loss from chargebacks and reputational damage.
2. **False Positives (Friction):** Rigid or poorly calibrated rules block legitimate customers, lowering checkout approval rates and overwhelming customer support.
3. **Operational Latency:** When a new attack pattern emerges, relying on code changes and deployment cycles to adjust rules costs hours of financial loss.

### Value Proposition
Provide an ultra-low-latency synchronous decision API capable of evaluating events in real time by combining **configurable dynamic rules** and **velocity counters (velocity checks)**, allowing risk teams to test and publish new rules in seconds without impacting checkout availability.

---

## 2. Personas and Users

| Persona | Role | Core Need |
| :--- | :--- | :--- |
| **Consumer Service (Checkout / Auth API)** | Client system integrating via HTTP/JSON | Receive a deterministic decision (`ALLOW`, `CHALLENGE`, or `BLOCK`) in **under 15ms (P99)**, with built-in resilience if subsystems fail. |
| **Risk / Fraud Analyst** | Business operator | Create, tune weights, and disable rules without deployments; validate impact in **Shadow Mode** before blocking real users. |
| **Support / Operations Engineer** | Troubleshooting and investigation | Query the auditable decision history and understand exactly **which rules** triggered a block (*Reason Codes*). |

---

## 3. Success Metrics (KPIs & Guardrails)

### Business & Operational Metrics
* **Time-to-Mitigate (TTM):** `< 30 seconds` between creating/activating a rule via API and enforcing it on live production requests.
* **Friction Rate (*Challenge Rate*):** Keep extra authentication requests (`CHALLENGE`) below `5%` of simulated legitimate traffic.
* **False Positive Prevention:** `0%` impact on end customers during rule validation via *Shadow Mode*.

### Technical Guardrails (SLAs)
* **P99 Latency (Evaluation):** `< 15ms` per request under a nominal load of `1,000 RPS`.
* **Availability / Resilience:** `99.99%` for the evaluation endpoint, operating in degraded mode (*Fail-Open*) if the distributed state store (Redis) becomes unavailable.
* **Audit Integrity:** `100%` of decisions made must be persisted asynchronously to the relational database without blocking the HTTP response.

---

## 4. Functional Requirements (V1 Scope)

### FR-01: Synchronous Event Evaluation (`POST /v1/evaluate`)
* Accept a JSON payload containing event metadata (`event_id`, `event_type`, `user_id`, `ip_address`, `amount`, `currency`, `country`, `device_id`, `timestamp`).
* Calculate the total `risk_score` by summing the weights of all matched active rules.
* Map the final score to an action based on configured thresholds:
  * `0 to 39`: `ALLOW`
  * `40 to 79`: `CHALLENGE` (requires 2FA / step-up verification)
  * `>= 80`: `BLOCK`
* Return in the response: `decision`, `risk_score`, `triggered_rules` (*Reason Codes*), `degraded_mode` (boolean), and `evaluation_time_ms`.

### FR-02: Dynamic Rule Management (`CRUD /v1/rules`)
* Support creating, listing, updating, and toggling rule statuses via REST API.
* Support logical operators over event fields (`==`, `!=`, `>`, `>=`, `<`, `<=`, `IN`, `NOT_IN`).
* Each rule must follow a three-state lifecycle:
  * `ACTIVE`: Evaluated and adds points to the official `risk_score`.
  * `SHADOW`: Evaluated and recorded in audit logs (`shadow_triggered_rules`), but **does not alter** the `risk_score` or the decision returned to the client.
  * `INACTIVE`: Ignored by the engine.

### FR-03: Velocity Checks (Sliding Windows)
* Support rules based on event frequency within a rolling time window (e.g., *"event count per `ip_address` in the last `300` seconds > `5`"*).
* Support grouping by dynamic keys (`user_id`, `ip_address`, `device_id`, or combinations).

### FR-04: Backtesting / Rule Simulation (`POST /v1/rules/simulate`)
*
