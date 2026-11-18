package domain

import "time"

type DecisionAction string

const (
	DecisionAllow     DecisionAction = "ALLOW"
	DecisionChallenge DecisionAction = "CHALLENGE"
	DecisionBlock     DecisionAction = "BLOCK"
)

type RuleStatus string

const (
	RuleStatusActive   RuleStatus = "ACTIVE"
	RuleStatusShadow   RuleStatus = "SHADOW"
	RuleStatusInactive RuleStatus = "INACTIVE"
)

type RuleType string

const (
	RuleTypeStatic   RuleType = "STATIC"
	RuleTypeVelocity RuleType = "VELOCITY"
)

type Operator string

const (
	OpEqual          Operator = "=="
	OpNotEqual       Operator = "!="
	OpGreaterThan    Operator = ">"
	OpGreaterOrEqual Operator = ">="
	OpLessThan       Operator = "<"
	OpLessOrEqual    Operator = "<="
	OpIn             Operator = "IN"
	OpNotIn          Operator = "NOT_IN"
)

// Event represents an incoming activity to be evaluated for fraud risk.
type Event struct {
	EventID   string    `json:"event_id"`
	EventType string    `json:"event_type"`
	UserID    string    `json:"user_id"`
	IPAddress string    `json:"ip_address"`
	DeviceID  string    `json:"device_id,omitempty"`
	Amount    float64   `json:"amount,omitempty"`
	Currency  string    `json:"currency,omitempty"`
	Country   string    `json:"country,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Condition defines a single logical check against an Event field or velocity metric.
type Condition struct {
	Field    string   `json:"field"`
	Operator Operator `json:"operator"`
	Value    any      `json:"value"`
}

// VelocityConfig holds sliding-window parameters for velocity rules (used in Milestone 3).
type VelocityConfig struct {
	GroupBy       string `json:"group_by"`
	WindowSeconds int    `json:"window_seconds"`
}

// Rule represents a configurable fraud detection rule.
type Rule struct {
	ID             string          `json:"id"`
	Code           string          `json:"code"`
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	Type           RuleType        `json:"type"`
	Status         RuleStatus      `json:"status"`
	Weight         int             `json:"weight"`
	Condition      Condition       `json:"condition"`
	VelocityConfig *VelocityConfig `json:"velocity_config,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// TriggeredRuleDetail explains why an active rule contributed to the risk score.
type TriggeredRuleDetail struct {
	Code        string `json:"code"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
}

// EvaluationResult is the output returned by the rule engine.
type EvaluationResult struct {
	EventID              string                `json:"event_id"`
	Decision             DecisionAction        `json:"decision"`
	RiskScore            int                   `json:"risk_score"`
	TriggeredRules       []TriggeredRuleDetail `json:"triggered_rules"`
	ShadowTriggeredRules []string              `json:"shadow_triggered_rules,omitempty"`
	DegradedMode         bool                  `json:"degraded_mode"`
	EvaluationTimeMs     float64               `json:"evaluation_time_ms"`
}
