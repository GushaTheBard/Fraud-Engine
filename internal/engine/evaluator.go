package engine

import (
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/GushaTheBard/Fraud-Engine/internal/domain"
)

const (
	ChallengeThreshold = 40
	BlockThreshold     = 80
)

// Evaluator executes deterministic fraud rules against incoming events.
type Evaluator struct{}

func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// Evaluate processes an event against a slice of rules and returns a risk decision.
func (e *Evaluator) Evaluate(event domain.Event, rules []domain.Rule) domain.EvaluationResult {
	start := time.Now()

	result := domain.EvaluationResult{
		EventID:        event.EventID,
		TriggeredRules: make([]domain.TriggeredRuleDetail, 0),
	}

	totalScore := 0

	for _, rule := range rules {
		if rule.Status == domain.RuleStatusInactive {
			continue
		}

		// Milestone 1 focuses on STATIC rules; VELOCITY rules will be enriched in Milestone 3.
		if rule.Type != domain.RuleTypeStatic {
			continue
		}

		matched, err := evaluateCondition(event, rule.Condition)
		if err != nil || !matched {
			continue
		}

		switch rule.Status {
		case domain.RuleStatusActive:
			totalScore += rule.Weight
			result.TriggeredRules = append(result.TriggeredRules, domain.TriggeredRuleDetail{
				Code:        rule.Code,
				Weight:      rule.Weight,
				Description: rule.Description,
			})
		case domain.RuleStatusShadow:
			result.ShadowTriggeredRules = append(result.ShadowTriggeredRules, rule.Code)
		}
	}

	result.RiskScore = totalScore
	result.Decision = mapScoreToDecision(totalScore)
	result.EvaluationTimeMs = float64(time.Since(start).Microseconds()) / 1000.0

	return result
}

func mapScoreToDecision(score int) domain.DecisionAction {
	switch {
	case score >= BlockThreshold:
		return domain.DecisionBlock
	case score >= ChallengeThreshold:
		return domain.DecisionChallenge
	default:
		return domain.DecisionAllow
	}
}

func evaluateCondition(event domain.Event, cond domain.Condition) (bool, error) {
	fieldVal, err := extractFieldValue(event, cond.Field)
	if err != nil {
		return false, err
	}

	switch cond.Operator {
	case domain.OpEqual:
		return reflect.DeepEqual(fieldVal, cond.Value), nil
	case domain.OpNotEqual:
		return !reflect.DeepEqual(fieldVal, cond.Value), nil
	case domain.OpGreaterThan, domain.OpGreaterOrEqual, domain.OpLessThan, domain.OpLessOrEqual:
		return compareNumeric(fieldVal, cond.Value, cond.Operator)
	case domain.OpIn:
		return checkMembership(fieldVal, cond.Value, true)
	case domain.OpNotIn:
		return checkMembership(fieldVal, cond.Value, false)
	default:
		return false, fmt.Errorf("unsupported operator: %s", cond.Operator)
	}
}

func extractFieldValue(event domain.Event, field string) (any, error) {
	switch field {
	case "event_type":
		return event.EventType, nil
	case "user_id":
		return event.UserID, nil
	case "ip_address":
		return event.IPAddress, nil
	case "device_id":
		return event.DeviceID, nil
	case "amount":
		return event.Amount, nil
	case "currency":
		return event.Currency, nil
	case "country":
		return event.Country, nil
	default:
		return nil, fmt.Errorf("unknown event field: %s", field)
	}
}

func compareNumeric(actual any, target any, op domain.Operator) (bool, error) {
	a, ok := toFloat64(actual)
	if !ok {
		return false, fmt.Errorf("actual field value is not numeric: %v", actual)
	}
	b, ok := toFloat64(target)
	if !ok {
		return false, fmt.Errorf("target rule value is not numeric: %v", target)
	}

	switch op {
	case domain.OpGreaterThan:
		return a > b, nil
	case domain.OpGreaterOrEqual:
		return a >= b, nil
	case domain.OpLessThan:
		return a < b, nil
	case domain.OpLessOrEqual:
		return a <= b, nil
	default:
		return false, fmt.Errorf("invalid numeric operator: %s", op)
	}
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func checkMembership(actual any, list any, shouldContain bool) (bool, error) {
	strActual, ok := actual.(string)
	if !ok {
		return false, fmt.Errorf("IN/NOT_IN currently supports string fields, got %T", actual)
	}

	switch items := list.(type) {
	case []string:
		found := slices.Contains(items, strActual)
		if shouldContain {
			return found, nil
		}
		return !found, nil
	case []any:
		found := false
		for _, item := range items {
			if s, ok := item.(string); ok && s == strActual {
				found = true
				break
			}
		}
		if shouldContain {
			return found, nil
		}
		return !found, nil
	default:
		return false, fmt.Errorf("expected slice for IN/NOT_IN operator, got %T", list)
	}
}
