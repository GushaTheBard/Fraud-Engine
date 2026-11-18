package engine_test

import (
	"testing"
	"time"

	"github.com/GushaTheBard/Fraud-Engine/internal/domain"
	"github.com/GushaTheBard/Fraud-Engine/internal/engine"
)

func TestEvaluator_Evaluate(t *testing.T) {
	baseRules := []domain.Rule{
		{
			Code:        "HIGH_AMOUNT_BRL",
			Description: "Transaction amount exceeds R$ 5,000.00",
			Type:        domain.RuleTypeStatic,
			Status:      domain.RuleStatusActive,
			Weight:      45,
			Condition: domain.Condition{
				Field:    "amount",
				Operator: domain.OpGreaterThan,
				Value:    5000.0,
			},
		},
		{
			Code:        "FOREIGN_COUNTRY",
			Description: "Transaction originated outside Brazil",
			Type:        domain.RuleTypeStatic,
			Status:      domain.RuleStatusActive,
			Weight:      40,
			Condition: domain.Condition{
				Field:    "country",
				Operator: domain.OpNotEqual,
				Value:    "BR",
			},
		},
		{
			Code:        "BLOCKED_COUNTRIES_LIST",
			Description: "Country is on high-risk watchlist",
			Type:        domain.RuleTypeStatic,
			Status:      domain.RuleStatusActive,
			Weight:      85,
			Condition: domain.Condition{
				Field:    "country",
				Operator: domain.OpIn,
				Value:    []string{"KP", "IR", "SY"},
			},
		},
		{
			Code:        "SHADOW_MICRO_TX",
			Description: "Testing small amount threshold without impacting users",
			Type:        domain.RuleTypeStatic,
			Status:      domain.RuleStatusShadow,
			Weight:      90,
			Condition: domain.Condition{
				Field:    "amount",
				Operator: domain.OpLessOrEqual,
				Value:    10.0,
			},
		},
		{
			Code:        "INACTIVE_LEGACY_RULE",
			Description: "Disabled rule that must never trigger",
			Type:        domain.RuleTypeStatic,
			Status:      domain.RuleStatusInactive,
			Weight:      100,
			Condition: domain.Condition{
				Field:    "currency",
				Operator: domain.OpEqual,
				Value:    "BRL",
			},
		},
	}

	tests := []struct {
		name               string
		event              domain.Event
		wantDecision       domain.DecisionAction
		wantScore          int
		wantTriggeredCodes []string
		wantShadowCodes    []string
	}{
		{
			name: "legitimate domestic transaction results in ALLOW",
			event: domain.Event{
				EventID:   "evt_01",
				EventType: "TRANSACTION",
				UserID:    "usr_1",
				IPAddress: "189.10.20.30",
				Amount:    250.00,
				Currency:  "BRL",
				Country:   "BR",
				Timestamp: time.Now(),
			},
			wantDecision:       domain.DecisionAllow,
			wantScore:          0,
			wantTriggeredCodes: []string{},
			wantShadowCodes:    nil,
		},
		{
			name: "high amount domestic transaction triggers CHALLENGE",
			event: domain.Event{
				EventID:   "evt_02",
				EventType: "TRANSACTION",
				UserID:    "usr_2",
				IPAddress: "189.10.20.31",
				Amount:    7500.00,
				Currency:  "BRL",
				Country:   "BR",
				Timestamp: time.Now(),
			},
			wantDecision:       domain.DecisionChallenge,
			wantScore:          45,
			wantTriggeredCodes: []string{"HIGH_AMOUNT_BRL"},
			wantShadowCodes:    nil,
		},
		{
			name: "high amount + foreign country combines scores into BLOCK",
			event: domain.Event{
				EventID:   "evt_03",
				EventType: "TRANSACTION",
				UserID:    "usr_3",
				IPAddress: "45.12.88.10",
				Amount:    6000.00,
				Currency:  "USD",
				Country:   "US",
				Timestamp: time.Now(),
			},
			wantDecision:       domain.DecisionBlock,
			wantScore:          85,
			wantTriggeredCodes: []string{"HIGH_AMOUNT_BRL", "FOREIGN_COUNTRY"},
			wantShadowCodes:    nil,
		},
		{
			name: "shadow rule matches micro transaction without adding to score or changing ALLOW",
			event: domain.Event{
				EventID:   "evt_04",
				EventType: "TRANSACTION",
				UserID:    "usr_4",
				IPAddress: "189.10.20.32",
				Amount:    5.00,
				Currency:  "BRL",
				Country:   "BR",
				Timestamp: time.Now(),
			},
			wantDecision:       domain.DecisionAllow,
			wantScore:          0,
			wantTriggeredCodes: []string{},
			wantShadowCodes:    []string{"SHADOW_MICRO_TX"},
		},
		{
			name: "watchlist country triggers IN operator and blocks immediately",
			event: domain.Event{
				EventID:   "evt_05",
				EventType: "LOGIN",
				UserID:    "usr_5",
				IPAddress: "175.45.176.1",
				Amount:    0,
				Currency:  "BRL",
				Country:   "KP",
				Timestamp: time.Now(),
			},
			wantDecision:       domain.DecisionBlock,
			wantScore:          125, // FOREIGN_COUNTRY (40) + BLOCKED_COUNTRIES_LIST (85)
			wantTriggeredCodes: []string{"FOREIGN_COUNTRY", "BLOCKED_COUNTRIES_LIST"},
			wantShadowCodes:    []string{"SHADOW_MICRO_TX"},
		},
	}

	ev := engine.NewEvaluator()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ev.Evaluate(tc.event, baseRules)

			if got.Decision != tc.wantDecision {
				t.Errorf("Decision = %s, want %s", got.Decision, tc.wantDecision)
			}
			if got.RiskScore != tc.wantScore {
				t.Errorf("RiskScore = %d, want %d", got.RiskScore, tc.wantScore)
			}
			if len(got.TriggeredRules) != len(tc.wantTriggeredCodes) {
				t.Fatalf("TriggeredRules count = %d, want %d", len(got.TriggeredRules), len(tc.wantTriggeredCodes))
			}
			for i, tr := range got.TriggeredRules {
				if tr.Code != tc.wantTriggeredCodes[i] {
					t.Errorf("TriggeredRules[%d].Code = %s, want %s", i, tr.Code, tc.wantTriggeredCodes[i])
				}
			}
			if len(got.ShadowTriggeredRules) != len(tc.wantShadowCodes) {
				t.Fatalf("ShadowTriggeredRules = %v, want %v", got.ShadowTriggeredRules, tc.wantShadowCodes)
			}
			for i, sc := range got.ShadowTriggeredRules {
				if sc != tc.wantShadowCodes[i] {
					t.Errorf("ShadowTriggeredRules[%d] = %s, want %s", i, sc, tc.wantShadowCodes[i])
				}
			}
		})
	}
}
