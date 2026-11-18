package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GushaTheBard/Fraud-Engine/internal/domain"
	"github.com/GushaTheBard/Fraud-Engine/internal/engine"
	"github.com/GushaTheBard/Fraud-Engine/internal/handler"
)

type stubRuleProvider struct {
	rules []domain.Rule
}

func (s *stubRuleProvider) GetRules() []domain.Rule {
	return s.rules
}

func TestEvaluateHandler_HandleEvaluate(t *testing.T) {
	provider := &stubRuleProvider{
		rules: []domain.Rule{
			{
				Code:        "HIGH_AMOUNT_BRL",
				Description: "Amount > 5000",
				Type:        domain.RuleTypeStatic,
				Status:      domain.RuleStatusActive,
				Weight:      85,
				Condition: domain.Condition{
					Field:    "amount",
					Operator: domain.OpGreaterThan,
					Value:    5000.0,
				},
			},
		},
	}

	h := handler.NewEvaluateHandler(engine.NewEvaluator(), provider)

	tests := []struct {
		name           string
		body           string
		wantStatus     int
		wantDecision   domain.DecisionAction
		wantProblemMsg string
	}{
		{
			name: "valid high-risk payload returns 200 and BLOCK",
			body: `{
				"event_id": "evt_1",
				"event_type": "TRANSACTION",
				"user_id": "usr_1",
				"ip_address": "189.45.120.14",
				"amount": 9000.00,
				"currency": "BRL",
				"country": "BR",
				"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `"
			}`,
			wantStatus:   http.StatusOK,
			wantDecision: domain.DecisionBlock,
		},
		{
			name: "missing required user_id returns 400 ProblemDetails",
			body: `{
				"event_id": "evt_2",
				"event_type": "TRANSACTION",
				"ip_address": "189.45.120.14",
				"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `"
			}`,
			wantStatus:     http.StatusBadRequest,
			wantProblemMsg: "field 'user_id' is required",
		},
		{
			name: "unknown JSON field returns 400 ProblemDetails",
			body: `{
				"event_id": "evt_3",
				"event_type": "TRANSACTION",
				"user_id": "usr_1",
				"ip_address": "189.45.120.14",
				"unexpected_field": true,
				"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `"
			}`,
			wantStatus:     http.StatusBadRequest,
			wantProblemMsg: `json: unknown field "unexpected_field"`,
		},
		{
			name: "negative amount returns 400 ProblemDetails",
			body: `{
				"event_id": "evt_4",
				"event_type": "TRANSACTION",
				"user_id": "usr_1",
				"ip_address": "189.45.120.14",
				"amount": -50.0,
				"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `"
			}`,
			wantStatus:     http.StatusBadRequest,
			wantProblemMsg: "field 'amount' must be greater than or equal to 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			h.HandleEvaluate(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.wantStatus, rec.Body.String())
			}

			if tc.wantStatus == http.StatusOK {
				var got domain.EvaluationResult
				if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
					t.Fatalf("failed to decode EvaluationResult: %v", err)
				}
				if got.Decision != tc.wantDecision {
					t.Errorf("Decision = %s, want %s", got.Decision, tc.wantDecision)
				}
			} else {
				var prob handler.ProblemDetails
				if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
					t.Fatalf("failed to decode ProblemDetails: %v", err)
				}
				if prob.Detail != tc.wantProblemMsg {
					t.Errorf("ProblemDetails.Detail = %q, want %q", prob.Detail, tc.wantProblemMsg)
				}
			}
		})
	}
}
