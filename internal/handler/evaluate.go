package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/GushaTheBard/Fraud-Engine/internal/domain"
	"github.com/GushaTheBard/Fraud-Engine/internal/engine"
)

// RuleProvider abstracts rule retrieval so Milestone 1 can use in-memory rules
// and Milestone 2+ can swap in PostgreSQL + cached repositories cleanly.
type RuleProvider interface {
	GetRules() []domain.Rule
}

// ProblemDetails follows RFC 7807 / RFC 9457 as specified in openapi.yaml.
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance,omitempty"`
}

type EvaluateHandler struct {
	evaluator    *engine.Evaluator
	ruleProvider RuleProvider
}

func NewEvaluateHandler(evaluator *engine.Evaluator, provider RuleProvider) *EvaluateHandler {
	return &EvaluateHandler{
		evaluator:    evaluator,
		ruleProvider: provider,
	}
}

func (h *EvaluateHandler) HandleEvaluate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var event domain.Event
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&event); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "Invalid Request Payload", err.Error())
		return
	}

	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeProblem(w, r, http.StatusBadRequest, "Invalid Request Payload", "request body must contain a single JSON object")
		return
	}

	if err := validateEvent(event); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "Validation Error", err.Error())
		return
	}

	rules := h.ruleProvider.GetRules()
	result := h.evaluator.Evaluate(event, rules)

	writeJSON(w, http.StatusOK, result)
}

func validateEvent(e domain.Event) error {
	if e.EventID == "" {
		return errors.New("field 'event_id' is required")
	}
	if e.EventType == "" {
		return errors.New("field 'event_type' is required")
	}
	if e.UserID == "" {
		return errors.New("field 'user_id' is required")
	}
	if e.IPAddress == "" {
		return errors.New("field 'ip_address' is required")
	}
	if e.Timestamp.IsZero() {
		return errors.New("field 'timestamp' is required")
	}
	if e.Amount < 0 {
		return errors.New("field 'amount' must be greater than or equal to 0")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ProblemDetails{
		Type:     "https://api.fraud-engine.dev/errors/validation-error",
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
	})
}
