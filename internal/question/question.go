// Package question collects user input without granting execution authority.
package question

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/chenchunrun/SecOps/internal/pubsub"
	"github.com/google/uuid"
)

type Field struct {
	ID      string   `json:"id"`
	Prompt  string   `json:"prompt"`
	Kind    string   `json:"kind" description:"text, single, or multiple"`
	Options []string `json:"options,omitempty"`
}
type Request struct {
	ID        string
	SessionID string
	Fields    []Field
	Closed    bool
}
type (
	Answers  map[string][]string
	response struct {
		answers  Answers
		canceled bool
	}
	pending struct {
		request Request
		result  chan response
	}
	Service struct {
		mu      sync.Mutex
		enabled bool
		pending map[string]pending
		broker  *pubsub.Broker[Request]
	}
)

func New() *Service {
	return &Service{pending: make(map[string]pending), broker: pubsub.NewBroker[Request]()}
}
func (s *Service) Enable() { s.mu.Lock(); defer s.mu.Unlock(); s.enabled = true }
func (s *Service) Subscribe(ctx context.Context) <-chan pubsub.Event[Request] {
	return s.broker.Subscribe(ctx)
}

func ValidateFields(fields []Field) error {
	if len(fields) == 0 || len(fields) > 8 {
		return errors.New("question requires 1 to 8 fields")
	}
	ids := map[string]bool{}
	for _, f := range fields {
		if strings.ContainsFunc(f.ID+f.Prompt, unicode.IsControl) {
			return errors.New("question labels must not contain control characters")
		}
		if strings.TrimSpace(f.ID) == "" || len(f.ID) > 64 || ids[f.ID] || strings.TrimSpace(f.Prompt) == "" || len(f.Prompt) > 512 {
			return errors.New("invalid or duplicate question field")
		}
		ids[f.ID] = true
		switch f.Kind {
		case "text":
			if len(f.Options) != 0 {
				return errors.New("text fields cannot contain options")
			}
		case "single", "multiple":
			if len(f.Options) < 2 || len(f.Options) > 12 {
				return errors.New("choice fields require 2 to 12 options")
			}
		default:
			return errors.New("unsupported question kind")
		}
		seen := map[string]bool{}
		for _, option := range f.Options {
			if strings.ContainsFunc(option, unicode.IsControl) {
				return errors.New("options must not contain control characters")
			}
			if strings.TrimSpace(option) == "" || len(option) > 256 || seen[option] {
				return errors.New("invalid or duplicate option")
			}
			seen[option] = true
		}
	}
	return nil
}

func ValidateAnswers(fields []Field, answers Answers) error {
	if err := ValidateFields(fields); err != nil {
		return err
	}
	if len(answers) != len(fields) {
		return errors.New("answer every field without extra keys")
	}
	for _, f := range fields {
		values := answers[f.ID]
		if len(values) == 0 || (f.Kind != "multiple" && len(values) != 1) || len(values) > 12 {
			return fmt.Errorf("invalid answer count for %s", f.ID)
		}
		seen := map[string]bool{}
		for _, value := range values {
			if strings.TrimSpace(value) == "" || len(value) > 4096 || seen[value] {
				return fmt.Errorf("invalid answer for %s", f.ID)
			}
			if f.Kind != "text" && !slices.Contains(f.Options, value) {
				return fmt.Errorf("unknown option for %s", f.ID)
			}
			seen[value] = true
		}
	}
	return nil
}

func (s *Service) Ask(ctx context.Context, sessionID string, fields []Field) (Answers, error) {
	if err := ValidateFields(fields); err != nil {
		return nil, err
	}
	if sessionID == "" {
		return nil, errors.New("question requires a session")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fields = slices.Clone(fields)
	for i := range fields {
		fields[i].Options = slices.Clone(fields[i].Options)
	}
	r := Request{ID: uuid.NewString(), SessionID: sessionID, Fields: fields}
	p := pending{request: r, result: make(chan response, 1)}
	s.mu.Lock()
	if !s.enabled || s.broker.GetSubscriberCount() == 0 || len(s.pending) >= 8 {
		s.mu.Unlock()
		return nil, errors.New("interactive questions unavailable; ask in normal text instead")
	}
	s.pending[r.ID] = p
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, r.ID)
		s.mu.Unlock()
		r.Closed = true
		s.broker.Publish(pubsub.UpdatedEvent, r)
	}()
	s.broker.Publish(pubsub.CreatedEvent, r)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-p.result:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if result.canceled {
			return nil, context.Canceled
		}
		return result.answers, nil
	}
}

func (s *Service) Respond(id, sessionID string, answers Answers, canceled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok || p.request.SessionID != sessionID {
		return errors.New("question is stale or belongs to another session")
	}
	if !canceled {
		if err := ValidateAnswers(p.request.Fields, answers); err != nil {
			return err
		}
	}
	copy := Answers{}
	for key, values := range answers {
		copy[key] = slices.Clone(values)
	}
	select {
	case p.result <- response{answers: copy, canceled: canceled}:
		delete(s.pending, id)
		return nil
	default:
		return errors.New("question already answered")
	}
}

func (s *Service) Active(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.pending[id]
	return ok
}
