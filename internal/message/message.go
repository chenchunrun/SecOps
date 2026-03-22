package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/chenchunrun/SecOps/internal/db"
	"github.com/chenchunrun/SecOps/internal/pubsub"
	"github.com/google/uuid"
)

type CreateMessageParams struct {
	Role             MessageRole
	Parts            []ContentPart
	Model            string
	Provider         string
	IsSummaryMessage bool
}

// UpdateOptions controls how BufferedUpdate behaves.
type UpdateOptions struct {
	// ForceDBWrite forces the DB write even if the threshold hasn't been reached.
	ForceDBWrite bool
	// SkipDBWrite skips the DB write for this call (e.g., intermediate reasoning deltas).
	SkipDBWrite bool
}

type Service interface {
	pubsub.Subscriber[Message]
	Create(ctx context.Context, sessionID string, params CreateMessageParams) (Message, error)
	Update(ctx context.Context, message Message) error
	// BufferedUpdate accumulates changes and writes to DB only when the delta
	// threshold is reached or ForceDBWrite is set. It always publishes to pubsub
	// immediately so the UI stays responsive. Use FlushBufferedUpdate to persist
	// any pending writes at the end of a step.
	BufferedUpdate(ctx context.Context, message Message, opts UpdateOptions) error
	FlushBufferedUpdate(ctx context.Context) error
	Get(ctx context.Context, id string) (Message, error)
	List(ctx context.Context, sessionID string) ([]Message, error)
	ListUserMessages(ctx context.Context, sessionID string) ([]Message, error)
	ListAllUserMessages(ctx context.Context) ([]Message, error)
	Delete(ctx context.Context, id string) error
	DeleteSessionMessages(ctx context.Context, sessionID string) error
}

// bufferedState holds pending writes for a single message.
type bufferedState struct {
	message  Message
	deltaCount int
}

type service struct {
	*pubsub.Broker[Message]
	q             db.Querier
	buffered      map[string]*bufferedState
	bufferedMutex sync.Mutex
}

// defaultFlushThreshold is the number of BufferedUpdate calls before a DB write occurs.
const defaultFlushThreshold = 5

func NewService(q db.Querier) Service {
	return &service{
		Broker:   pubsub.NewBroker[Message](),
		q:        q,
		buffered: make(map[string]*bufferedState),
	}
}

func (s *service) Delete(ctx context.Context, id string) error {
	message, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	err = s.q.DeleteMessage(ctx, message.ID)
	if err != nil {
		return err
	}
	// Clone the message before publishing to avoid race conditions with
	// concurrent modifications to the Parts slice.
	s.Publish(pubsub.DeletedEvent, message.Clone())
	return nil
}

func (s *service) Create(ctx context.Context, sessionID string, params CreateMessageParams) (Message, error) {
	if params.Role != Assistant {
		params.Parts = append(params.Parts, Finish{
			Reason: "stop",
		})
	}
	partsJSON, err := marshalParts(params.Parts)
	if err != nil {
		return Message{}, err
	}
	isSummary := int64(0)
	if params.IsSummaryMessage {
		isSummary = 1
	}
	dbMessage, err := s.q.CreateMessage(ctx, db.CreateMessageParams{
		ID:               uuid.New().String(),
		SessionID:        sessionID,
		Role:             string(params.Role),
		Parts:            string(partsJSON),
		Model:            sql.NullString{String: string(params.Model), Valid: true},
		Provider:         sql.NullString{String: params.Provider, Valid: params.Provider != ""},
		IsSummaryMessage: isSummary,
	})
	if err != nil {
		return Message{}, err
	}
	message, err := s.fromDBItem(dbMessage)
	if err != nil {
		return Message{}, err
	}
	// Clone the message before publishing to avoid race conditions with
	// concurrent modifications to the Parts slice.
	s.Publish(pubsub.CreatedEvent, message.Clone())
	return message, nil
}

func (s *service) DeleteSessionMessages(ctx context.Context, sessionID string) error {
	messages, err := s.List(ctx, sessionID)
	if err != nil {
		return err
	}
	for _, message := range messages {
		if message.SessionID == sessionID {
			err = s.Delete(ctx, message.ID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Update persists a message change to the database and publishes to pubsub.
// For streaming callbacks prefer BufferedUpdate which batches writes.
func (s *service) Update(ctx context.Context, message Message) error {
	if err := s.writeMessageToDB(ctx, message); err != nil {
		return err
	}
	s.Publish(pubsub.UpdatedEvent, message.Clone())
	return nil
}


// Call this at the end of each agent step to ensure the final state is saved.
func (s *service) FlushBufferedUpdate(ctx context.Context) error {
	s.bufferedMutex.Lock()
	states := make(map[string]*bufferedState, len(s.buffered))
	for id, st := range s.buffered {
		states[id] = st
	}
	clear(s.buffered)
	s.bufferedMutex.Unlock()

	for _, st := range states {
		if err := s.writeMessageToDB(ctx, st.message); err != nil {
			return err
		}
	}
	return nil
}

// BufferedUpdate accumulates message changes and writes to DB only when the delta
// threshold is reached or ForceDBWrite is set. Pubsub publish always happens immediately.
func (s *service) BufferedUpdate(ctx context.Context, message Message, opts UpdateOptions) error {
	// Always publish to pubsub immediately so the UI stays responsive.
	s.Publish(pubsub.UpdatedEvent, message.Clone())

	if opts.SkipDBWrite {
		// Just track in buffer without writing (for intermediate reasoning deltas).
		s.bufferedMutex.Lock()
		s.buffered[message.ID] = &bufferedState{message: message, deltaCount: 0}
		s.bufferedMutex.Unlock()
		return nil
	}

	shouldFlush := opts.ForceDBWrite

	s.bufferedMutex.Lock()
	st, exists := s.buffered[message.ID]
	if !exists {
		st = &bufferedState{message: message, deltaCount: 0}
		s.buffered[message.ID] = st
	}
	st.message = message
	st.deltaCount++
	if !shouldFlush && st.deltaCount < defaultFlushThreshold {
		s.bufferedMutex.Unlock()
		return nil
	}
	// Flush this message now.
	delete(s.buffered, message.ID)
	s.bufferedMutex.Unlock()

	return s.writeMessageToDB(ctx, message)
}

// writeMessageToDB serializes and persists a message to the database.
func (s *service) writeMessageToDB(ctx context.Context, message Message) error {
	parts, err := marshalParts(message.Parts)
	if err != nil {
		return err
	}
	finishedAt := sql.NullInt64{}
	if f := message.FinishPart(); f != nil {
		finishedAt.Int64 = f.Time
		finishedAt.Valid = true
	}
	return s.q.UpdateMessage(ctx, db.UpdateMessageParams{
		ID:         message.ID,
		Parts:      string(parts),
		FinishedAt: finishedAt,
	})
}

func (s *service) Get(ctx context.Context, id string) (Message, error) {
	dbMessage, err := s.q.GetMessage(ctx, id)
	if err != nil {
		return Message{}, err
	}
	return s.fromDBItem(dbMessage)
}

func (s *service) List(ctx context.Context, sessionID string) ([]Message, error) {
	dbMessages, err := s.q.ListMessagesBySession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	messages := make([]Message, len(dbMessages))
	for i, dbMessage := range dbMessages {
		messages[i], err = s.fromDBItem(dbMessage)
		if err != nil {
			return nil, err
		}
	}
	return messages, nil
}

func (s *service) ListUserMessages(ctx context.Context, sessionID string) ([]Message, error) {
	dbMessages, err := s.q.ListUserMessagesBySession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	messages := make([]Message, len(dbMessages))
	for i, dbMessage := range dbMessages {
		messages[i], err = s.fromDBItem(dbMessage)
		if err != nil {
			return nil, err
		}
	}
	return messages, nil
}

func (s *service) ListAllUserMessages(ctx context.Context) ([]Message, error) {
	dbMessages, err := s.q.ListAllUserMessages(ctx)
	if err != nil {
		return nil, err
	}
	messages := make([]Message, len(dbMessages))
	for i, dbMessage := range dbMessages {
		messages[i], err = s.fromDBItem(dbMessage)
		if err != nil {
			return nil, err
		}
	}
	return messages, nil
}

func (s *service) fromDBItem(item db.Message) (Message, error) {
	parts, err := unmarshalParts([]byte(item.Parts))
	if err != nil {
		return Message{}, err
	}
	return Message{
		ID:               item.ID,
		SessionID:        item.SessionID,
		Role:             MessageRole(item.Role),
		Parts:            parts,
		Model:            item.Model.String,
		Provider:         item.Provider.String,
		CreatedAt:        item.CreatedAt,
		UpdatedAt:        item.UpdatedAt,
		IsSummaryMessage: item.IsSummaryMessage != 0,
	}, nil
}

type partType string

const (
	reasoningType  partType = "reasoning"
	textType       partType = "text"
	imageURLType   partType = "image_url"
	binaryType     partType = "binary"
	toolCallType   partType = "tool_call"
	toolResultType partType = "tool_result"
	finishType     partType = "finish"
)

type partWrapper struct {
	Type partType    `json:"type"`
	Data ContentPart `json:"data"`
}

func marshalParts(parts []ContentPart) ([]byte, error) {
	wrappedParts := make([]partWrapper, len(parts))

	for i, part := range parts {
		var typ partType

		switch part.(type) {
		case ReasoningContent:
			typ = reasoningType
		case TextContent:
			typ = textType
		case ImageURLContent:
			typ = imageURLType
		case BinaryContent:
			typ = binaryType
		case ToolCall:
			typ = toolCallType
		case ToolResult:
			typ = toolResultType
		case Finish:
			typ = finishType
		default:
			return nil, fmt.Errorf("unknown part type: %T", part)
		}

		wrappedParts[i] = partWrapper{
			Type: typ,
			Data: part,
		}
	}
	return json.Marshal(wrappedParts)
}

func unmarshalParts(data []byte) ([]ContentPart, error) {
	temp := []json.RawMessage{}

	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, err
	}

	parts := make([]ContentPart, 0)

	for _, rawPart := range temp {
		var wrapper struct {
			Type partType        `json:"type"`
			Data json.RawMessage `json:"data"`
		}

		if err := json.Unmarshal(rawPart, &wrapper); err != nil {
			return nil, err
		}

		switch wrapper.Type {
		case reasoningType:
			part := ReasoningContent{}
			if err := json.Unmarshal(wrapper.Data, &part); err != nil {
				return nil, err
			}
			parts = append(parts, part)
		case textType:
			part := TextContent{}
			if err := json.Unmarshal(wrapper.Data, &part); err != nil {
				return nil, err
			}
			parts = append(parts, part)
		case imageURLType:
			part := ImageURLContent{}
			if err := json.Unmarshal(wrapper.Data, &part); err != nil {
				return nil, err
			}
			parts = append(parts, part)
		case binaryType:
			part := BinaryContent{}
			if err := json.Unmarshal(wrapper.Data, &part); err != nil {
				return nil, err
			}
			parts = append(parts, part)
		case toolCallType:
			part := ToolCall{}
			if err := json.Unmarshal(wrapper.Data, &part); err != nil {
				return nil, err
			}
			parts = append(parts, part)
		case toolResultType:
			part := ToolResult{}
			if err := json.Unmarshal(wrapper.Data, &part); err != nil {
				return nil, err
			}
			parts = append(parts, part)
		case finishType:
			part := Finish{}
			if err := json.Unmarshal(wrapper.Data, &part); err != nil {
				return nil, err
			}
			parts = append(parts, part)
		default:
			return nil, fmt.Errorf("unknown part type: %s", wrapper.Type)
		}
	}

	return parts, nil
}
