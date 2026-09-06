package tools

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/question"
)

const QuestionToolName = "question"

//go:embed question.md
var questionDescription string

type QuestionParams struct {
	Fields []question.Field `json:"fields"`
}

// BuildInteractionToolSet creates the fixed, non-authorizing user-input tools.
func BuildInteractionToolSet(service *question.Service) []fantasy.AgentTool {
	if service == nil {
		return nil
	}
	return []fantasy.AgentTool{fantasy.NewAgentTool(QuestionToolName, questionDescription,
		func(ctx context.Context, params QuestionParams, call fantasy.ToolCall) (fantasy.ToolResponse, error) {
			decoder := json.NewDecoder(strings.NewReader(call.Input))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&params); err != nil {
				return fantasy.ToolResponse{}, fmt.Errorf("invalid question parameters: %w", err)
			}
			var extra any
			if err := decoder.Decode(&extra); err != io.EOF {
				return fantasy.ToolResponse{}, fmt.Errorf("question parameters must contain one JSON object")
			}
			answers, err := service.Ask(ctx, GetSessionFromContext(ctx), params.Fields)
			if err != nil {
				return fantasy.ToolResponse{}, fmt.Errorf("collect user input: %w", err)
			}
			data, err := json.Marshal(answers)
			if err != nil {
				return fantasy.ToolResponse{}, err
			}
			return fantasy.NewTextResponse(string(data)), nil
		})}
}
