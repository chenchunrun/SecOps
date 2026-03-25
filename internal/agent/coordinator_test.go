package agent

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"charm.land/catwalk/pkg/catwalk"
	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSessionAgent is a minimal mock for the SessionAgent interface.
type mockSessionAgent struct {
	model     Model
	runFunc   func(ctx context.Context, call SessionAgentCall) (*fantasy.AgentResult, error)
	cancelled []string
}

func TestRetryAfterDuration(t *testing.T) {
	t.Parallel()

	t.Run("uses numeric retry-after seconds", func(t *testing.T) {
		err := &fantasy.ProviderError{
			StatusCode:      http.StatusTooManyRequests,
			ResponseHeaders: map[string]string{"Retry-After": "7"},
		}
		got := retryAfterDuration(err)
		require.Equal(t, 7*time.Second, got)
	})

	t.Run("falls back when header missing", func(t *testing.T) {
		err := &fantasy.ProviderError{StatusCode: http.StatusTooManyRequests}
		got := retryAfterDuration(err)
		require.Equal(t, 15*time.Second, got)
	})

	t.Run("caps very large retry-after", func(t *testing.T) {
		err := &fantasy.ProviderError{
			StatusCode:      http.StatusTooManyRequests,
			ResponseHeaders: map[string]string{"Retry-After": "9999"},
		}
		got := retryAfterDuration(err)
		require.Equal(t, 2*time.Minute, got)
	})
}

func TestCoordinatorProviderRateLimitState(t *testing.T) {
	t.Parallel()

	c := &coordinator{
		rateLimit: coordinatorRateLimitState{
			nextAllowedRun: make(map[string]time.Time),
		},
	}

	c.setProviderRateLimit("zai", 3*time.Second)
	wait, limited := c.providerRateLimitWait("zai")
	require.True(t, limited)
	require.Greater(t, wait, time.Second)

	c.rateLimit.mu.Lock()
	c.rateLimit.nextAllowedRun["zai"] = time.Now().Add(-time.Second)
	c.rateLimit.mu.Unlock()
	wait, limited = c.providerRateLimitWait("zai")
	require.False(t, limited)
	require.Zero(t, wait)
}

func TestSameProviderModel(t *testing.T) {
	t.Parallel()

	base := Model{
		CatwalkCfg: catwalk.Model{ID: "minimax/MiniMax-M2.5-highspeed"},
		ModelCfg: config.SelectedModel{
			Provider: "zai",
			Model:    "minimax/MiniMax-M2.5-highspeed",
		},
	}

	t.Run("same provider and model id", func(t *testing.T) {
		other := base
		require.True(t, sameProviderModel(base, other))
	})

	t.Run("same provider but different model", func(t *testing.T) {
		other := base
		other.CatwalkCfg.ID = "minimax/MiniMax-Text-01"
		other.ModelCfg.Model = "minimax/MiniMax-Text-01"
		require.False(t, sameProviderModel(base, other))
	})

	t.Run("different provider", func(t *testing.T) {
		other := base
		other.ModelCfg.Provider = "openai"
		require.False(t, sameProviderModel(base, other))
	})

	t.Run("falls back to selected model when catwalk id empty", func(t *testing.T) {
		left := Model{
			ModelCfg: config.SelectedModel{
				Provider: "zai",
				Model:    "glm-4.7-flash",
			},
		}
		right := Model{
			ModelCfg: config.SelectedModel{
				Provider: "zai",
				Model:    "glm-4.7-flash",
			},
		}
		require.True(t, sameProviderModel(left, right))
	})
}

func TestShouldFallbackToDeepOnRateLimit(t *testing.T) {
	t.Parallel()

	large := Model{
		CatwalkCfg: catwalk.Model{ID: "minimax/MiniMax-M2.5-highspeed"},
		ModelCfg: config.SelectedModel{
			Provider: "zai",
			Model:    "minimax/MiniMax-M2.5-highspeed",
		},
	}
	smallSame := large
	smallDifferent := Model{
		CatwalkCfg: catwalk.Model{ID: "minimax/MiniMax-Text-01"},
		ModelCfg: config.SelectedModel{
			Provider: "zai",
			Model:    "minimax/MiniMax-Text-01",
		},
	}

	require.False(t, shouldFallbackToDeepOnRateLimit(false, true, large, smallDifferent))
	require.False(t, shouldFallbackToDeepOnRateLimit(true, false, large, smallDifferent))
	require.False(t, shouldFallbackToDeepOnRateLimit(true, true, large, smallSame))
	require.True(t, shouldFallbackToDeepOnRateLimit(true, true, large, smallDifferent))
}

func (m *mockSessionAgent) Run(ctx context.Context, call SessionAgentCall) (*fantasy.AgentResult, error) {
	return m.runFunc(ctx, call)
}

func (m *mockSessionAgent) Model() Model                        { return m.model }
func (m *mockSessionAgent) SetModels(large, small Model)        {}
func (m *mockSessionAgent) SetTools(tools []fantasy.AgentTool)  {}
func (m *mockSessionAgent) SetSystemPrompt(systemPrompt string) {}
func (m *mockSessionAgent) Cancel(sessionID string) {
	m.cancelled = append(m.cancelled, sessionID)
}
func (m *mockSessionAgent) CancelAll()                                  {}
func (m *mockSessionAgent) IsSessionBusy(sessionID string) bool         { return false }
func (m *mockSessionAgent) IsBusy() bool                                { return false }
func (m *mockSessionAgent) QueuedPrompts(sessionID string) int          { return 0 }
func (m *mockSessionAgent) QueuedPromptsList(sessionID string) []string { return nil }
func (m *mockSessionAgent) ClearQueue(sessionID string)                 {}
func (m *mockSessionAgent) Summarize(context.Context, string, fantasy.ProviderOptions) error {
	return nil
}

// newTestCoordinator creates a minimal coordinator for unit testing runSubAgent.
func newTestCoordinator(t *testing.T, env fakeEnv, providerID string, providerCfg config.ProviderConfig) *coordinator {
	cfg, err := config.Init(env.workingDir, "", false)
	require.NoError(t, err)
	cfg.Config().Providers.Set(providerID, providerCfg)
	return &coordinator{
		cfg:      cfg,
		sessions: env.sessions,
	}
}

// newMockAgent creates a mockSessionAgent with the given provider and run function.
func newMockAgent(providerID string, maxTokens int64, runFunc func(context.Context, SessionAgentCall) (*fantasy.AgentResult, error)) *mockSessionAgent {
	return &mockSessionAgent{
		model: Model{
			CatwalkCfg: catwalk.Model{
				DefaultMaxTokens: maxTokens,
			},
			ModelCfg: config.SelectedModel{
				Provider: providerID,
			},
		},
		runFunc: runFunc,
	}
}

// agentResultWithText creates a minimal AgentResult with the given text response.
func agentResultWithText(text string) *fantasy.AgentResult {
	return &fantasy.AgentResult{
		Response: fantasy.Response{
			Content: fantasy.ResponseContent{
				fantasy.TextContent{Text: text},
			},
		},
	}
}

func TestRunSubAgent(t *testing.T) {
	const providerID = "test-provider"
	providerCfg := config.ProviderConfig{ID: providerID}

	t.Run("happy path", func(t *testing.T) {
		env := testEnv(t)
		coord := newTestCoordinator(t, env, providerID, providerCfg)

		parentSession, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		agent := newMockAgent(providerID, 4096, func(_ context.Context, call SessionAgentCall) (*fantasy.AgentResult, error) {
			assert.Equal(t, "do something", call.Prompt)
			assert.Equal(t, int64(4096), call.MaxOutputTokens)
			return agentResultWithText("done"), nil
		})

		resp, err := coord.runSubAgent(t.Context(), subAgentParams{
			Agent:          agent,
			SessionID:      parentSession.ID,
			AgentMessageID: "msg-1",
			ToolCallID:     "call-1",
			Prompt:         "do something",
			SessionTitle:   "Test Session",
		})
		require.NoError(t, err)
		assert.Equal(t, "done", resp.Content)
		assert.False(t, resp.IsError)
	})

	t.Run("ModelCfg.MaxTokens overrides default", func(t *testing.T) {
		env := testEnv(t)
		coord := newTestCoordinator(t, env, providerID, providerCfg)

		parentSession, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		agent := &mockSessionAgent{
			model: Model{
				CatwalkCfg: catwalk.Model{
					DefaultMaxTokens: 4096,
				},
				ModelCfg: config.SelectedModel{
					Provider:  providerID,
					MaxTokens: 8192,
				},
			},
			runFunc: func(_ context.Context, call SessionAgentCall) (*fantasy.AgentResult, error) {
				assert.Equal(t, int64(8192), call.MaxOutputTokens)
				return agentResultWithText("ok"), nil
			},
		}

		resp, err := coord.runSubAgent(t.Context(), subAgentParams{
			Agent:          agent,
			SessionID:      parentSession.ID,
			AgentMessageID: "msg-1",
			ToolCallID:     "call-1",
			Prompt:         "test",
			SessionTitle:   "Test",
		})
		require.NoError(t, err)
		assert.Equal(t, "ok", resp.Content)
	})

	t.Run("session creation failure with canceled context", func(t *testing.T) {
		env := testEnv(t)
		coord := newTestCoordinator(t, env, providerID, providerCfg)

		parentSession, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		agent := newMockAgent(providerID, 4096, nil)

		// Use a canceled context to trigger CreateTaskSession failure.
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err = coord.runSubAgent(ctx, subAgentParams{
			Agent:          agent,
			SessionID:      parentSession.ID,
			AgentMessageID: "msg-1",
			ToolCallID:     "call-1",
			Prompt:         "test",
			SessionTitle:   "Test",
		})
		require.Error(t, err)
	})

	t.Run("provider not configured", func(t *testing.T) {
		env := testEnv(t)
		coord := newTestCoordinator(t, env, providerID, providerCfg)

		parentSession, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		// Agent references a provider that doesn't exist in config.
		agent := newMockAgent("unknown-provider", 4096, nil)

		_, err = coord.runSubAgent(t.Context(), subAgentParams{
			Agent:          agent,
			SessionID:      parentSession.ID,
			AgentMessageID: "msg-1",
			ToolCallID:     "call-1",
			Prompt:         "test",
			SessionTitle:   "Test",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "model provider not configured")
	})

	t.Run("agent run error returns error response", func(t *testing.T) {
		env := testEnv(t)
		coord := newTestCoordinator(t, env, providerID, providerCfg)

		parentSession, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		agent := newMockAgent(providerID, 4096, func(_ context.Context, _ SessionAgentCall) (*fantasy.AgentResult, error) {
			return nil, errors.New("agent exploded")
		})

		resp, err := coord.runSubAgent(t.Context(), subAgentParams{
			Agent:          agent,
			SessionID:      parentSession.ID,
			AgentMessageID: "msg-1",
			ToolCallID:     "call-1",
			Prompt:         "test",
			SessionTitle:   "Test",
		})
		// runSubAgent returns (errorResponse, nil) when agent.Run fails — not a Go error.
		require.NoError(t, err)
		assert.True(t, resp.IsError)
		assert.Equal(t, "error generating response", resp.Content)
	})

	t.Run("session setup callback is invoked", func(t *testing.T) {
		env := testEnv(t)
		coord := newTestCoordinator(t, env, providerID, providerCfg)

		parentSession, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		var setupCalledWith string
		agent := newMockAgent(providerID, 4096, func(_ context.Context, _ SessionAgentCall) (*fantasy.AgentResult, error) {
			return agentResultWithText("ok"), nil
		})

		_, err = coord.runSubAgent(t.Context(), subAgentParams{
			Agent:          agent,
			SessionID:      parentSession.ID,
			AgentMessageID: "msg-1",
			ToolCallID:     "call-1",
			Prompt:         "test",
			SessionTitle:   "Test",
			SessionSetup: func(sessionID string) {
				setupCalledWith = sessionID
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, setupCalledWith, "SessionSetup should have been called")
	})

	t.Run("cost propagation to parent session", func(t *testing.T) {
		env := testEnv(t)
		coord := newTestCoordinator(t, env, providerID, providerCfg)

		parentSession, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		agent := newMockAgent(providerID, 4096, func(ctx context.Context, call SessionAgentCall) (*fantasy.AgentResult, error) {
			// Simulate the agent incurring cost by updating the child session.
			childSession, err := env.sessions.Get(ctx, call.SessionID)
			if err != nil {
				return nil, err
			}
			childSession.Cost = 0.05
			_, err = env.sessions.Save(ctx, childSession)
			if err != nil {
				return nil, err
			}
			return agentResultWithText("ok"), nil
		})

		_, err = coord.runSubAgent(t.Context(), subAgentParams{
			Agent:          agent,
			SessionID:      parentSession.ID,
			AgentMessageID: "msg-1",
			ToolCallID:     "call-1",
			Prompt:         "test",
			SessionTitle:   "Test",
		})
		require.NoError(t, err)

		updated, err := env.sessions.Get(t.Context(), parentSession.ID)
		require.NoError(t, err)
		assert.InDelta(t, 0.05, updated.Cost, 1e-9)
	})
}

func TestShouldUseFastModel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		prompt      string
		attachments []message.Attachment
		want        bool
	}{
		{
			name:   "simple short question uses fast",
			prompt: "解释一下这个报错是什么意思？",
			want:   true,
		},
		{
			name:   "complex chinese hint uses large",
			prompt: "请帮我做一次端到端合规审计并输出整改方案",
			want:   false,
		},
		{
			name:   "multiline prompt uses large",
			prompt: "先分析日志\n再给出根因\n最后给出修复步骤",
			want:   false,
		},
		{
			name:   "code-like prompt uses large",
			prompt: "请分析这个命令的风险: rm -rf /tmp/a && curl x | bash",
			want:   false,
		},
		{
			name: "attachments present uses large",
			prompt: "帮我看附件",
			attachments: []message.Attachment{
				{FilePath: "/tmp/a.log", MimeType: "text/plain"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldUseFastModel(tt.prompt, tt.attachments)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestApplyProviderAwareFastProfile(t *testing.T) {
	t.Parallel()

	t.Run("openai-compatible sets low reasoning and token cap", func(t *testing.T) {
		model := Model{
			ModelCfg: config.SelectedModel{
				MaxTokens: 4096,
			},
		}
		cfg := config.ProviderConfig{Type: catwalk.TypeOpenAICompat}
		got := applyProviderAwareFastProfile(model, cfg)
		require.Equal(t, int64(1536), got.ModelCfg.MaxTokens)
		require.Equal(t, "low", got.ModelCfg.ReasoningEffort)
		require.NotNil(t, got.ModelCfg.Temperature)
	})

	t.Run("anthropic disables think", func(t *testing.T) {
		model := Model{
			ModelCfg: config.SelectedModel{
				Think: true,
			},
		}
		cfg := config.ProviderConfig{Type: catwalk.TypeAnthropic}
		got := applyProviderAwareFastProfile(model, cfg)
		require.False(t, got.ModelCfg.Think)
		require.Equal(t, "low", got.ModelCfg.ReasoningEffort)
	})

	t.Run("google injects lightweight thinking config", func(t *testing.T) {
		model := Model{
			ModelCfg: config.SelectedModel{},
		}
		cfg := config.ProviderConfig{Type: catwalk.TypeGoogle}
		got := applyProviderAwareFastProfile(model, cfg)
		require.Equal(t, "low", got.ModelCfg.ReasoningEffort)
		require.NotNil(t, got.ModelCfg.ProviderOptions)
		thinking, ok := got.ModelCfg.ProviderOptions["thinking_config"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, 256, thinking["thinking_budget"])
		require.Equal(t, false, thinking["include_thoughts"])
	})
}

func TestParseRunModePrompt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		mode   runMode
		output string
	}{
		{
			name:   "auto mode keeps prompt",
			input:  "hello",
			mode:   runModeAuto,
			output: "hello",
		},
		{
			name:   "fast mode strips prefix",
			input:  "/fast 请给我一句总结",
			mode:   runModeFast,
			output: "请给我一句总结",
		},
		{
			name:   "deep mode strips prefix",
			input:  "/deep 帮我做完整排障",
			mode:   runModeDeep,
			output: "帮我做完整排障",
		},
		{
			name:   "case insensitive fast",
			input:  "  /FAST status  ",
			mode:   runModeFast,
			output: "status",
		},
		{
			name:   "similar prefix is not treated as directive",
			input:  "/faster status",
			mode:   runModeAuto,
			output: "/faster status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMode, gotPrompt := parseRunModePrompt(tt.input)
			require.Equal(t, tt.mode, gotMode)
			require.Equal(t, tt.output, gotPrompt)
		})
	}
}

func TestUpdateParentSessionCost(t *testing.T) {
	t.Run("accumulates cost correctly", func(t *testing.T) {
		env := testEnv(t)
		cfg, err := config.Init(env.workingDir, "", false)
		require.NoError(t, err)
		coord := &coordinator{cfg: cfg, sessions: env.sessions}

		parent, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		child, err := env.sessions.CreateTaskSession(t.Context(), "tool-1", parent.ID, "Child")
		require.NoError(t, err)

		// Set child cost.
		child.Cost = 0.10
		_, err = env.sessions.Save(t.Context(), child)
		require.NoError(t, err)

		err = coord.updateParentSessionCost(t.Context(), child.ID, parent.ID)
		require.NoError(t, err)

		updated, err := env.sessions.Get(t.Context(), parent.ID)
		require.NoError(t, err)
		assert.InDelta(t, 0.10, updated.Cost, 1e-9)
	})

	t.Run("accumulates multiple child costs", func(t *testing.T) {
		env := testEnv(t)
		cfg, err := config.Init(env.workingDir, "", false)
		require.NoError(t, err)
		coord := &coordinator{cfg: cfg, sessions: env.sessions}

		parent, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		child1, err := env.sessions.CreateTaskSession(t.Context(), "tool-1", parent.ID, "Child1")
		require.NoError(t, err)
		child1.Cost = 0.05
		_, err = env.sessions.Save(t.Context(), child1)
		require.NoError(t, err)

		child2, err := env.sessions.CreateTaskSession(t.Context(), "tool-2", parent.ID, "Child2")
		require.NoError(t, err)
		child2.Cost = 0.03
		_, err = env.sessions.Save(t.Context(), child2)
		require.NoError(t, err)

		err = coord.updateParentSessionCost(t.Context(), child1.ID, parent.ID)
		require.NoError(t, err)
		err = coord.updateParentSessionCost(t.Context(), child2.ID, parent.ID)
		require.NoError(t, err)

		updated, err := env.sessions.Get(t.Context(), parent.ID)
		require.NoError(t, err)
		assert.InDelta(t, 0.08, updated.Cost, 1e-9)
	})

	t.Run("child session not found", func(t *testing.T) {
		env := testEnv(t)
		cfg, err := config.Init(env.workingDir, "", false)
		require.NoError(t, err)
		coord := &coordinator{cfg: cfg, sessions: env.sessions}

		parent, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)

		err = coord.updateParentSessionCost(t.Context(), "non-existent", parent.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get child session")
	})

	t.Run("parent session not found", func(t *testing.T) {
		env := testEnv(t)
		cfg, err := config.Init(env.workingDir, "", false)
		require.NoError(t, err)
		coord := &coordinator{cfg: cfg, sessions: env.sessions}

		parent, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)
		child, err := env.sessions.CreateTaskSession(t.Context(), "tool-1", parent.ID, "Child")
		require.NoError(t, err)

		err = coord.updateParentSessionCost(t.Context(), child.ID, "non-existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get parent session")
	})

	t.Run("zero cost handled correctly", func(t *testing.T) {
		env := testEnv(t)
		cfg, err := config.Init(env.workingDir, "", false)
		require.NoError(t, err)
		coord := &coordinator{cfg: cfg, sessions: env.sessions}

		parent, err := env.sessions.Create(t.Context(), "Parent")
		require.NoError(t, err)
		child, err := env.sessions.CreateTaskSession(t.Context(), "tool-1", parent.ID, "Child")
		require.NoError(t, err)

		err = coord.updateParentSessionCost(t.Context(), child.ID, parent.ID)
		require.NoError(t, err)

		updated, err := env.sessions.Get(t.Context(), parent.ID)
		require.NoError(t, err)
		assert.InDelta(t, 0.0, updated.Cost, 1e-9)
	})
}

func TestCoordinatorUpdateStateCaching(t *testing.T) {
	t.Parallel()

	c := &coordinator{}
	modelSig := "model-signature-v1"
	toolSig := "tools-signature-v1"

	needsModels, needsTools := c.shouldRefresh(false, modelSig, toolSig)
	require.True(t, needsModels)
	require.True(t, needsTools)

	c.markUpdated(modelSig, toolSig, true, true)

	needsModels, needsTools = c.shouldRefresh(false, modelSig, toolSig)
	require.False(t, needsModels)
	require.False(t, needsTools)

	needsModels, needsTools = c.shouldRefresh(false, "model-signature-v2", toolSig)
	require.True(t, needsModels)
	require.False(t, needsTools)

	needsModels, needsTools = c.shouldRefresh(true, modelSig, toolSig)
	require.True(t, needsModels)
	require.True(t, needsTools)
}

func TestBuildAnthropicProvider_AllowsNilHeadersWithBearerKey(t *testing.T) {
	t.Parallel()

	env := testEnv(t)
	cfg, err := config.Init(env.workingDir, "", false)
	require.NoError(t, err)

	c := &coordinator{cfg: cfg}

	provider, err := c.buildAnthropicProvider("", "Bearer test-token", nil, "")
	require.NoError(t, err)
	require.NotNil(t, provider)
}
