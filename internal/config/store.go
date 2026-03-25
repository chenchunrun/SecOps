package config

import (
	"cmp"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"charm.land/catwalk/pkg/catwalk"
	hyperp "github.com/chenchunrun/SecOps/internal/agent/hyper"
	"github.com/chenchunrun/SecOps/internal/oauth"
	"github.com/chenchunrun/SecOps/internal/oauth/copilot"
	"github.com/chenchunrun/SecOps/internal/oauth/hyper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Encrypted value marker prefix written to config files.
const encryptedMarker = "ENC:"

// sensitivePrefixes is the list of key prefixes that identify sensitive values.
var sensitivePrefixes = []string{"oauth", "refresh_token", "api_key", "secret", "access_token", "bearer"}

func deriveKeyFromIdentity(homeDir, username string) ([]byte, error) {
	if homeDir == "" || username == "" {
		return nil, errors.New("home directory or username not set")
	}
	h := sha256.Sum256([]byte(homeDir + ":" + username + ":crush-secrets-v1"))
	return h[:], nil
}

func currentIdentity() (homeDir, username string) {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		homeDir = h
	}
	if homeDir == "" {
		homeDir = os.Getenv("HOME")
	}

	if u, err := user.Current(); err == nil && u != nil {
		username = u.Username
	}
	if username == "" {
		username = os.Getenv("USER")
	}
	if username == "" {
		username = os.Getenv("LOGNAME")
	}

	return homeDir, username
}

func deriveKeyCandidates() [][]byte {
	candidates := make([][]byte, 0, 2)
	seen := map[string]struct{}{}

	homeDir, username := currentIdentity()
	if k, err := deriveKeyFromIdentity(homeDir, username); err == nil {
		ks := string(k)
		seen[ks] = struct{}{}
		candidates = append(candidates, k)
	}

	// Compatibility with values encrypted by older builds.
	legacyHome := os.Getenv("HOME")
	legacyUser := os.Getenv("USER")
	if k, err := deriveKeyFromIdentity(legacyHome, legacyUser); err == nil {
		ks := string(k)
		if _, exists := seen[ks]; !exists {
			candidates = append(candidates, k)
		}
	}

	return candidates
}

func deriveKey() ([]byte, error) {
	keys := deriveKeyCandidates()
	if len(keys) == 0 {
		return nil, errors.New("no key material available")
	}
	return keys[0], nil
}

// encrypt encrypts a plaintext string using AES-256-GCM and returns a base64-encoded
// "ENC:<ciphertext>" string suitable for writing to a config file.
func encrypt(plaintext string) (string, error) {
	key, err := deriveKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encryptedMarker + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// decrypt reverses encrypt: it strips the ENC: marker, decodes base64, and
// returns the plaintext using AES-256-GCM.
func decrypt(encoded string) (string, error) {
	if !strings.HasPrefix(encoded, encryptedMarker) {
		return "", errors.New("not an encrypted value")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(encoded[len(encryptedMarker):])
	if err != nil {
		return "", err
	}
	keys := deriveKeyCandidates()
	if len(keys) == 0 {
		return "", errors.New("no key material available")
	}

	var lastErr error
	for _, key := range keys {
		block, err := aes.NewCipher(key)
		if err != nil {
			lastErr = err
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			lastErr = err
			continue
		}
		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			return "", errors.New("ciphertext too short")
		}
		nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ct, nil)
		if err == nil {
			return string(plaintext), nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("failed to decrypt config value")
	}
	return "", lastErr
}

// isSensitive returns true if the given key name refers to a sensitive field
// that should be encrypted before being written to disk.
func isSensitive(key string) bool {
	lower := strings.ToLower(key)
	for _, prefix := range sensitivePrefixes {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

// jsonMarshal wraps json.Marshal for use within this package.
func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ConfigStore is the single entry point for all config access. It owns the
// pure-data Config, runtime state (working directory, resolver, known
// providers), and persistence to both global and workspace config files.
type ConfigStore struct {
	config         *Config
	workingDir     string
	resolver       VariableResolver
	globalCfgPath  string // ~/.config/crush/crush.json
	globalDataPath string // ~/.local/share/crush/crush.json
	workspacePath  string // .crush/crush.json
	knownProviders []catwalk.Provider
}

// Config returns the pure-data config struct (read-only after load).
func (s *ConfigStore) Config() *Config {
	return s.config
}

// WorkingDir returns the current working directory.
func (s *ConfigStore) WorkingDir() string {
	return s.workingDir
}

// Resolver returns the variable resolver.
func (s *ConfigStore) Resolver() VariableResolver {
	return s.resolver
}

// Resolve resolves a variable reference using the configured resolver.
func (s *ConfigStore) Resolve(key string) (string, error) {
	if s.resolver == nil {
		return "", fmt.Errorf("no variable resolver configured")
	}
	return s.resolver.ResolveValue(key)
}

// KnownProviders returns the list of known providers.
func (s *ConfigStore) KnownProviders() []catwalk.Provider {
	return s.knownProviders
}

// SetupAgents configures the coder and task agents on the config.
func (s *ConfigStore) SetupAgents() {
	s.config.SetupAgents()
}

// configPath returns the file path for the given scope.
func (s *ConfigStore) configPath(scope Scope) string {
	switch scope {
	case ScopeGlobalConfig:
		return s.globalCfgPath
	case ScopeWorkspace:
		return s.workspacePath
	default:
		return s.globalDataPath
	}
}

// HasConfigField checks whether a key exists in the config file for the given
// scope.
func (s *ConfigStore) HasConfigField(scope Scope, key string) bool {
	data, err := os.ReadFile(s.configPath(scope))
	if err != nil {
		return false
	}
	return gjson.Get(string(data), key).Exists()
}

// SetConfigField sets a key/value pair in the config file for the given scope.
func (s *ConfigStore) SetConfigField(scope Scope, key string, value any) error {
	path := s.configPath(scope)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			data = []byte("{}")
		} else {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Encrypt sensitive values before persisting.
	writeValue := value
	if isSensitive(key) {
		var plaintext string
		switch v := value.(type) {
		case string:
			plaintext = v
		default:
			// Marshal structs (e.g. oauth.Token) to JSON for encryption.
			plaintext, err = jsonMarshal(value)
			if err != nil {
				return fmt.Errorf("failed to marshal sensitive value for encryption: %w", err)
			}
		}
		var encrypted string
		encrypted, err = encrypt(plaintext)
		if err != nil {
			return fmt.Errorf("failed to encrypt sensitive value: %w", err)
		}
		writeValue = encrypted
	}

	newValue, err := sjson.Set(string(data), key, writeValue)
	if err != nil {
		return fmt.Errorf("failed to set config field %s: %w", key, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create config directory %q: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(newValue), 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

// RemoveConfigField removes a key from the config file for the given scope.
func (s *ConfigStore) RemoveConfigField(scope Scope, key string) error {
	path := s.configPath(scope)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	newValue, err := sjson.Delete(string(data), key)
	if err != nil {
		return fmt.Errorf("failed to delete config field %s: %w", key, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create config directory %q: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(newValue), 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

// UpdatePreferredModel updates the preferred model for the given type and
// persists it to the config file at the given scope.
func (s *ConfigStore) UpdatePreferredModel(scope Scope, modelType SelectedModelType, model SelectedModel) error {
	s.config.Models[modelType] = model
	if err := s.SetConfigField(scope, fmt.Sprintf("models.%s", modelType), model); err != nil {
		return fmt.Errorf("failed to update preferred model: %w", err)
	}
	if err := s.recordRecentModel(scope, modelType, model); err != nil {
		return err
	}
	return nil
}

// SetCompactMode sets the compact mode setting and persists it.
func (s *ConfigStore) SetCompactMode(scope Scope, enabled bool) error {
	if s.config.Options == nil {
		s.config.Options = &Options{}
	}
	s.config.Options.TUI.CompactMode = enabled
	return s.SetConfigField(scope, "options.tui.compact_mode", enabled)
}

// SetTransparentBackground sets the transparent background setting and persists it.
func (s *ConfigStore) SetTransparentBackground(scope Scope, enabled bool) error {
	if s.config.Options == nil {
		s.config.Options = &Options{}
	}
	s.config.Options.TUI.Transparent = &enabled
	return s.SetConfigField(scope, "options.tui.transparent", enabled)
}

// SetProviderAPIKey sets the API key for a provider and persists it.
func (s *ConfigStore) SetProviderAPIKey(scope Scope, providerID string, apiKey any) error {
	var providerConfig ProviderConfig
	var exists bool
	var setKeyOrToken func()

	switch v := apiKey.(type) {
	case string:
		if err := s.SetConfigField(scope, fmt.Sprintf("providers.%s.api_key", providerID), v); err != nil {
			return fmt.Errorf("failed to save api key to config file: %w", err)
		}
		setKeyOrToken = func() { providerConfig.APIKey = v }
	case *oauth.Token:
		if err := cmp.Or(
			s.SetConfigField(scope, fmt.Sprintf("providers.%s.api_key", providerID), v.AccessToken),
			s.SetConfigField(scope, fmt.Sprintf("providers.%s.oauth", providerID), v),
		); err != nil {
			return err
		}
		setKeyOrToken = func() {
			providerConfig.APIKey = v.AccessToken
			providerConfig.OAuthToken = v
			switch providerID {
			case string(catwalk.InferenceProviderCopilot):
				providerConfig.SetupGitHubCopilot()
			}
		}
	}

	providerConfig, exists = s.config.Providers.Get(providerID)
	if exists {
		setKeyOrToken()
		s.config.Providers.Set(providerID, providerConfig)
		return nil
	}

	var foundProvider *catwalk.Provider
	for _, p := range s.knownProviders {
		if string(p.ID) == providerID {
			foundProvider = &p
			break
		}
	}

	if foundProvider != nil {
		providerConfig = ProviderConfig{
			ID:           providerID,
			Name:         foundProvider.Name,
			BaseURL:      foundProvider.APIEndpoint,
			Type:         foundProvider.Type,
			Disable:      false,
			ExtraHeaders: make(map[string]string),
			ExtraParams:  make(map[string]string),
			Models:       foundProvider.Models,
		}
		setKeyOrToken()
	} else {
		return fmt.Errorf("provider with ID %s not found in known providers", providerID)
	}
	s.config.Providers.Set(providerID, providerConfig)
	return nil
}

// RefreshOAuthToken refreshes the OAuth token for the given provider.
func (s *ConfigStore) RefreshOAuthToken(ctx context.Context, scope Scope, providerID string) error {
	providerConfig, exists := s.config.Providers.Get(providerID)
	if !exists {
		return fmt.Errorf("provider %s not found", providerID)
	}

	if providerConfig.OAuthToken == nil {
		return fmt.Errorf("provider %s does not have an OAuth token", providerID)
	}

	var newToken *oauth.Token
	var refreshErr error
	switch providerID {
	case string(catwalk.InferenceProviderCopilot):
		newToken, refreshErr = copilot.RefreshToken(ctx, providerConfig.OAuthToken.RefreshToken)
	case hyperp.Name:
		newToken, refreshErr = hyper.ExchangeToken(ctx, providerConfig.OAuthToken.RefreshToken)
	default:
		return fmt.Errorf("OAuth refresh not supported for provider %s", providerID)
	}
	if refreshErr != nil {
		return fmt.Errorf("failed to refresh OAuth token for provider %s: %w", providerID, refreshErr)
	}

	slog.Info("Successfully refreshed OAuth token", "provider", providerID)
	providerConfig.OAuthToken = newToken
	providerConfig.APIKey = newToken.AccessToken

	switch providerID {
	case string(catwalk.InferenceProviderCopilot):
		providerConfig.SetupGitHubCopilot()
	}

	s.config.Providers.Set(providerID, providerConfig)

	if err := cmp.Or(
		s.SetConfigField(scope, fmt.Sprintf("providers.%s.api_key", providerID), newToken.AccessToken),
		s.SetConfigField(scope, fmt.Sprintf("providers.%s.oauth", providerID), newToken),
	); err != nil {
		return fmt.Errorf("failed to persist refreshed token: %w", err)
	}

	return nil
}

// recordRecentModel records a model in the recent models list.
func (s *ConfigStore) recordRecentModel(scope Scope, modelType SelectedModelType, model SelectedModel) error {
	if model.Provider == "" || model.Model == "" {
		return nil
	}

	if s.config.RecentModels == nil {
		s.config.RecentModels = make(map[SelectedModelType][]SelectedModel)
	}

	eq := func(a, b SelectedModel) bool {
		return a.Provider == b.Provider && a.Model == b.Model
	}

	entry := SelectedModel{
		Provider: model.Provider,
		Model:    model.Model,
	}

	current := s.config.RecentModels[modelType]
	withoutCurrent := slices.DeleteFunc(slices.Clone(current), func(existing SelectedModel) bool {
		return eq(existing, entry)
	})

	updated := append([]SelectedModel{entry}, withoutCurrent...)
	if len(updated) > maxRecentModelsPerType {
		updated = updated[:maxRecentModelsPerType]
	}

	if slices.EqualFunc(current, updated, eq) {
		return nil
	}

	s.config.RecentModels[modelType] = updated

	if err := s.SetConfigField(scope, fmt.Sprintf("recent_models.%s", modelType), updated); err != nil {
		return fmt.Errorf("failed to persist recent models: %w", err)
	}

	return nil
}

// ImportCopilot attempts to import a GitHub Copilot token from disk.
func (s *ConfigStore) ImportCopilot() (*oauth.Token, bool) {
	if s.HasConfigField(ScopeGlobal, "providers.copilot.api_key") || s.HasConfigField(ScopeGlobal, "providers.copilot.oauth") {
		return nil, false
	}

	diskToken, hasDiskToken := copilot.RefreshTokenFromDisk()
	if !hasDiskToken {
		return nil, false
	}

	slog.Info("Found existing GitHub Copilot token on disk. Authenticating...")
	token, err := copilot.RefreshToken(context.TODO(), diskToken)
	if err != nil {
		slog.Error("Unable to import GitHub Copilot token", "error", err)
		return nil, false
	}

	if err := s.SetProviderAPIKey(ScopeGlobal, string(catwalk.InferenceProviderCopilot), token); err != nil {
		return token, false
	}

	if err := cmp.Or(
		s.SetConfigField(ScopeGlobal, "providers.copilot.api_key", token.AccessToken),
		s.SetConfigField(ScopeGlobal, "providers.copilot.oauth", token),
	); err != nil {
		slog.Error("Unable to save GitHub Copilot token to disk", "error", err)
	}

	slog.Info("GitHub Copilot successfully imported")
	return token, true
}
