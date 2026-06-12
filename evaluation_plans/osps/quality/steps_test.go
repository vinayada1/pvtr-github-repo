package quality

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
)

func Test_InsightsListsRepositories(t *testing.T) {
	tests := []struct {
		name       string
		payload    data.Payload
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name: "insights contains repositories",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Repositories: []si.ProjectRepository{
								{
									Url: "https://github.com/org/repo",
								},
							},
						},
					},
				},
			},
			wantResult: gemara.Passed,
			wantMsg:    "Insights contains a list of repositories",
		},
		{
			name: "insights does not contain repositories",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Repositories: []si.ProjectRepository{},
						},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Insights does not contain a list of repositories",
		},
		{
			name: "insights is nil",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Insights does not contain a list of repositories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMsg, _ := InsightsListsRepositories(tt.payload)
			if gotResult != tt.wantResult {
				t.Errorf("result = %v, want %v", gotResult, tt.wantResult)
			}
			if gotMsg != tt.wantMsg {
				t.Errorf("message = %q, want %q", gotMsg, tt.wantMsg)
			}
		})
	}
}

func Test_NoUnreviewableBinariesInRepo(t *testing.T) {
	t.Run("invalid payload returns unknown", func(t *testing.T) {
		result, msg, _ := NoUnreviewableBinariesInRepo(data.Payload{})
		if result != gemara.Unknown {
			t.Errorf("result = %v, want Unknown", result)
		}
		if msg == "" {
			t.Error("expected non-empty message for invalid payload")
		}
	})
}

type stubAIClient struct {
	response *sdkai.AnalyzeResponse
	err      error
}

var compactPacketFiles = []string{"assessment.json", "ai_interaction.json"}

var legacyPacketFiles = []string{
	"run-metadata.json",
	"manifest.json",
	"prompt.txt",
	"schema.json",
	"response.txt",
	"response.json",
	"attempt.json",
	"verdict.json",
	"failure.json",
	"evidence.txt",
}

var packetSecretValues = []string{
	"super-secret-key",
	"ghp-secret-123",
	"proxy-user",
	"proxy-pass",
	"query-secret",
	"sk-live-1234567890abcdef",
}

func (s stubAIClient) Analyze(ctx context.Context, prompt, content string, schema *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	return s.response, s.err
}

func assertContainsAll(t *testing.T, label, got string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %s to include %s, got %s", label, want, got)
		}
	}
}

func assertContainsNone(t *testing.T, label, got string, unwanted []string) {
	t.Helper()
	for _, value := range unwanted {
		if strings.Contains(got, value) {
			t.Fatalf("%s leaked %q: %s", label, value, got)
		}
	}
}

func assertFilesExist(t *testing.T, dir string, names []string) {
	t.Helper()
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected packet file %s: %v", name, err)
		}
	}
}

func assertFilesAbsent(t *testing.T, dir string, names []string) {
	t.Helper()
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("expected no %s in compact packet, got err=%v", name, err)
		}
	}
}

func TestTestExecutionDocumentation(t *testing.T) {
	originalFactory := newAIClientFromConfig
	originalEvidenceLoader := loadTestExecutionDocumentationEvidence
	resetTestExecutionDocumentationCachedResults()
	t.Cleanup(func() {
		newAIClientFromConfig = originalFactory
		loadTestExecutionDocumentationEvidence = originalEvidenceLoader
		resetTestExecutionDocumentationCachedResults()
	})

	payload := data.Payload{Config: &sdkconfig.Config{}}
	loadTestExecutionDocumentationEvidence = func(payload data.Payload) (string, error) {
		return "README\nRun `go test ./...` before opening a PR.", nil
	}

	t.Run("no AI config preserves legacy behavior", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return nil, nil
		}

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview {
			t.Fatalf("result = %v, want NeedsReview", result)
		}
		if msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("message = %q, want %q", msg, testExecutionDocumentationFallbackMessage)
		}
	})

	t.Run("partial live AI config falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = sdkai.NewClientFromConfig

		partialPayload := data.Payload{Config: &sdkconfig.Config{Vars: map[string]interface{}{
			"ai_provider": "openai",
			"ai_model":    "gpt-4o-mini",
		}}}

		result, msg, _ := TestExecutionDocumentation(partialPayload)
		if result != gemara.NeedsReview {
			t.Fatalf("result = %v, want NeedsReview", result)
		}
		if msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("message = %q, want %q", msg, testExecutionDocumentationFallbackMessage)
		}
	})

	t.Run("ai returns pass verdict", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{JSON: []byte(`{"verdict":"pass","confidence":0.91,"reasoning":"README explains that contributors run go test before opening a PR.","evidence_location":"README#testing"}`)}}, nil
		}

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.Passed {
			t.Fatalf("result = %v, want Passed", result)
		}
		if !strings.HasPrefix(msg, "[AI-Assisted]") {
			t.Fatalf("expected AI-assisted message, got %q", msg)
		}
	})

	t.Run("ai returns fail verdict", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{JSON: []byte(`{"verdict":"fail","confidence":0.84,"reasoning":"The docs mention tests exist but never explain when or how to run them.","evidence_location":"README#development"}`)}}, nil
		}

		result, _, _ := TestExecutionDocumentation(payload)
		if result != gemara.Failed {
			t.Fatalf("result = %v, want Failed", result)
		}
	})

	t.Run("invalid AI response falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{JSON: []byte(`{"verdict":"pass","confidence":0.84,"reasoning":"","evidence_location":"README#development"}`)}}, nil
		}

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview || msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})

	t.Run("ai timeout falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{err: context.DeadlineExceeded}, nil
		}

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview || msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})

	t.Run("ai provider error falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{err: errors.New("provider unavailable")}, nil
		}

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview || msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})

	t.Run("ai success writes evidence packet with redacted config", func(t *testing.T) {
		tempDir := t.TempDir()
		loadTestExecutionDocumentationEvidence = func(payload data.Payload) (string, error) {
			return "README\nRun `go test ./...` with token ghp-secret-123 before opening a PR.\nAuthorization: Bearer sk-live-1234567890abcdef", nil
		}
		payloadWithWrites := data.Payload{Config: &sdkconfig.Config{
			ServiceName:    "my-scan",
			WriteDirectory: tempDir,
			Write:          true,
			Vars: map[string]interface{}{
				"owner":             "test-owner",
				"repo":              "config-repo-name",
				"ai_provider":       "openai",
				"ai_model":          "gpt-4o-mini",
				"ai_api_key":        "super-secret-key",
				"ai_base_url":       "https://proxy-user:proxy-pass@example.test/v1?api_key=query-secret&mode=test",
				"ai_write_evidence": true,
				"github_token":      "ghp-secret-123",
			},
		}, GraphqlRepoData: &data.GraphqlRepoData{}}
		payloadWithWrites.Repository.Name = "graph-repo-name"
		payloadWithWrites.Repository.DefaultBranchRef.Name = "main"
		payloadWithWrites.Repository.DefaultBranchRef.Target.OID = "abc123def456"
		payloadWithWrites.Repository.Object.Tree.Entries = []struct {
			Name string
			Type string
			Path string
		}{
			{Name: "README.md", Type: "blob", Path: "README.md"},
			{Name: "CONTRIBUTING.md", Type: "blob", Path: "CONTRIBUTING.md"},
		}
		payloadWithWrites.Repository.ContributingGuidelines.Body = "Use the documented test workflow before requesting review."

		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{
				Text: "raw model response mentioning https://proxy-user:proxy-pass@example.test/v1?api_key=query-secret&mode=test and ghp-secret-123 and sk-live-1234567890abcdef",
				JSON: []byte(`{"verdict":"pass","confidence":0.91,"reasoning":"README explains that contributors run go test with ghp-secret-123 before opening a PR. Authorization: Bearer sk-live-1234567890abcdef","evidence_location":"README#testing ghp-secret-123"}`),
				Metadata: sdkai.ResponseMetadata{
					Provider:     sdkai.ProviderOpenAI,
					Model:        "gpt-4o-mini-2024-07-18",
					RequestID:    "req-123",
					FinishReason: "stop",
				},
			}}, nil
		}

		result, _, _ := TestExecutionDocumentation(payloadWithWrites)
		if result != gemara.Passed {
			t.Fatalf("result = %v, want Passed", result)
		}

		packetMatches, err := filepath.Glob(filepath.Join(tempDir, "my-scan", "ai-evidence", "OSPS-QA-06.02", "*"))
		if err != nil {
			t.Fatalf("glob packet dir: %v", err)
		}
		if len(packetMatches) != 1 {
			t.Fatalf("expected 1 packet directory, got %d (%v)", len(packetMatches), packetMatches)
		}

		packetDir := packetMatches[0]
		assertFilesExist(t, packetDir, compactPacketFiles)
		assertFilesAbsent(t, packetDir, legacyPacketFiles)

		assessment, err := os.ReadFile(filepath.Join(packetDir, "assessment.json"))
		if err != nil {
			t.Fatalf("read assessment: %v", err)
		}
		assessmentText := string(assessment)
		if !strings.Contains(assessmentText, "REDACTED") {
			t.Fatalf("expected assessment to redact ai_api_key, got %s", assessmentText)
		}
		assertContainsAll(t, "assessment", assessmentText, []string{
			`"packet_version": "1"`,
			`"repository_owner": "test-owner"`,
			`"repository_name": "graph-repo-name"`,
			`"default_branch": "main"`,
			`"commit_sha": "abc123def456"`,
			`"outcome": "succeeded"`,
		})
		assertContainsAll(t, "assessment", assessmentText, []string{
			`"attempt_stage": "assessment_completed"`,
			`"result": "Passed"`,
			`"verdict": "pass"`,
			`"reasoning":`,
			`"evidence_location": "README#testing REDACTED"`,
		})
		assertContainsNone(t, "assessment", assessmentText, []string{
			"super-secret-key",
			"proxy-user",
			"proxy-pass",
			"query-secret",
		})
		// The SDK's defense-in-depth redactor scrubs any "api_key=" assignment up
		// to the next delimiter, so the non-sensitive mode=test query parameter is
		// dropped along with the redacted secret. Userinfo, host, and path remain.
		if !strings.Contains(assessmentText, "https://REDACTED:REDACTED@example.test/v1?api_key=REDACTED") {
			t.Fatalf("assessment did not preserve sanitized ai_base_url: %s", assessmentText)
		}

		if err := filepath.WalkDir(packetDir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}

			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			assertContainsNone(t, path, string(body), packetSecretValues)
			return nil
		}); err != nil {
			t.Fatalf("walk packet dir: %v", err)
		}

		interaction, err := os.ReadFile(filepath.Join(packetDir, "ai_interaction.json"))
		if err != nil {
			t.Fatalf("read ai_interaction: %v", err)
		}
		interactionText := string(interaction)
		assertContainsAll(t, "ai_interaction.json", interactionText, []string{
			`"prompt":`,
			`"schema":`,
			`"test_execution_documentation_assessment"`,
			`"evidence":`,
			`"sources":`,
			`"content":`,
			`"response":`,
			`"verdict": "pass"`,
			"https://github.com/test-owner/graph-repo-name/blob/abc123def456/README.md",
			"https://github.com/test-owner/graph-repo-name/blob/abc123def456/CONTRIBUTING.md",
		})
		assertContainsNone(t, "ai_interaction.json", interactionText, []string{
			"Authorization: Bearer sk-live-1234567890abcdef",
			"ghp-secret-123",
			"super-secret-key",
			"proxy-user",
			"proxy-pass",
			"query-secret",
		})

	})

	t.Run("write false skips evidence packet creation", func(t *testing.T) {
		tempDir := t.TempDir()
		payloadWithoutWrites := data.Payload{Config: &sdkconfig.Config{
			ServiceName:    "my-scan",
			WriteDirectory: tempDir,
			Write:          false,
			Vars: map[string]interface{}{
				"ai_provider":       "openai",
				"ai_model":          "gpt-4o-mini",
				"ai_api_key":        "super-secret-key",
				"ai_write_evidence": true,
			},
		}}

		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{
				JSON:     []byte(`{"verdict":"pass","confidence":0.91,"reasoning":"README explains that contributors run go test before opening a PR.","evidence_location":"README#testing"}`),
				Metadata: sdkai.ResponseMetadata{Provider: sdkai.ProviderOpenAI, Model: "gpt-4o-mini", RequestID: "req-456", FinishReason: "stop"},
			}}, nil
		}

		result, _, _ := TestExecutionDocumentation(payloadWithoutWrites)
		if result != gemara.Passed {
			t.Fatalf("result = %v, want Passed", result)
		}

		packetMatches, err := filepath.Glob(filepath.Join(tempDir, "my-scan", "ai-evidence", "OSPS-QA-06.02", "*"))
		if err != nil {
			t.Fatalf("glob packet dir: %v", err)
		}
		if len(packetMatches) != 0 {
			t.Fatalf("expected no packet directories when write=false, got %v", packetMatches)
		}
	})

	t.Run("ai evidence writing disabled skips evidence packet creation", func(t *testing.T) {
		tempDir := t.TempDir()
		payloadWithoutEvidenceWrites := data.Payload{Config: &sdkconfig.Config{
			ServiceName:    "my-scan",
			WriteDirectory: tempDir,
			Write:          true,
			Vars: map[string]interface{}{
				"ai_provider": "openai",
				"ai_model":    "gpt-4o-mini",
				"ai_api_key":  "super-secret-key",
			},
		}}

		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{
				JSON:     []byte(`{"verdict":"pass","confidence":0.91,"reasoning":"README explains that contributors run go test before opening a PR.","evidence_location":"README#testing"}`),
				Metadata: sdkai.ResponseMetadata{Provider: sdkai.ProviderOpenAI, Model: "gpt-4o-mini", RequestID: "req-789", FinishReason: "stop"},
			}}, nil
		}

		result, _, _ := TestExecutionDocumentation(payloadWithoutEvidenceWrites)
		if result != gemara.Passed {
			t.Fatalf("result = %v, want Passed", result)
		}

		packetMatches, err := filepath.Glob(filepath.Join(tempDir, "my-scan", "ai-evidence", "OSPS-QA-06.02", "*"))
		if err != nil {
			t.Fatalf("glob packet dir: %v", err)
		}
		if len(packetMatches) != 0 {
			t.Fatalf("expected no packet directories when ai_write_evidence is unset, got %v", packetMatches)
		}
	})

	t.Run("ai verdict log redacts model-derived evidence location", func(t *testing.T) {
		var logOutput bytes.Buffer
		payloadWithLogger := data.Payload{Config: &sdkconfig.Config{
			Logger: hclog.New(&hclog.LoggerOptions{
				Level:  hclog.Info,
				Output: &logOutput,
			}),
			Vars: map[string]interface{}{
				"ai_provider":  "openai",
				"ai_model":     "gpt-4o-mini",
				"ai_api_key":   "super-secret-key",
				"github_token": "ghp-secret-123",
			},
		}}

		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{
				JSON: []byte(`{"verdict":"pass","confidence":0.91,"reasoning":"Looks good","evidence_location":"README#testing ghp-secret-123 Authorization: Bearer sk-live-1234567890abcdef"}`),
			}}, nil
		}

		result, _, _ := TestExecutionDocumentation(payloadWithLogger)
		if result != gemara.Passed {
			t.Fatalf("result = %v, want Passed", result)
		}

		logs := logOutput.String()
		assertContainsNone(t, "logs", logs, []string{"ghp-secret-123", "sk-live-1234567890abcdef"})
		if !strings.Contains(logs, "evidence_location=\"README#testing REDACTED Authorization: Bearer REDACTED\"") {
			t.Fatalf("expected sanitized evidence location in logs, got %s", logs)
		}
	})

	t.Run("provider failure writes reduced evidence packet", func(t *testing.T) {
		tempDir := t.TempDir()
		payloadWithWrites := data.Payload{Config: &sdkconfig.Config{
			ServiceName:    "my-scan",
			WriteDirectory: tempDir,
			Write:          true,
			Vars: map[string]interface{}{
				"owner":             "test-owner",
				"repo":              "test-repo",
				"ai_provider":       "openai",
				"ai_model":          "gpt-4o-mini",
				"ai_api_key":        "super-secret-key",
				"ai_write_evidence": true,
			},
		}}

		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{err: errors.New("provider unavailable")}, nil
		}

		result, msg, _ := TestExecutionDocumentation(payloadWithWrites)
		if result != gemara.NeedsReview || msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("got (%v, %q), want fallback", result, msg)
		}

		packetMatches, err := filepath.Glob(filepath.Join(tempDir, "my-scan", "ai-evidence", "OSPS-QA-06.02", "*"))
		if err != nil {
			t.Fatalf("glob packet dir: %v", err)
		}
		if len(packetMatches) != 1 {
			t.Fatalf("expected 1 packet directory, got %d (%v)", len(packetMatches), packetMatches)
		}

		packetDir := packetMatches[0]
		assertFilesExist(t, packetDir, compactPacketFiles)
		assertFilesAbsent(t, packetDir, legacyPacketFiles)

		assessmentBody, err := os.ReadFile(filepath.Join(packetDir, "assessment.json"))
		if err != nil {
			t.Fatalf("read assessment packet: %v", err)
		}
		assertContainsAll(t, "failed assessment", string(assessmentBody), []string{
			`"outcome": "failed"`,
			`"attempt_stage": "provider_call"`,
			`"assessment_message": "Review project documentation to ensure it explains when and how tests are run"`,
			`"failure_message": "provider unavailable"`,
		})
	})

	t.Run("duplicate catalog execution reuses cached AI result and packet", func(t *testing.T) {
		tempDir := t.TempDir()
		loadTestExecutionDocumentationEvidence = func(payload data.Payload) (string, error) {
			return "README\nRun `go test ./...` before opening a PR.", nil
		}
		payloadWithWrites := data.Payload{Config: &sdkconfig.Config{
			ServiceName:    "my-scan",
			WriteDirectory: tempDir,
			Write:          true,
			Vars: map[string]interface{}{
				"owner":             "test-owner",
				"repo":              "test-repo",
				"ai_provider":       "openai",
				"ai_model":          "gpt-4o-mini",
				"ai_api_key":        "super-secret-key",
				"ai_write_evidence": true,
			},
		}, GraphqlRepoData: &data.GraphqlRepoData{}}
		payloadWithWrites.Repository.Name = "test-repo"
		payloadWithWrites.Repository.DefaultBranchRef.Target.OID = "abc123def456"
		payloadWithWrites.Repository.Object.Tree.Entries = []struct {
			Name string
			Type string
			Path string
		}{
			{Name: "README.md", Type: "blob", Path: "README.md"},
		}

		callCount := 0
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{
				JSON: []byte(`{"verdict":"pass","confidence":0.91,"reasoning":"README explains that contributors run go test before opening a PR.","evidence_location":"README#testing"}`),
				Metadata: sdkai.ResponseMetadata{
					Provider:     sdkai.ProviderOpenAI,
					Model:        "gpt-4o-mini-2024-07-18",
					RequestID:    "req-123",
					FinishReason: "stop",
				},
			}}, nil
		}
		baseFactory := newAIClientFromConfig
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			client, err := baseFactory(cfg)
			if err == nil {
				callCount++
			}
			return client, err
		}

		firstResult, firstMessage, _ := TestExecutionDocumentation(payloadWithWrites)
		secondResult, secondMessage, _ := TestExecutionDocumentation(payloadWithWrites)
		if firstResult != gemara.Passed || secondResult != gemara.Passed {
			t.Fatalf("expected cached success results, got (%v, %v)", firstResult, secondResult)
		}
		if firstMessage != secondMessage {
			t.Fatalf("expected cached message reuse, got %q and %q", firstMessage, secondMessage)
		}
		if callCount != 1 {
			t.Fatalf("expected exactly 1 AI call across duplicate executions, got %d", callCount)
		}

		packetMatches, err := filepath.Glob(filepath.Join(tempDir, "my-scan", "ai-evidence", "OSPS-QA-06.02", "*"))
		if err != nil {
			t.Fatalf("glob packet dir: %v", err)
		}
		if len(packetMatches) != 1 {
			t.Fatalf("expected 1 packet directory for duplicate executions, got %d (%v)", len(packetMatches), packetMatches)
		}
	})

	t.Run("provider failure is not cached across duplicate executions", func(t *testing.T) {
		tempDir := t.TempDir()
		loadTestExecutionDocumentationEvidence = func(payload data.Payload) (string, error) {
			return "README\nRun `go test ./...` before opening a PR.", nil
		}
		payloadWithWrites := data.Payload{Config: &sdkconfig.Config{
			ServiceName:    "my-scan",
			WriteDirectory: tempDir,
			Write:          true,
			Vars: map[string]interface{}{
				"owner":             "test-owner",
				"repo":              "test-repo",
				"ai_provider":       "openai",
				"ai_model":          "gpt-4o-mini",
				"ai_api_key":        "super-secret-key",
				"ai_write_evidence": true,
			},
		}, GraphqlRepoData: &data.GraphqlRepoData{}}
		payloadWithWrites.Repository.Name = "test-repo"
		payloadWithWrites.Repository.DefaultBranchRef.Target.OID = "abc123def456"
		payloadWithWrites.Repository.Object.Tree.Entries = []struct {
			Name string
			Type string
			Path string
		}{
			{Name: "README.md", Type: "blob", Path: "README.md"},
		}

		callCount := 0
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			callCount++
			return stubAIClient{err: errors.New("provider unavailable")}, nil
		}

		firstResult, firstMessage, _ := TestExecutionDocumentation(payloadWithWrites)
		secondResult, secondMessage, _ := TestExecutionDocumentation(payloadWithWrites)
		if firstResult != gemara.NeedsReview || secondResult != gemara.NeedsReview {
			t.Fatalf("expected fallback results, got (%v, %v)", firstResult, secondResult)
		}
		if firstMessage != testExecutionDocumentationFallbackMessage || secondMessage != testExecutionDocumentationFallbackMessage {
			t.Fatalf("expected fallback messages, got %q and %q", firstMessage, secondMessage)
		}
		if callCount != 2 {
			t.Fatalf("expected provider failure path to retry on duplicate execution, got %d calls", callCount)
		}

		packetMatches, err := filepath.Glob(filepath.Join(tempDir, "my-scan", "ai-evidence", "OSPS-QA-06.02", "*"))
		if err != nil {
			t.Fatalf("glob packet dir: %v", err)
		}
		if len(packetMatches) != 2 {
			t.Fatalf("expected 2 packet directories for repeated provider failures, got %d (%v)", len(packetMatches), packetMatches)
		}
	})
}

func TestTestExecutionDocumentationEvidence(t *testing.T) {
	if !testExecutionDocumentationReadmeName("README.md") || !testExecutionDocumentationReadmeName("README.rst") || testExecutionDocumentationReadmeName("NOTES.md") {
		t.Fatal("unexpected readme name matching behavior")
	}

	payload := data.Payload{GraphqlRepoData: &data.GraphqlRepoData{}}
	payload.Repository.Object.Tree.Entries = []struct {
		Name string
		Type string
		Path string
	}{
		{Name: "README.md", Type: "blob", Path: "README.md"},
		{Name: "CONTRIBUTING.md", Type: "blob", Path: "CONTRIBUTING.md"},
	}
	payload.Repository.ContributingGuidelines.Body = "Use the documented test workflow before requesting review."

	evidence, err := testExecutionDocumentationEvidence(payload)
	if err != nil {
		t.Fatalf("unexpected evidence error: %v", err)
	}
	if evidence != "CONTRIBUTING\nUse the documented test workflow before requesting review." {
		t.Fatalf("unexpected evidence payload: %q", evidence)
	}

	payload.Config = &sdkconfig.Config{Vars: map[string]interface{}{"owner": "test-owner", "repo": "test-repo"}}
	payload.Repository.Name = "test-repo"
	payload.Repository.DefaultBranchRef.Target.OID = "abc123def456"
	sources := testExecutionDocumentationEvidenceSources(payload, evidence)
	wantSources := []string{
		"https://github.com/test-owner/test-repo/blob/abc123def456/README.md",
		"https://github.com/test-owner/test-repo/blob/abc123def456/CONTRIBUTING.md",
	}
	if len(sources) != len(wantSources) {
		t.Fatalf("unexpected sources: %v", sources)
	}
	for i, want := range wantSources {
		if sources[i] != want {
			t.Fatalf("source[%d] = %q, want %q", i, sources[i], want)
		}
	}

	fallbackSources := testExecutionDocumentationEvidenceSources(data.Payload{}, "README\nRun go test ./...\n\nCONTRIBUTING\nOpen a PR after CI passes.")
	wantFallbackSources := []string{"/README", "/CONTRIBUTING"}
	if len(fallbackSources) != len(wantFallbackSources) {
		t.Fatalf("unexpected fallback sources: %v", fallbackSources)
	}
	for i, want := range wantFallbackSources {
		if fallbackSources[i] != want {
			t.Fatalf("fallbackSource[%d] = %q, want %q", i, fallbackSources[i], want)
		}
	}
}
