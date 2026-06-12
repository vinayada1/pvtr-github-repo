package quality

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/gemaraproj/go-gemara"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
)

const testExecutionDocumentationFallbackMessage = "Review project documentation to ensure it explains when and how tests are run"

var testExecutionDocumentationSchema = &sdkai.Schema{
	Name:        "test_execution_documentation_assessment",
	Description: "Structured assessment of whether repository documentation explains when and how tests are run.",
	Strict:      true,
	Value: json.RawMessage(`{
		"type": "object",
		"properties": {
			"verdict": {"type": "string", "enum": ["pass", "fail"]},
			"confidence": {"type": "number"},
			"reasoning": {"type": "string"},
			"evidence_location": {"type": "string"}
		},
		"required": ["verdict", "confidence", "reasoning", "evidence_location"],
		"additionalProperties": false
	}`),
}

var newAIClientFromConfig = sdkai.NewClientFromConfig
var loadTestExecutionDocumentationEvidence = testExecutionDocumentationEvidence

var testExecutionDocumentationRunCache = struct {
	mu      sync.Mutex
	results map[string]testExecutionDocumentationCachedResult
}{
	results: map[string]testExecutionDocumentationCachedResult{},
}

type testExecutionDocumentationAssessment struct {
	Verdict          string  `json:"verdict"`
	Confidence       float64 `json:"confidence"`
	Reasoning        string  `json:"reasoning"`
	EvidenceLocation string  `json:"evidence_location"`
}

type testExecutionDocumentationCachedResult struct {
	Result     gemara.Result
	Message    string
	Confidence gemara.ConfidenceLevel
}

type testExecutionDocumentationPacketOutcome string

const (
	testExecutionDocumentationPacketOutcomeSucceeded testExecutionDocumentationPacketOutcome = "succeeded"
	testExecutionDocumentationPacketOutcomeFailed    testExecutionDocumentationPacketOutcome = "failed"
)

func RepoIsPublic(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.RepositoryMetadata.IsPublic() {
		return gemara.Passed, "Repository is public", confidence
	}
	return gemara.Failed, "Repository is private", confidence
}

func InsightsListsRepositories(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Insights.Project.Repositories) > 0 {
		return gemara.Passed, "Insights contains a list of repositories", confidence
	}

	return gemara.Failed, "Insights does not contain a list of repositories", confidence
}

func StatusChecksAreRequiredByRulesets(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// get the name of all status checks that were run
	var statusChecks []string
	for _, check := range payload.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes {
		for _, run := range check.StatusCheckRollup.Commit.CheckSuites.Nodes {
			for _, checkRun := range run.CheckRuns.Nodes {
				statusChecks = append(statusChecks, checkRun.Name)
			}
		}
	}

	// get the rules that apply to the default branch
	rules := payload.GetRulesets(payload.Repository.DefaultBranchRef.Name)
	if len(rules) == 0 {
		return gemara.Passed, "No rulesets found for default branch, continuing to evaluate branch protection", confidence
	}

	// get the name of all required status checks
	var requiredChecks []string
	for _, rule := range payload.Rulesets {
		for _, requiredCheck := range rule.Parameters.RequiredChecks {
			requiredChecks = append(requiredChecks, requiredCheck.Context)
		}
	}

	// check whether all executed checks are required
	missingChecks := []string{}
	for _, check := range statusChecks {
		found := false
		for _, requiredCheck := range requiredChecks {
			if check == requiredCheck {
				found = true
				break
			}
		}
		if !found {
			missingChecks = append(missingChecks, check)
		}
	}

	if len(missingChecks) > 0 {
		return gemara.Failed, fmt.Sprintf("Some executed status checks are not mandatory but all should be: %s (NOTE: Not continuing to evaluate branch protection: combining requirements in rulesets and branch protection is not recommended)", strings.Join(missingChecks, ", ")), confidence
	}

	return gemara.Passed, "No status checks were run that are not required by the rules", confidence
}

func StatusChecksAreRequiredByBranchProtection(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// get the name of all status checks that were run
	var statusChecks []string
	for _, check := range payload.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes {
		for _, run := range check.StatusCheckRollup.Commit.CheckSuites.Nodes {
			for _, checkRun := range run.CheckRuns.Nodes {
				statusChecks = append(statusChecks, checkRun.Name)
			}
		}
	}

	requiredChecks := payload.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts

	// check whether all executed checks are required
	missingChecks := []string{}
	for _, check := range statusChecks {
		found := false
		for _, requiredCheck := range requiredChecks {
			if check == requiredCheck {
				found = true
				break
			}
		}
		if !found {
			missingChecks = append(missingChecks, check)
		}
	}

	if len(missingChecks) > 0 {
		return gemara.Failed, fmt.Sprintf("Some executed status checks are not mandatory but all should be: %s", strings.Join(missingChecks, ", ")), confidence
	}

	return gemara.Passed, "No status checks were run that are not required by branch protection", confidence
}

func NoBinariesInRepo(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// TODO: This only checks the top 3 levels of the repository tree
	// for common binary file extensions and it fails on very large repositories.
	suspectedBinaries, err := payload.GetSuspectedBinaries()
	if err != nil {
		payload.Config.Logger.Trace(fmt.Sprintf("unexpected response while checking for binaries: %s", err.Error()))
		return gemara.Unknown, "Error while scanning repository for binaries, potentially due to repo size. See logs for details.", confidence
	}

	if len(suspectedBinaries) == 0 {
		return gemara.Passed, "No common binary file extensions were found in the repository", confidence
	}
	return gemara.Failed, fmt.Sprintf("Suspected binaries found in the repository: %s", strings.Join(suspectedBinaries, ", ")), confidence
}

// NoUnreviewableBinariesInRepo is the assessment step for OSPS-QA-05.02.
// It checks that the version control system does not contain unreviewable binary
// artifacts such as compiled executables, shared libraries, or archive binaries.
// Acceptable binary content (images, audio, video, fonts, PDFs) is not flagged.
func NoUnreviewableBinariesInRepo(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	unreviewableBinaries, err := payload.GetUnreviewableBinaries()
	if err != nil {
		if payload.Config != nil && payload.Config.Logger != nil {
			payload.Config.Logger.Trace(fmt.Sprintf("unexpected response while checking for unreviewable binaries: %s", err.Error()))
		}
		return gemara.Unknown, "Error while scanning repository for unreviewable binaries, potentially due to repo size. See logs for details.", confidence
	}

	if len(unreviewableBinaries) == 0 {
		return gemara.Passed, "No unreviewable binary artifacts were found in the repository", confidence
	}
	return gemara.Failed, fmt.Sprintf("Unreviewable binary artifacts found in the repository: %s", strings.Join(unreviewableBinaries, ", ")), confidence
}

func RequiresNonAuthorApproval(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	protection := payload.Repository.DefaultBranchRef.BranchProtectionRule

	if !protection.RequiresApprovingReviews {
		return gemara.Failed, "Branch protection rule does not require reviews", confidence
	}

	reviewCount := payload.Repository.DefaultBranchRef.RefUpdateRule.RequiredApprovingReviewCount
	if reviewCount < 1 {
		return gemara.Failed, "Branch protection rule requires 0 approving reviews", confidence
	}

	if !protection.RequireLastPushApproval {
		return gemara.Failed, "Branch protection does not require re-approval after new commits", confidence
	}

	return gemara.Passed, fmt.Sprintf("Branch protection requires %d approving reviews and re-approval after new commits", reviewCount), confidence
}

func HasOneOrMoreStatusChecks(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// get the name of all status checks that were run
	var statusChecks []string
	for _, check := range payload.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes {
		for _, run := range check.StatusCheckRollup.Commit.CheckSuites.Nodes {
			for _, checkRun := range run.CheckRuns.Nodes {
				statusChecks = append(statusChecks, checkRun.Name)
			}
		}
	}

	if len(statusChecks) > 0 {
		return gemara.Passed, fmt.Sprintf("%d status checks were run", len(statusChecks)), confidence
	}

	return gemara.Failed, "No status checks were run", confidence
}

func VerifyDependencyManagement(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// Validate required fields
	if payload.Repository.Name == "" || payload.Repository.DefaultBranchRef.Name == "" ||
		payload.Repository.DefaultBranchRef.Target.OID == "" {
		return gemara.Unknown, "Missing required repository data", confidence
	}

	// Check dependency manifests
	// TODO: Do a quality check on the dependency manifests
	return countDependencyManifests(payload)
}

func countDependencyManifests(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	manifestsCount := payload.DependencyManifestsCount
	if manifestsCount > 0 {
		return gemara.Passed, fmt.Sprintf("Found %d dependency manifests from GitHub API", manifestsCount), confidence
	}
	return gemara.NeedsReview, "No dependency manifests found in the GitHub dependency graph API. Review project to ensure dependencies are managed.", confidence
}

func TestExecutionDocumentation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	logger := testExecutionDocumentationLogger(payload)
	cacheKey := testExecutionDocumentationCacheKey(payload)
	if cachedResult, ok := lookupTestExecutionDocumentationCachedResult(cacheKey); ok {
		logger.Trace("OSPS-QA-06.02: reusing cached AI verdict", "cache_key", cacheKey)
		return cachedResult.Result, cachedResult.Message, cachedResult.Confidence
	}
	// Cache only usable AI verdicts. Provider/config/schema failures remain
	// retryable so duplicate catalog executions can still emit failure packets
	// and recover if the transient problem clears later in the run.
	storeAndReturn := func(result gemara.Result, message string, confidence gemara.ConfidenceLevel) (gemara.Result, string, gemara.ConfidenceLevel) {
		storeTestExecutionDocumentationCachedResult(cacheKey, testExecutionDocumentationCachedResult{
			Result:     result,
			Message:    message,
			Confidence: confidence,
		})
		return result, message, confidence
	}

	client, err := testExecutionDocumentationClient(payload)
	if err != nil {
		writeTestExecutionDocumentationFailurePacket(payload, logger, testExecutionDocumentationPacketDetails{
			Prompt:       testExecutionDocumentationPrompt(),
			Outcome:      testExecutionDocumentationPacketOutcomeFailed,
			AttemptStage: "client_construction",
			Failure:      err,
		})
		logger.Warn("OSPS-QA-06.02: AI client construction failed", "err", err)
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}
	if client == nil {
		logger.Warn("OSPS-QA-06.02: AI is not configured (ai_provider/ai_api_key missing); falling back")
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}

	evidence, err := loadTestExecutionDocumentationEvidence(payload)
	if err != nil {
		logger.Warn("OSPS-QA-06.02: failed to load README/CONTRIBUTING evidence", "err", err)
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}
	if strings.TrimSpace(evidence) == "" {
		logger.Warn("OSPS-QA-06.02: no README or CONTRIBUTING content available in payload")
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}
	sources := testExecutionDocumentationEvidenceSources(payload, evidence)

	response, err := client.Analyze(context.Background(), testExecutionDocumentationPrompt(), evidence, testExecutionDocumentationSchema)
	if err != nil {
		writeTestExecutionDocumentationFailurePacket(payload, logger, testExecutionDocumentationPacketDetails{
			Prompt:       testExecutionDocumentationPrompt(),
			Evidence:     evidence,
			Sources:      sources,
			Outcome:      testExecutionDocumentationPacketOutcomeFailed,
			AttemptStage: "provider_call",
			Failure:      err,
		})
		logger.Warn("OSPS-QA-06.02: AI provider call failed", "err", err)
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}

	assessment, err := parseTestExecutionDocumentationAssessment(response)
	if err != nil {
		writeTestExecutionDocumentationFailurePacket(payload, logger, testExecutionDocumentationPacketDetails{
			Prompt:       testExecutionDocumentationPrompt(),
			Evidence:     evidence,
			Sources:      sources,
			Response:     response,
			Outcome:      testExecutionDocumentationPacketOutcomeFailed,
			AttemptStage: "schema_validation",
			Failure:      err,
		})
		logger.Warn("OSPS-QA-06.02: AI response failed schema validation", "err", err)
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}

	result, ok := testExecutionDocumentationResult(assessment.Verdict)
	if !ok {
		writeTestExecutionDocumentationFailurePacket(payload, logger, testExecutionDocumentationPacketDetails{
			Prompt:       testExecutionDocumentationPrompt(),
			Evidence:     evidence,
			Sources:      sources,
			Response:     response,
			Assessment:   assessment,
			Outcome:      testExecutionDocumentationPacketOutcomeFailed,
			AttemptStage: "unknown_verdict",
			Failure:      fmt.Errorf("unknown verdict %q", assessment.Verdict),
		})
		logger.Warn("OSPS-QA-06.02: AI returned unknown verdict", "verdict", assessment.Verdict)
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}
	// Logs keep the verdict summary but avoid persisting raw model-selected
	// snippets from repository content. The returned result message stays raw so
	// the normal evaluator output remains useful, while packet persistence is
	// separately sanitized by the SDK writer below.
	sanitizedAssessment := sanitizeTestExecutionDocumentationAssessment(payload, assessment)
	logger.Info("OSPS-QA-06.02: AI verdict received",
		"verdict", sanitizedAssessment.Verdict,
		"confidence", sanitizedAssessment.Confidence,
		"evidence_location", sanitizedAssessment.EvidenceLocation,
	)

	message = fmt.Sprintf(
		"[AI-Assisted] verdict=%s confidence=%.2f\nreasoning: %s\nevidence_location: %s",
		assessment.Verdict, assessment.Confidence,
		assessment.Reasoning, assessment.EvidenceLocation,
	)
	if err := captureTestExecutionDocumentationEvidencePacket(payload, testExecutionDocumentationPacketDetails{
		Prompt:     testExecutionDocumentationPrompt(),
		Evidence:   evidence,
		Sources:    sources,
		Response:   response,
		Assessment: assessment,
		Result:     result,
		Message:    message,
		Confidence: mapAIConfidence(assessment.Confidence),
		Outcome:    testExecutionDocumentationPacketOutcomeSucceeded,
	}); err != nil {
		logger.Warn("OSPS-QA-06.02: failed to write AI evidence packet", "err", err)
	}
	return storeAndReturn(result, message, mapAIConfidence(assessment.Confidence))
}

// testExecutionDocumentationLogger returns the payload's logger, or a no-op
// logger when one is not wired through. The logger is only used for
// diagnostic breadcrumbs along the early-exit paths.
func testExecutionDocumentationLogger(payload data.Payload) hclog.Logger {
	if payload.Config != nil && payload.Config.Logger != nil {
		return payload.Config.Logger
	}
	return hclog.NewNullLogger()
}

// mapAIConfidence converts the model's 0..1 confidence score into a gemara
// ConfidenceLevel bucket. A zero score is treated as Undetermined so callers
// that omit confidence don't get misreported as Low.
func mapAIConfidence(score float64) gemara.ConfidenceLevel {
	switch {
	case score <= 0:
		return gemara.Undetermined
	case score < 0.5:
		return gemara.Low
	case score < 0.8:
		return gemara.Medium
	default:
		return gemara.High
	}
}

func DocumentsTestMaintenancePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.NeedsReview, "Review project documentation to ensure it contains a clear policy for maintaining tests", confidence
}

func testExecutionDocumentationClient(payload data.Payload) (sdkai.Client, error) {
	if payload.Config == nil {
		return nil, nil
	}
	return newAIClientFromConfig(*payload.Config)
}

func testExecutionDocumentationEvidence(payload data.Payload) (string, error) {
	parts := []string{}

	// Limit the model input to contributor-facing documentation. Repository
	// contents can be large and noisy; OSPS-QA-06.02 is specifically about
	// documented test execution guidance, so README and CONTRIBUTING are the
	// conservative evidence boundary for this first AI-assisted control. Future
	// slices can expand this with a bounded allowlist such as TESTING.md or
	// docs/development.md without changing the AI evaluation contract.
	if readme := strings.TrimSpace(testExecutionDocumentationReadmeContent(payload)); readme != "" {
		parts = append(parts, "README\n"+readme)
	}

	if payload.GraphqlRepoData != nil {
		if contributing := strings.TrimSpace(payload.Repository.ContributingGuidelines.Body); contributing != "" {
			parts = append(parts, "CONTRIBUTING\n"+contributing)
		}
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("no README or CONTRIBUTING content available")
	}

	return strings.Join(parts, "\n\n"), nil
}

func testExecutionDocumentationEvidenceSources(payload data.Payload, evidence string) []string {
	sources := []string{}
	readmeSourceAdded := false
	if readmePath := testExecutionDocumentationReadmePath(payload); readmePath != "" {
		sources = append(sources, testExecutionDocumentationEvidenceSource(payload, readmePath))
		readmeSourceAdded = true
	}
	contributingSourceAdded := false
	if contributingPath := testExecutionDocumentationContributingPath(payload); contributingPath != "" {
		sources = append(sources, testExecutionDocumentationEvidenceSource(payload, contributingPath))
		contributingSourceAdded = true
	}
	// When path metadata is missing, keep source labels aligned with the section
	// headers sent to the model so evidence packets still explain provenance.
	if !readmeSourceAdded && strings.Contains(evidence, "README\n") {
		sources = append(sources, "/README")
	}
	if !contributingSourceAdded && strings.Contains(evidence, "CONTRIBUTING\n") {
		sources = append(sources, "/CONTRIBUTING")
	}
	return sources
}

func testExecutionDocumentationEvidenceSource(payload data.Payload, path string) string {
	if blobURL := testExecutionDocumentationBlobURL(payload, path); blobURL != "" {
		return blobURL
	}
	return testExecutionDocumentationRepoAbsolutePath(path)
}

func testExecutionDocumentationBlobURL(payload data.Payload, path string) string {
	repositoryOwner := ""
	repositoryName := ""
	commitSHA := ""
	if payload.Config != nil {
		repositoryOwner = strings.TrimSpace(payload.Config.GetString("owner"))
		repositoryName = strings.TrimSpace(payload.Config.GetString("repo"))
	}
	if payload.GraphqlRepoData != nil {
		if strings.TrimSpace(payload.Repository.Name) != "" {
			repositoryName = strings.TrimSpace(payload.Repository.Name)
		}
		commitSHA = strings.TrimSpace(payload.Repository.DefaultBranchRef.Target.OID)
	}
	trimmedPath := strings.TrimLeft(strings.TrimSpace(path), "/")
	if repositoryOwner == "" || repositoryName == "" || commitSHA == "" || trimmedPath == "" {
		return ""
	}
	return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", repositoryOwner, repositoryName, commitSHA, trimmedPath)
}

func testExecutionDocumentationCacheKey(payload data.Payload) string {
	if payload.Config == nil {
		return ""
	}
	writeDir := strings.TrimSpace(payload.Config.WriteDirectory)
	if writeDir == "" {
		return ""
	}
	// The cache is scoped to the output location, service, repository, and commit
	// so repeated catalog entries in one scan reuse a verdict without sharing AI
	// results across repositories or working trees.
	serviceName := strings.TrimSpace(payload.Config.ServiceName)
	repositoryOwner := strings.TrimSpace(payload.Config.GetString("owner"))
	repositoryName := strings.TrimSpace(payload.Config.GetString("repo"))
	commitSHA := ""
	if payload.GraphqlRepoData != nil {
		if strings.TrimSpace(payload.Repository.Name) != "" {
			repositoryName = strings.TrimSpace(payload.Repository.Name)
		}
		commitSHA = strings.TrimSpace(payload.Repository.DefaultBranchRef.Target.OID)
	}
	return strings.Join([]string{
		writeDir,
		serviceName,
		repositoryOwner,
		repositoryName,
		commitSHA,
		"OSPS-QA-06.02",
	}, "|")
}

func lookupTestExecutionDocumentationCachedResult(cacheKey string) (testExecutionDocumentationCachedResult, bool) {
	if cacheKey == "" {
		return testExecutionDocumentationCachedResult{}, false
	}
	testExecutionDocumentationRunCache.mu.Lock()
	defer testExecutionDocumentationRunCache.mu.Unlock()
	result, ok := testExecutionDocumentationRunCache.results[cacheKey]
	return result, ok
}

func storeTestExecutionDocumentationCachedResult(cacheKey string, result testExecutionDocumentationCachedResult) {
	if cacheKey == "" {
		return
	}
	testExecutionDocumentationRunCache.mu.Lock()
	defer testExecutionDocumentationRunCache.mu.Unlock()
	testExecutionDocumentationRunCache.results[cacheKey] = result
}

func resetTestExecutionDocumentationCachedResults() {
	testExecutionDocumentationRunCache.mu.Lock()
	defer testExecutionDocumentationRunCache.mu.Unlock()
	testExecutionDocumentationRunCache.results = map[string]testExecutionDocumentationCachedResult{}
}

func testExecutionDocumentationRepoAbsolutePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	return "/" + strings.TrimLeft(trimmed, "/")
}

func testExecutionDocumentationReadmeContent(payload data.Payload) string {
	if payload.GraphqlRepoData == nil || payload.RestData == nil {
		return ""
	}

	readmePath := testExecutionDocumentationReadmePath(payload)
	if readmePath == "" {
		return ""
	}

	content, err := payload.GetFileContent(readmePath)
	if err != nil || content == nil {
		return ""
	}

	readme, err := content.GetContent()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(readme)
}

func testExecutionDocumentationReadmePath(payload data.Payload) string {
	if payload.GraphqlRepoData == nil {
		return ""
	}
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		if testExecutionDocumentationReadmeName(entry.Name) {
			return entry.Path
		}
	}
	return ""
}

func testExecutionDocumentationReadmeName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return lower == "readme" || strings.HasPrefix(lower, "readme.")
}

func testExecutionDocumentationContributingPath(payload data.Payload) string {
	if payload.GraphqlRepoData == nil {
		return ""
	}
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(entry.Name))
		if lower == "contributing" || strings.HasPrefix(lower, "contributing.") {
			return entry.Path
		}
	}
	return ""
}

func testExecutionDocumentationPrompt() string {
	return strings.TrimSpace(`You are assessing OSPS-QA-06.02: the project's documentation MUST clearly document WHEN and HOW tests are run. This is a contributor-facing requirement.

Use only the supplied README and CONTRIBUTING content as evidence.

Return verdict "pass" only when BOTH of the following are clearly explained:
  - WHEN tests run (e.g. on every pull request, before merge, on a schedule, locally before commit).
  - HOW tests are run (concrete commands to run tests locally AND/OR a description of how they run in CI/CD).

A pass is stronger when the documentation also explains what the tests cover and how to interpret results, but those are not strictly required.

Return verdict "fail" when any of the following hold:
  - The documentation is missing or only implies that tests exist.
  - It covers WHEN but not HOW, or HOW but not WHEN.
  - Instructions are vague (e.g. "run the tests" with no command or workflow reference).
  - The only test discussion is aimed at end users, not contributors.

Cite the most relevant section header or quoted snippet in evidence_location.`)
}

func parseTestExecutionDocumentationAssessment(response *sdkai.AnalyzeResponse) (*testExecutionDocumentationAssessment, error) {
	if response == nil || len(response.JSON) == 0 {
		return nil, fmt.Errorf("ai response did not include structured output")
	}

	var assessment testExecutionDocumentationAssessment
	if err := json.Unmarshal(response.JSON, &assessment); err != nil {
		return nil, err
	}

	assessment.Verdict = strings.ToLower(strings.TrimSpace(assessment.Verdict))
	assessment.Reasoning = strings.TrimSpace(assessment.Reasoning)
	assessment.EvidenceLocation = strings.TrimSpace(assessment.EvidenceLocation)
	if assessment.Reasoning == "" || assessment.EvidenceLocation == "" {
		return nil, fmt.Errorf("ai response missing reasoning or evidence location")
	}

	return &assessment, nil
}

func testExecutionDocumentationResult(verdict string) (gemara.Result, bool) {
	// verdict is already lowercased and trimmed by
	// parseTestExecutionDocumentationAssessment, the sole caller.
	switch verdict {
	case "pass":
		return gemara.Passed, true
	case "fail":
		return gemara.Failed, true
	default:
		return gemara.NeedsReview, false
	}
}

// testExecutionDocumentationPacketDetails carries whichever artifacts are
// available for a given AI attempt, whether it ended in a usable verdict or
// a fallback. It is the control-specific input that captureTestExecutionDocumentationEvidencePacket
// translates into a provider-neutral sdkai.PacketAttempt.
type testExecutionDocumentationPacketDetails struct {
	Prompt       string
	Evidence     string
	Sources      []string
	Response     *sdkai.AnalyzeResponse
	Assessment   *testExecutionDocumentationAssessment
	Result       gemara.Result
	Message      string
	Confidence   gemara.ConfidenceLevel
	Outcome      testExecutionDocumentationPacketOutcome
	AttemptStage string
	Failure      error
}

// captureTestExecutionDocumentationEvidencePacket persists the per-attempt
// AI evidence packet for OSPS-QA-06.02 by delegating to the SDK's
// provider-neutral packet writer. The shim is responsible only for mapping
// control-specific verdict types and repository payload fields onto the
// generic sdkai.PacketAttempt; redaction, file layout, and on-disk format
// live in the SDK so future AI-assisted controls can reuse them.
func captureTestExecutionDocumentationEvidencePacket(payload data.Payload, details testExecutionDocumentationPacketDetails) error {
	if payload.Config == nil {
		return nil
	}

	repositoryName := strings.TrimSpace(payload.Config.GetString("repo"))
	defaultBranch := ""
	commitSHA := ""
	if payload.GraphqlRepoData != nil {
		if strings.TrimSpace(payload.Repository.Name) != "" {
			repositoryName = strings.TrimSpace(payload.Repository.Name)
		}
		defaultBranch = strings.TrimSpace(payload.Repository.DefaultBranchRef.Name)
		commitSHA = strings.TrimSpace(payload.Repository.DefaultBranchRef.Target.OID)
	}

	attempt := sdkai.PacketAttempt{
		ControlID:         "OSPS-QA-06.02",
		RepositoryOwner:   strings.TrimSpace(payload.Config.GetString("owner")),
		RepositoryName:    repositoryName,
		DefaultBranch:     defaultBranch,
		CommitSHA:         commitSHA,
		Outcome:           string(details.Outcome),
		AttemptStage:      resolvePacketAttemptStage(details),
		Result:            fmt.Sprintf("%v", details.Result),
		Confidence:        fmt.Sprintf("%v", details.Confidence),
		AssessmentMessage: resolvePacketAttemptMessage(details),
		Failure:           details.Failure,
		Prompt:            details.Prompt,
		Schema:            testExecutionDocumentationSchema,
		Evidence:          details.Evidence,
		EvidenceSources:   details.Sources,
		Response:          details.Response,
	}
	if details.Assessment != nil {
		attempt.Verdict = details.Assessment.Verdict
		attempt.Reasoning = details.Assessment.Reasoning
		attempt.EvidenceLocation = details.Assessment.EvidenceLocation
	}

	return sdkai.WritePacket(*payload.Config, attempt)
}

// writeTestExecutionDocumentationFailurePacket persists a failure-path
// evidence packet and surfaces any packet-writer error to the logger so a
// broken writer does not silently disappear on the failure paths the way it
// would have with an `_ =` discard.
func writeTestExecutionDocumentationFailurePacket(payload data.Payload, logger hclog.Logger, details testExecutionDocumentationPacketDetails) {
	if err := captureTestExecutionDocumentationEvidencePacket(payload, details); err != nil {
		logger.Warn("OSPS-QA-06.02: failed to write AI evidence packet",
			"attempt_stage", details.AttemptStage,
			"err", err,
		)
	}
}

func resolvePacketAttemptStage(details testExecutionDocumentationPacketDetails) string {
	if strings.TrimSpace(details.AttemptStage) != "" {
		return details.AttemptStage
	}
	if details.Outcome == testExecutionDocumentationPacketOutcomeSucceeded {
		return "assessment_completed"
	}
	return "attempt_recorded"
}

func resolvePacketAttemptMessage(details testExecutionDocumentationPacketDetails) string {
	if strings.TrimSpace(details.Message) != "" {
		return details.Message
	}
	if details.Outcome == testExecutionDocumentationPacketOutcomeFailed && details.Failure != nil {
		return testExecutionDocumentationFallbackMessage
	}
	if details.Failure != nil {
		return details.Failure.Error()
	}
	return ""
}

// sanitizeTestExecutionDocumentationAssessment redacts model-derived fields
// before they are surfaced in scanner logs, reusing the SDK sanitizer so the
// rules stay aligned with what WritePacket persists.
func sanitizeTestExecutionDocumentationAssessment(payload data.Payload, assessment *testExecutionDocumentationAssessment) testExecutionDocumentationAssessment {
	if assessment == nil {
		return testExecutionDocumentationAssessment{}
	}
	if payload.Config == nil {
		return testExecutionDocumentationAssessment{
			Verdict:          assessment.Verdict,
			Confidence:       assessment.Confidence,
			Reasoning:        sdkai.RedactPatterns(assessment.Reasoning),
			EvidenceLocation: sdkai.RedactPatterns(assessment.EvidenceLocation),
		}
	}
	sanitizer := sdkai.NewSanitizer(*payload.Config)
	return testExecutionDocumentationAssessment{
		Verdict:          assessment.Verdict,
		Confidence:       assessment.Confidence,
		Reasoning:        sanitizer.RedactText(assessment.Reasoning),
		EvidenceLocation: sanitizer.RedactText(assessment.EvidenceLocation),
	}
}
