# Privateer Plugin for GitHub Repositories

This application performs automated assessments against GitHub repositories using controls defined in the [Open Source Project Security Baseline v2025.02.25](https://baseline.openssf.org). The application consumes the OSPS Baseline controls using [Gemara](https://github.com/gemaraproj/go-gemara) layer 2 and produces results of the automated assessments using layer 4.

Many of the assessments depend upon the presence of a [Security Insights](https://github.com/ossf/security-insights) file at the root of the repository, or `./github/security-insights.yml`.

## Work in Progress

Currently 39 control requirements across OSPS Baselines levels 1-3 are covered, with 13 not yet implemented. [Maturity Level 1](https://baseline.openssf.org/versions/2025-02-25.html#level-1) requirements are the most rigorously tested and are recommended for use. The results of these layer 1 assessments are integrated into [LFX Insights](https://insights.linuxfoundation.org/project/k8s/repository/kubernetes-kubernetes/security), powering the [Security & Best Practices results](https://insights.linuxfoundation.org/docs/metrics/security/).

![alt text](kubernetes_insights_baseline.png)

Level 2 and Level 3 requirements are undergoing current development and may be less rigorously tested.

## Local Usage

To run the GitHub scanner locally, you will need the Privateer (`pvtr`) framework and the GitHub repository scanner (`pvtr-github-repo-scanner`) plugin.

1. Install pvtr using one of the methods described [here](https://github.com/privateerproj/privateer/blob/main/README.md#step-2-choose-your-installation-method).
2. Next, download the `pvtr-github-repo-scanner` plugin from the [releases](https://github.com/ossf/pvtr-github-repo-scanner/releases).

The following command is an example where the `pvtr`, the `pvtr-github-repo-scanner`, and the `config.yaml` are in the same directory.
```sh
./pvtr run --binaries-path .
```
If the binaries and the config files are in different directories specify the complete path using `--binaries-path` and `--config` flags.

You may have to adjust the plugin name in the config.yaml file to match them.

## AI-Assisted Checks

Some OSPS Baseline controls can be assessed with the help of a large language
model (LLM). AI is **opt-in**: when AI settings are absent the scanner
behaves exactly as before and no requests leave the host.

### Configuration

Add the AI keys under the per-service `vars` block:

```yaml
services:
  my-scan:
    plugin: github-repo
    vars:
      owner: <github org or user>
      repo: <github repo>
      token: <github classic token>

      # --- Required to enable AI ---
      ai_provider: <provider id>             # see "Provider examples" below
      ai_model: <chat model id>              # e.g. gpt-4o-mini
      ai_api_key: <your-provider-api-key>    # not needed when ai_dry_run is true

      # --- Optional (defaults shown) ---
      ai_base_url: https://api.openai.com/v1 # override the OpenAI endpoint
      ai_timeout: 30s                        # per-request timeout
      ai_max_tokens: 256                     # response token budget
      ai_dry_run: false                      # skip real provider calls
      ai_write_evidence: false               # persist AI evidence packets
```

| Key             | Required | Description                                                                                          |
| --------------- | :------: | ---------------------------------------------------------------------------------------------------- |
| `ai_provider`   |   yes    | AI provider id. Only `openai` is supported today.                                                    |
| `ai_model`      |   yes    | Chat-completions model id offered by the provider (e.g. `gpt-4o-mini`).                              |
| `ai_api_key`    |   yes¹   | Provider API key. Not persisted to evidence packets.                                                 |
| `ai_base_url`   |    no    | Override the OpenAI endpoint. Use this to target an OpenAI-compatible endpoint (self-hosted runtime, local mock, dev proxy). The SDK speaks only the OpenAI wire protocol in this release. |
| `ai_timeout`    |    no    | Per-request timeout as a Go duration (`30s`, `1m`, …).                                               |
| `ai_max_tokens` |    no    | Maximum tokens in the model response.                                                                |
| `ai_dry_run`    |    no    | When `true`, skip real provider calls (see [Dry-run](#dry-run)).                                     |
| `ai_write_evidence` | no | When `true`, persist AI evidence packets. Requires AI to be configured and `write: true`. Defaults to `false`. |

¹ Not required when `ai_dry_run: true`.

If any required key is missing, the scanner skips AI for that check and falls
back to its existing review-needed behavior; the run does not fail.

### Provider examples

> Only the `openai` provider is implemented in this release. The
> "OpenAI-compatible endpoint" example below still uses the `openai`
> provider, just with `ai_base_url` pointed at a different endpoint that
> speaks the OpenAI wire protocol.

**OpenAI**

```yaml
ai_provider: openai
ai_model: <chat model id>   # for example, gpt-4o-mini
ai_api_key: sk-...
```

**OpenAI-compatible endpoint** (self-hosted runtime, local mock, or dev proxy)

```yaml
ai_provider: openai
ai_model: <chat model id exposed by the endpoint>
ai_api_key: <key accepted by the endpoint>
ai_base_url: http://127.0.0.1:8000/v1
```

### Interpreting `[AI-Assisted]` results

A successful AI-assisted check produces a result message prefixed with
`[AI-Assisted]`:

```
[AI-Assisted] verdict=pass confidence=0.91
reasoning: README explains that contributors run `go test ./...` before opening a PR.
evidence_location: README#testing
```

- `verdict` maps to the Gemara result (`pass` → `Passed`, `fail` → `Failed`).
- `confidence` is the model's self-reported 0–1 score, mapped to Low
  (`<0.5`), Medium (`<0.8`), or High (`≥0.8`).
- If the call times out, fails, or returns a malformed response, the result
  falls back to `NeedsReview` and the run continues.

Treat AI verdicts as a useful signal that still warrants spot-checking,
especially at Low or Medium confidence.

### Evidence packets

Evidence packet writing is a separate opt-in from enabling AI. When AI is
configured, `write: true` is set in the top-level config, and
`ai_write_evidence: true` is set in `vars` (or `--write-ai-evidence` is passed
on the command line), each AI-assisted attempt writes the following files:

```
<write-directory>/<service>/ai-evidence/<control-id>/<timestamp>-<request-id>/
  assessment.json     # verdict, confidence, reasoning, redacted config snapshot
  ai_interaction.json # prompt, schema, supplied evidence, raw model response
```

The SDK owns the provider-neutral packet format and redacts known secrets from
both files before writing them:
`ai_api_key`, `token`, credentials embedded in `ai_base_url`, and common
bearer-token / GitHub-token patterns. Packets are intended for human review
and for re-running the assessment offline.

Leave `ai_write_evidence` unset or `false` in routine CI jobs unless you intend
to retain the prompt, evidence, schema, response, and mapped verdict artifacts.

### Cost and operational notes

- **One provider call per applicable control per scan**, cached for the
  duration of the run.
- The scanner sends only the specific repository content the check needs as
  evidence (e.g. documentation files or configuration snippets), not the
  full repository or its source code.
- You are responsible for any provider usage charges. Start with a low-cost
  model (a `-mini`-class chat-completions model is usually sufficient) and a
  small `ai_max_tokens` budget.

### Currently supported AI-assisted checks

| Control         | What it assesses                                                                                            |
| --------------- | ----------------------------------------------------------------------------------------------------------- |
| `OSPS-QA-06.02` | Whether contributor-facing documentation (README, `CONTRIBUTING`) explains *when* and *how* tests are run. |

### Dry-run

Set `ai_dry_run: true` (or pass `--dry-run-ai` on the `pvtr` command line) to
exercise the AI-assisted code paths without making a real provider call. The
SDK returns a fixed placeholder response with `finish_reason: dry_run` and
logs the prompt and schema instead of sending them to the provider.

```yaml
ai_provider: <provider id>   # for example, openai
ai_model: <chat model id>    # for example, gpt-4o-mini
ai_dry_run: true
```

Use dry-run to:

- check that your config is valid and that the scanner picks up the AI keys,
- optionally produce evidence packets without using any provider quota,
- inspect the exact prompt and schema the scanner would send.

`ai_api_key` is not required in this mode, but `ai_provider` and `ai_model`
still are. Because the placeholder response carries no real verdict,
AI-assisted checks fall back to their standard `NeedsReview` message in
dry-run mode; `assessment.json` and `ai_interaction.json` are written only when
both `write: true` and `ai_write_evidence: true` are set.

## Docker Usage

```sh
# build the image
docker build . -t local
docker run \
  -v ./config.yml:/.privateer/config.yml \
  -v ./evaluation_results:/.privateer/bin/evaluation_results \
  local
```

## GitHub Actions Usage

See the [OSPS Security Baseline Scanner](https://github.com/marketplace/actions/open-source-project-security-baseline-scanner)

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](.github/CONTRIBUTING.md) for more information.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
