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

Some checks can use AI to assess repository documentation when AI settings are provided in the scanner config. AI is optional. If AI is not configured, the scanner continues to use its existing non-AI behavior.

For the initial rollout, configure AI with these keys in the scanner config:

```yaml
ai_provider: openai
ai_model: <an OpenAI chat model available in your account>
ai_api_key: <your-openai-api-key>
ai_timeout: 30s
ai_max_tokens: 256
```

Notes:

- `ai_provider`, `ai_model`, and `ai_api_key` are required for live AI-assisted analysis.
- `ai_timeout` is optional and defaults to `30s`.
- `ai_max_tokens` is optional and defaults to `256`.
- Keep API keys in the config only if that matches your local security practices.

When an evaluation uses AI successfully, the result message is prefixed with `[AI-Assisted]`. That label means the check used AI to assess the supplied evidence and returned a structured pass/fail result.

### Currently supported AI-assisted check

OSPS-QA-06.02 uses AI to assess contributor-facing test execution guidance found in README and CONTRIBUTING content.

A passing result means the supporting documentation clearly explains when tests run and how they are run.

If AI is configured incorrectly, unavailable, or returns an unusable response, the scanner falls back to the normal review-needed behavior rather than failing the entire run.

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
