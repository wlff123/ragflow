# Sensitive processing acceptance tests

## Rule-based log cleaning

When `sensitive_processing` is configured, startup registers the shared Engine
for process-wide logging, independently of individual document switches. Zap
messages/fields (including `With`, Sugar and standard Go logging), task events,
pipeline log snapshots and Redis failure reasons are cleaned before writing.
Complete JSON strings are decoded so escaped credentials retain field context.
Cleaning never changes model requests/responses or document replacement counts.

Each log cleaning call uses a fresh 200 ms context budget; individual regex
execution remains subject to its configured match timeout. Inputs exceeding
256 KiB, unsupported structures, panics and cleaning failures produce a fixed
hidden-content marker instead of raw input. No callback may log recursively.
Without configured sensitive processing, logging retains its original behavior.
Historical records are not rewritten. Matching is limited to the configured
rules; arbitrary hashes, encrypted values and encoded payloads are not decoded.

Run log integration checks without external model services:

```bash
bash build.sh --test -run 'TestRuleLog|TestLogJSON|TestLogCleaner|TestLogCore|TestRuleCleaning' ./internal/common ./internal/sensitive ./internal/service ./internal/agent/canvas
```

## Deployment acceptance

`TestSensitiveRequirementMatrix` exercises a real RAGFlow deployment and an
OpenAI-compatible embedding service. Use a disposable test deployment: the
suite creates accounts, model instances, datasets and documents, and retains
acceptance artifacts for inspection. No deployment address or model is built in.

Required environment variables:

| Variable | Meaning |
|---|---|
| `RAGFLOW_ACCEPTANCE_URL` | RAGFlow root URL, without `/api/v1` |
| `RAGFLOW_ACCEPTANCE_EMBEDDING_URL` | Embedding service root URL; forwarded requests include `/v1` |
| `RAGFLOW_ACCEPTANCE_EMBEDDING_MODEL` | Model name supported by that service |
| `RAGFLOW_ACCEPTANCE_EMBEDDING_MAX_TOKENS` | Positive model context limit |

Optional variables:

| Variable | Meaning |
|---|---|
| `RAGFLOW_ACCEPTANCE_EMBEDDING_API_KEY` | Upstream Bearer credential; omitted for unauthenticated test services |
| `RAGFLOW_ACCEPTANCE_OUTPUT` | Evidence directory; defaults to a temporary test directory |
| `RAGFLOW_ACCEPTANCE_OBSERVER_LISTEN` | Observer TCP bind address, in `host:port` form; defaults to an ephemeral loopback listener |
| `RAGFLOW_ACCEPTANCE_OBSERVER_URL` | Observer root URL reachable from RAGFlow; defaults to its local listener URL |
| `RAGFLOW_ACCEPTANCE_FULL` | Set to `1` to include extended requirements |
| `RAGFLOW_ACCEPTANCE_ASR_CONFIG` | Path to a private JSON configuration for the optional audio scenario |

For separate hosts or containers, set both observer variables and make the
chosen listener port reachable from the RAGFlow service. Use a restricted test
network: the observer forwards model requests and is not an authenticated API.

The ASR JSON fields are `provider`, `model`, `max_tokens`, `base_url`, `api_key`,
`audio_file`, `expected_text`, `replacement_count`, and `sensitive_values` (an
array of synthetic values). Choose a provider supported by the deployment;
`expected_text` must be non-sensitive transcript text expected in the chunks.
The current audio scenario uploads the fixture as WAV. Keep credentials and
environment-specific configuration outside the repository.

Run with the repository build wrapper:

```bash
bash build.sh --test-e2e ./internal/sensitive -run '^TestSensitiveRequirementMatrix$' -count=1 -v
```

Missing API/embedding endpoints skip the matrix. Once endpoints are supplied,
missing model settings fail the test. Missing ASR configuration skips only the
audio scenario. A skipped scenario is not a successful end-to-end validation.

`fixtures_e2e_test.go` generates synthetic PDF, image and presentation samples;
it does not read customer files or connect to a particular machine.
