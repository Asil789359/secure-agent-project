# Secure AI Research Assistant — offline teaching prototype

Python 3.10+. No dependencies, API key, or network needed.

```bash
python secure_agent.py "What was cloud spend in 2025?"
python -m unittest -v test_security.py
```

## Security model
- Fixed, authenticated-in-principle `Principal` context; demo CLI clearance is **not authentication**. A real API must derive principal/tenant/roles from verified server-side identity, not a user-supplied parameter.
- Tenant and classification checks happen before search results reach the generator.
- Strict tool allowlist and argument schemas; calculator uses only explicit arithmetic.
- Deterministic evidence extraction from a small trusted corpus; arbitrary document instructions are not executed.
- Citation verification checks both the source ID and an exact supported fact, for this deliberately restricted dataset.
- Security events log event type and code, not queries or retrieved content.
- Ten adversarial tests plus two positive tests.

## Important limitations
This is an **offline rule-based agent scaffold**, not a deployed LLM or a guarantee of prompt-injection resistance. The generator is deterministic, not model-driven. Its `trusted_facts` mapping is handcrafted; generalizing to arbitrary PDFs requires a genuine evidence-entailment checker and a human-review fallback. The CLI `--clearance` option is for demonstrations only and must never be exposed as an authorization mechanism in production. No real secrets or networked tools are present.

## Production extensions
Use authenticated server-side identity; per-document ACL filtering inside your vector/BM25 retrieval layers; per-tool authorization; strict JSON Schema validation; output PII/DLP scans; bounded tool-call budgets; approval gates for writes or external actions; separate trusted prompts from untrusted source text; human-reviewed citation audit; monitoring and regression tests. Keep the model from selecting its own authorization context.
