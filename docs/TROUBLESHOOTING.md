# Guardrail OS: Troubleshooting Guide for Verification Failures

This guide provides operational procedures for diagnosing and resolving failures in the Guardrail OS safety kernel.

## 1. Logic Verification Failures (FormalVerifier/Z3)

### SYMPTOM: [VERIFIER_ERR] Logic violation in step
**Cause:** The agent's proposed action violates a formal policy invariant (e.g., attempting to write outside of `/workspace/`).
**Resolution:**
1. **Check Resource Path:** Ensure the resource string starts exactly with the allowed prefix (e.g., `/workspace/`).
2. **Policy Simulation:** Use the `Simulation Sandbox` in the dashboard or `guardrail-cli.py verify --policy "..." --context "{...}"` to isolate the failing rule.
3. **Template Sync:** Verify that the policy template is up to date with the latest kernel requirements.

### SYMPTOM: SMT Solver Timeout (Unknown Result)
**Cause:** The policy expression is too complex or recursive for the Z3 solver to verify within the 10ms budget.
**Resolution:**
1. **Simplify Invariants:** Reduce the use of nested quantifiers (FORALL/EXISTS).
2. **Enable Caching:** Ensure the verification context is being reused to take advantage of the results cache.

## 2. Semantic Guard Failures (Guard Model)

### SYMPTOM: Intent Blocked (Hijacking/Social Engineering)
**Cause:** The LLM-based Guard Model detected adversarial intent patterns (e.g., prompt injection).
**Resolution:**
1. **Clarify Intent:** Rephrase the request to be more specific and technical, avoiding social engineering patterns.
2. **Confidence Check:** If the confidence is low, review the "Reasoning" field in the audit logs to understand the model's hesitation.

## 3. RAG Knowledge Poisoning

### SYMPTOM: [FILTERED: KNOWLEDGE POISONING DETECTED]
**Cause:** A retrieved document contained adversarial instructions (e.g., "ignore previous instructions").
**Resolution:**
1. **Sanitize Source:** Remove the adversarial snippets from the source documentation or vector database.
2. **Pattern Tuning:** If this was a false positive, update the `poison_patterns` regex in `src/guardrail/rag_rails.py`.

## 4. Connectivity Errors

### SYMPTOM: Kernel state fetch failed (500 Internal Server Error)
**Cause:** Backend crash, often due to misconfigured API keys or dependency issues.
**Resolution:**
1. **Check logs:** Run `tail -f logs/backend.log` (if enabled) or check the AI Studio console.
2. **API Key:** Verify `GEMINI_API_KEY` is set correctly in the environment.
3. **Restart Server:** Run `npm run dev` to restart the kernel and the dashboard.
