# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `salient-core`, please report it
responsibly:

1. **Do NOT open a public GitHub issue.**
2. Use GitHub's private vulnerability reporting: go to the repository's
   **Security** tab → **Report a vulnerability**
   (<https://github.com/baggybin/salient-core/security/advisories/new>).
   Include a description and, if possible, a proof of concept.
3. You will receive an acknowledgment within 48 hours.
4. A fix will be prioritized based on severity.

## Scope

`salient-core` is a coordination kernel — it provides inter-agent message
passing, policy gates, a knowledge graph, and a runner architecture. It does
not directly execute network operations, offensive tooling, or any
domain-specific work. Security vulnerabilities in the kernel's own
infrastructure (the bus, the scope gate, the safeguards engine, the runner)
are in scope. Domain-specific vulnerabilities belong in the downstream
application that uses the kernel.

## Design Principles

The kernel enforces a **default-deny** posture:
- Every tool invocation passes through scope + safeguards gates enforced
  *below* the model.
- Inter-agent delegation is typed and reach-limited.
- Operator approval gates gate dangerous or cross-team operations.
