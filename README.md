# security-specs

Design specifications, threat models, and policy documents for security systems.

These are **not** IETF RFCs and are not on any standards track. They are working
specifications: written to be precise enough to implement against, to argue with,
and to test conformance to. Each one states its own status, what is implemented,
and what is merely specified.

The numbering convention (`SPEC-NNNN`) exists so that source code can cite a
section and have that citation resolve to something a reader can actually open.
A citation that points at nothing is worse than no citation.

## Specifications

| ID | Title | Status | Implemented? |
|---|---|---|---|
| [SPEC-0001](specs/0001-mcp-signed-trust-envelope.md) | Signed Trust-Envelope for MCP Tool Results | Draft v0.3.2 — appsec-reviewed | **Yes** — reference implementation and conformance suite below |
| [SPEC-0002](specs/0002-mcp-content-classification-federated-trust-ai-provenance.md) | Content Classification, Federated Trust, and Universal AI Provenance | Community Draft v0.3 | **Partly** — §4.2 only; §5, §6, §7 are specified, not built |

## Reference implementation

[`mcp-security-platform`](https://github.com/webr0ck/mcp-security-platform)
implements SPEC-0001 and the §4.2 substrate of SPEC-0002. Its source cites these
documents by section throughout.

There is a conformance suite that separates what works from what does not:

```bash
git clone https://github.com/webr0ck/mcp-security-platform
cd mcp-security-platform
./scripts/run_spec0002_verification.sh --offline
```

Everything specified-but-unbuilt reports as a **skip** naming the exact module to
write. Nothing is asserted green that is not.

An independent verifier, usable without the gateway, is published as
[`mcp-trust-verifier`](https://github.com/webr0ck/mcp-security-platform/tree/main/sdk/mcp-trust-verifier).

## Adversarial test harness

[`mcp-envelope-harness`](https://github.com/webr0ck/mcp-envelope-harness) is a
separate repository holding the end-to-end tests, including a two-arm
control/protected prompt-injection experiment. Read its caveats section before
citing its result — the sample size is one.

## Scope

Nothing here is limited to any one employer, product, or deployment. Every
example is an illustrative composite; none is drawn from a production
environment.

## Contributing

Disagreement is the point. Open an issue against a specific section number.
A specification that nobody has attacked has not been reviewed.

## Licence

Documents in this repository are licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — quote them, implement
them, fork them, with attribution. Code in the reference implementation is MIT
and licensed separately in its own repository.
