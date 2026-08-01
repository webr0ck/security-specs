---
title: "Signed Trust Envelopes, Content Classification, Federated Trust, and Universal AI Provenance: An Extension to MCP SEP-1913 and a General Framework for AI Artifact Integrity"
status: Community Draft v0.3 (revision)
author: Alexander Romanov
date: 2026-06-26
revised: 2026-06-27
extends: MCP SEP-1913 - Trust and Sensitivity Annotations (PR #1913)
updates: none
reference_impl: github.com/webr0ck/mcp-security-platform
implementation_status: "§4.2 signed-envelope substrate implemented in the reference implementation at github.com/webr0ck/mcp-security-platform; §5 content classification, §6 federation, and §7 universal AI provenance are SPECIFIED but NOT YET IMPLEMENTED - see Implementation Status note in §1."
changelog: "v3 (2026-06-27): added §3 Threat Model, §1.6 Design Trade-offs, §8.2 Version Negotiation, §8.5 Versioning Policy, §9.8-9.11 security subsections, §10 Privacy Considerations, §14 Open Issues, Appendix D Deployment Scenarios. Corrected BLP/Biba property attributions. Upgraded [BLP73]/[Biba77] to primary MITRE sources. Full section renumbering."
---

# SPEC-0002 - Content Classification, Federated Trust, and Universal AI Provenance

> **Read this first - what is built and what is not.**
>
> | Section | Mechanism | Status |
> |---|---|---|
> | §4.2 | Signed trust envelope | **Implemented** - see [SPEC-0001](0001-mcp-signed-trust-envelope.md) and the reference gateway |
> | §5 | Content classification (Bell-LaPadula axis) | Specified only |
> | §6 | Federated trust (signed trust list, transparency log) | Specified only |
> | §7 | Artifact Provenance Envelope / C2PA interop | Specified only |
>
> The three unbuilt sections have module stubs and a conformance suite in the
> reference implementation that **skip** with the exact module to write. Nothing
> in that suite reports green for a mechanism that does not exist. If you want
> the part that demonstrably works today, read SPEC-0001 instead.
>
> The per-section coverage table is generated from that suite and lives at
> [`proxy/tests/spec0002/STATUS.md`](https://github.com/webr0ck/mcp-security-platform/blob/main/proxy/tests/spec0002/STATUS.md)
> in the reference implementation. It is the authoritative answer to "is §N wired
> into the request path?" - this document states intent, that file states fact.

---

## Abstract

SEP-1913 defines a vocabulary of trust and sensitivity annotations for MCP tool results - hint annotations (`sensitiveHint`, `privateHint`, `openWorldHint`, `maliciousActivityHint`) and an `attribution` field. (This document derives a five-level source-trust tier - `untrustedPublic` through `system` - from those hints; see §4.2.2. The tiers are this extension's integrity model, not SEP-1913 field values.) It does not specify how those annotations can be made *verifiable* across process or organizational boundaries, how content type (not just source trustworthiness) should influence data flow policy, how trust labels should compose across multiple gateways, or how provenance should extend to AI-generated artifacts beyond MCP tool calls.

This document specifies four mechanisms across two scopes:

**MCP-specific (§4-§6):** (1) A signed per-invocation trust envelope that makes SEP-1913 labels cryptographically verifiable, binding each label to a certificate profile and a content hash so a downstream consumer that did not produce the label can validate it; (2) a MIME-inspired content classification system adding a Bell-LaPadula confidentiality axis orthogonal to Biba integrity; (3) a federated trust architecture extending single-gateway deployments to multi-organization scenarios using a signed trust list and transparency log.

**MCP-independent (§7):** (4) A generalized Artifact Provenance Envelope (APE) - a signed provenance format for any AI-generated artifact that exists outside the MCP wire: files written to disk, code committed to repositories, documents sent by agents, pipeline reports. APE uses the same signing infrastructure as mechanisms (1)-(3) but is not bound to MCP protocol objects. It is designed for interoperability with C2PA and is applicable to any AI agent framework, not only MCP-based systems.

All four mechanisms are backward-compatible with SEP-1913 and with deployments that implement only a subset.

Section 4.2 defines the signed envelope mechanism that makes SEP-1913 labels verifiable. Section 5 defines the MIME-inspired content classification system. Section 6 specifies the federated trust architecture. Section 7 generalizes the signed-envelope pattern to all AI-generated artifacts. Section 8 presents the unified extended envelope schema.

---

---

## Table of Contents

1.  Introduction
    1.1.  Problem 1: Content Classes Are Invisible
    1.2.  Problem 2: Single-Gateway Trust Does Not Compose
    1.3.  Problem 3: AI Provenance Stops at MCP
    1.4.  Relationship to SEP-1913
    1.5.  Implementation Status
    1.6.  Design Trade-offs
2.  Terminology
3.  Threat Model
    3.1.  Assets Protected
    3.2.  Trusted Components
    3.3.  Untrusted Components
    3.4.  Attacker Capabilities
    3.5.  Security Assumptions
    3.6.  Goals and Non-Goals
4.  Background and Motivation
    4.1.  SEP-1913: Vocabulary Without Verification
    4.2.  Signed Trust Envelopes: Making Labels Verifiable
    4.3.  What This Document Adds
5.  Content Classification System
    5.1.  Design Principles
    5.2.  Content Class Registry
    5.3.  Schema
    5.4.  Integration with Biba Integrity and BLP Confidentiality
    5.5.  Multi-Class Handling
    5.6.  Sink Policy Grammar
    5.7.  Registry Governance
    5.8.  Implementation Notes and Wiring Guide
        5.8.1.  Where Classification Happens
        5.8.2.  Registry Schema Extension
        5.8.3.  Backward Compatibility with v0.1 Consumers
        5.8.4.  Performance Considerations
        5.8.5.  Audit Log Extensions
        5.8.6.  Error Conditions and Failure Behavior
6.  Federated Trust Architecture
    6.1.  Overview
    6.2.  Trust List Format
    6.3.  Trust Scope
    6.4.  Transparency Log
    6.5.  Cross-Gateway Envelope Forwarding
    6.6.  Governance Model
    6.7.  Revocation
7.  Universal AI Provenance
    7.1.  Scope
    7.2.  Artifact Provenance Envelope
    7.3.  Artifact Types
    7.4.  C2PA Interoperability
    7.5.  Pipeline Provenance Chain
    7.6.  Trust Inheritance in Multi-Agent Pipelines
    7.7.  Model Revocation
8.  Extended Envelope Schema
    8.1.  Backward Compatibility
    8.2.  Version Negotiation and Graceful Degradation
    8.3.  Full Extended Schema
    8.4.  Signing Input Construction
    8.5.  Versioning Policy
9.  Security Considerations
    9.1.  Content Class Spoofing
    9.2.  Federation Trust List Attacks
    9.3.  Transparency Log Gaps
    9.4.  Model Identity Spoofing
    9.5.  Pipeline Taint Injection
    9.6.  BLP Declassification Attacks
    9.7.  APE Replay and Binding Attacks
    9.8.  Confused Deputy and Privilege Escalation
    9.9.  Malicious MCP Servers and Compromised Clients
    9.10. Replay and Freshness Attacks
    9.11. Downgrade Attacks
10. Privacy Considerations
    10.1. Metadata Disclosure
    10.2. Execution-Origin Information
    10.3. Telemetry and Data Minimization
    10.4. User Consent and Enterprise Audit
11. Project Registry Governance
    11.1. Content Class Registry
    11.2. OID Namespace
    11.3. C2PA Assertion Type
12. Future Work
13. Open Issues
14. References
Appendix A.  Implementation Conformance Checklist
Appendix B.  Test Vectors
Appendix C.  Threat Model Summary
Appendix D.  Deployment Scenarios

---

## 1. Introduction

SEP-1913 defines the vocabulary for annotating MCP tool results with trust and sensitivity metadata: `sensitiveHint` and `privateHint` mark sensitive/internal data, `openWorldHint` marks data drawn from untrusted/external sources, `maliciousActivityHint` flags detected suspicious patterns, and `attribution` records provenance. This document derives a five-level source-trust tier (untrustedPublic, trustedPublic, internal, user, system) from these hints and maps it to Biba integrity ranks (§4.2.2); the tiers are this extension's integrity model, not native SEP-1913 field values. This vocabulary is necessary but not sufficient for three reasons: the labels are unsigned and a downstream consumer that did not produce them cannot verify them; the annotations address source trustworthiness but not content type; and the scope is limited to individual MCP tool results rather than multi-agent pipeline artifacts.

Section 4.2 of this document specifies the signed trust envelope mechanism that makes SEP-1913 labels verifiable: every MCP tool result leaving the gateway proxy carries a signed envelope that binds a Biba integrity label to the content via a cryptographic commitment. The labeler is a sub-CA-authorized proxy component, not the tool server itself. The consumer verifies the envelope before acting on the result. Session taint propagates via a minimum-integrity floor.

This foundation is necessary but not sufficient. Three gaps remain after the signed envelope mechanism is fully deployed.

### 1.1. Problem 1: Content Classes Are Invisible

The Biba integrity model (implemented in the signed envelope mechanism - see §4.2) answers one question: *how trustworthy is the source of this data?* It does not answer a second, orthogonal question: *what kind of data is this?*

A web search result (integrity rank 1, trustedPublic) and a PII record (integrity rank 2, internal) may have the same or similar integrity labels, but they should flow to completely different sinks under completely different policies. A `financial/trade-order` must never be driven by a `search-result/web` input regardless of integrity rank - the content class itself is a policy input, independent of source trustworthiness.

The missing layer is a BLP-style confidentiality axis: classification of *what the data is* rather than *where it came from*. Bell-LaPadula's "no write down" confidentiality rule - high-classification data must not flow to low-classification sinks - maps directly onto the MCP problem: `pii/ssn` must not flow to a logging sink; `financial/trade-order` must not be composed from `external-content/raw` inputs.

Without a content classification system, policy authors must embed content semantics into tool names and registry entries ad hoc, with no standard vocabulary, no compositional semantics for mixed-content results, and no interoperability between gateways.

### 1.2. Problem 2: Single-Gateway Trust Does Not Compose

The signed envelope mechanism (§4.2) assumes one trust anchor: the proxy's sub-CA. In a single-organization deployment, this is correct. But real deployments span multiple organizations. An enterprise AI platform may aggregate results from its own internal MCP gateway, a cloud-provider MCP gateway, and a third-party data-provider MCP gateway. Each gateway has its own sub-CA and its own labeler identity.

The signing mechanism in §4.2 does not define how a consumer receiving an envelope signed by an unfamiliar sub-CA should validate it. Without a federated trust model, the options are: accept all envelopes (defeating the security property), reject cross-org envelopes (defeating utility), or require all participants to share a single CA (defeating organizational independence).

The federated trust architecture in Section 6 solves this by defining a signed, versioned trust list of authorized labeler sub-CA fingerprints - analogous to the CA/Browser Forum root store but scoped to MCP labeler identities - plus a transparency log so that new sub-CA additions are publicly auditable.

### 1.3. Problem 3: AI Provenance Stops at MCP

The envelope mechanism (§4.2) is defined over `CallToolResult` - the MCP protocol object representing a tool's response. But AI-generated content flows through pipelines in many forms that have no MCP structure: an LLM generates a response text, an agent composes a document, a multi-agent pipeline produces a report, an AI model generates code that gets committed to a repository.

None of these carry provenance today. The same integrity and content-class problems that motivated the signed envelope mechanism (§4.2) for tool results apply equally to LLM outputs, agent documents, and pipeline artifacts:

- An LLM response composed from web-search inputs has been tainted by external content; downstream consumers cannot know this without a provenance record.
- An AI-generated code file has no cryptographic binding to the model version and generation context that produced it; a compromised or jailbroken model's output is indistinguishable from a clean model's output.
- A multi-agent pipeline output may have traversed agents of varying integrity ranks; the final artifact's trustworthiness depends on the full path, not just the last agent's identity.

Section 7 generalizes the signed-envelope pattern from MCP tool results to all AI-generated artifacts, with a C2PA interoperability layer so that downstream content authenticity systems can verify AI provenance alongside camera and tool provenance.

### 1.4. Relationship to SEP-1913

This document is additive to SEP-1913. It does not replace any normative requirement of SEP-1913. Section 4.2 specifies the signed trust envelope mechanism that makes SEP-1913 labels verifiable. Sections 5-7 add content classification, federation, and AI provenance. A consumer that implements this document MUST continue to accept envelopes without `content_class`, `federation`, or `ai_provenance` fields and MUST treat them as if those fields are absent rather than malformed.

The extended envelope schema (Section 8) is a strict superset of the v0.1 envelope schema defined in §4.2. All new fields are OPTIONAL at the envelope level and REQUIRED only when the feature they support is active (e.g., `federation` fields are REQUIRED when a cross-gateway forwarding is performed).

### 1.5. Implementation Status

This document is a specification. To avoid overstating what exists, the implementation status of each part is stated explicitly:

- **§4.2 - Signed trust envelope substrate**: implemented in the reference implementation (github.com/webr0ck/mcp-security-platform). The verifier performs SPKI pinning, parsed-OID EKU checking, `signed_at` validity, the `MAX_ENVELOPE_AGE` freshness bound, and content-hash recomputation; envelope signing uses ES256 over JCS-canonical input. In the current reference implementation, leaf certificates are produced by a self-signed certificate builder in a demo provisioner - the step-ca-based sub-CA issuance and automated 15-minute leaf rotation described in §4.2.3 are the intended production design, not the current demo state.
- **§5 - Content classification (BLP axis)**: SPECIFIED, NOT YET IMPLEMENTED. The registry, sink-policy grammar, multi-class union semantics, and the Wazuh rule recommendations are design-stage.
- **§6 - Federated trust**: SPECIFIED, NOT YET IMPLEMENTED. Trust List signing, M-of-N governance, transparency-log inclusion-proof verification, and cross-gateway forwarding are design-stage.
- **§7 - Universal AI provenance (APE)**: SPECIFIED, NOT YET IMPLEMENTED. The APE schema, model-provenance fields, pipeline-path propagation, and C2PA embedding are design-stage.

The conformance checklist (Appendix A) and test vectors (Appendix B) are normative targets for an implementation, not a record of passing tests. Where this document says "the gateway MUST …" it states a requirement on a conformant implementation, not a claim that the current reference implementation already does so.

**Reading convention - normative vs rationale**: Throughout this document, sentences containing RFC 2119 keywords (MUST, MUST NOT, SHOULD, SHOULD NOT, MAY) state requirements on conformant implementations. Surrounding prose - motivation, worked examples, threat analysis, and trade-off discussion - is explanatory rationale and does not itself impose requirements. Implementers seeking only required behavior may focus on RFC 2119 sentences and the conformance checklist in Appendix A.

### 1.6. Design Trade-offs

This extension is not cost-free. Adopters should weigh the following trade-offs before committing to a conformant deployment:

- **Implementor complexity.** Layer A envelope verification (§4.2) adds a signature-validation path, JWKS/key management, nonce-replay state, and Trust List refresh logic to every consuming client. Deployments without this infrastructure should start with Layer B (advisory) while building toward full conformance.
- **New client-side responsibilities.** Clients that previously relied on TLS for integrity assurance now MUST verify `signed_at` freshness, nonce uniqueness, Trust List membership, and SPKI pinning - responsibilities formerly implicit in the transport layer.
- **Federation governance overhead.** The Trust List (§6) requires an operational owner responsible for key rotation, revocation, cross-gateway reconciliation, and the monitoring window (§6.6 entry-approval process). This is an organizational commitment, not only a code integration.
- **Content-class registry learning curve.** Operators must model BLP/Biba labels (§5.4) correctly for each tool server. Mislabeling degrades to either over-blocking (usability cost) or silent declassification (§9.6 risk). The registry should be reviewed by a security architect, not delegated to tool-server owners.
- **Legacy-compatibility mode.** Mixed deployments where some consumers are v0.1-only run in advisory mode (Layer B only), losing cryptographic guarantees until both sides upgrade. See §8.1 for transition guidance.
- **Provenance vs. privacy tension.** APE envelopes (§7) carry model identifiers, generation-parameter hashes, and full pipeline paths - information that improves audit but also exposes internal architecture. See §10 for privacy mitigations.

These costs are manageable in stages: start with §4.2 signed envelopes (highest ROI, already implemented), defer §6 federation until multi-org deployments are needed, and treat §7 APE as a long-term objective. The specification is modular; each extension field is OPTIONAL at the envelope level.

---

## 2. Terminology

**Artifact**: Any AI-generated output: an LLM response text, an agent-composed document, AI-generated code, a multi-agent pipeline output, or a model-generated binary. Distinct from an MCP `CallToolResult`, which is a protocol-level object; an artifact may be produced from one or more tool results or from model inference alone.

**Artifact Provenance Envelope (APE)**: The generalized signed envelope defined in Section 7 that carries provenance for AI artifacts outside the MCP protocol. A superset of the signed trust envelope defined in §4.2.

**BLP (Bell-LaPadula)**: The Bell-LaPadula confidentiality security model [BLP73]. Two properties: the simple security property ("no read up") and the ★-property ("no write down" - high-classification data must not flow to lower-classification destinations). The content classification mechanism in §5 is conceptually inspired by the ★-property intuition. This specification does not implement the full formal BLP model.

**Biba Integrity Model**: The Biba integrity security model [Biba77]. Two properties: the simple integrity property ("no read down") and the ★-integrity property ("no write up" - a subject cannot write to a higher-integrity destination). The signed envelope and session taint floor in §4.2 are conceptually inspired by the ★-integrity property intuition. This specification does not implement the full formal Biba model.

**C2PA (Coalition for Content Provenance and Authenticity)**: An open technical standard (c2pa.org) for attaching signed provenance manifests to media files and documents. This document defines how APEs embed as C2PA assertions.

**Content Class**: A structured identifier for the semantic category of data contained in a tool result or AI artifact. Format: `<domain>/<subtype>`, e.g., `pii/email`, `financial/trade-order`. Defined in the Content Class Registry (Section 5.2).

**Content Class Registry**: The authoritative list of defined content classes, their confidentiality floors, and their applicable sink policy constraints. Maintained by the mcp-security-platform governance committee.

**Confidentiality Floor**: The minimum sink confidentiality level required to receive data of a given content class. A sink with confidentiality level below this floor MUST NOT receive content of that class.

**Cross-Gateway Forwarding**: The act of a gateway (Gateway A) forwarding a tool result that was already labeled by a different gateway (Gateway B) to its own downstream consumer, either re-signing (dual-signature mode) or relaying unchanged (relay mode).

**Dual-Signature Chain**: An envelope produced by cross-gateway forwarding in re-sign mode, containing both the original Gateway B leaf signature and a Gateway A outer signature, with the original envelope nested as `forwarded_envelope`.

**Effective Content Class**: For a result containing multiple content types, the union class formed by taking the strictest confidentiality floor across all constituent classes.

**Effective Integrity Rank**: Per the session-taint rules in §4.2, `min(integrity_rank for all sources in session)`. For pipeline provenance (Section 7.5), `min(integrity_rank for all steps in pipeline_path)`.

**Federation Root**: The governance-level keypair(s) whose public key(s) are used to verify the signature over the Trust List. The federation root is not a CA; it does not issue certificates. It only signs the Trust List document.

**Gateway**: An mcp-security-platform proxy instance that mediates MCP tool calls, enforces policy, labels results via TrustLabeler, and verifies envelopes on behalf of consumers. The proxy model is defined in §4.2 of this document.

**Generation Parameters Hash**: A cryptographic hash over the system prompt, model version string, temperature, top-p, and other sampling parameters used to produce an LLM output. Proves the generation context, not only the content.

**Governance Root**: Synonym for Federation Root when the document discusses governance operations (Trust List signing, key rotation).

**Inclusion Proof**: A Merkle audit path demonstrating that a given leaf (e.g., a sub-CA fingerprint) is included in the transparency log's current tree head. Required before a verifier trusts a labeler sub-CA not previously seen.

**Integrity Rank**: Per the Biba integrity model in §4.2, a numeric value 0-4 mapped from this document's five-level source-trust tier (which is in turn derived from SEP-1913 hint annotations; see §4.2.2): untrustedPublic=0, trustedPublic=1, internal=2, user=3, system=4.

**Labeler**: The TrustLabeler component inside a Gateway. Per §4.2 of this document, the labeler signs envelopes using a short-lived leaf certificate issued by a sub-CA whose SPKI fingerprint appears in the Trust List.

**Model Commitment Hash**: A hash over `model_id || model_version || model_sha256_digest` that commits to the exact model binary that produced an artifact. Prevents model-ID string spoofing.

**Pipeline Path**: An ordered list of `{agent_id, action, integrity_rank, timestamp}` records representing the sequence of agents and tools that processed data before producing an artifact.

**Relay Mode**: Cross-gateway forwarding mode where Gateway A forwards a Gateway B envelope unchanged to its downstream consumer, without adding an outer signature.

**Re-Sign Mode**: Cross-gateway forwarding mode where Gateway A adds an outer signature over the original (Gateway B) envelope, producing a Dual-Signature Chain.

**Sink**: A tool, API, or output channel that receives data from an AI pipeline. Per the signed envelope mechanism (§4.2), sinks have a `required_integrity` floor. This document adds a `required_content_class_floor` and content-class allow/deny lists.

**Sub-CA**: A certificate authority subordinate to the enterprise Root CA, whose SPKI fingerprint is pinned in the Trust List. The MCP platform operates as a Sub-CA - it does not own a Root CA. Issues labeler leaf certificates. Per the certificate profile in §4.2, nameConstrained to the mcp-security-platform namespace.

**Transparency Log**: An append-only, Merkle-tree-backed log of labeler sub-CA SPKI fingerprints (and optionally individual signed assertions). Modeled after RFC 6962 (Certificate Transparency) and Sigstore Rekor.

**Trust List**: A signed, versioned JSON document listing authorized labeler sub-CA SPKI fingerprints and their trust scopes. Analogous to a browser root store but scoped to MCP labeler identities.

**Trust Scope**: Per-entry constraints in the Trust List bounding what a labeler sub-CA is authorized to assert: which tool servers it can vouch for, which content classes, and the maximum integrity rank it may assign.

**Terminology notes for consistency:**

- **Signed Trust Envelope** (also "signed envelope", "envelope"): the Layer A signed structure defined in §4.2 and carried in `CallToolResult._meta`. Both "signed envelope" and "signed trust envelope" are accepted short forms throughout this document; they refer to the same object.
- **Labeler** (lowercase) vs **TrustLabeler** (capitalized): "labeler" refers to the role - the gateway component that assigns and signs labels. "TrustLabeler" is the specific component name in the reference implementation. Where the distinction matters (implementation-specific contexts), "TrustLabeler" is used.
- **Gateway** vs **proxy**: Gateway is defined in §2 and detailed in §4.2. This document uses "gateway" as the standard term; "proxy" appears only when contrasting with tool-server topology.
- **Content class** vs **content type**: "content class" is the registered identifier (e.g., `pii/email`). "Content type" is generic English; it does not refer to the registry.

---

## 3. Threat Model

This section defines the threat model that governs all security requirements in this document. The conformance checklist (Appendix A) and security analysis (§9) reference this model. Appendix C provides a summary table mapping each threat to its mitigating section.

### 3.1. Assets Protected

- **Integrity-label↔content binding**: the assurance that the integrity label on a tool result was assigned by an authorized gateway component and has not been tampered with in transit.
- **Content-class↔content binding**: the assurance that the content class on a tool result correctly identifies the data category and has not been reclassified by an intermediary.
- **The Trust List**: the authoritative, signed enumeration of authorized labeler sub-CAs. Compromise allows introducing unauthorized labelers.
- **The transparency log**: the append-only record of Trust List updates. Compromise enables undetected sub-CA registration.
- **AI artifact provenance records (APE)**: the signed chain of custody for AI-generated artifacts across pipeline steps.

### 3.2. Trusted Components

The following components are trusted within the model - their correct operation is assumed, not proved by the protocol:

- **Gateway proxy / TrustLabeler**: the component that assigns labels, signs envelopes, and enforces policy. Compromise is the catastrophic case; it is mitigated by short-lived leaf keys (§4.2.3) and the transparency log (§6.4).
- **Labeler sub-CA and its key material**: issues the short-lived leaf certificates used for signing. Protected by HSM integration (Future Work, §13) and 15-minute TTL.
- **The gateway tool/content-class registry**: the local configuration that determines what integrity rank and content class each tool server receives. Under gateway operator control; not accessible by tool servers.
- **Governance key holders** (for federation): the M-of-N set of parties who control the Trust List. Each individual key holder is untrusted; the set is trusted only when M-of-N are in agreement (§6.6).

### 3.3. Untrusted Components

The following components are explicitly untrusted - the protocol provides no guarantees that depend on their honesty:

- **Tool servers**: any tool server may be malicious, misconfigured, or compromised. Labels MUST be assigned by the gateway, never by the tool server (§5.1 P1, §4.2.1).
- **Network intermediaries and relays**: a man-in-the-middle may attempt to modify envelope fields in transit. Mitigated by the content-hash binding in Layer A (§4.2).
- **Trust List distribution server**: may be compromised; delivering a modified Trust List is a denial-of-service only because Trust List signature verification does not depend on the distribution server's integrity (§9.2).
- **Individual pipeline agents**: an agent in a multi-agent pipeline may process tainted data; its output integrity rank is computed by the framework, not self-asserted (§7.6).
- **Inference endpoints**: API-level model identity assurance rests on the labeler honestly reporting what endpoint it called; hardware attestation is not in scope (§9.4 residual risk).

### 3.4. Attacker Capabilities

This specification defends against adversaries with the following capabilities:

1. **Controls a tool server**: can emit arbitrary content and attempt to self-assert labels.
2. **MITM on envelope-in-transit**: can read and attempt to modify envelope fields before consumer verification.
3. **Compromises one governance key**: can attempt to produce a rogue Trust List; defeated by M-of-N requirement (§6.6).
4. **Takes the transparency log offline**: can attempt to prevent inclusion-proof verification for new sub-CAs (§9.3).
5. **Controls an inference path**: can attempt to substitute model output while asserting a trusted model's identity; partially mitigated by the model commitment hash (§7.2.1, §9.4).
6. **Network-level rollback**: can attempt to serve an older Trust List version; defeated by sequence-number monotonicity (§6.2).

### 3.5. Security Assumptions

- SHA-256 and ES256/ES384 are computationally unfeasible to break.
- The verifier's envelope verification code is deterministic, correct, and runs in a trusted execution context (i.e., the client is not itself compromised - see §9.9 residual risk).
- The gateway honestly assigns labels from its own registry; a malicious gateway operator is an out-of-scope adversary for the signing mechanism, but is partially constrained by the transparency log.
- At most M−1 of the N governance key holders are simultaneously compromised.

### 3.6. Goals and Non-Goals

**Goals - this specification addresses:**

- Reducing credential and sensitive-data exposure by classifying content at the gateway before it reaches downstream sinks.
- Privilege and integrity separation via the Biba integrity model (§4.2) and BLP confidentiality axis (§5).
- Making label assertion local to an authorized gateway component, not delegated to tool servers.
- Cross-organizational authorization boundaries via federated trust (§6).
- Provenance of AI-generated artifacts beyond MCP tool calls (§7).

**Non-Goals - this specification does NOT address:**

- Endpoint or host compromise (a compromised gateway defeats all guarantees).
- Operating-system security or malware detection on client or server hosts.
- Transport security beyond requiring TLS for Trust List distribution endpoints and inference endpoints.
- Application or model sandboxing.
- Runtime model-weight integrity (see §9.4 residual risk).
- Human-author content provenance (out of scope; C2PA covers camera-captured content).

A conformant implementation provides the guarantees above only within the threat model defined in §3.2-§3.5. It is not a complete security model for an AI deployment.

---

## 4. Background and Motivation

### 4.1. SEP-1913: Vocabulary Without Verification

SEP-1913 (MCP Enhancement Proposal, PR #1913) defines a vocabulary for annotating MCP tool results with trust and sensitivity metadata. Its annotation fields are `sensitiveHint` (granular sensitivity, e.g. low/medium/high), `privateHint` (marks internal/private data), `openWorldHint` (marks data drawn from untrusted/external sources), `maliciousActivityHint` (signals detected suspicious patterns), and `attribution` (provenance information about the tool result's origin). SEP-1913 deliberately does not impose a single ordered `source` tier; this document constructs one. Specifically, this extension derives a five-level source-trust tier - `untrustedPublic`, `trustedPublic`, `internal`, `user`, `system` - from those hints (see §4.2.2) and uses it as the Biba integrity axis. Throughout this document, references to a "source tier" or "trust tier" denote this extension's derived model, not a native SEP-1913 field.

This vocabulary is necessary and well-designed for communicating intent. It does not, however, provide any mechanism for a downstream consumer to verify the labels. A gateway that receives a `CallToolResult` carrying SEP-1913 hint annotations (or this document's derived tier) has no cryptographic assurance that the labels were not set by the tool server itself, modified in transit, or forged by a network intermediary. The labels travel as unsigned JSON fields in `_meta`, indistinguishable in their integrity properties from the tool result content they describe.

Three structural gaps follow from the absence of verification:

1. **Unverifiable provenance**: A consumer that did not produce the SEP-1913 label cannot trust it without an out-of-band agreement with the producer. In multi-gateway and multi-organization deployments this is impractical.

2. **No content-type policy axis**: SEP-1913 addresses source trustworthiness (where did this come from?) but not content type (what is this?). Two results with identical `source` tiers may require completely different data-flow policies based on their content - a `pii/ssn` result and a `search-result/web` result may both be `trustedPublic`, but should never reach the same sinks.

3. **MCP-only scope**: SEP-1913 annotations apply to `CallToolResult` objects. LLM responses, agent-composed documents, and multi-agent pipeline outputs have no equivalent annotation mechanism, leaving the majority of AI-generated content without any trust or provenance metadata.

### 4.2. Signed Trust Envelopes: Making Labels Verifiable

This section specifies the signed trust envelope mechanism that makes SEP-1913 labels cryptographically verifiable. The reference implementation is at `github.com/webr0ck/mcp-security-platform`.

#### 4.2.1. Design Principles

**The proxy is the sole label-asserter**: Content class and integrity labels MUST be assigned by the gateway proxy's registry, not by the tool server. A tool server that self-asserts its trust tier or content class bypasses all policy enforcement. The gateway assigns labels from its own registry, keyed by `server_id`. This requirement is an interoperability invariant: equivalent security guarantees MAY be achieved by any architecture in which the label-asserter is a component the tool server cannot influence; "gateway proxy registry" denotes that trust boundary, not a mandated deployment topology.

**Two layers**: The envelope uses two layers with different trust properties.

```
Trust Boundary Diagram

Tool Server (untrusted)       │  Gateway / TrustLabeler (TRUST BOUNDARY)  │  Consumer
──────────────────────────────┼────────────────────────────────────────────┼──────────────────────
  - Emits tool results        │  - Assigns labels from registry            │  - Verifies Layer A
  - MUST NOT self-assert      │  - Signs Layer A (ES256/JCS, authoritative)│  - Enforces BLP/Biba
    labels or content classes │  - Injects Layer B (in-band advisory)      │  - Trusts no unsigned
  - Untrusted by design       │  - Enforces taint floor before forwarding  │    label from server
──────────────────────────────┼────────────────────────────────────────────┼──────────────────────
     (§3.3 Untrusted)         │     (§3.2 Trusted; §4.2.3 cert profile)   │   (deterministic code)

Layer A (authoritative):  ══════════════════════════════════════════════════════►  verified
Layer B (advisory only):  ──────────────────────────────────────────────────────►  probabilistic
```

**Layer A** (authoritative, cryptographically verified): A JWS (JSON Web Signature, ES256) over a canonical signing input that includes: the content hash (JCS/RFC 8785 canonical JSON of `content[]` and `structuredContent`), the assigned integrity label, a nonce, and call identity fields (`result_id`, `tool_name`, `server_id`, `signed_at`). Layer A lives in `CallToolResult._meta["io.mcp-security-platform/trust-envelope/v0.1"]`. Verification is deterministic code; the model never affects it. This is the authoritative enforcement layer.

**Layer B** (advisory, non-authoritative): An in-band MIME-style wrapper injected into the tool result text, prefixing the content with an explicit untrusted-source notice for non-conformant consumers that do not process `_meta`. Unsigned; provides probabilistic benefit only for consumers that are not envelope-aware.

#### 4.2.2. Biba Integrity Model and SEP-1913 Mapping

This document defines a five-level source-trust tier and maps it to Biba integer ranks 0-4. The tier is derived from SEP-1913 hint annotations by the gateway registry - for example, a server whose results carry `openWorldHint: true` (untrusted/external) maps to `untrustedPublic`; a server marked `privateHint` for internal data maps to `internal`; the `user` and `system` tiers are assigned by the gateway to caller- and platform-originated content respectively. The derivation rules are a registry concern (the gateway assigns the tier per `server_id`), not a SEP-1913 field lookup. The tier-to-rank mapping is:

| Source-trust tier (this document) | Biba Integrity Rank |
|------------------------|---------------------|
| `untrustedPublic`      | 0                   |
| `trustedPublic`        | 1                   |
| `internal`             | 2                   |
| `user`                 | 3                   |
| `system`               | 4                   |

The gateway assigns `integrity_rank` from its registry - never from server self-assertion. Session taint is computed as the minimum integrity rank across all sources touched in the session (`effective_integrity = min(integrity_rank for all results in session)`). Sinks declare `required_integrity`; the gateway denies any call where `effective_integrity < required_integrity`. Binary session-taint enforcement: any rank-0 result taints the session for high-sensitivity sinks. Taint is written durably before the result is forwarded; store errors fail closed.

#### 4.2.3. Certificate Profile

The certificate profile specifies: a Sub-CA issued by the enterprise Root CA (the MCP platform does not own a Root CA - it operates as a Sub-CA subordinate to the company PKI), nameConstrained to the mcp-security-platform namespace, with a labeler EKU (`1.3.6.1.4.1.<PEN>.mcp.labeler`). Leaf certificates are short-lived (15-minute TTL). The verifier performs SPKI pinning against the Sub-CA, parsed-OID EKU check (no `anyExtendedKeyUsage`), point-in-time validity at `signed_at`, `MAX_ENVELOPE_AGE` freshness bound (600 seconds), and content hash recomputation.

```
Certificate / Credential Flow

  Root CA (Company PKI - offline, HSM-protected)
      │ issues (offline, long-lived)
      ▼
  Sub-CA (MCP Platform - nameConstrained to mcp-security-platform namespace,
          labeler EKU = 1.3.6.1.4.1.<PEN>.mcp.labeler)
      │ SPKI fingerprint pinned in Trust List (§6.2) and verifier config
      │ issues (step-ca, automated, 15-min TTL)
      ▼
  Labeler Leaf Certificate
      │ used by TrustLabeler to sign
      ▼
  Signed Envelope (ES256 over JCS-canonical input)
      │ forwarded to Consumer
      ▼
  Verifier checks:
    [1] SPKI pin matches sub-CA in Trust List entry
    [2] EKU contains labeler OID (no anyExtendedKeyUsage)
    [3] signed_at within leaf validity window
    [4] signed_at + MAX_ENVELOPE_AGE (600s) > now
    [5] content_hash recomputed and matches
```

#### 4.2.4. What the Signed Envelope Does Not Cover

The signed envelope mechanism deliberately defers three capabilities:

1. **Federated trust**: the verifier only accepts envelopes from its own pinned sub-CA. Cross-organization scenarios are undefined - addressed by Section 6 of this document.
2. **Per-value taint (C-precise model)**: the envelope implements binary session taint. Fine-grained tracking of which argument values carry which labels is deferred to Future Work (Section 13).
3. **BLP confidentiality axis**: the envelope models only integrity (Biba). Content-type-based data flow policy is not addressed - added by Section 5 of this document.

Additionally, the signed envelope is scoped to MCP `CallToolResult` objects. It provides no envelope mechanism for LLM outputs, agent documents, or pipeline artifacts - addressed by Section 7 of this document.

### 4.3. What This Document Adds

To aid reviewers, this section distinguishes established practices this document reuses from new contributions.

**Established practices reused:**

- Signed JSON envelopes (JWS, RFC 7515) and JSON canonicalization (JCS, RFC 8785).
- Certificate Transparency / Merkle-tree transparency logs (RFC 6962, Sigstore Rekor).
- C2PA signed provenance manifests (C2PA 2.1).
- Biba integrity model and Bell-LaPadula confidentiality model (existing formal models, 1973-1977).
- OAuth 2.1 / PKCE for MCP transport authentication (not extended here; referenced as existing practice).
- Principle of least privilege, proxy-interposition for label assignment (existing security design patterns).

**New contributions of this document:**

- A BLP confidentiality axis applied orthogonally to Biba integrity on MCP tool results - making content *type* a first-class policy input alongside source *trustworthiness*.
- A standardized content-class registry vocabulary (`pii/ssn`, `financial/trade-order`, etc.) with defined confidentiality floors and sink-policy grammar.
- A federated Trust List scoped specifically to MCP labeler identities, making execution-locality of label assertion explicit and verifiable across organizations.
- Trust-scope constraints bounding what each labeler may assert - not present in generic PKI or CT models.
- An Artifact Provenance Envelope (APE) generalizing the signed-envelope pattern to non-MCP AI artifacts, with C2PA interoperability for the `io.mcp-security-platform.ai-provenance` assertion type.
- Pipeline-path integrity propagation applying the Biba minimum operation across multi-agent chains.

**Content classification** (Section 5): a MIME-inspired content classification system adding a Bell-LaPadula confidentiality axis orthogonal to Biba integrity. Two results with identical integrity labels but different content types (`pii/ssn` vs. `search-result/web`) are now distinguishable by policy, with standard vocabulary and compositional semantics.

**Federated trust** (Section 6): a signed Trust List, transparency log, and cross-gateway envelope forwarding protocol that extends the signed envelope mechanism from single-organization to multi-organization deployments. Modeled after the CA/Browser Forum root store but scoped to MCP labeler identities.

**Universal AI provenance** (Section 7): an Artifact Provenance Envelope (APE) that generalizes the signed-envelope pattern from MCP tool results to all AI-generated artifacts - LLM responses, agent documents, AI code, pipeline reports - with C2PA interoperability. Closes the gap where tainted-source content can escape the integrity model by being transformed by an LLM step.

---

## 5. Content Classification System

### 5.1. Design Principles

The content classification system is governed by the following design principles, each tied to a specific attack or failure mode it defeats.

**P1 (Proxy-assigned, never self-asserted)**: Content classes MUST be assigned by the gateway proxy's registry, not by the tool server. A tool server that self-asserts `system-config` for its outputs when it is actually delivering `external-content/raw` would bypass all class-based sink policies. The same argument that justifies proxy-assigned integrity ranks (§4.2) applies here. Equivalent guarantees MAY be achieved by any architecture in which the label-asserter is a component the tool server cannot influence; "gateway proxy registry" denotes that trust boundary, not a mandated deployment topology.

*Attack defeated*: A malicious or misconfigured tool server claims a high-trust content class to bypass sink restrictions.

**P2 (Signed with content hash)**: Content class MUST be included in the Layer A signing input and bound to the content hash. An envelope where the class field is mutable post-signing allows a man-in-the-middle to reclassify content after it leaves the gateway.

*Attack defeated*: A network intermediary or compromised relay replaces `pii/ssn` with `search-result/web` on an envelope, causing a high-sensitivity result to flow to a low-sensitivity sink.

**P3 (Union semantics for multi-class results)**: When a result contains multiple content types, the effective class is the union, and policy evaluates against the strictest applicable floor across all constituent classes. There is no down-rounding of multi-class results.

*Attack defeated*: An attacker crafts a result that mixes a low-sensitivity content type with a high-sensitivity type, hoping the classifier picks the lower of the two.

**P4 (Orthogonal to integrity rank)**: Content class governs the BLP confidentiality axis (what data is, where it can go). Integrity rank governs the Biba integrity axis (how trustworthy the source is, whether it can drive actions). A sink policy MAY gate on either or both axes independently. Neither axis subsumes the other.

*Failure mode avoided*: Treating integrity rank as a proxy for content sensitivity. A `system` (rank 4) source might still produce `external-content/raw` if it fetches web data; the content class correctly identifies the sensitivity regardless of the tool server's trust level (the Biba integrity model defined in §4.2 governs only source trust, not content type).

**P5 (Fail-closed on unknown class)**: A result with no content class assigned, or with an unrecognized class, MUST be treated as the most restrictive applicable default. The default class for unknown results is `external-content/raw` with a confidentiality floor of `restricted`.

*Attack defeated*: A new tool server is registered without a content class entry; its results bypass class-based policy by defaulting to unrestricted.

**P6 (Immutable registry)**: The Content Class Registry is append-only. Existing entries may be deprecated but not removed or modified. This ensures that existing signed envelopes remain verifiable and their class semantics do not shift retroactively.

### 5.2. Content Class Registry

Content classes use a hierarchical two-segment format: `<domain>/<subtype>`. The domain identifies the broad category; the subtype narrows it. Future versions MAY add a third segment: `<domain>/<subtype>/<qualifier>`.

The initial registry defines the following classes. Each entry specifies: the class identifier, a human-readable description, the default confidentiality floor, and whether it requires explicit sink allowlisting.

```
+----------------------------------+-------------------+-------------------+----------+
| Class Identifier                 | Description       | Conf. Floor       | Allowlist|
+----------------------------------+-------------------+-------------------+----------+
| pii/email                        | Email addresses   | restricted        | yes      |
| pii/name                         | Personal names    | restricted        | yes      |
| pii/ssn                          | Social Security / | secret            | yes      |
|                                  | national ID nos.  |                   |          |
| pii/dob                          | Dates of birth    | restricted        | yes      |
| pii/location                     | Physical location | restricted        | yes      |
| pii/health                       | General health    | secret            | yes      |
| pii/biometric                    | Biometric data    | top-secret        | yes      |
| pii/generic                      | PII not elsewhere | restricted        | yes      |
|                                  | classified        |                   |          |
+----------------------------------+-------------------+-------------------+----------+
| financial/trade-order            | Pending or placed | secret            | yes      |
|                                  | securities orders |                   |          |
| financial/balance                | Account balance   | restricted        | yes      |
| financial/transaction            | Transaction       | restricted        | yes      |
|                                  | history           |                   |          |
| financial/payment-instrument     | Card/bank account | secret            | yes      |
|                                  | numbers           |                   |          |
| financial/generic                | Financial data    | restricted        | yes      |
|                                  | NEC               |                   |          |
+----------------------------------+-------------------+-------------------+----------+
| medical/diagnosis                | Medical diagnoses | secret            | yes      |
| medical/prescription             | Prescriptions     | secret            | yes      |
| medical/lab-result               | Lab test results  | secret            | yes      |
| medical/generic                  | Medical data NEC  | restricted        | yes      |
+----------------------------------+-------------------+-------------------+----------+
| code/executable                  | Compiled binary   | internal          | yes      |
|                                  | or bytecode       |                   |          |
| code/patch                       | Source code diff  | internal          | no       |
| code/source                      | Source code file  | internal          | no       |
| code/script                      | Shell/scripting   | internal          | yes      |
|                                  | language file     |                   |          |
| code/generic                     | Code NEC          | internal          | no       |
+----------------------------------+-------------------+-------------------+----------+
| search-result/web                | Result from a     | public            | no       |
|                                  | public web search |                   |          |
| search-result/internal           | Result from an    | internal          | no       |
|                                  | internal search   |                   |          |
| search-result/restricted         | Result from a     | restricted        | no       |
|                                  | restricted corpus |                   |          |
+----------------------------------+-------------------+-------------------+----------+
| system-config                    | System or app     | secret            | yes      |
|                                  | configuration     |                   |          |
| system-credential                | Credentials,      | top-secret        | yes      |
|                                  | tokens, secrets   |                   |          |
| system-log                       | System or app     | internal          | no       |
|                                  | log data          |                   |          |
| system-generic                   | System data NEC   | internal          | no       |
+----------------------------------+-------------------+-------------------+----------+
| user-data/preference             | User preferences  | restricted        | yes      |
| user-data/content                | User-created      | restricted        | yes      |
|                                  | content           |                   |          |
| user-data/generic                | User data NEC     | restricted        | yes      |
+----------------------------------+-------------------+-------------------+----------+
| external-content/raw             | Unprocessed       | public            | no       |
|                                  | external content  |                   |          |
| external-content/processed       | External content  | public            | no       |
|                                  | post-LLM          |                   |          |
| external-content/vendor          | Vendor-supplied   | internal          | no       |
|                                  | dataset           |                   |          |
+----------------------------------+-------------------+-------------------+----------+
| ai-output/llm-response           | Raw LLM response  | public            | no       |
|                                  | text              |                   |          |
| ai-output/agent-document         | Agent-composed    | internal          | no       |
|                                  | document          |                   |          |
| ai-output/pipeline-report        | Multi-agent       | internal          | no       |
|                                  | pipeline output   |                   |          |
| ai-output/code                   | AI-generated code | internal          | yes      |
+----------------------------------+-------------------+-------------------+----------+
```

**Confidentiality Floor levels** (ordered from least to most restrictive):

```
public < internal < restricted < secret < top-secret
```

A sink with confidentiality level `L` MUST NOT receive content whose effective confidentiality floor is `F` where `F > L`. (BLP "no write down" restated for sinks: a sink cannot receive content classified above its clearance level.)

**"Allowlist required"** means that the sink must have an explicit entry in its `content_class_allowlist` for this class before receiving content of this type, even if the confidentiality floor is met. This provides an additional defense-in-depth gate for high-sensitivity content classes.

### 5.3. Schema

Content class information is carried as a new field `content_class` within the trust envelope (see Section 8 for the full extended schema). The sub-object is:

```json
{
  "content_class": {
    "primary": "pii/email",
    "additional": ["search-result/web"],
    "effective": "pii/email",
    "conf_floor": "restricted",
    "allowlist_required": true,
    "assigned_by": "gateway.example.org",
    "assigned_at": "2026-06-26T10:00:00Z"
  }
}
```

Fields:

- `primary` (REQUIRED): The single content class that best describes the primary content of this result. MUST be a registered class identifier.
- `additional` (OPTIONAL): An array of additional content class identifiers present in this result. MUST contain only registered class identifiers. MAY be empty or absent if no additional classes apply.
- `effective` (REQUIRED): The effective content class for policy evaluation - the class with the strictest confidentiality floor across `primary` and all `additional` entries. MUST be computed by the gateway and MUST NOT be set by the tool server.
- `conf_floor` (REQUIRED): The confidentiality floor corresponding to the `effective` class. MUST match the registry entry for `effective`.
- `allowlist_required` (REQUIRED): Boolean. TRUE if any class in `primary` or `additional` has `allowlist_required: true` in the registry. Once TRUE, it cannot be overridden to FALSE by other classes in the union.
- `assigned_by` (REQUIRED): The gateway identity that assigned the content class. MUST match the `labeler_id` in the outer trust envelope.
- `assigned_at` (REQUIRED): ISO 8601 UTC timestamp of classification.

### 5.4. Integration with Biba Integrity and BLP Confidentiality

The signed envelope mechanism (§4.2) implements the Biba integrity axis: source trustworthiness governs whether a session can drive an action sink. This document adds the BLP confidentiality axis: content type governs whether a result may be delivered to a receiving sink.

The two axes operate independently and both MUST be satisfied for a data flow to be permitted:

```
ALLOW data flow if:
  (1) effective_integrity >= sink.required_integrity          [Biba, §4.2]
  AND
  (2) content_floor(effective_class) <= sink.conf_level       [BLP, this document]
  AND
  (3) if content.allowlist_required:
        effective_class IN sink.content_class_allowlist       [allowlist gate]
```

The BLP axis is evaluated by comparing the content's effective confidentiality floor against the **sink's** declared confidentiality level (`conf_level`) - *not* against the integrity rank. The following matrix illustrates the BLP "no write down" check alone (content floor on the rows, sink clearance on the columns); "OK" means the content's floor is at or below the sink's clearance:

```
                              SINK CONFIDENTIALITY LEVEL (conf_level / clearance)
                         public   internal  restricted  secret  top-secret
                       +--------+---------+-----------+-------+-----------+
  C   public           |  OK    |   OK    |    OK     |  OK   |   OK      |
  O   internal         |  DENY  |   OK    |    OK     |  OK   |   OK      |
  N   restricted       |  DENY  |  DENY   |    OK     |  OK   |   OK      |
  T   secret           |  DENY  |  DENY   |   DENY    |  OK   |   OK      |
  E   top-secret       |  DENY  |  DENY   |   DENY    | DENY  |  OK (*)   |
  N                    +--------+---------+-----------+-------+-----------+
  T  FLOOR
              (*) top-secret content ALWAYS additionally requires an explicit
                  allowlist entry at the sink, regardless of conf_level.
```

This matrix shows only the BLP (confidentiality) axis. The Biba (integrity) axis is **orthogonal** and is evaluated independently: a flow is permitted only when BOTH `effective_integrity >= sink.required_integrity` (Biba) AND the BLP cell above is "OK" AND any applicable allowlist gate is satisfied (see the combined ALLOW conditions earlier in this section). A flow that is "OK" on the BLP matrix may still be denied by the Biba check, and vice versa - neither axis is a function of the other. This is the orthogonality asserted in Design Principle P4. The worked examples below and the Appendix B.1 test vectors evaluate the two axes in exactly this independent manner.

**Policy evaluation decision flowchart** (corresponds to the 6-step order in §5.6):

```
Incoming data flow request
        │
        ▼
  [1] Biba check: effective_integrity >= sink.required_integrity?
        │ NO ──► DENY (log: biba_floor)
        │ YES
        ▼
  [2] BLP check: content_floor(effective_class) <= sink.conf_level?
        │ NO ──► DENY (log: blp_floor)
        │ YES
        ▼
  [3] Denylist check: effective_class ∉ content_class_denylist
       AND all(c ∉ denylist for c in additional)?
        │ NO ──► DENY (log: content_class_denylist)
        │ YES
        ▼
  [4] Allowlist check (if allowlist non-empty):
       effective_class ∈ content_class_allowlist?
        │ NO ──► DENY (log: content_class_allowlist)
        │ YES (or allowlist empty)
        ▼
  [5] Require-class check (if require_content_class=true):
       content_class field present?
        │ NO ──► DENY (log: content_class_missing)
        │ YES (or require_content_class=false)
        ▼
  [6] Max-additional check (if max_additional_classes set):
       len(additional) <= max_additional_classes?
        │ NO ──► DENY (log: content_class_count)
        │ YES
        ▼
      ALLOW
```

**Practical examples**:

*Example A*: A session that called a web search tool (integrity rank 0 = `untrustedPublic`) produces a `search-result/web` result (conf floor = `public`). A note-taking sink has `required_integrity = 1`, `conf_level = internal`. The Biba check fails (0 < 1) regardless of content class. DENY.

*Example B*: A session calls an internal document store (integrity rank 2 = `internal`) that returns `user-data/content` (conf floor = `restricted`). A summary-display sink has `required_integrity = 2`, `conf_level = restricted`, and `user-data/content` in its `content_class_allowlist`. Both checks pass. ALLOW.

*Example C*: A session calls an internal tool (integrity rank 2) that returns a result with `primary = search-result/internal` and `additional = [pii/email]`. The effective class is `pii/email` (conf floor = `restricted`, `allowlist_required = true`). A logging sink has `required_integrity = 2` and `conf_level = public`. BLP check fails (restricted > public). DENY. Even if the logging sink had `conf_level = restricted`, the allowlist gate would still require `pii/email` to be explicitly listed in `sink.content_class_allowlist`.

### 5.5. Multi-Class Handling

A single MCP tool result may contain multiple content types in its payload - for example, a CRM record might contain both `pii/email` and `financial/balance`. The gateway registry MUST assign content class by inspecting the result structure (pattern matching, schema validation, or explicit registry configuration per tool), not by trusting any field in the result itself.

**Union rule**: The `effective` class is the class with the highest confidentiality floor across all classes present. When two classes have the same confidentiality floor, either may be chosen as `effective` (the floor value is what matters for policy). All classes MUST appear in either `primary` or `additional`.

**Allowlist union**: If any class in the union has `allowlist_required = true`, the result as a whole has `allowlist_required = true`. The presence of a non-allowlist-required class in the union does not reduce this requirement.

**Sink allowlist matching**: When `allowlist_required = true`, the sink's `content_class_allowlist` MUST contain the `effective` class OR a wildcard matching it. Wildcard format: `pii/*` matches any `pii/<subtype>`; `*` matches any class (SHOULD NOT be used except for explicitly general-purpose sinks).

**Attestation**: The gateway MUST include all detected classes in the signed envelope. Omitting a detected class to reduce the effective floor is a signing-integrity violation detectable by auditors reviewing logged results against registry patterns.

### 5.6. Sink Policy Grammar

Sink policies are declared in the gateway registry as a structured object per tool/sink. The following grammar extends the sink policy defined in §4.2 to include content class constraints.

```
sink_policy ::= {
  "required_integrity": <integer 0-4>,      // §4.2 field, REQUIRED
  "conf_level": <conf_level>,               // NEW, REQUIRED
  "content_class_allowlist": [<class_id>],  // NEW, OPTIONAL
  "content_class_denylist": [<class_id>],   // NEW, OPTIONAL
  "require_content_class": <boolean>,       // NEW, OPTIONAL, default false
  "max_additional_classes": <integer>       // NEW, OPTIONAL, default unlimited
}

conf_level ::= "public" | "internal" | "restricted" | "secret" | "top-secret"

class_id ::= <domain> "/" <subtype>       // registered class or wildcard
           | <domain> "/*"                // domain wildcard
           | "*"                          // full wildcard (restricted use)
```

**Field semantics**:

- `required_integrity`: Inherited from the signed envelope mechanism (§4.2). Minimum integrity rank required to drive this sink.
- `conf_level`: The sink's declared confidentiality level. Results with `conf_floor > conf_level` MUST NOT be delivered to this sink.
- `content_class_allowlist`: If non-empty, the result's `effective` class MUST match at least one entry. Applied in addition to `conf_level`. Used for sinks that should only receive specific content types even if confidentiality levels match.
- `content_class_denylist`: The result's `effective` class (and all entries in `additional`) MUST NOT match any entry. Takes precedence over `content_class_allowlist`. Used to explicitly block content types that would otherwise pass confidentiality checks.
- `require_content_class`: If `true`, results with no content class assigned (absent `content_class` field) MUST be rejected. Useful for high-security sinks that should only process explicitly classified content.
- `max_additional_classes`: If set, results with more than this many entries in `additional` MUST be rejected. Useful for sinks that should only receive single-type results, as mixed results may indicate aggregation that warrants separate routing.

**Policy evaluation order** (MUST be applied in this sequence):

```
1. Biba check: effective_integrity >= required_integrity
2. BLP check: conf_floor(effective_class) <= conf_level
3. Denylist check: effective_class NOT IN content_class_denylist
                   AND all(c NOT IN content_class_denylist for c in additional)
4. Allowlist check (if content_class_allowlist non-empty):
                   effective_class IN content_class_allowlist
5. Require-class check (if require_content_class = true):
                   content_class field MUST be present
6. Max-additional check (if max_additional_classes set):
                   len(additional) <= max_additional_classes
```

Any step returning DENY terminates evaluation; the gateway MUST NOT proceed to subsequent steps.

**Example registry entry for a financial trade sink**:

```json
{
  "tool_id": "trade-execution-api",
  "sink_policy": {
    "required_integrity": 3,
    "conf_level": "secret",
    "content_class_allowlist": ["financial/trade-order"],
    "content_class_denylist": ["search-result/web", "search-result/internal",
                               "external-content/raw", "external-content/processed"],
    "require_content_class": true,
    "max_additional_classes": 0
  }
}
```

This policy requires: user-level integrity (rank 3), secret confidentiality level, only `financial/trade-order` content (no other types), no external content of any kind, a content class MUST be present, and no mixed-content results (max_additional_classes = 0). A web search result cannot drive a trade, regardless of integrity rank.

### 5.7. Registry Governance

The Content Class Registry is maintained as a versioned, append-only JSON document at `config/content-class-registry.json` in the gateway's configuration. Entries may be added; existing entries MUST NOT be modified or removed (deprecation is allowed via a `deprecated: true` field).

Registry updates MUST be signed by a gateway operator key and applied atomically. The gateway MUST reload the registry without dropping in-flight requests. On registry version mismatch between two federated gateways, the receiving gateway MUST use its own registry version for class validation and MUST log the mismatch for operator review.

New class proposals from gateway operators MUST go through a review process before being added. The review checks: uniqueness (does a suitable class already exist), scope clarity (is the class definition unambiguous), and floor appropriateness (is the confidentiality floor correctly calibrated).

---

### 5.8. Implementation Notes and Wiring Guide

This section provides non-normative guidance on wiring the content classification system into the mcp-security-platform gateway, specifically into the TrustLabeler and the invocation path that currently implements the taint-floor enforcement defined in §4.2.

#### 5.8.1. Where Classification Happens

Content classification occurs at the TrustLabeler component, after the tool result has been received from the upstream MCP server and before the result is forwarded to the consumer. The classification step is inserted into the existing signing pipeline immediately before JCS canonicalization:

```
[MCP Server Response]
    |
    v
[Gateway Proxy - existing invocation path]
    |
    v
[Trust Tier Lookup] ← §4.2: lookup server_id in registry → integrity_rank
    |
    v
[Content Class Lookup] ← §5: lookup server_id in registry → content_class
    |
    v
[Multi-Class Detection] ← §5: scan result content for additional classes
    |
    v
[Effective Class Computation] ← §5: compute union, strictest floor
    |
    v
[JCS Canonicalization] ← covers content_hash + label (incl. content_class)
    |
    v
[ES256 Sign] ← §4.2 + §5: sign covers content class
    |
    v
[Taint Floor Check] ← §4.2: write taint before forward
    |
    v
[BLP + Allowlist Check] ← §5: check before forward
    |
    v
[Forward to Consumer]
```

The critical ordering invariant is: **classification and signing MUST occur before the taint check and the BLP check**. The signed class label is the authoritative input to policy enforcement; it must be committed (signed) before it is used to make an enforcement decision.

#### 5.8.2. Registry Schema Extension

The gateway's tool registry (currently storing `trust_tier` and `required_integrity` per tool server) is extended to include content class information:

```json
{
  "server_id": "brave-search-mcp",
  "trust_tier": "trustedPublic",
  "integrity_rank": 1,
  "default_content_class": "search-result/web",
  "content_class_detection": {
    "enabled": false,
    "patterns": []
  },
  "sink_policies": {
    "note-taking-tool": {
      "required_integrity": 1,
      "conf_level": "internal",
      "content_class_denylist": [],
      "content_class_allowlist": [],
      "require_content_class": false,
      "max_additional_classes": null
    }
  }
}
```

When `content_class_detection.enabled` is `false`, the gateway uses `default_content_class` for all results from this server and sets `additional = []`. When `enabled` is `true`, the gateway applies the configured `patterns` (regex or JSONPath expressions) to the result content to detect additional classes.

For the initial implementation of this extension proposal, per-pattern detection MAY be deferred and all servers MAY be configured with `enabled: false` and explicit `default_content_class` entries. This provides the full policy-enforcement benefit of content classification without requiring content scanning, at the cost of less precise multi-class detection. Implementors SHOULD enable detection for servers known to return mixed-class content (e.g., a CRM API that may return both contact data and financial summaries).

#### 5.8.3. Backward Compatibility with v0.1 Consumers

Consumers implementing only the signed envelope mechanism (§4.2) that do not understand the `content_class` field in the envelope will simply ignore it. The gateway MUST NOT break these consumers when it begins attaching `content_class` fields. The `schema_version` bump from `v0.1` to `v0.2` (Section 8.1) signals to conformant consumers that extended fields are present.

During a transition period, gateway operators MAY emit both `v0.1` and `v0.2` envelope keys simultaneously under their respective `_meta` keys. Consumers implementing the signing mechanism in §4.2 use the `v0.1` key; consumers implementing this document prefer the `v0.2` key. The signed content MUST be identical in both - the gateway signs the same canonical content hash and integrity label in both versions, with the `v0.2` version additionally covering `content_class` and `federation` fields.

#### 5.8.4. Performance Considerations

Content classification adds two operations to the hot path:

1. **Registry lookup**: A read against the in-memory tool registry for `default_content_class`. This is O(1) against a hash map and adds negligible latency (sub-microsecond).

2. **Pattern-based detection** (when enabled): Regex or JSONPath scanning of the tool result content. Implementations MUST use a linear-time regex engine (RE2, Hyperscan, or Rust's `regex` crate). PCRE and other backtracking engines MUST NOT be used against tool result content - attacker-controlled payloads can trigger catastrophic backtracking (reference: Cloudflare global outage, July 2019, caused by one backtracking WAF rule deployed to production).

   For results exceeding the implementation's scan limit or triggering a scan timeout, implementations MUST NOT silently truncate. Scanning the first N bytes and passing the remainder uninspected is the standard WAF bypass technique against inspection-bounded scanners and directly defeats the content classification guarantee. Instead, any result that cannot be fully scanned MUST be treated as fully untrusted: `integrity_rank = 0` (untrustedPublic), `conf_floor = secret`, `allowlist_required = true`. The result still flows if the receiving sink's policy permits untrusted content at secret classification - it is not dropped - but it cannot reach a tighter sink without explicit operator allowlisting. The audit log entry MUST include `scan_limit_exceeded` or `scan_timeout` as the `deny_reason` so the event is observable. A per-invocation scan timeout of 500 ms is RECOMMENDED.

The BLP + allowlist check (policy evaluation) is a constant-time operation against the pre-loaded sink policy object and adds negligible latency.

The signing input is extended by the `content_class` sub-object (approximately 300-500 bytes of additional JSON). JCS canonicalization and ES256 signing time are dominated by the content hash size, not the label size. The additional fields are expected to add < 0.1 ms to signing latency on a modern CPU.

#### 5.8.5. Audit Log Extensions

The existing `TOOL_INVOCATION` audit event (defined in the gateway implementation per §4.2) is extended with content class fields. The schema below is the normative IR-ready format - every field marked REQUIRED MUST be present; RECOMMENDED fields SHOULD be present in production deployments.

```json
{
  "event_type": "TOOL_INVOCATION",
  "timestamp": "2026-06-26T10:00:00.000Z",

  "request": {
    "request_id": "<uuid>",
    "conversation_id": "<mcp-conversation-uuid>",
    "parent_request_id": "<uuid-or-null>",
    "correlation_id": "<trace-id-from-upstream-header>"
  },

  "actor": {
    "user_id": "<identity-provider-subject>",
    "username": "<human-readable-name>",
    "auth_method": "oauth2|mtls|apikey|session",
    "token_id": "<jwt-jti-or-apikey-id>",
    "oauth_client_id": "<client-id-or-null>",
    "scopes": ["mcp:invoke"],
    "session_id": "<gateway-session-uuid>"
  },

  "network": {
    "source_ip": "203.0.113.42",
    "user_agent": "MyMCPClient/1.0",
    "gateway_id": "gw-prod-sg-01"
  },

  "tool_name": "brave-search",
  "server_id": "brave-search-mcp",
  "outcome": "deny",
  "deny_reasons": ["blp_floor"],
  "duration_ms": 4,

  "integrity_rank": 1,
  "content_class": {
    "effective": "search-result/web",
    "conf_floor": "public",
    "additional": [],
    "assigned_by": "labeler.gateway.example.org"
  },

  "sink": {
    "tool_name": "note-taking-tool",
    "required_integrity": 1,
    "conf_level": "internal",
    "deny_at_step": "blp_check"
  },

  "envelope": {
    "result_id": "<uuid>",
    "signed_at": "2026-06-26T10:00:00Z",
    "labeler_id": "labeler.gateway.example.org",
    "sub_ca_fp": "sha256:abc123..."
  }
}
```

**IR-readiness notes:**

- `request.request_id` + `request.conversation_id`: join all events in a single MCP conversation. Use `conversation_id` to reconstruct the full agent session; use `request_id` to find the exact invocation.
- `request.parent_request_id`: non-null in multi-agent chains - traces which upstream call triggered this one.
- `request.correlation_id`: propagated from the client's `X-Correlation-ID` or W3C `traceparent` header. Allows joining gateway logs with upstream application logs across systems.
- `actor.session_id`: the gateway's own session identifier. A single `user_id` may have multiple parallel sessions; `session_id` scopes the blast radius.
- `actor.token_id`: the JWT `jti` claim or API key identifier - allows token revocation to be correlated with events generated while the token was active.
- `duration_ms`: required for distinguishing ReDoS / scan-timeout events from normal denials in SIEM triage.
- `envelope.sub_ca_fp`: allows instant correlation with Trust List entries and revocation events without re-fetching the envelope.

Fields REQUIRED in all deployments: `event_type`, `timestamp`, `request.request_id`, `actor.user_id`, `actor.session_id`, `network.source_ip`, `tool_name`, `server_id`, `outcome`, `duration_ms`.

Fields REQUIRED when `outcome = deny`: `deny_reasons`, `sink.deny_at_step`.

Fields REQUIRED when a signed envelope is present: `envelope.result_id`, `envelope.signed_at`, `envelope.labeler_id`, `envelope.sub_ca_fp`.

The `deny_reasons` field is extended with the following values specific to this extension proposal:

| deny_reason | Meaning |
|-------------|---------|
| `blp_floor` | Content's conf_floor exceeds sink's conf_level |
| `content_class_denylist` | Effective class matched sink's denylist |
| `content_class_allowlist` | Allowlist required and effective class not in allowlist |
| `content_class_missing` | Sink has require_content_class=true and result has no class |
| `content_class_count` | Result has more additional classes than sink's max_additional_classes |
| `trust_scope_violation` | Labeler asserted label outside its registered trust scope |
| `trust_list_sequence_rollback` | Trust List sequence number <= last accepted |
| `inclusion_proof_failed` | Transparency log inclusion proof verification failed |
| `scan_limit_exceeded` | Result exceeded the implementation's content scan size limit; treated as untrustedPublic/secret |
| `scan_timeout` | Pattern-based detection did not complete within the timeout budget; treated as untrustedPublic/secret |

Wazuh rule recommendations (extending the baseline audit rules defined with the gateway implementation):

- Rule 100002 (level 10): `TOOL_INVOCATION` + `outcome=deny` + `deny_reasons=blp_floor`. Indicates a data-flow policy violation - content attempted to reach a sink above its classification level.
- Rule 100003 (level 12): `TOOL_INVOCATION` + `deny_reasons=trust_scope_violation`. Indicates a labeler is asserting outside its registered scope - possible labeler misconfiguration or compromise.
- Rule 100004 (level 14): `TOOL_INVOCATION` + `deny_reasons=inclusion_proof_failed`. Indicates a sub-CA without a valid transparency log entry - possible unauthorized sub-CA registration.
- Rule 100005 (level 14): `TOOL_INVOCATION` + `deny_reasons=trust_list_sequence_rollback`. Indicates an active Trust List rollback attack attempt.

#### 5.8.6. Error Conditions and Failure Behavior

This subsection specifies required behavior for error and failure cases in the classification and enforcement pipeline. All denial decisions MUST be logged with the applicable `deny_reason` codes from §5.8.5.

**Envelope verification failure (signature invalid, hash mismatch, expired):**
The gateway verifier MUST treat a result with a malformed or unverifiable envelope as having `integrity_rank = 0` (untrustedPublic). If the sink's `required_integrity > 0`, the result MUST be denied. The verifier MUST NOT surface the unverified content to the consumer under any fallback path other than explicit advisory mode (see §8.2). Retry is not appropriate; the failure indicates tampering or misconfiguration.

**Unknown content class (class string not in registry):**
If the content class label in a received envelope is not recognized by the verifying consumer, the consumer MUST treat it as the most restrictive registered class (`conf_floor = secret`, `allowlist_required = true`) unless the operator has explicitly configured a default for unrecognized classes. Implementations SHOULD log unrecognized class strings at warning severity.

**Trust List fetch failure:**
If the gateway cannot fetch an updated Trust List (network failure, timeout, unreachable log server), it MUST continue operating with the last successfully fetched Trust List for a configurable grace period (RECOMMENDED maximum: 24 hours). If the grace period expires without a successful refresh, the gateway MUST either: (a) fail closed - deny all cross-gateway envelopes until the Trust List is refreshed - or (b) alert the operator and continue in advisory mode for cross-gateway traffic only. Operators MUST configure one of these behaviors explicitly; there is no silent default.

**Transparency log inclusion proof failure:**
If inclusion proof verification fails for a sub-CA entry (§6.4), the gateway MUST deny the envelope and log the event at severity level 14 (Wazuh Rule 100004: `TOOL_INVOCATION` + `deny_reasons=inclusion_proof_failed` - defined in §5.8.5). The gateway MUST NOT silently accept an envelope whose sub-CA lacks a valid inclusion proof.

**Classification pipeline internal error:**
If the classification step (content class lookup, multi-class detection, or effective class computation) encounters an internal error, the gateway MUST deny the result rather than forwarding it unclassified. A fail-open stance - forwarding content without a class label when classification fails - defeats the purpose of the policy enforcement pipeline.

**Timeout behavior:**
Signature verification and Trust List refresh operations SHOULD complete within 500ms. Implementations that exceed this threshold for signature verification SHOULD surface a health metric; operations that exceed 2000ms SHOULD be treated as failures with the behavior described for their respective error case above. These thresholds are non-normative defaults; operators MAY configure tighter bounds.

---

## 6. Federated Trust Architecture

### 6.1. Overview

The signed envelope mechanism (§4.2) operates with a single trust anchor: the mcp-security-platform sub-CA whose SPKI fingerprint is pinned in each gateway's verifier configuration. This model is correct for single-organization deployments. It fails for multi-organization scenarios because it provides no mechanism for Org A's gateway to validate an envelope signed by Org B's labeler.

The federated trust architecture introduces three components that together solve this:

1. **Trust List**: A signed JSON document enumerating authorized labeler sub-CA SPKI fingerprints across all participating organizations. Each gateway operator trusts envelopes signed by any sub-CA on the Trust List within that sub-CA's declared trust scope.

2. **Transparency Log**: An append-only, Merkle-tree-backed log of Trust List updates and sub-CA registrations. Provides external auditability - any party can verify that a sub-CA was properly registered and that the Trust List was not silently modified.

3. **Cross-Gateway Forwarding**: A defined protocol for how a gateway forwards an already-labeled result to its own downstream consumers, preserving the original envelope's verifiability while optionally adding its own outer attestation.

The following diagram contrasts the single-gateway (§4.2) architecture with the federated (§6) architecture:

```
SINGLE-GATEWAY (§4.2)                      FEDERATED (§6)
=====================                     ====================

  Tool Server A                              Tool Server A
       |                                          |
       v                                          v
  [Gateway / Proxy]                         [Gateway A / Org A]
       |                                    (sub-CA: FP-A)
  TrustLabeler                                    |
  (sub-CA: pinned locally)               TrustLabeler-A
       |                                          |
  Signed Envelope (§4.2)                  Signed Envelope
  (verified vs local sub-CA)             (sig by Leaf-A, cert by FP-A)
       |                                          |
       v                                          v
  Consumer                                  [Gateway B / Org B]
  (verifies vs pinned sub-CA)           (validates FP-A vs Trust List)
                                         [Cross-Gateway Forward]
                                                  |
                                      Re-sign (dual-sig) or Relay
                                                  |
                                                  v
                                          Consumer / Org B
                                     (verifies Trust List + incl. proof)

                                              Trust List
                                         [FP-A, FP-B, FP-C, ...]
                                         (signed by Governance Root)
                                                  |
                                         Transparency Log
                                         (Merkle tree, Rekor-style)
                                         (inclusion proofs for FPs)
```

### 6.2. Trust List Format

The Trust List is a signed JSON document with the following top-level structure:

```json
{
  "schema_version": "0.1",
  "list_id": "mcp-trust-list-prod",
  "sequence": 47,
  "issued_at": "2026-06-26T00:00:00Z",
  "expires_at": "2026-07-26T00:00:00Z",
  "governance_root_key_id": "gov-root-2026-v1",
  "entries": [ ... ],
  "revoked_entries": [ ... ],
  "signature": {
    "alg": "ES384",
    "kid": "gov-root-2026-v1",
    "sig": "<base64url JWS detached signature over canonical JSON of all other fields>"
  }
}
```

**Top-level fields**:

- `schema_version` (REQUIRED): Must be "0.1" for this version of the spec.
- `list_id` (REQUIRED): A stable identifier for this trust list instance. Different deployments (prod, staging) MUST use different `list_id` values.
- `sequence` (REQUIRED): A monotonically increasing integer. Verifiers MUST reject a Trust List with a sequence number lower than or equal to the last accepted sequence number. This prevents rollback attacks.
- `issued_at` (REQUIRED): ISO 8601 UTC timestamp of issuance.
- `expires_at` (REQUIRED): ISO 8601 UTC timestamp of expiry. Verifiers MUST reject Trust Lists past their expiry.
- `governance_root_key_id` (REQUIRED): Identifies which governance root key was used to sign this list. Verifiers MUST verify the signature against the corresponding root public key from their pre-configured governance key set.
- `entries` (REQUIRED): Array of trust entries (see below).
- `revoked_entries` (OPTIONAL): Array of revoked entry identifiers with revocation timestamps and reasons.
- `signature` (REQUIRED): JWS detached signature over the canonical JSON (JCS/RFC 8785) of all other top-level fields, using the governance root key.

**Trust entry structure**:

```json
{
  "entry_id": "org-a-gateway-prod-2026",
  "org_id": "org-a",
  "gateway_id": "gateway-prod",
  "sub_ca_spki_fp": "sha256:abc123...",
  "sub_ca_cert_pem": "<optional embedded cert>",
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_until": "2027-01-01T00:00:00Z",
  "trust_scope": {
    "tool_server_ids": ["server-a", "server-b"],
    "tool_server_id_pattern": null,
    "max_integrity_rank": 2,
    "content_classes": ["search-result/internal", "user-data/*", "code/*"],
    "content_classes_excluded": ["system-credential", "pii/biometric"]
  },
  "transparency_log": {
    "log_id": "rekor.sigstore.dev",
    "log_entry_id": "24296fb24b8ad77a...",
    "inclusion_proof_required": true
  },
  "added_at": "2026-01-01T00:00:00Z",
  "added_by_sequence": 1
}
```

**Entry fields**:

- `entry_id` (REQUIRED): Stable unique identifier for this entry. Used in `revoked_entries`.
- `org_id` (REQUIRED): Organization identifier. MUST be globally unique within the trust list's scope.
- `gateway_id` (REQUIRED): Gateway identifier within the organization. Concatenation `org_id:gateway_id` MUST be unique in the list.
- `sub_ca_spki_fp` (REQUIRED): SHA-256 fingerprint of the sub-CA's Subject Public Key Info, hex-encoded with `sha256:` prefix. This is what verifiers pin.
- `sub_ca_cert_pem` (OPTIONAL): The sub-CA certificate in PEM encoding, included for convenience. If present, verifiers MUST verify that its SPKI matches `sub_ca_spki_fp`.
- `valid_from` / `valid_until` (REQUIRED): The period during which envelopes signed by leaf certs under this sub-CA are valid. Verifiers MUST check `envelope.signed_at` falls within this range.
- `trust_scope` (REQUIRED): Bounds on what this sub-CA's labeler may assert. See Section 6.3.
- `transparency_log` (REQUIRED): Identifies the transparency log entry where this sub-CA registration was logged. `inclusion_proof_required` governs whether verifiers MUST verify the inclusion proof before trusting this entry.
- `added_at` / `added_by_sequence` (REQUIRED): When and at which Trust List sequence number this entry was added.

### 6.3. Trust Scope

Trust scope is the set of constraints bounding what a labeler sub-CA is authorized to assert. A label MUST be rejected if it violates the trust scope of the sub-CA that signed it, even if the sub-CA is otherwise on the Trust List.

**Trust scope fields**:

- `tool_server_ids` (OPTIONAL): Explicit list of tool server IDs this labeler may vouch for. If present, any envelope with a `server_id` not in this list MUST be rejected.
- `tool_server_id_pattern` (OPTIONAL): A glob pattern (e.g., `org-a-*`) matching allowed `server_id` values. Used when the exact set of server IDs is not known in advance. If both `tool_server_ids` and `tool_server_id_pattern` are present, the envelope's `server_id` MUST match at least one.
- `max_integrity_rank` (REQUIRED): The maximum `integrity_rank` value this labeler may assign. A labeler registered for external web-search tools MUST NOT assert `system` (rank 4) or `user` (rank 3) for those results. If the envelope's `integrity_rank > max_integrity_rank`, the envelope MUST be rejected.
- `content_classes` (OPTIONAL): If present, a list of content class identifiers (including wildcards) that this labeler is authorized to assign. Any envelope asserting a class not matched by this list MUST be rejected.
- `content_classes_excluded` (OPTIONAL): Content classes this labeler is explicitly prohibited from asserting, regardless of what `content_classes` permits. Takes precedence.

**Trust scope enforcement** is performed by the receiving gateway or consumer after Trust List lookup:

```
1. Look up entry by sub_ca_spki_fp from envelope's cert chain
2. Check entry.valid_from <= envelope.signed_at <= entry.valid_until
3. If trust_scope.tool_server_ids present:
   REQUIRE envelope.server_id IN trust_scope.tool_server_ids
4. If trust_scope.tool_server_id_pattern present:
   REQUIRE envelope.server_id matches pattern
5. REQUIRE envelope.integrity_rank <= trust_scope.max_integrity_rank
6. If trust_scope.content_classes present:
   REQUIRE envelope.content_class.effective matches at least one entry
7. REQUIRE envelope.content_class.effective NOT IN trust_scope.content_classes_excluded
```

Any step failing causes the envelope to be rejected and MUST be logged as a trust scope violation event.

### 6.4. Transparency Log

The transparency log provides external auditability for the trust list. It is an append-only, Merkle-tree-backed log modeled after RFC 6962 (Certificate Transparency) and Sigstore Rekor.

**Logged objects**: The following events MUST be submitted to the transparency log:

1. **Sub-CA registration**: When a new sub-CA is added to the Trust List, a log entry MUST be created containing the sub-CA's SPKI fingerprint, the `entry_id`, `org_id`, and `gateway_id`, the governance root signature over the new Trust List version, and the `added_at` timestamp.

2. **Trust List update**: Each new Trust List version (sequence number) MUST produce a log entry containing the new sequence number, the `list_id`, the hash of the full Trust List JSON, and the governance root key ID that signed it.

3. **Sub-CA revocation** (SHOULD): When a sub-CA is revoked, a log entry SHOULD be created containing the `entry_id`, revocation timestamp, and reason.

**Log entry structure** (Rekor-compatible):

```json
{
  "kind": "mcp-trust-list-entry",
  "apiVersion": "0.0.1",
  "spec": {
    "event_type": "sub_ca_registration",
    "entry_id": "org-a-gateway-prod-2026",
    "sub_ca_spki_fp": "sha256:abc123...",
    "org_id": "org-a",
    "gateway_id": "gateway-prod",
    "trust_list_sequence": 1,
    "trust_list_hash": "sha256:def456...",
    "governance_sig": "<base64url>",
    "timestamp": "2026-01-01T00:00:00Z"
  }
}
```

**Inclusion proof verification**: Before trusting an envelope signed by a sub-CA where the Trust List entry has `inclusion_proof_required: true`, the verifier MUST:

1. Retrieve the inclusion proof for the sub-CA's log entry from the configured transparency log.
2. Verify the Merkle audit path from the log entry's leaf hash to the current signed tree head.
3. Verify the signed tree head's signature against the transparency log's public key.

If inclusion proof verification fails, the envelope MUST be rejected. The verifier SHOULD cache verified inclusion proofs to avoid per-envelope log lookups.

The following sequence diagram shows the cross-org envelope validation flow including transparency log verification:

```
Consumer/Org B          Gateway B           Trust List          Transparency Log
      |                     |                    |                     |
      | recv envelope        |                    |                    |
      | (signed by Org A     |                    |                    |
      |  sub-CA FP-A)        |                    |                    |
      |-------------------->|                    |                    |
      |                     | fetch Trust List   |                    |
      |                     |------------------>|                    |
      |                     | <return list       |                    |
      |                     | (seq N, sig valid) |                    |
      |                     |                    |                    |
      |                     | lookup entry FP-A  |                    |
      |                     | in list entries    |                    |
      |                     |                    |                    |
      |                     | check trust scope  |                    |
      |                     | (rank, classes,    |                    |
      |                     |  server_id)        |                    |
      |                     |                    |                    |
      |                     | if incl_proof req: |                    |
      |                     | get incl proof     |                    |
      |                     |---------------------------------------->|
      |                     | <return proof      |                    |
      |                     | (Merkle path +     |                    |
      |                     |  signed tree head) |                    |
      |                     |                    |                    |
      |                     | verify Merkle path |                    |
      |                     | verify tree head   |                    |
      |                     | sig                |                    |
      |                     |                    |                    |
      |                     | verify envelope    |                    |
      |                     | sig vs FP-A cert   |                    |
      |                     | (SPKI pin, EKU,    |                    |
      |                     |  freshness, hash)  |                    |
      |                     |                    |                    |
      |  ALLOW / DENY        |                    |                    |
      |<--------------------|                    |                    |
```

**Monitoring requirement**: Each gateway operator MUST run a log monitor that polls the transparency log for new entries. If a new sub-CA SPKI fingerprint appears in the log attributed to the operator's `org_id` or `gateway_id` that was not authorized through the operator's own key management process, the operator MUST treat this as a critical security incident (potential sub-CA compromise or unauthorized Trust List update).

### 6.5. Cross-Gateway Envelope Forwarding

When Gateway A receives a result labeled by Gateway B (e.g., because Gateway A is a consumer aggregating results from multiple upstream gateways), Gateway A MUST handle the forwarded envelope in one of two defined modes.

**Mode 1: Relay (Unchanged Forwarding)**

Gateway A validates the original envelope against the Trust List (per Section 6.4) and forwards it to its downstream consumer without modification. The downstream consumer performs its own Trust List validation.

Requirements for Relay mode:
- Gateway A MUST validate the envelope (Trust List lookup, trust scope, inclusion proof) before relaying. Gateway A MUST NOT relay an envelope it cannot validate.
- Gateway A MUST log the relay event, including its own validation result, in its audit log.
- Gateway A MUST add a `relay_chain` entry to the envelope's `_meta` field (outside the signed portion) listing its identity and validation timestamp. This field is informational and unsigned.
- The downstream consumer MUST perform its own independent validation. It MUST NOT skip validation because Gateway A relayed the envelope.

**Mode 2: Re-Sign (Dual-Signature Chain)**

Gateway A signs a new outer envelope over the original Gateway B envelope, producing a dual-signature chain. The original envelope is preserved as `forwarded_envelope` inside the new outer envelope.

```json
{
  "io.mcp-security-platform/trust-envelope/v0.2": {
    "label": {
      "integrity_rank": 1,
      "content_class": { ... },
      "origin_gateway": "gateway-a.org-a.example",
      "forwarded_from": "gateway-b.org-b.example"
    },
    "binding": {
      "result_id": "...",
      "tool_name": "...",
      "server_id": "...",
      "content_hash": "...",
      "signed_at": "2026-06-26T10:05:00Z",
      "nonce": "..."
    },
    "sig": "<Gateway A JWS>",
    "forwarded_envelope": {
      "label": { ... },
      "binding": { ... },
      "sig": "<original Gateway B JWS>"
    }
  }
}
```

Requirements for Re-Sign mode:
- Gateway A MUST validate the original Gateway B envelope before re-signing. Gateway A MUST NOT re-sign an invalid envelope.
- The outer label's `integrity_rank` MUST be `min(outer_rank, inner_rank)` - Gateway A cannot promote the integrity rank above what Gateway B asserted. (This preserves the Biba integrity model defined in §4.2.)
- The outer label's content class `effective` MUST be the stricter of Gateway A's own classification and Gateway B's asserted class. Gateway A MUST NOT assert a less restrictive content class than Gateway B.
- The `forwarded_envelope` field MUST contain the complete original Gateway B envelope exactly as received, without modification.
- The outer signature covers the canonical JSON of `label`, `binding`, and the hash of `forwarded_envelope` (not its content inline, to avoid double-counting in size-constrained contexts).

**Mode selection**: Gateway operators SHOULD use Re-Sign mode when the downstream consumer may not have direct access to the Trust List or transparency log (e.g., air-gapped environments, resource-constrained consumers). Relay mode is appropriate when the downstream consumer is a full gateway participant capable of independent validation.

### 6.6. Governance Model

The Trust List is a security-critical document. Its governance MUST enforce separation of duties and resist single-point-of-compromise attacks.

This governance model is structurally identical to the threshold signing used in The Update Framework (TUF) [TUF] for software update root metadata, and follows the same principles as the DNSSEC root KSK ceremony (ICANN uses 7-of-14 key holders across two geographic regions) and CA/Browser Forum root CA key ceremonies. The formal threat analysis in TUF applies directly to this Trust List governance model.

**M-of-N governance**: Trust List updates MUST be signed by at least M of N designated governance key holders, where M and N are deployment-defined (recommended: M=2, N=3 for small federations; M=3, N=5 for large federations). A Trust List signed by fewer than M governance keys MUST be rejected.

Implementation: the Trust List's `signature` field contains a multi-signature structure rather than a single signature. Each key holder signs the canonical Trust List JSON independently; the `signature` field is an array of `{kid, sig}` objects. Verifiers check that at least M valid signatures from distinct registered governance keys are present.

**Key holder separation (REQUIRED)**: The M signing keys that satisfy a threshold MUST belong to key holders who are organizationally and temporally independent - they MUST NOT share a common credential store, HSM, or administrative domain. The intent is that compromising a single system, person, or credential store cannot yield M valid signatures. Governance key holders SHOULD be enrolled at different times (staggered enrollment) so that a single supply-chain event cannot compromise all keys simultaneously. This requirement is derived from TUF's defense against a single compromise event covering multiple threshold keys.

**Governance key rotation**: Governance keys MUST be rotated on a schedule no longer than 1 year. Rotation requires M-of-N approval from the outgoing key set to sign a key-rotation event in the transparency log. The new governance public key MUST be logged before taking effect. Verifiers receive new governance public keys via an out-of-band, signed key distribution mechanism (e.g., embedded in a software update or configuration management system).

**New entry approval process**: Adding a new sub-CA to the Trust List requires:
1. Applicant submits a sub-CA registration request containing the SPKI fingerprint, organization identity proofs, and intended trust scope.
2. At least two governance key holders independently verify the request.
3. M-of-N governance keys sign the new Trust List version.
4. The new Trust List version is published.
5. A transparency log entry is created for the new sub-CA.
6. A monitoring window of 7 days during which any operator may raise an objection before the entry becomes operationally active.

### 6.7. Revocation

Three revocation scenarios are addressed.

**Sub-CA revocation**: If a labeler sub-CA is compromised, the governance committee creates a new Trust List version (with incremented sequence number) that moves the entry to `revoked_entries` with a `revocation_timestamp` and `reason`. Verifiers that refresh the Trust List within the configured TTL will reject envelopes signed by the revoked sub-CA after the revocation timestamp. Verifiers MUST refresh the Trust List at least every 24 hours and MUST NOT cache Trust Lists past their `expires_at`.

For envelopes with `signed_at < revocation_timestamp`, the revocation does not retroactively invalidate them, but deployers SHOULD treat them with increased suspicion and MAY choose to re-audit any actions taken based on them.

**Governance key revocation**: If a governance key is compromised, the remaining M-1 governance key holders MUST immediately trigger an emergency key rotation. If fewer than M-1 valid governance keys remain (catastrophic scenario), the trust federation MUST be considered compromised. All participants MUST suspend acceptance of the affected Trust List and obtain a fresh Trust List via an out-of-band channel with manual verification.

**Leaf certificate revocation**: Labeler leaf certificates are short-lived (15-minute TTL per the certificate profile in §4.2), so revocation at the leaf level is handled by key expiry in most cases. If a leaf key is compromised and must be revoked before its TTL, the sub-CA operator MUST disable the leaf provisioner and rotate to a new leaf key. The `MAX_ENVELOPE_AGE` bound (600 seconds, per §4.2) limits the blast radius of a compromised leaf to envelopes signed within a 10-minute window.

---

## 7. Universal AI Provenance

### 7.1. Scope

#### Why §4.2 Is Not Enough

The signed trust envelope (§4.2) solves provenance for content on the MCP wire: it lives in `CallToolResult._meta` and is verified by the consuming gateway while the MCP message is in flight. Once that message is processed and an agent acts on it - writing a file, committing code, generating a report, sending an email - the MCP structure is gone. There is no `_meta` to carry provenance forward. The artifact exists independently of any MCP session, and the only record of its origin is whatever the agent chooses to assert.

This creates a gap: a downstream consumer of the artifact (a code reviewer, a compliance system, a human) cannot tell whether it was produced by a trusted model from verified inputs or fabricated entirely. The signed envelope on the tool result that fed into the artifact is not visible at artifact level.

The Artifact Provenance Envelope (APE) closes this gap. It uses the same signing infrastructure (§4.2 sub-CA + labeler EKU + ES256/JCS) but binds a signature to the artifact itself rather than to an MCP message - so provenance travels with the artifact wherever it goes.

#### Who Signs and When

APE signing is the responsibility of the **agent orchestration layer** - not the inference API, not the MCP gateway, not a post-hoc signing service. The agent orchestration layer is the only component that simultaneously has access to:

- The model identity that produced the output (`model_id`)
- The tool results that contributed to it (each already carrying a §4.2 signed envelope - their `result_id` values are recorded in the APE's `pipeline_path`)
- The full generation context (session ID, conversation ID, prompts)
- The final artifact content (needed to compute `artifact_hash`)

**Signing MUST occur at the moment the artifact is finalized, before it is written to any persistent store or transmitted outside the agent session.** Signing after storage (e.g., signing a file that has already been committed) is insufficient - the content could have been modified between generation and signing.

**Concrete signing points by agent type:**

| Agent type | When to sign | What triggers it |
|---|---|---|
| **Claude Code / coding agent** | Before writing a generated file to disk or committing to a repository | The `write_file` or `git commit` tool call - sign before the MCP tool invocation that persists the artifact |
| **Document-composing agent** | Before the final document is returned to the user or stored | At the end of the composition pipeline, after all inputs have been assembled |
| **Multi-agent pipeline** | Each agent signs its intermediate output; the orchestrator signs the final report | Per-agent output signing + final aggregation signing |
| **LLM inference wrapper** | After each model completion, before the response is returned to the caller | Post-inference hook in the agent harness |

For **Claude Code specifically**: the agent harness SHOULD implement a signing hook that fires on any tool call whose effect is to persist an AI-generated artifact (filesystem writes, git operations, API POSTs). The hook receives the artifact content, constructs the APE, signs it using the gateway's labeler key infrastructure, and attaches the APE as a sidecar (e.g., `generated_file.py.ape.json`) or embeds it in the file's metadata where the format supports it.

**What if the agent cannot sign?** If the agent harness does not implement APE signing, the MCP gateway SHOULD implement a best-effort APE at the boundary where the artifact leaves the MCP session - this is weaker (the gateway did not observe generation context) but captures at minimum the artifact hash, the session identity, and the time of transit. This is explicitly a fallback; the gateway-signed APE SHOULD be marked `signing_context: "gateway_boundary"` to distinguish it from an agent-signed APE.

#### Artifact Types In Scope

- **LLM responses**: Raw text or structured output produced by a language model in response to a prompt.
- **Agent documents**: Structured documents (Markdown, JSON, PDF-equivalent) composed by an agent from one or more inputs.
- **AI-generated code**: Source code, patches, or scripts produced by model inference.
- **Pipeline reports**: Artifacts produced by a multi-agent pipeline where multiple agents each contribute processing steps.
- **Model output**: Generic model output not fitting the above categories (e.g., classification labels, embeddings, structured predictions).

The following are explicitly out of scope (existing provenance standards apply):

- Camera-captured images with C2PA hardware attestation.
- Human-authored documents (provenance for human content is a separate concern).
- Binary model weights (model provenance is the responsibility of the model registry, not the inference layer).

### 7.2. Artifact Provenance Envelope (APE)

The Artifact Provenance Envelope is a JSON structure that carries signed provenance for an AI-generated artifact. It is designed to be carried out-of-band (as a sidecar file) or inline (as metadata in a structured artifact format). It is NOT embedded in `_meta` since it applies to artifacts that have no MCP structure - `_meta` only exists on MCP wire messages, which the artifact has already left.

The APE MUST be signed using the same ES256 labeler key infrastructure as Layer A (§4.2), using the same sub-CA + labeler EKU, subject to the same Trust List requirements.

**APE top-level structure**:

```json
{
  "schema": "io.mcp-security-platform/artifact-provenance/v0.1",
  "artifact_id": "<uuid>",
  "artifact_type": "llm-response",
  "artifact_hash": {
    "alg": "sha256",
    "value": "<hex hash of artifact bytes>"
  },
  "content_class": {
    "primary": "ai-output/llm-response",
    "additional": [],
    "effective": "ai-output/llm-response",
    "conf_floor": "public",
    "allowlist_required": false,
    "assigned_by": "gateway.example.org",
    "assigned_at": "2026-06-26T10:00:00Z"
  },
  "integrity_rank": 0,
  "model_provenance": {
    "model_id": "claude-sonnet-4-6",
    "model_version": "20251001",
    "model_commitment_hash": "<hash>",
    "generation_params_hash": "<hash>",
    "inference_endpoint": "https://api.anthropic.com/v1/messages"
  },
  "pipeline_path": [],
  "signing_context": "agent",
  "labeler_id": "labeler.gateway.example.org",
  "signed_at": "2026-06-26T10:00:00Z",
  "nonce": "<random 128-bit base64url>",
  "c2pa": {
    "assertion_type": "io.mcp-security-platform.ai-provenance",
    "assertion_oid": "1.3.6.1.4.1.<PEN>.mcp.c2pa.ai-provenance",
    "claim_generator": "mcp-security-platform/0.1"
  },
  "sig": "<JWS ES256 detached signature>"
}
```

**Signing input**: The JWS signing input is the JCS canonical JSON of all fields except `sig`. The same canonicalization rules as the signing mechanism in §4.2 apply.

**Key fields**:

- `artifact_id`: Globally unique identifier (UUID v4) for this artifact instance. Enables correlation between the artifact and its provenance record.
- `artifact_type`: One of the defined artifact types (Section 7.3).
- `artifact_hash`: SHA-256 hash of the artifact's canonical bytes. For text artifacts: UTF-8 bytes. For structured artifacts: JCS canonical JSON bytes. For binary artifacts: raw bytes. This binds the envelope to the exact artifact content.
- `integrity_rank`: The Biba integrity rank of this artifact, computed from the minimum rank across all inputs to the artifact (see Section 7.6).
- `model_provenance`: Fields describing the model that produced the artifact. See Section 7.2.1.
- `pipeline_path`: Ordered array of pipeline steps that produced this artifact. See Section 7.5.
- `c2pa`: C2PA embedding metadata. See Section 7.4.

#### 7.2.1. Model Provenance Sub-Object

```json
{
  "model_id": "claude-sonnet-4-6",
  "model_version": "20251001",
  "model_commitment_hash": "sha256:<hash of model_id||model_version||model_api_endpoint>",
  "generation_params_hash": "sha256:<hash of canonical generation params JSON>",
  "inference_endpoint": "https://api.anthropic.com/v1/messages"
}
```

- `model_id` (REQUIRED): The model identifier string as returned by the inference API.
- `model_version` (REQUIRED): The model version or snapshot identifier. For APIs that do not expose version strings, use the date-of-call as a proxy.
- `model_commitment_hash` (REQUIRED): SHA-256 of the concatenation `model_id || ":" || model_version || ":" || inference_endpoint`. This is a commitment to the model identity tuple, not a hash of the model weights (which the labeler cannot access). It prevents model-ID string substitution attacks (see Section 9.4).
- `generation_params_hash` (REQUIRED): SHA-256 of the JCS canonical JSON of the generation parameters object, which MUST include at minimum: `system_prompt_hash`, `temperature`, `top_p`, `max_tokens`, `model_id`, `model_version`. The system prompt itself is hashed (not included) to avoid leaking confidential prompts while still committing to them.
- `inference_endpoint` (OPTIONAL): The API endpoint used for inference. Included for auditability; allows verification that the model was called through an authorized endpoint.

#### 7.2.2. Generation Parameters Object

The generation parameters object (hashed into `generation_params_hash`) MUST have the following structure:

```json
{
  "model_id": "claude-sonnet-4-6",
  "model_version": "20251001",
  "system_prompt_hash": "sha256:<hash of system prompt bytes>",
  "temperature": 1.0,
  "top_p": 1.0,
  "max_tokens": 8192,
  "stop_sequences": [],
  "tool_choice": null,
  "tools_available": ["tool-a", "tool-b"]
}
```

The canonical form is JCS (RFC 8785). Additional implementation-specific fields MAY be included; their names MUST be prefixed with `x-` to avoid conflicts with future standard fields.

### 7.3. Artifact Types

The `artifact_type` field MUST be one of the following registered values:

| Artifact Type        | Description                                               | Default Content Class        |
|----------------------|-----------------------------------------------------------|------------------------------|
| `llm-response`       | Raw LLM response text (model forward pass output)        | `ai-output/llm-response`     |
| `agent-document`     | Structured document composed by an agent                 | `ai-output/agent-document`   |
| `ai-code`            | Source code, patch, or script produced by model inference| `ai-output/code`             |
| `pipeline-output`    | Artifact produced by a multi-agent pipeline              | `ai-output/pipeline-report`  |
| `model-output`       | Generic model output (classification, embeddings, etc.)  | `ai-output/llm-response`     |

**Default content class**: If the labeler cannot determine a more specific content class from the artifact, it MUST assign the default class for the artifact type. The artifact's actual content may cause a more specific class to be assigned (e.g., if an `llm-response` contains PII, the effective class becomes `pii/generic` or a more specific PII class).

### 7.4. C2PA Interoperability

C2PA (Coalition for Content Provenance and Authenticity) is an open standard for signing provenance manifests over media files and documents. An AI-generated document may already carry C2PA provenance (e.g., from a document-creation tool). This section defines how an APE is embedded as a C2PA assertion so that the AI agent provenance is interoperable with C2PA-aware content authenticity systems.

**C2PA assertion type**: The APE is embedded as a C2PA `c2pa.assertion` with the following assertion label:

```
io.mcp-security-platform.ai-provenance
```

**OID**: The C2PA assertion type is registered under the mcp-security-platform Private Enterprise Number arc:

```
1.3.6.1.4.1.<PEN>.mcp.c2pa.ai-provenance
```

(The PEN will be assigned upon IANA registration; see Section 11.2.)

**C2PA claim mapping**: When embedding an APE as a C2PA assertion, the following C2PA claim fields MUST be populated:

| C2PA Claim Field            | Maps From APE Field                              |
|-----------------------------|--------------------------------------------------|
| `claim_generator`           | `c2pa.claim_generator` (e.g., "mcp-security-platform/0.1") |
| `assertions[].label`        | `"io.mcp-security-platform.ai-provenance"`       |
| `assertions[].data`         | Full APE JSON (excluding `sig`)                  |
| `assertions[].hash`         | SHA-256 of APE JSON bytes                        |
| `signature_info.issuer`     | `labeler_id` from APE                            |
| `signature_info.time`       | `signed_at` from APE                             |
| `ingredients[*].hash`       | `artifact_hash` from APE for each input artifact |

**Embedding modes**:

1. **Sidecar file**: The C2PA manifest (containing the APE assertion) is stored as a separate `.c2pa` file alongside the artifact. The artifact file is unmodified. The C2PA manifest references the artifact via its hash.

2. **Inline embedding**: For file formats that support C2PA inline embedding (PDF, JPEG, MP4, etc.), the manifest is embedded in the file's metadata structure per the C2PA specification. For formats that do not natively support C2PA embedding (e.g., plain text, JSON), the sidecar mode MUST be used.

3. **APE-only**: When C2PA embedding is not required or supported by the deployment, the APE MAY be carried without C2PA wrapping. This is the minimum required mode; C2PA embedding is RECOMMENDED but not REQUIRED.

**C2PA validation**: A C2PA verifier that encounters an `io.mcp-security-platform.ai-provenance` assertion MUST:
1. Extract the embedded APE JSON.
2. Verify the APE signature per Section 7.2 (Trust List lookup, sub-CA SPKI, EKU, freshness, artifact hash).
3. Report the APE verification result as part of the C2PA manifest's trust signal.

A C2PA verifier that does not recognize the `io.mcp-security-platform.ai-provenance` assertion type MUST treat the assertion as an unrecognized extension and MUST NOT fail validation solely because of its presence (per C2PA extensibility rules).

### 7.5. Pipeline Provenance Chain

A multi-agent pipeline produces artifacts by chaining agents: Agent A calls tools and produces an intermediate artifact; Agent B receives Agent A's output and produces a further artifact; Agent C synthesizes the final output. The final artifact's trustworthiness depends on the full chain.

The `pipeline_path` field in the APE records this chain as an ordered array of step records:

```json
{
  "pipeline_path": [
    {
      "step": 1,
      "agent_id": "agent-search",
      "agent_type": "llm-agent",
      "action": "web_search",
      "tool_server_id": "brave-search-mcp",
      "input_artifact_ids": [],
      "output_artifact_id": "artifact-uuid-1",
      "integrity_rank": 0,
      "content_class": "search-result/web",
      "timestamp": "2026-06-26T10:00:00Z",
      "envelope_ref": "io.mcp-security-platform/trust-envelope/v0.1:<result_id>"
    },
    {
      "step": 2,
      "agent_id": "agent-summarizer",
      "agent_type": "llm-agent",
      "action": "llm_inference",
      "tool_server_id": null,
      "input_artifact_ids": ["artifact-uuid-1"],
      "output_artifact_id": "artifact-uuid-2",
      "integrity_rank": 0,
      "content_class": "ai-output/llm-response",
      "timestamp": "2026-06-26T10:00:05Z",
      "envelope_ref": null
    },
    {
      "step": 3,
      "agent_id": "agent-composer",
      "agent_type": "llm-agent",
      "action": "document_compose",
      "tool_server_id": null,
      "input_artifact_ids": ["artifact-uuid-2"],
      "output_artifact_id": "artifact-uuid-3",
      "integrity_rank": 0,
      "content_class": "ai-output/agent-document",
      "timestamp": "2026-06-26T10:00:10Z",
      "envelope_ref": null
    }
  ]
}
```

The following diagram shows how taint propagates through this pipeline:

```
  [Web Search Tool]          [Agent-Summarizer]        [Agent-Composer]
  trust_tier=untrustedPublic  (LLM inference)           (LLM inference)
  integrity_rank=0            input: artifact-uuid-1    input: artifact-uuid-2
         |                    rank = min(0) = 0          rank = min(0) = 0
         |                           |                          |
  [Trust Envelope]                   |                          |
  integrity_rank=0                   |                          |
  content_class=                     |                          |
   search-result/web                 |                          |
         |                           |                          |
         v                           v                          v
  artifact-uuid-1             artifact-uuid-2            artifact-uuid-3
  rank=0                      rank=0 (inherited)          rank=0 (inherited)
  class=search-result/web     class=ai-output/llm-resp    class=ai-output/agent-doc
                                                                |
                                                      FINAL APE:
                                                      integrity_rank = min(0,0,0) = 0
                                                      effective_class = search-result/web
                                                        (strictest in pipeline)
                                                      pipeline_path = [step1, step2, step3]
```

**Pipeline path construction**: The agent framework (or gateway) is responsible for constructing the `pipeline_path`. Each step MUST be appended before the step's output is used by the next agent. The pipeline path is an append-only log during construction.

**Pipeline path signing**: The APE is signed over the full `pipeline_path` array. A verifier can inspect the path to understand the full processing history. The `integrity_rank` field in each step records the rank that step contributed; the APE's top-level `integrity_rank` MUST equal `min(step.integrity_rank for all steps in pipeline_path)`. This extends the Biba minimum operation defined in §4.2 to multi-agent pipeline paths.

### 7.6. Trust Inheritance in Multi-Agent Pipelines

The Biba integrity model's minimum operation (greatest lower bound) governs trust inheritance in multi-agent pipelines, extending the session-taint rules defined in §4.2 to multi-step pipeline paths. The key principle: an agent's output cannot have higher integrity rank than the lowest-ranked input it processed.

**Formal rule**:

```
output.integrity_rank = min(
  agent.own_integrity_rank,           // the agent's own trust level
  min(input.integrity_rank            // all direct inputs
      for input in agent.inputs),
  min(tool_result.integrity_rank      // all tool results used
      for tool_result in agent.tool_calls)
)
```

This computation is recursive: if Agent B's inputs include Agent A's output, and Agent A called a web search tool (rank 0), then Agent B's output is rank 0 regardless of Agent B's own trust level or any other inputs it processed.

**Implementation requirement**: The agent framework MUST compute and record the output integrity rank at each step, not just at the final output. Intermediate artifacts MUST carry their own APEs so that the chain is auditable at each stage, not only at the terminal artifact.

**Taint recovery**: Once a pipeline step introduces a taint (rank 0 input), the taint persists for all subsequent steps that use that tainted artifact as input. There is no mechanism for a later, higher-trust agent to "cleanse" tainted data by processing it. This is a deliberate design choice aligned with Biba: if a high-trust agent could promote the integrity rank of tainted data by processing it, an attacker who controls the tainted source could exploit the high-trust agent as a laundering mechanism.

Deployers who need to process untrusted-source content and produce trusted outputs MUST use explicit human-in-the-loop validation checkpoints: a human reviews the untrusted content, and a new pipeline starts from the human's validated paraphrase (with `user` integrity rank, level 3). This is the correct trust boundary, not automated promotion.

### 7.7. Model Revocation

If a model is found to have been compromised (jailbroken, manipulated via training data poisoning, running with an altered checkpoint), or if a model version is withdrawn by its provider, previously-signed artifacts from that model may need to have their trust retroactively downgraded.

**Model revocation list**: The Trust List MAY include a `revoked_models` section listing `(model_id, model_version, time_range)` tuples:

```json
{
  "revoked_models": [
    {
      "model_id": "example-model",
      "model_version": "20250101",
      "compromised_from": "2025-01-01T00:00:00Z",
      "compromised_until": "2025-02-01T00:00:00Z",
      "reason": "Training data poisoning discovered",
      "max_trust_rank_override": 0
    }
  ]
}
```

**Revocation effect**: Verifiers that check APE model provenance fields MUST apply the following rule when a `(model_id, model_version)` match is found in `revoked_models`:

```
if artifact.model_provenance.model_id == revoked.model_id
   AND artifact.model_provenance.model_version == revoked.model_version
   AND revoked.compromised_from <= artifact.signed_at <= revoked.compromised_until:

   effective_integrity_rank = min(
     artifact.integrity_rank,
     revoked.max_trust_rank_override
   )
```

This does not delete or invalidate the artifact or its signature. It downgrades the effective integrity rank for policy evaluation purposes, so that downstream sinks with `required_integrity > max_trust_rank_override` will deny the artifact.

**Notification requirement**: Gateway operators SHOULD subscribe to model provider security advisories and SHOULD update the `revoked_models` section of the Trust List within 24 hours of a confirmed model compromise disclosure.

**Limitation**: Model revocation via the Trust List can only downgrade effective integrity rank - it cannot retroactively invalidate actions already taken based on artifacts from a revoked model. This is a fundamental limitation of any post-hoc revocation scheme. Deployers in high-stakes environments (financial, medical, legal) SHOULD implement compensating controls: audit reviews of all actions driven by AI artifacts during the compromise window.

---

## 8. Extended Envelope Schema

### 8.1. Backward Compatibility

The extended envelope schema is a strict superset of the v0.1 envelope schema defined in §4.2. All new fields are OPTIONAL at the envelope level. A consumer implementing only the signing mechanism in §4.2 that encounters an envelope with extension fields MUST ignore unrecognized fields (per the standard JSON extensibility principle).

A consumer implementing this document MUST:
1. Accept v0.1-conformant envelopes (no `content_class`, `federation`, or `ai_provenance` fields) without error.
2. Apply default values for absent extension fields per Section 5.1 P5 (content class defaults to `external-content/raw`; federation fields default to single-gateway mode; ai_provenance absent means no artifact provenance is available).
3. Not require the extended fields for basic integrity enforcement (Sections 5 through 7 features are gated on the presence of their respective fields).

The `schema_version` field in the envelope MUST be updated to `"v0.2"` when any extension field from §5-§7 is present. Envelopes implementing only the signing mechanism in §4.2 use `"v0.1"`. Consumers MUST be able to process both versions.

### 8.2. Version Negotiation and Graceful Degradation

Extension-aware peers advertise support by including a `capabilities` object in their MCP initialization exchange carrying `"sep1913_ext_version": "<version>"`. Where both peers advertise support, the highest commonly supported version governs envelope handling.

**When a peer does not advertise capability:**

- The extension-aware peer falls back to **advisory-only mode** (Layer B only - see §4.2.1). It MUST surface a downgrade indication to the operator (log entry, metric, or health signal) so that the absence of cryptographic guarantees is not silent.
- Connectivity is preserved; only the cryptographic enforcement layer is absent.
- This fallback is explicitly NOT suitable for zero-trust deployments - see §9.11 (Downgrade Attacks).

**Feature-level negotiation:** Extensions are independently optional. A peer MAY support the signed-envelope mechanism (§4.2) without federation (§6) or artifact provenance (§7). Each feature is negotiated separately:

| Feature | Capability key | Requires |
|---------|---------------|----------|
| Signed envelopes | `sep1913_ext_version: "v0.1"` | §4.2 |
| Content classification | `sep1913_ext_version: "v0.2"` | §4.2 + §5 |
| Federation | `sep1913_federation: true` | §4.2 + §6 |
| Artifact provenance | `sep1913_ape: true` | §4.2 + §7 |

**Graceful degradation guarantee:** An extension-aware consumer talking to a v0.1-only peer MUST remain functionally interoperable - losing only cryptographic guarantees, never MCP connectivity. Sinks that declare `require_content_class: true` or `required_integrity > 0` SHOULD configure fallback behavior (deny-by-default or flag-for-review) when operating in advisory mode.

**During the transition period** (§8.1), gateway operators MAY emit both `v0.1` and `v0.2` envelope keys simultaneously. Extension-aware consumers prefer the `v0.2` key; v0.1-only consumers use the `v0.1` key and ignore unrecognized `_meta` fields.

### 8.3. Full Extended Schema (Normative)

The schema defined in this section is normative. Implementations MUST accept envelopes conforming to this structure and MUST reject envelopes that include unknown required fields or omit required fields. Unknown optional fields MUST be ignored (forward compatibility). The complete extended envelope appears in `CallToolResult._meta` under the key `"io.mcp-security-platform/trust-envelope/v0.2"`. When both v0.1 and v0.2 keys are present (transition period), verifiers MUST prefer v0.2.

```json
{
  "io.mcp-security-platform/trust-envelope/v0.2": {
    "schema_version": "v0.2",

    "label": {
      "integrity_rank": 1,
      "trust_tier": "trustedPublic",
      "content_class": {
        "primary": "search-result/web",
        "additional": [],
        "effective": "search-result/web",
        "conf_floor": "public",
        "allowlist_required": false,
        "assigned_by": "labeler.gateway.example.org",
        "assigned_at": "2026-06-26T10:00:00Z"
      }
    },

    "binding": {
      "result_id": "<uuid>",
      "tool_name": "brave-search",
      "server_id": "brave-search-mcp",
      "content_hash": {
        "alg": "sha256",
        "value": "<hex>"
      },
      "signed_at": "2026-06-26T10:00:00Z",
      "nonce": "<base64url 128-bit random>"
    },

    "federation": {
      "labeler_id": "labeler.gateway.example.org",
      "sub_ca_spki_fp": "sha256:<hex>",
      "trust_list_id": "mcp-trust-list-prod",
      "trust_list_sequence": 47,
      "org_id": "org-a",
      "gateway_id": "gateway-prod",
      "forwarded_envelope": null,
      "relay_chain": []
    },

    "ai_provenance": null,

    "sig": {
      "alg": "ES256",
      "kid": "<labeler leaf cert thumbprint>",
      "value": "<base64url JWS detached signature>"
    }
  }
}
```

**When cross-gateway forwarding in re-sign mode, the outer envelope**:

```json
{
  "io.mcp-security-platform/trust-envelope/v0.2": {
    "schema_version": "v0.2",

    "label": {
      "integrity_rank": 1,
      "trust_tier": "trustedPublic",
      "content_class": { ... }
    },

    "binding": {
      "result_id": "<same as inner>",
      "tool_name": "brave-search",
      "server_id": "brave-search-mcp",
      "content_hash": { "alg": "sha256", "value": "<hex>" },
      "signed_at": "2026-06-26T10:05:00Z",
      "nonce": "<new nonce for outer sig>"
    },

    "federation": {
      "labeler_id": "labeler.gateway-b.org-b.example",
      "sub_ca_spki_fp": "sha256:<FP-B>",
      "trust_list_id": "mcp-trust-list-prod",
      "trust_list_sequence": 47,
      "org_id": "org-b",
      "gateway_id": "gateway-b-prod",
      "forwarded_envelope": {
        "io.mcp-security-platform/trust-envelope/v0.2": {
          "label": { "integrity_rank": 1, ... },
          "binding": { ... },
          "federation": {
            "labeler_id": "labeler.gateway-a.org-a.example",
            "sub_ca_spki_fp": "sha256:<FP-A>",
            "org_id": "org-a",
            "gateway_id": "gateway-a-prod",
            "forwarded_envelope": null,
            "relay_chain": []
          },
          "ai_provenance": null,
          "sig": { "alg": "ES256", "kid": "...", "value": "<Gateway A sig>" }
        }
      },
      "relay_chain": []
    },

    "ai_provenance": null,

    "sig": {
      "alg": "ES256",
      "kid": "<Gateway B labeler leaf cert thumbprint>",
      "value": "<base64url Gateway B JWS>"
    }
  }
}
```

**For APE (artifact provenance outside MCP)**, the envelope is a standalone JSON document, not embedded in `_meta`. See Section 7.2 for its structure.

### 8.4. Signing Input Construction

The signing input for the extended envelope is the JCS (RFC 8785) canonical JSON of the following object, constructed by the labeler before signing:

```json
{
  "schema_version": "v0.2",
  "label": { ... },
  "binding": {
    "result_id": "...",
    "tool_name": "...",
    "server_id": "...",
    "content_hash": { ... },
    "signed_at": "...",
    "nonce": "..."
  },
  "federation": {
    "labeler_id": "...",
    "sub_ca_spki_fp": "...",
    "trust_list_id": "...",
    "trust_list_sequence": ...,
    "org_id": "...",
    "gateway_id": "...",
    "forwarded_envelope_hash": "<sha256 of forwarded_envelope JSON if present, else null>"
  },
  "ai_provenance": { ... }
}
```

Note: `forwarded_envelope` is NOT included inline in the signing input - only its hash (`forwarded_envelope_hash`) is committed. This prevents the signing input from becoming arbitrarily large due to nested envelope chains. The verifier MUST compute the hash of the received `forwarded_envelope` and compare it to `forwarded_envelope_hash` before verifying the outer signature.

For APE signing (Section 7.2), the signing input is the JCS canonical JSON of all APE fields except `sig`, including the full `pipeline_path` array.

### 8.5. Versioning Policy

This section defines what constitutes a breaking versus non-breaking change to this specification, and how future revisions are expected to be handled.

**Non-breaking changes** (minor version bump, e.g., v0.2 → v0.3):
- Adding new optional fields to the envelope schema (ignored by older consumers per §8.3)
- Adding new content class registry entries
- Adding new `deny_reason` codes
- Clarifying normative text without changing required behavior
- Adding new appendices or informative sections

**Breaking changes** (major version bump or new capability key):
- Adding new required fields to the envelope schema
- Changing the signing input construction (§8.4) - existing signatures would fail verification
- Changing the Trust List format (§6.2) in ways that require new parser logic
- Removing or renaming existing capability keys (§8.2)
- Changing the semantics of existing fields (e.g., redefining `integrity_rank` scale)

**Extension lifecycle**: Future extensions to this specification SHOULD be published as separate community proposals referencing this document, following the same SEP process used for SEP-1913. Backward compatibility is maintained by the capability negotiation mechanism defined in §8.2 - a peer that does not advertise a new capability key MUST be treated as not supporting that extension, and the extension-aware peer MUST degrade gracefully rather than failing connectivity.

**Deprecation**: Fields or behaviors that are deprecated in a future revision SHOULD remain supported for at least one major version transition to allow implementers time to migrate. Deprecations SHOULD be announced via the Open Issues mechanism (§14) before being finalized.

---

## 9. Security Considerations

### 9.1. Content Class Spoofing

**Threat**: An attacker controls a tool server and attempts to self-assert a favorable content class (e.g., asserting `search-result/internal` when actually delivering `external-content/raw`) to bypass sink policies that block external content.

**Mitigation**: Per Design Principle P1 (Section 5.1), content classes are NEVER accepted from the tool server itself. The gateway proxy registry assigns content classes based on the registered profile of each tool server (`server_id`). The registry is under gateway operator control and is not readable or writable by tool servers.

**Residual risk**: A malicious gateway operator could mis-classify a tool server's content class in the registry. This risk is mitigated by the Trust List's trust scope constraints (Section 6.3): a labeler sub-CA's trust scope bounds the content classes it may assert. A misconfiguration that assigns `search-result/internal` to an external web-search tool can be detected by auditors reviewing the transparency log against the declared trust scope. The proxy-assignment model for content class mirrors the integrity rank proxy-assignment from §4.2.

**Residual risk - multi-class omission**: A gateway might detect only some content types in a result (e.g., detecting PII but missing that the result also contains financial data), assigning an incomplete union. This can occur with complex or obfuscated payloads. Deployers SHOULD implement content scanning at the gateway using dedicated classifiers, not only pattern matching, for high-sensitivity content classes.

### 9.2. Federation Trust List Attacks

**Threat 1 - Trust List rollback**: An attacker in a network-privileged position replaces the Trust List with an older version (lower sequence number) that includes a revoked sub-CA.

**Mitigation**: Verifiers MUST reject Trust Lists with sequence numbers less than or equal to the last accepted sequence number (Section 6.2). Verifiers MUST maintain the last accepted sequence number persistently. Combined with Trust List TTL enforcement, this prevents serving stale Trust Lists beyond the TTL window.

**Threat 2 - Governance key compromise**: An attacker obtains one governance key and uses it to push a Trust List update adding a malicious sub-CA.

**Mitigation**: M-of-N governance signature requirement (Section 6.6). With M=2, a single key compromise is insufficient. With M=3 (recommended for large federations), an attacker must compromise 3 keys simultaneously. All Trust List updates are logged to the transparency log; the monitoring requirement (Section 6.4) means unauthorized updates are detectable within the monitoring poll interval.

**Threat 3 - Trust scope evasion**: A compromised labeler attempts to assert a content class or integrity rank outside its registered trust scope.

**Mitigation**: Trust scope is enforced by the receiving verifier (Section 6.3), not by the labeler itself. Even if a labeler generates an out-of-scope assertion, the verifier rejects it. The labeler cannot modify its own trust scope entry in the Trust List (only governance key holders can update the Trust List).

**Threat 4 - Trust List distribution compromise**: An attacker compromises the Trust List distribution server and serves a modified Trust List.

**Mitigation**: The Trust List is signed by M-of-N governance keys. A modified Trust List has an invalid signature and MUST be rejected by verifiers. Distribution server compromise results in denial of service (verifiers cannot obtain a fresh Trust List) but not trust bypass, because the signature verification requirement does not depend on the distribution server's integrity.

### 9.3. Transparency Log Gaps

**Threat**: A sub-CA is added to the Trust List without a corresponding transparency log entry, or the inclusion proof is forged.

**Mitigation**: For entries with `inclusion_proof_required: true`, verifiers MUST verify the inclusion proof before trusting the entry (Section 6.4). An inclusion proof can only be forged by breaking the Merkle tree's hash function (SHA-256), which is computationally infeasible with current algorithms.

**Threat - log availability attack**: An attacker takes the transparency log offline at the moment a verifier needs to check an inclusion proof, preventing new sub-CAs from being validated.

**Mitigation**: Verifiers SHOULD cache successfully verified inclusion proofs with a TTL of at least the leaf certificate TTL (15 minutes). For entries whose inclusion proofs have been previously verified and cached, the cache MAY be used during log unavailability. New sub-CAs (no cache entry) fail closed - the verifier MUST reject envelopes from uncached sub-CAs when the log is unavailable and `inclusion_proof_required: true`.

**Threat - split-view attack**: The transparency log shows different tree heads to different verifiers, allowing the log operator to present one view to monitors and another to verifiers.

**Mitigation**: This is an inherent risk of any transparency log that does not have a consistency-proof mechanism (Gossip protocol). Deployers SHOULD implement a Gossip protocol per RFC 6962bis to detect split views. This is listed as Future Work (Section 13) for this specification.

### 9.4. Model Identity Spoofing

**Threat**: A compromised labeler or a rogue inference proxy substitutes a different model's output (from a jailbroken or compromised model) while asserting the `model_id` of a trusted model in the APE.

**Mitigation (scope)**: The `model_commitment_hash` (Section 7.2.1) is a digest over the *self-asserted* tuple `(model_id, model_version, inference_endpoint)`; it is not a secret and any party can recompute it from those public strings. Its security value is therefore narrow and precise: by being inside the JWS-signed APE, it binds the labeler non-repudiably to the model identity it asserted, and prevents a *relay or network intermediary* from silently rewriting the asserted model identity without invalidating the signature. It does NOT independently verify that the asserted model actually produced the output - a labeler (or anyone who controls the inference path) can assert any identity it likes. Honest model-identity assurance therefore rests on trusting the labeler to call the model API directly through the stated `inference_endpoint`; the commitment hash records that assertion, it does not prove it. Strong assurance requires the hardware attestation noted under Residual Risk.

**Residual risk**: The `model_commitment_hash` is a commitment to the model identity string, not to the model weights. An attacker who has compromised the model serving infrastructure and can substitute the weights while returning the correct model_id string in API responses can defeat this mechanism. This is a fundamental limitation of any API-level provenance scheme that cannot inspect model weights directly. Hardware-level attestation (e.g., AMD SEV-SNP or Intel TDX for inference environments) is the correct defense at this level but is out of scope for this specification.

### 9.5. Pipeline Taint Injection

**Threat**: An attacker-controlled intermediate artifact in a pipeline asserts a higher integrity rank than it actually has, causing downstream agents to trust it and potentially allowing the taint to be laundered.

**Mitigation**: The `pipeline_path` is append-only and each step's `integrity_rank` is recorded by the gateway/agent framework, not by the agent itself. The APE's top-level `integrity_rank` is computed as the minimum across all pipeline path steps and is verified by the labeler before signing. An agent cannot self-promote its output's integrity rank. This mirrors the proxy-assignment principle from §4.2 extended to multi-agent pipelines.

**Threat - path truncation**: An attacker removes steps from the `pipeline_path` before the APE is signed, hiding that a high-rank output derived from a low-rank source.

**Mitigation**: Each step in the `pipeline_path` includes a reference to the previous step's output artifact ID and (where available) the trust envelope reference for tool results. Verifiers SHOULD traverse the pipeline_path and verify that the chain is complete and consistent. Gaps in the path (missing steps or unexplained jumps in artifact IDs) MUST be treated as trust failures.

---

### 9.6. BLP Declassification Attacks (Open Problem)

**Threat**: An attacker constructs a request that routes high-classification content through a multi-step pipeline designed to "process" the content and re-label the output as lower classification. For example: feed `pii/ssn` data to an LLM summarizer that produces an `ai-output/llm-response`, then claim the output is only `ai-output/llm-response` (conf floor: public) and route it to a public logging sink. This is the AI-pipeline equivalent of a classical BLP declassification attack, and it is already occurring in practice against enterprise DLP systems - users paste SSNs or confidential documents into LLMs, obtain paraphrased summaries, and the output evades pattern-based classifiers.

**Why this specification does not fully mitigate it**: The attack requires that the labeler classify LLM output based solely on the artifact type (`ai-output/llm-response`) rather than on the semantic content of the inputs that produced it. For this specification to prevent the attack, two conditions must both hold: (1) the agent orchestration layer faithfully records all classified inputs in the APE pipeline_path, and (2) the labeler enforces the strictest input floor on the output's effective class. Condition (1) is assumption, not enforcement - an attacker who controls the agent harness can omit inputs from the pipeline_path, defeating condition (2). There is currently no cryptographic mechanism in this specification that forces a pipeline to declare all its inputs. This is an open problem in AI information-flow control; see also §14 (Open Issues) and the FIDES [FIDES25] and CaMeL [CaMeL25] work on per-value taint tracking as a research direction toward a real solution.

**What deployers can do in the interim**: Treat any LLM output that could have been derived from high-classification inputs as carrying the highest classification of those inputs, by policy - not by relying on pipeline_path propagation. Apply explicit `content_class_denylist` rules on sensitive sinks to block processed-content classes entirely, regardless of what the APE claims. This is a conservative operational posture, not a protocol-level guarantee.

### 9.7. APE Replay and Binding Attacks

**Threat 1 - APE replay**: An attacker captures a valid APE for a trusted AI artifact and attaches it to a different (malicious) artifact, attempting to pass the malicious artifact off as trustworthy.

**Mitigation**: The APE's `artifact_hash` binds the envelope to the exact artifact bytes. A verifier MUST recompute the artifact's hash and compare it to `artifact_hash` before accepting the APE. Any mismatch MUST cause rejection. This is the same defense as the content hash binding in the signed envelope (§4.2), extended to artifact provenance.

**Threat 2 - APE sidecar substitution**: In sidecar mode (Section 7.4), the APE file and artifact file are separate. An attacker replaces the sidecar APE with a different APE (from a different artifact) while keeping the malicious artifact.

**Mitigation**: Because the APE's `artifact_hash` must match the artifact's content, a substituted APE (from a different, legitimate artifact) will have a different `artifact_hash` and will fail verification. Verifiers MUST always verify `artifact_hash` against the actual artifact content, even in sidecar mode. Deployers SHOULD use atomic storage operations (write artifact and sidecar together) to reduce the window for substitution attacks.

**Threat 3 - pipeline_path forgery**: An attacker forges a pipeline_path that claims a clean origin (no web search steps) for an artifact that was actually derived from external content.

**Mitigation**: Each pipeline step that involves a tool call MUST include an `envelope_ref` pointing to the signed trust envelope (v0.1 or v0.2) for that tool result. Verifiers SHOULD dereference `envelope_ref` entries and verify that the referenced tool result envelopes are valid and consistent with the step's declared `integrity_rank`. A forged path that claims rank 2 for a web search step would require the attacker to produce a valid signed envelope (§4.2) for a web search result with rank 2 - which is impossible if the gateway correctly assigns rank 0 to untrustedPublic sources.

For pipeline steps involving LLM inference (no tool call), there is no `envelope_ref`. The integrity_rank for these steps is computed from the agent's own rank and its input ranks. An attacker who can forge input artifact IDs can potentially insert false steps. This is mitigated by requiring each intermediate artifact's APE to be stored and retrievable, and by requiring the step's `input_artifact_ids` to reference existing, verified APEs. Full mitigation requires an artifact store with append-only semantics and content-addressed storage (artifact_id is a function of artifact_hash, not an arbitrary UUID).

### 9.8. Confused Deputy and Privilege Escalation

**Threat**: A gateway holds credentials with broad upstream scope. A lower-trust caller induces the gateway to act on its behalf beyond the caller's own authority - the classic confused-deputy scenario. In the MCP context: a caller with low Biba rank manipulates the gateway into forwarding a high-integrity tool call, or a client with no clearance for `secret`-floor content routes a request through a gateway that does have that clearance.

**Mitigation**: Trust scope (§6.3) bounds each labeler sub-CA to the server IDs, content classes, and maximum integrity ranks it may assert. The receiving verifier enforces trust scope, not the labeler itself (§6.3 step 5). Gateways operating in re-sign mode (§6.5) MUST NOT widen the outer integrity rank above the inner rank, and MUST NOT assert a less restrictive content class than the forwarded envelope.

**Privilege escalation** is the downstream consequence of a successful confused-deputy attack: the attacker's data reaches a sink it would not otherwise reach. The layered defense (Biba check → BLP check → allowlist gate - see §5.4 flowchart) provides defense in depth: an escalation attempt must clear all three checks, not just one.

**Residual risk**: A gateway operator who misconfigures trust scope entries can inadvertently grant excessive authority. The transparency log (§6.4) and monitoring requirement provide external auditability.

### 9.9. Malicious MCP Servers and Compromised Clients

**Threat (malicious server)**: A malicious tool server emits correctly-formatted MCP responses with content designed to manipulate downstream AI behavior (prompt injection, jailbreak payloads, exfiltration triggers).

**Mitigation**: Per Design Principle P1 (§5.1), content classes are assigned by the gateway from its registry - the tool server has no control over its own integrity rank or content class. Layer A (§4.2.1) binds the content hash to the label; a server cannot make its malicious output appear trusted. The Biba minimum operation (§7.6) ensures that tainted data contaminates the entire pipeline path.

**Threat (compromised client)**: A compromised consumer ignores envelope verification entirely, acting on any result regardless of its label.

**Mitigation**: This is an explicit non-goal (§3.6). Once the verifying endpoint is itself adversary-controlled, the extension provides no protection. Deployers SHOULD implement defense-in-depth at the sink level (human-in-the-loop for high-consequence actions) and treat client compromise as a separate incident-response scenario.

**Local malware**: An attacker with code execution on the client host can similarly bypass envelope verification. This is an endpoint-compromise scenario, explicitly out of scope per §3.6.

### 9.10. Replay and Freshness Attacks

**Threat**: An attacker captures a valid signed envelope and replays it later (e.g., to re-authorize an action with a stale result, or to pass a previously-valid but now-revoked sub-CA's envelope).

**Mitigation**: Three controls compose to bound replay windows:

- **Nonce**: each envelope carries a cryptographically random 128-bit nonce. Verifiers MUST maintain a nonce seen-set and reject any nonce presented more than once within the `MAX_ENVELOPE_AGE` window.
- **`MAX_ENVELOPE_AGE`** (600 seconds): verifiers MUST reject any envelope where `now > signed_at + 600s`, regardless of the leaf certificate's validity period. This limits the replay window to 10 minutes even if the nonce cache is lost.
- **Leaf certificate TTL** (15 minutes, §4.2.3): after the leaf cert expires, the sub-CA SPKI pinning check fails even if the envelope is otherwise valid.

For APE replay (artifact provenance envelopes), the `artifact_hash` binds the APE to specific artifact bytes; a replayed APE fails verification against any different artifact (§9.7).

### 9.11. Downgrade Attacks

**Threat**: An on-path adversary strips the extension `_meta` field from tool results, forcing all consumers into advisory-only (Layer B) mode. Alternatively, the adversary presents an older Trust List version with a lower sequence number to restore a previously-revoked sub-CA.

**Mitigation**:

- **Trust List rollback**: verifiers MUST reject Trust Lists with sequence numbers ≤ the last accepted sequence number (§6.2). The sequence number MUST be persisted durably across restarts.
- **Extension stripping**: consumers configured in enforcing mode (non-advisory) MUST treat the absence of a required `v0.2` envelope as a verification failure, not a graceful fallback. This SHOULD be the default in zero-trust deployments.
- **Advisory fallback**: in non-zero-trust deployments, advisory mode is a legitimate operating state during transitions. Operators MUST be notified when enforcing mode degrades to advisory (§8.2 version negotiation).

**Residual risk**: Advisory mode (Layer B only) provides no cryptographic guarantees - it is a probabilistic hint to LLMs, not a security control. Deployers that cannot enforce Layer A SHOULD compensate with human review at high-consequence sinks.

---

## 10. Privacy Considerations

### 10.1. Metadata Disclosure

APE envelopes (§7) carry `model_id`, `model_version`, `inference_endpoint`, and a full `pipeline_path` listing agent identities, tool servers, timestamps, and per-step content classes. This information reveals internal architecture - the model version in use, the agent topology, and which tool servers handle what data types - to any party that receives the APE.

**Mitigations**: Producers MAY omit `pipeline_path` node identifiers (replacing agent IDs with opaque hashes) when downstream consumers do not require per-step auditability. The `generation_params` object MUST be hashed into `generation_params_hash` - it MUST NOT be carried in clear in the envelope (§7.2.2). Deployers SHOULD evaluate which APE fields are strictly necessary for their downstream verification use case and omit the rest.

### 10.2. Execution-Origin Information

The Trust List (§6.2) and per-envelope `federation` sub-object carry `org_id` and `gateway_id` fields identifying which organization produced a labeled result. In multi-tenant environments, this can allow cross-tenant enumeration of which organizations are participating in a federation.

**Mitigations**: In multi-tenant deployments, `org_id` and `gateway_id` SHOULD be scoped per-tenant or anonymized unless the federation's trust model explicitly requires cross-tenant visibility. The Trust List itself is a signed document whose distribution can be restricted to federation participants.

### 10.3. Telemetry and Data Minimization

Transparency-log inclusion (§6.4) creates a permanent, externally auditable record of sub-CA registrations. The log MUST contain only commitments and hashes - `sub_ca_spki_fp`, `entry_id`, governance signatures - never content payloads, PII, or tool result data. Implementations SHOULD apply data minimization: carry only the envelope fields required by the verifier's policy.

### 10.4. User Consent and Enterprise Audit

Provenance recording is simultaneously a feature (audit trail, forensics) and a risk (surveillance, data retention). Deployments MUST document:

- Which APE metadata fields are retained, for how long, and by which parties.
- The legal basis for retention under applicable data-protection regulation.
- The process by which a data subject may request deletion of provenance records associated with their activity.

The inherent tension - provenance minimization weakens audit; full provenance raises surveillance concerns - cannot be resolved by the protocol. Deployers MUST resolve it in their privacy governance. This specification makes the tension explicit so that governance decisions are informed rather than accidental.

---

## 11. Project Registry Governance

This section defines the governance model for identifiers introduced by this specification. These are project-internal registries, not IANA registrations.

### 11.1. Content Class Registry

The mcp-security-platform project maintains a Content Class Registry. Initial entries are defined in §5.2. New entries may be submitted by gateway operators to the project governance committee. Each submission MUST include:

- Proposed class identifier (`<domain>/<subtype>` format)
- Description of the content type
- Rationale for the proposed confidentiality floor
- Whether `allowlist_required` should be true or false, with rationale
- At least two example tool results that would be classified under this class

**Review criteria**: uniqueness (no existing class covers this content), clarity (class boundaries are unambiguous), calibration (confidentiality floor is appropriate relative to existing entries).

**Stability**: Approved entries are permanent. Entries may be deprecated (`deprecated: true`) but MUST NOT be removed or have their semantics changed. Changed semantics require a new class.

### 11.2. OID Namespace

The following OID arcs are reserved under the project namespace. A Private Enterprise Number (PEN) from IANA is required before production use; the placeholder `<PEN>` is used throughout this document. Obtaining a PEN is a pre-production deployment step, not a community review prerequisite.

| OID | Purpose |
|-----|---------|
| `1.3.6.1.4.1.<PEN>.mcp.labeler` | Labeler Extended Key Usage (§4.2) |
| `1.3.6.1.4.1.<PEN>.mcp.c2pa.ai-provenance` | C2PA assertion type for APE (§7.4) |
| `1.3.6.1.4.1.<PEN>.mcp.content-class.registry` | OID arc for content class identifiers |
| `1.3.6.1.4.1.<PEN>.mcp.trust-list` | OID arc for Trust List schema versioning |

### 11.3. C2PA Assertion Type

The assertion label `io.mcp-security-platform.ai-provenance` is defined by this specification for the APE embedding described in §7.4. If the APE specification matures into a cross-framework standard, this label SHOULD be submitted to the C2PA Technical Working Group for formal registration. Until then it is a project-defined identifier. C2PA consumers verifying this assertion type MUST follow the procedure in §7.4.

---

## 12. Future Work

The following items are explicitly out of scope for this proposal and are candidates for follow-on community proposals.

**Future proposal: C-precise per-value taint tracking**: This specification implements per-artifact taint (every artifact has one integrity rank). CaMeL and FIDES demonstrate that per-value taint (tracking which specific field values in an artifact derive from which taint sources) is achievable but requires a conformant consumer embedded in the agent harness. This is a materially different integration architecture and warrants a dedicated specification.

**Future proposal: HSM integration for labeler keys**: The signed envelope mechanism (§4.2) relies on labeler leaf keys stored in step-ca and exportable. A future community proposal should define the interface between the TrustLabeler component and an HSM (Hardware Security Module) for non-exportable key storage, covering the PKCS#11 or KMS API contract, key attestation, and failover behavior.

**Gossip protocol for transparency log consistency**: Section 9.3 notes that split-view attacks against the transparency log are not mitigated without a Gossip protocol. RFC 6962bis defines a Gossip mechanism; future deployments SHOULD implement it. A follow-on proposal should document the recommended Gossip configuration for the mcp-security-platform federation.

**Trust scope automation**: Currently, trust scope entries in the Trust List are manually configured by governance key holders. A follow-on proposal could define a machine-readable tool server capability schema that automatically informs trust scope bounds (e.g., a tool server that declares it only returns `search-result/web` content cannot be granted `secret` confidentiality classification).

**Multi-modal artifact provenance**: Section 7.1 explicitly scopes out camera-captured images (covered by C2PA) and model weights. A follow-on proposal should address multi-modal artifacts where a single artifact (e.g., a generated PDF) contains both AI-generated text and AI-generated images, requiring composite provenance records from both the text model and the image model.

**Streaming artifact provenance**: The APE (Section 7.2) assumes a complete artifact is available at signing time. For streaming LLM outputs (token-by-token), the full artifact hash cannot be computed until generation is complete. A follow-on proposal should define a streaming-compatible provenance scheme (e.g., progressive hashing, or a commitment to the final hash published after stream completion).

**RBAC integration for content class access**: This specification defines content class policies at the tool/sink level. A follow-on proposal should define how content class restrictions integrate with role-based access control - e.g., a user with the `analyst` role may access `search-result/internal` but not `financial/trade-order`, even when the sink's policy would otherwise permit it.

---

## 13. Open Issues

The following design questions are unresolved and presented for community discussion. Comments are welcome via the channels listed in the Community Feedback section.

1. **Execution locality - MUST or advisory?** Should label-assertion locality (the requirement that labels be assigned by a gateway proxy, not by the tool server) be a hard MUST for all conformant implementations, or SHOULD - allowing direct-server labeling with documented trade-offs? The current text uses MUST (§4.2.1 P1), but an equivalence clause permits alternative architectures. Whether that equivalence clause is sufficient or whether mandatory gateway interposition is required for interoperability is an open question.

2. **Locality negotiation during MCP capability exchange.** Should execution-locality and labeling capability be formally negotiated as part of the MCP `initialize` / capabilities exchange? The current version negotiation (§8.2) covers extension version but not deployment topology. Explicit locality negotiation would let servers declare whether they support gateway-mediated or direct labeling - enabling clients to make explicit trust decisions.

3. **Cryptographic verifiability of trust metadata.** Should trust-scope entries in the Trust List (§6.3) be cryptographically signed by the asserting organization's own key, so that a verifier can confirm the scope claim rather than relying solely on governance-root attestation? This would add complexity (per-org signing keys) but reduce the blast radius of a governance-root compromise.

4. **Machine-readable execution policies.** Should the sink policy grammar (§5.6) be standardized as a machine-readable, interchangeable format - so that policies can be shared across gateway implementations and audited without reading implementation code? The current spec defines a structured object but leaves the registry format to the implementation.

5. **Streaming artifact provenance.** The APE (§7.2) assumes a complete artifact at signing time. For streaming LLM outputs, a hash cannot be committed until generation completes. Should a streaming-compatible provenance scheme (e.g., progressive hash commitment, or a post-stream hash publication with a nonce linking to the in-flight stream) be standardized in this document or deferred to a follow-on proposal?

6. **Terminology for the trust tier.** This document derives a five-level trust tier (`untrustedPublic` through `system`) from SEP-1913 hint annotations (§4.2.2). Should this tier be proposed for adoption in SEP-1913 itself, or left as an extension-local model? Adoption in SEP-1913 would improve interoperability; keeping it local avoids coupling.

---

## 14. References

References marked **(N)** are required reading for anyone implementing this proposal - they define protocols or schemas this specification builds on directly. All others are background and related work.

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels," BCP 14, RFC 2119, March 1997. **(N)**
https://www.rfc-editor.org/rfc/rfc2119

[RFC5280] Cooper, D., et al., "Internet X.509 Public Key Infrastructure Certificate and CRL Profile," RFC 5280, May 2008. **(N)**
https://www.rfc-editor.org/rfc/rfc5280

[RFC6962] Laurie, B., Langley, A., and Kasper, E., "Certificate Transparency," RFC 6962, June 2013. **(N)**
https://www.rfc-editor.org/rfc/rfc6962
(Append-only Merkle tree structure used in the transparency log design of §6.4.)

[RFC7515] Jones, M., Bradley, J., and Sakimura, N., "JSON Web Signature (JWS)," RFC 7515, May 2015. **(N)**
https://www.rfc-editor.org/rfc/rfc7515

[RFC7517] Jones, M., "JSON Web Key (JWK)," RFC 7517, May 2015. **(N)**
https://www.rfc-editor.org/rfc/rfc7517

[RFC8551] Schaad, J., Ramsdell, B., and Turner, S., "S/MIME Version 4.0," RFC 8551, April 2019.
https://www.rfc-editor.org/rfc/rfc8551
(Signing model that inspired the two-layer envelope design in §4.2.)

[RFC8785] Rundgren, A., Jordan, B., and Erdtman, S., "JSON Canonicalization Scheme (JCS)," RFC 8785, June 2020. **(N)**
https://www.rfc-editor.org/rfc/rfc8785
(All signing inputs use JCS to ensure deterministic byte sequences.)

[MCP-SPEC] Anthropic, "Model Context Protocol Specification," 2024-2026. **(N)**
https://modelcontextprotocol.io/specification
(Canonical MCP specification: `CallToolResult`, `_meta` field conventions, and tool result schemas this proposal extends.)

[MCP-CORE] Anthropic, "MCP Core Architecture," Model Context Protocol documentation. **(N)**
https://modelcontextprotocol.io/docs/concepts/architecture

[MCP-TOOLS] Anthropic, "MCP Tools Specification," Model Context Protocol documentation. **(N)**
https://modelcontextprotocol.io/docs/concepts/tools
(`tools/call` and `tools/list` protocol messages, `CallToolResult` schema, and `_meta` field - the signing target for the envelope mechanism in §4.2.)

[SEP-1913] MCP Community, "SEP-1913: Trust and Sensitivity Annotations for Tool Results," GitHub PR #1913, 2025. **(N)**
https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1913
(Pinned to commit f46d45ef8eb60ff3fb2f38651bd076097f9ccdf4. Defines the `sensitiveHint`, `privateHint`, `openWorldHint`, `maliciousActivityHint`, and `attribution` vocabulary this document extends. §4.2.2 derives a five-level source-trust tier from those hints; the tier is this extension's construction, not a native SEP-1913 field.)

[C2PA24] Coalition for Content Provenance and Authenticity, "C2PA Technical Specification," version 2.1, 2024. **(N)**
https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html
(Signed manifest format and trust model. §7.4 defines APE interoperability with C2PA.)

[BLP73] Bell, D.E., and LaPadula, L.J., "Secure Computer Systems: Mathematical Foundations and Model," MITRE Corporation Technical Report MTR-2547, 1973.
https://apps.dtic.mil/sti/citations/AD0770768

[Biba77] Biba, K.J., "Integrity Considerations for Secure Computer Systems," MITRE Corporation Technical Report ESD-TR-76-372, 1977.
https://apps.dtic.mil/sti/citations/ADA039324
(The ★-integrity property - "no write up" - that the signed envelope session taint floor (§4.2) implements. This document extends Biba taint to multi-agent pipeline paths and AI artifact provenance.)

[CaMeL25] Debenedetti, E., Shumailov, I., Fan, T., Hayes, J., Carlini, N., Fabian, D., Kern, C., Shi, C., Terzis, A., and Tramèr, F., "Defeating Prompt Injections by Design," arXiv:2503.18813, March 2025.
https://arxiv.org/abs/2503.18813
(CaMeL is the system introduced by this paper: capability-based data-flow tracking, enforced by a custom interpreter, to prevent tainted data reaching privileged sinks. Informs the pipeline_path design in §7.5 and identifies per-value taint as Future Work.)

[FIDES25] Costa, M., Köpf, B., Kolluri, A., Paverd, A., Russinovich, M., Salem, A., Tople, S., Wutschitz, L., and Zanella-Béguelin, S., "Securing AI Agents with Information-Flow Control," arXiv:2505.23643, Microsoft Research, 2025.
https://arxiv.org/abs/2505.23643
(Introduces Fides, a planner that tracks confidentiality and integrity labels and deterministically enforces information-flow policies; reference code at github.com/microsoft/fides. Validates the `(integrity, confidentiality)` label-pair model used in §5. Fides's lattice-meet (minimum) propagation rule is the basis for §7.6's trust inheritance.)

[InstructionHierarchy24] Wallace, E., et al., "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions," OpenAI, arXiv:2404.13208, 2024.
https://arxiv.org/abs/2404.13208
(OpenAI's approach to model-side instruction hierarchy enforcement. Complements the proxy-side deterministic controls in this specification by reducing model susceptibility to injection in well-trained models. The two layers are orthogonal.)

[Merkle87] Merkle, R.C., "A Digital Signature Based on a Conventional Encryption Function," Advances in Cryptology - CRYPTO '87, Lecture Notes in Computer Science, vol. 293, Springer, 1988. DOI: 10.1007/3-540-48184-2_32
(The Merkle tree structure used in the transparency log design of §6.4.)

[Rekor] Sigstore Project, "Rekor: Software Supply Chain Transparency Log."
https://github.com/sigstore/rekor
https://docs.sigstore.dev/logging/overview/
(Production implementation of an RFC 6962-compatible transparency log. MAY be used as the transparency log backend for federation deployments that do not require a private log.)

[Sigstore] Sigstore Community, "Sigstore: A New Standard for Signing, Verifying, and Protecting Software."
https://www.sigstore.dev/
(The broader Sigstore ecosystem that Rekor is part of. The trust list governance model in §6.6 is conceptually similar to Sigstore's root-of-trust structure.)

[Spotlighting24] Hines, K., Lopez, G., Hall, M., Zarfati, F., Zunger, Y., and Kiciman, E., "Defending Against Indirect Prompt Injection Attacks with Spotlighting," Microsoft Research, arXiv:2403.14720, March 2024.
https://arxiv.org/abs/2403.14720
(In-band delimiter marking that serves as this specification's Layer B advisory layer (§4.2). Spotlighting reduces injection attack success rates from >50% to <2% but not to zero; the deterministic Layer A controls (§4.2) close the remaining gap.)

[StruQ24] Chen, S., Piet, J., Sitawarin, C., and Wagner, D., "StruQ: Defending Against Prompt Injection with Structured Queries," UC Berkeley, arXiv:2402.06363, February 2024.
https://arxiv.org/abs/2402.06363

[SecAlign24] Chen, S., Zharmagambetov, A., Mahloujifar, S., Chaudhuri, K., Wagner, D., and Guo, C., "SecAlign: Defending Against Prompt Injection with Preference Optimization," arXiv:2410.05451, October 2024.
https://arxiv.org/abs/2410.05451
(StruQ and SecAlign train models to treat structured prompt channels differently from data channels. Complementary to the proxy-side controls in this specification; both approaches reduce injection risk orthogonally.)

[DLM00] Myers, A.C., and Liskov, B., "Protecting Privacy using the Decentralized Label Model," ACM Transactions on Software Engineering and Methodology, 9(4):410-442, 2000.
https://www.cs.cornell.edu/andru/papers/iflow-tosem.pdf
(The Decentralized Label Model (DLM) provides the formal foundation for "labels travel with data; join on combine; gate at sink" - the minimal subset this specification implements in §5.6 and §7.5.)

[Willison23] Willison, S., "Delimiters won't save you from prompt injection," May 2023.
https://simonwillison.net/2023/May/11/delimiters-wont-save-you/
(Foundational argument that in-band delimiters are insufficient as the sole injection defense. Motivates the deterministic signed Layer A control.)

[Willison25] Willison, S., "The Lethal Trifecta," June 2025.
https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
(Framing of the three conditions that make an agent unconditionally exploitable: private data + untrusted content + exfiltration channel. The Biba enforcement model in §4.2 and this specification directly addresses this threat model.)

[MCP-INSPECTOR] Anthropic, "MCP Inspector - a tool for testing and debugging MCP servers."
https://modelcontextprotocol.io/docs/tools/inspector
(Reference tool for validating MCP protocol conformance during implementation.)

[MCP-SECURITY] Anthropic, "MCP Security Considerations," Model Context Protocol documentation.
https://modelcontextprotocol.io/docs/concepts/transports#security-considerations
(Anthropic's own security guidance for MCP transport layer. This specification addresses the content integrity and provenance layer above the transport.)

[MCP-BLOG] Anthropic, "Introducing the Model Context Protocol," November 2024.
https://www.anthropic.com/news/model-context-protocol
(Original Anthropic blog post announcing MCP. Establishes the intended use cases and ecosystem model that motivates the security extensions in this document.)

[C2PA-EXPLAINER] Coalition for Content Provenance and Authenticity, "C2PA Explainer," 2024.
https://c2pa.org/
(Non-normative explainer of C2PA concepts. The camera → AI generator → manipulation attestation chain described here motivates the multi-agent pipeline provenance design in §7.5.)

[RTBAS25] Zhong, P.Y., Chen, S., Wang, R., McCall, M., Titzer, B.L., Miller, H., and Gibbons, P.B., "RTBAS: Defending LLM Agents Against Prompt Injection and Privacy Leakage," Carnegie Mellon University / Two Sigma, arXiv:2502.08966, February 2025.
https://arxiv.org/abs/2502.08966
(Adapts information-flow control to tool-based agent systems, auto-executing only tool calls that preserve integrity and confidentiality and prompting for user confirmation otherwise - the per-call analogue of the sink-gating model in §5.6 and the human-in-the-loop checkpoint in §7.6.)

---

## Appendix A. Implementation Conformance Checklist

This appendix provides a machine-checkable implementation checklist. Each item references the section that defines the requirement. Requirements are written so that conformance can be objectively tested: each MUST or MUST NOT statement describes observable behavior (a field value, a cryptographic operation, a denial decision, a log entry) that can be verified without inspecting implementation internals. Test vectors in Appendix B provide concrete inputs and expected outputs for the cryptographic and policy-enforcement requirements.

### A.1. Content Classification (Section 5)

```
[ ] A.1.1  Gateway assigns content class from registry; MUST NOT accept
           self-assertion from tool server.                        [§5.1 P1]
[ ] A.1.2  Content class is included in Layer A signing input,
           bound to the content hash.                             [§5.1 P2]
[ ] A.1.3  When multiple content types are detected, effective class
           is computed as the union (strictest floor).            [§5.1 P3]
[ ] A.1.4  Content class axis is evaluated independently of integrity
           rank axis; neither subsumes the other.                 [§5.1 P4]
[ ] A.1.5  Unknown or absent content class defaults to
           external-content/raw with conf_floor=public.           [§5.1 P5]
[ ] A.1.6  Registry is append-only; existing entries are never
           removed or semantically modified.                      [§5.1 P6]
[ ] A.1.7  content_class.effective field is computed by gateway,
           not set by tool server.                                [§5.3]
[ ] A.1.8  content_class.allowlist_required is true if ANY class
           in the union has allowlist_required=true.              [§5.5]
[ ] A.1.9  Sink policy evaluation follows the defined order:
           Biba → BLP → denylist → allowlist → require-class →
           max-additional.                                        [§5.6]
[ ] A.1.10 Denylist takes precedence over allowlist.              [§5.6]
[ ] A.1.11 require_content_class=true sinks MUST reject results
           with absent content_class field.                       [§5.6]
[ ] A.1.12 top-secret class ALWAYS requires allowlist entry,
           regardless of sink conf_level.                         [§5.4]
```

### A.2. Federated Trust (Section 6)

```
[ ] A.2.1  Trust List signature is verified against pre-configured
           governance root public key(s).                         [§6.2]
[ ] A.2.2  Trust List with sequence number <= last accepted sequence
           is rejected (rollback prevention).                     [§6.2]
[ ] A.2.3  Trust List past expires_at is rejected.                [§6.2]
[ ] A.2.4  Trust scope is enforced by receiving verifier, not
           by labeler.                                            [§6.3]
[ ] A.2.5  Envelope integrity_rank is checked against
           trust_scope.max_integrity_rank.                        [§6.3]
[ ] A.2.6  Envelope server_id is checked against
           trust_scope.tool_server_ids or pattern.                [§6.3]
[ ] A.2.7  Envelope content_class.effective is checked against
           trust_scope.content_classes and
           trust_scope.content_classes_excluded.                  [§6.3]
[ ] A.2.8  For entries with inclusion_proof_required=true, inclusion
           proof MUST be verified before trusting entry.          [§6.4]
[ ] A.2.9  New sub-CAs with uncached inclusion proofs fail closed
           when log is unavailable.                               [§6.4]
[ ] A.2.10 Trust List is refreshed at least every 24 hours.       [§6.7]
[ ] A.2.11 In Relay mode, Gateway A validates before relaying;
           downstream consumer also validates independently.      [§6.5]
[ ] A.2.12 In Re-Sign mode, outer integrity_rank = min(outer, inner);
           outer content class is stricter of A and B.            [§6.5]
[ ] A.2.13 forwarded_envelope is included unchanged in Re-Sign mode;
           forwarded_envelope_hash is in signing input.           [§6.5]
[ ] A.2.14 Trust List update requires M-of-N governance key
           signatures.                                            [§6.6]
```

### A.3. Universal AI Provenance (Section 7)

```
[ ] A.3.1  APE is signed using same sub-CA + labeler EKU
           infrastructure as Layer A (§4.2).                      [§7.2]
[ ] A.3.2  APE sig covers JCS canonical JSON of all fields
           except sig.                                            [§7.2]
[ ] A.3.3  artifact_hash binds APE to exact artifact bytes
           (UTF-8 for text, JCS for structured, raw for binary).  [§7.2]
[ ] A.3.4  model_commitment_hash covers model_id || model_version
           || inference_endpoint.                                 [§7.2.1]
[ ] A.3.5  generation_params_hash covers canonical JSON of
           generation params including system_prompt_hash.        [§7.2.2]
[ ] A.3.6  pipeline_path records each step with agent_id,
           action, integrity_rank, and timestamp.                 [§7.5]
[ ] A.3.7  APE top-level integrity_rank = min(step.integrity_rank
           for all steps in pipeline_path).                       [§7.5]
[ ] A.3.8  Intermediate artifacts carry their own APEs;
           chain is auditable at each stage.                      [§7.6]
[ ] A.3.9  No mechanism exists for a later agent to promote
           integrity rank of tainted upstream artifact.           [§7.6]
[ ] A.3.10 Model revocation list is checked during APE verification;
           revoked models have their rank overridden.             [§7.7]
[ ] A.3.11 C2PA assertion type io.mcp-security-platform.ai-provenance
           is used when embedding APE in C2PA manifest.           [§7.4]
[ ] A.3.12 APE verification result is reported as trust signal
           in C2PA manifest verification.                         [§7.4]
```

### A.4. Extended Envelope Schema (Section 8)

```
[ ] A.4.1  v0.1-conformant envelopes (no extension fields) are
           accepted without error.                                [§8.1]
[ ] A.4.2  schema_version="v0.2" when any extension field from
           §5-§7 is present.                                      [§8.1]
[ ] A.4.3  Consumers prefer v0.2 key over v0.1 when both present. [§8.1]
[ ] A.4.4  Absent content_class defaults to external-content/raw. [§8.1]
[ ] A.4.5  Signing input uses forwarded_envelope_hash (not inline
           forwarded_envelope) for nested envelope chains.        [§8.4]
```

---

## Appendix B. Test Vectors

This appendix provides minimal test vectors for verifying implementation correctness. These are normative targets for a conformant implementation of §5-§7.

**Executable form.** These vectors are run as a suite against a spec oracle at [`proxy/tests/spec0002/test_appendix_b_vectors.py`](https://github.com/webr0ck/mcp-security-platform/blob/main/proxy/tests/spec0002/test_appendix_b_vectors.py) in the reference implementation. Read what that does and does not prove: it evaluates the rows below against an oracle implementing this paper's algorithms, so it shows the normative logic is internally self-consistent - **not** that the gateway enforces it. A failure there means this specification is wrong (or the oracle drifted from it). Whether a given section is wired into the live request path is answered only by [`STATUS.md`](https://github.com/webr0ck/mcp-security-platform/blob/main/proxy/tests/spec0002/STATUS.md), and today §5-§7 answer "no".

### B.1. Content Class Policy Evaluation

The following table provides test cases for the two-axis policy evaluation (Section 5.4). Each row specifies: effective_integrity_rank, effective_content_class, sink_required_integrity, sink_conf_level, sink_allowlist (relevant entries), expected decision.

```
+------+------------------------+------------------+-------------+------------------+--------+
| Rank | Effective Class        | Sink Req. Int.   | Sink Level  | Allowlist        | Result |
+------+------------------------+------------------+-------------+------------------+--------+
|  0   | search-result/web      |  1               | public      | none             | DENY   |
|      | (Biba fails: 0 < 1)    |                  |             |                  |        |
+------+------------------------+------------------+-------------+------------------+--------+
|  1   | search-result/web      |  1               | public      | none             | ALLOW  |
|      | (Biba: 1>=1, BLP:      |                  |             |                  |        |
|      | public<=public, no     |                  |             |                  |        |
|      | allowlist req.)        |                  |             |                  |        |
+------+------------------------+------------------+-------------+------------------+--------+
|  2   | pii/email              |  2               | public      | none             | DENY   |
|      | (BLP fails:            |                  |             |                  |        |
|      | restricted > public)   |                  |             |                  |        |
+------+------------------------+------------------+-------------+------------------+--------+
|  2   | pii/email              |  2               | restricted  | [pii/email]      | ALLOW  |
|      | (Biba+BLP pass,        |                  |             |                  |        |
|      | allowlist match)       |                  |             |                  |        |
+------+------------------------+------------------+-------------+------------------+--------+
|  2   | pii/email              |  2               | restricted  | none (but req.)  | DENY   |
|      | (allowlist required    |                  |             |                  |        |
|      | and empty)             |                  |             |                  |        |
+------+------------------------+------------------+-------------+------------------+--------+
|  3   | financial/trade-order  |  3               | secret      | [financial/      | ALLOW  |
|      |                        |                  |             | trade-order]     |        |
+------+------------------------+------------------+-------------+------------------+--------+
|  1   | financial/trade-order  |  3               | secret      | [financial/      | DENY   |
|      | (Biba fails: 1 < 3)    |                  |             | trade-order]     |        |
+------+------------------------+------------------+-------------+------------------+--------+
|  3   | financial/trade-order  |  3               | internal    | [financial/      | DENY   |
|      | (BLP fails:            |                  |             | trade-order]     |        |
|      | secret > internal)     |                  |             |                  |        |
+------+------------------------+------------------+-------------+------------------+--------+
|  2   | pii/email + fin/bal    |  2               | secret      | [pii/email,      | ALLOW  |
|      | effective=pii/email    |                  |             | financial/*]     |        |
|      | (stricter of the two)  |                  |             |                  |        |
+------+------------------------+------------------+-------------+------------------+--------+
```

### B.2. Pipeline Integrity Rank Propagation

The following traces verify that the minimum operation correctly propagates taint through a multi-agent pipeline (Section 7.6).

**Trace B.2.1 - web taint propagates to final output**:

```
Step 1: agent-search calls web-search-mcp
        tool result: integrity_rank=0 (untrustedPublic)
        step_rank = 0

Step 2: agent-summarizer processes step 1 output
        agent own rank = 2 (internal identity)
        input ranks: [0]
        step_rank = min(2, 0) = 0

Step 3: agent-composer processes step 2 output
        agent own rank = 2
        input ranks: [0]
        step_rank = min(2, 0) = 0

Final APE integrity_rank = min(0, 0, 0) = 0
EXPECTED: Final artifact has integrity_rank=0
EXPECTED: Any sink with required_integrity >= 1 DENIES this artifact
```

**Trace B.2.2 - all-internal pipeline preserves rank**:

```
Step 1: agent-reader calls internal-docs-mcp
        tool result: integrity_rank=2 (internal)
        step_rank = 2

Step 2: agent-summarizer processes step 1 output
        agent own rank = 2
        input ranks: [2]
        step_rank = min(2, 2) = 2

Step 3: agent-composer processes step 2 output
        agent own rank = 2
        input ranks: [2]
        step_rank = min(2, 2) = 2

Final APE integrity_rank = min(2, 2, 2) = 2
EXPECTED: Final artifact has integrity_rank=2
EXPECTED: Sinks with required_integrity <= 2 may receive this artifact
         (subject to BLP and allowlist checks)
```

**Trace B.2.3 - mixed pipeline: one tainted step contaminates all downstream**:

```
Step 1: agent-reader calls internal-docs-mcp
        tool result: integrity_rank=2
        step_rank = 2

Step 2: agent-enricher calls web-search-mcp
        tool result: integrity_rank=0
        inputs: [step1_output, web_result]
        step_rank = min(2, 2, 0) = 0

Step 3: agent-composer processes step 2 output
        inputs: [step2_output]
        step_rank = min(2, 0) = 0

Final APE integrity_rank = min(2, 0, 0) = 0
EXPECTED: Final artifact has integrity_rank=0 despite step 1 being clean
EXPECTED: Introducing ONE web search at step 2 taints the entire
          downstream pipeline
```

### B.3. Trust Scope Enforcement Test Cases

The following test cases verify trust scope enforcement (Section 6.3).

**TC B.3.1 - labeler asserts rank above max_integrity_rank**:

```
Trust List entry:
  org_id: org-a
  trust_scope.max_integrity_rank: 1

Received envelope:
  integrity_rank: 2
  sub_ca_spki_fp: (matches org-a entry)

EXPECTED: REJECT - integrity_rank (2) > max_integrity_rank (1)
EXPECTED: Log event: trust_scope_violation, field: integrity_rank
```

**TC B.3.2 - labeler asserts excluded content class**:

```
Trust List entry:
  org_id: org-a
  trust_scope.content_classes: ["search-result/*"]
  trust_scope.content_classes_excluded: ["system-credential"]

Received envelope:
  content_class.effective: "system-credential"
  sub_ca_spki_fp: (matches org-a entry)

EXPECTED: REJECT - system-credential is in content_classes_excluded
EXPECTED: Log event: trust_scope_violation, field: content_class_excluded
```

**TC B.3.3 - labeler asserts class outside content_classes whitelist**:

```
Trust List entry:
  org_id: org-a
  trust_scope.content_classes: ["search-result/*", "ai-output/*"]

Received envelope:
  content_class.effective: "pii/email"
  sub_ca_spki_fp: (matches org-a entry)

EXPECTED: REJECT - pii/email does not match search-result/* or ai-output/*
EXPECTED: Log event: trust_scope_violation, field: content_class_not_in_scope
```

**TC B.3.4 - server_id not in allowed server list**:

```
Trust List entry:
  org_id: org-a
  trust_scope.tool_server_ids: ["server-search", "server-kb"]

Received envelope:
  server_id: "server-financial"
  sub_ca_spki_fp: (matches org-a entry)

EXPECTED: REJECT - server-financial not in tool_server_ids
EXPECTED: Log event: trust_scope_violation, field: server_id
```

---

## Appendix C. Threat Model Summary

This appendix provides a consolidated threat model for this extension proposal, mapping each threat to the section that mitigates it. This is intended as a reference for security reviewers performing appsec sign-off.

| # | Threat | Mitigated By | Section |
|---|--------|--------------|---------|
| T-01 | Tool server self-asserts favorable content class | Proxy-assigned classification (P1; mirrors §4.2 integrity rank principle) | §5.1 |
| T-02 | Network intermediary reclassifies content post-signing | Content class in Layer A signing input (P2; same defense as §4.2 content hash) | §5.1 |
| T-03 | Mixed-class result downgraded to least-sensitive class | Union semantics: strictest floor wins (P3) | §5.1 |
| T-04 | Integrity rank used as content sensitivity proxy | Axes are orthogonal; both evaluated independently (P4) | §5.1 |
| T-05 | Unclassified result bypasses class-based policy | Fail-closed default: external-content/raw (P5) | §5.1 |
| T-06 | Class registry manipulated to lower a floor | Append-only registry; updates require operator key (P6) | §5.1 |
| T-07 | Cross-org envelope from malicious sub-CA | Trust List + SPKI pinning + trust scope | §6.2, §6.3 |
| T-08 | Trust List rollback to include revoked sub-CA | Sequence number monotonicity enforcement | §6.2 |
| T-09 | Governance key compromise enables rogue Trust List | M-of-N governance signature requirement | §6.6 |
| T-10 | Sub-CA added without governance approval | Transparency log + monitoring requirement | §6.4 |
| T-11 | Trust List distribution server compromise | Trust List signature verification (not server-trust) | §6.2 |
| T-12 | Split-view transparency log attack | Gossip protocol (Future Work, §13) | §9.3 |
| T-13 | Log availability attack blocks new sub-CA validation | Fail-closed for uncached inclusion proofs | §9.3 |
| T-14 | Labeler asserts rank/class outside trust scope | Trust scope enforcement by receiving verifier | §6.3 |
| T-15 | Model ID spoofing in APE | model_commitment_hash commits to identity tuple | §7.2.1 |
| T-16 | Pipeline path truncation hides tainted step | Path completeness check; artifact_id chain validation | §9.5 |
| T-17 | Agent promotes tainted artifact integrity rank | No promotion mechanism; taint is irreversible | §7.6 |
| T-18 | Compromised model output trusted indefinitely | Model revocation list in Trust List | §7.7 |
| T-19 | APE artifact hash mismatch (tampering) | Artifact hash verified during APE sig check | §7.2 |
| T-20 | Relay Gateway forwards unvalidated envelope | Relay mode requires validation before forwarding | §6.5 |

---

```
Author's Address

   Alexander Romanov
   Cyber Defence Unit Manager

   Reference implementation: github.com/webr0ck/mcp-security-platform
   Blog: purplehootie.com
```

---

---

## Appendix D. Deployment Scenarios

This appendix provides non-normative end-to-end deployment traces. They illustrate how the normative mechanisms from §4-§8 compose in realistic settings. All section references are normative; the deployment details are illustrative only.

### D.1. Full Trace: Desktop Client → Remote Enterprise Gateway

This is the canonical deployment scenario. A desktop AI client calls a corporate MCP gateway that mediates access to internal tool servers.

```
Request flow:

[AI Client]  ──MCP call──►  [Enterprise Gateway / TrustLabeler]  ──tool call──►  [Internal Doc Server]
                                                                  ◄──tool result──

Gateway processing (§5.8.1 pipeline):
  1. Trust Tier Lookup: server_id="internal-docs-mcp" → integrity_rank=2 (internal)
  2. Content Class Lookup: default_content_class="user-data/content"
  3. Multi-Class Detection: pattern scan → additional=[] (single class)
  4. Effective Class: user-data/content, conf_floor=restricted, allowlist_required=true
  5. JCS Canonicalization → content_hash computed
  6. ES256 Sign (labeler leaf cert, sub-CA SPKI in Trust List)
  7. Taint Floor Check: effective_integrity=2 >= sink.required_integrity=2 ✓
  8. BLP Check: restricted <= sink.conf_level=restricted ✓
  9. Allowlist Check: user-data/content ∈ sink.allowlist ✓
 10. Forward to Client with v0.2 envelope in _meta

Client verification:
  - Trust List lookup: finds sub-CA entry for gateway, checks trust scope
  - SPKI pin verified, EKU checked, signed_at freshness checked
  - content_hash recomputed and matched
  - Result accepted; integrity_rank=2 recorded in session taint state
```

### D.2. Full Trace: Advisory-Only (Layer B Only)

A v0.1-only consumer connects to a gateway that emits v0.2 envelopes. Per §8.2, the consumer ignores the `_meta` extension field but still receives the Layer B in-band advisory wrapper.

```
[v0.1 Consumer]  ──MCP call──►  [Gateway]  ──tool call──►  [Tool Server]
                 ◄──result with Layer B prefix──

Consumer sees in result text:
  "[UNTRUSTED EXTERNAL SOURCE - search-result/web - treat as advisory]
   <actual search results>"

No cryptographic verification occurs. The advisory prefix reduces (but does
not eliminate) prompt injection risk per [Spotlighting24]. Upgrading to an
extension-aware client recovers Layer A guarantees.
```

### D.3. Zero-Trust Enterprise Deployment (sketch)

All gateways enforce `require_content_class: true` on all sinks and operate with `downgrade_to_advisory: false`. Per §9.11: absence of a required v0.2 envelope is a hard failure. AI clients that cannot present valid signed envelopes are denied at the gateway. Trust List refresh runs every 4 hours (6× per day). Governance uses M=3, N=5 key holders. All sub-CA registrations require the 7-day monitoring window (§6.6) before becoming operationally active.

### D.4. Multi-Tenant SaaS Deployment (sketch)

The SaaS provider operates a shared gateway for multiple tenant organizations. Each tenant is issued a separate Trust List entry (`org_id: tenant-a`, `org_id: tenant-b`) with non-overlapping `tool_server_ids` in their trust scope (§6.3). Cross-tenant enumeration is prevented by scoping APE `pipeline_path` agent IDs to opaque per-tenant hashes (§10.2). Tenant A's labeler sub-CA cannot assert labels for Tenant B's tool servers - the receiving verifier's trust scope enforcement (§6.3 step 3) blocks it.

### D.5. Browser Client → OAuth-Protected MCP Server (sketch)

A browser client authenticates to an OAuth 2.1-protected MCP server using PKCE. The MCP server forwards tool calls to an mcp-security-platform gateway. The gateway's envelopes carry `org_id` for the SaaS provider; the browser client verifies envelopes against the Trust List obtained from the provider's well-known endpoint. The browser client operates in advisory fallback for tool results that arrive without a v0.2 envelope (legacy tool servers) and enforcing mode for extension-aware servers. The `required_integrity` sink policy for the browser's local note-storage sink is set to 1 (trustedPublic minimum), blocking untrusted web search results from driving write operations.

---

*End of MCP-SEP-1913-EXT*

---

## Community Feedback

The authors welcome feedback via the MCP community discussion channels:

- [GitHub Discussions - spec feedback & RFCs](https://github.com/modelcontextprotocol/specification/discussions) - primary channel; where the spec authors watch
- [GitHub Issues - spec bugs & ambiguities](https://github.com/modelcontextprotocol/specification/issues)
- [Discord - community Q&A, implementations, tooling](https://discord.gg/anthropic) - `#mcp` channel
- [MCP docs & community links](https://modelcontextprotocol.io)

