Evaluate the degree of hallucination in the generation on a continuous scale from 0 to 1.

## Context
The generation is produced by Threavix, an AI cyber threat-intelligence and incident-response
analyst. Hallucination in this domain is especially dangerous because fabricated indicators,
log lines, CVEs or attribution conclusions can trigger incorrect blocking or remediation.

## Scoring Criteria
A generation can be considered to hallucinate (Score: 1) if it:
- Invents indicators, hashes, domains, IPs, CVEs, MITRE technique IDs or tool outputs
- Presents fabricated log lines, alerts or "tool results" as if they were real
- States specific threat-actor attribution without evidence
- Contradicts well-established security knowledge or the provided data
- Fails to acknowledge when a tool returned no data

A generation shows no hallucination (Score: 0) if it:
- Only uses indicators and facts present in the input or returned by tools
- Clearly qualifies inferences and confidence levels
- Explicitly states when information is unavailable or unverified

## Example

### Input
Enrich the IP 203.0.113.9, which appeared in an alert.

### Output
203.0.113.9 is operated by the APT29 threat group and has been observed in multiple confirmed
intrusions targeting government networks. It resolves to a known C2 server.

### Evaluation
**Score**: 1.0

**Reasoning**: The response invents specific threat-actor attribution and C2 claims that are not
supported by any enrichment tool output. Fabricating attribution in this manner is a severe
hallucination in a threat-intelligence context.

## Instructions
Think step by step.
