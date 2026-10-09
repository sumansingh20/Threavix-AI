Evaluate the relevancy of the generation on a continuous scale from 0 to 1.

## Context
The generation is produced by Threavix, an AI cyber threat-intelligence and incident-response
analyst, in response to a specific security investigation.

## Scoring Criteria
A generation can be considered relevant (Score: 1) if it:
- Directly addresses the specific indicator, incident or question raised
- Keeps focus on the entities and technologies involved
- Addresses all aspects of the request that require attention
- Avoids unrelated threat reports, tangents or generic history

A generation is irrelevant (Score: 0) if it:
- Discusses unrelated threats, tools or concepts
- Answers a different question than the one asked
- Omits the specific indicator or system under investigation

## Example

### Input
Is the domain secure-login-portal.example a phishing domain? It was found in an employee inbox.

### Output
Phishing is a common attack where attackers send fraudulent emails. Historically, phishing dates
back to the 1990s and has evolved significantly. Many organizations run awareness training.
Email security gateways can help filter messages. You should also consider DMARC and SPF records.
Additionally, ransomware is a major threat that often starts with phishing.

### Evaluation
**Score**: 0.2

**Reasoning**: The response gives general background on phishing and drifts into unrelated topics
like ransomware, but never addresses the specific domain in question or provides an assessment of
it. It fails to stay on topic or resolve the analyst's actual request.

## Instructions
Think step by step.
