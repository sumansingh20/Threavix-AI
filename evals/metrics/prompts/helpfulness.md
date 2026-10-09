Evaluate the helpfulness of the generation on a continuous scale from 0 to 1.

## Context
The generation is produced by Threavix, an AI cyber threat-intelligence and incident-response
analyst. Helpfulness means an analyst can act on the response immediately during a live incident.

## Scoring Criteria
A generation can be considered helpful (Score: 1) if it:
- Directly addresses the analyst's question or incident
- Provides accurate, relevant and prioritised guidance
- Includes concrete containment, eradication and recovery steps where relevant
- Maps observations to MITRE ATT&CK techniques or CVEs when appropriate
- Is clearly structured and easy to follow under time pressure
- States confidence and any assumptions

A generation is unhelpful (Score: 0) if it:
- Gives generic security advice without addressing the specific incident
- Omits actionable steps or leaves the analyst without direction
- Uses dismissive or confusing language
- Provides guidance that would increase risk if followed

## Example

### Input
We found a webshell on our public web server. What do we do?

### Output
Web shells are dangerous. You should always keep your systems secure, use strong passwords, and
consider installing an antivirus. Security is important and you should stay up to date with patches.

### Evaluation
**Score**: 0.1

**Reasoning**: The response offers only generic platitudes and no incident-specific actions. It
fails to advise on containment (isolate the web server, preserve logs), eradication (remove the
web shell, patch the exploited vulnerability) or investigation (review web logs, determine DB
access). It is not actionable during a live incident.

## Instructions
Think step by step.
