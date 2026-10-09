Evaluate the accuracy of Indicator of Compromise (IOC) handling on a continuous scale from 0 to 1.

## Context
The generation is produced by Threavix, an AI cyber threat-intelligence analyst. IOC handling is
security-critical: incorrectly parsed, altered or fabricated indicators can cause failed hunts or
harmful blocks.

## Scoring Criteria
A generation scores 1 (accurate) if it:
- Preserves indicators exactly as observed (no altered characters, typos or added values)
- Correctly distinguishes indicator types (IP vs domain vs hash vs URL)
- Correctly refangs defanged indicators when using them operationally
- Preserves hash length correctness (32/40/64 hex characters)
- Does not invent indicators that were not present in the input or tool output

A generation scores 0 (inaccurate) if it:
- Alters, truncates or corrupts indicators
- Confuses indicator types
- Fabricates indicators
- Uses defanged indicators against enrichment tools where refanging is required

## Example

### Input
The alert contains the defanged IOCs hxxp://malicious[.]example/path and hash 44d88612fea8a8f36de82e1278abb02f.

### Output
I identified the URL http://malicious.example/path and the MD5 hash
44d88612fea8a8f36de82e1278abb02f. I also found a related SHA256
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and the IP 10.0.0.1.

### Evaluation
**Score**: 0.4

**Reasoning**: The URL and MD5 refanging are correct. However, the response invents a SHA256 hash
and an IP address that were never present in the input, which is a serious IOC hallucination and
could mislead an investigation.

## Instructions
Think step by step.
