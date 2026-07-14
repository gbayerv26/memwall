# Security policy

memwall is a security tool, so reports about its own weaknesses are
especially welcome — including heuristic bypasses.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(Security tab -> Report a vulnerability), or email ggbayervaldivia@gmail.com. Do not open a
public issue for anything exploitable. Target first response: 72 hours.

## In scope

- Ways to smuggle a poisoned memory past the rule engine or the gateway
  (novel bypass patterns are valid reports — they become new rules)
- Ways to make the gateway corrupt, drop, or leak protocol traffic
- Ways to tamper with the audit trail or quarantine store

## Known, documented trade-offs (not vulnerabilities)

- The gateway **fails open** on internal scan errors by design, so it never
  takes your memory server down. Deployments that prefer fail-closed should
  say so in an issue — it is a planned policy option.
- Heuristics are a triage layer with false negatives by design; the judge
  pass exists to raise precision, not to guarantee it.
