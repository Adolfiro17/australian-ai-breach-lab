# Attribution

## Design sources

The lab is organised around two bodies of work.

1. **A set of AI security lecture notes** supplied by the author, which walk
   through a three-layer framework for securing agentic AI (information,
   instructions, actions), with a sales-agent scenario and red teaming as the
   wrapper. Those notes drove the control vocabulary used here and the mapping
   of each module to a lecture layer.

2. **Public reporting on recent Australian cyber incidents**. The lab's
   modules are named after and loosely themed on real incidents; the scenarios
   themselves use fictional data, roles and systems. Nothing in this repository
   should be read as a factual account of any specific real incident. Each
   module references the incident class rather than the operational detail of a
   named breach.

   - Optus (2022): a widely reported API-side exposure of customer records.
   - Medibank (2022): a widely reported ransomware and data-extortion incident.
   - Latitude Financial (2023): a widely reported incident involving third-party
     credentials.
   - DP World Australia (2023): a widely reported ransomware incident that
     disrupted port operations.
   - MediSecure (2024): a widely reported incident affecting a national
     e-prescription system.
   - Qantas (2025): a widely reported incident affecting a third-party call
     centre.
   - A fictional 2026 Australian retailer incident is used as the capstone. It
     is not a report of any real retailer's breach.

   The reader is referred to the relevant public reporting and to the Office of
   the Australian Information Commissioner for the actual facts of each case.

## MAESTRO framework

Module 8 applies the MAESTRO (Multi-Agent Environment, Security, Threat, Risk
and Outcome) framework to the lab's own architecture. The author's own PhD
direction extends MAESTRO, along with the OWASP LLM Top 10 and MITRE ATLAS, to
explicitly name the human-in-the-loop trust boundary as a distinct failure
mode.

## Format inspiration

The attack-and-defend lab format, with each module paired to an automated test,
follows the pattern used in the author's companion labs:

- [Secure Agentic SOC Lab](https://github.com/Adolfiro17/secure-agentic-soc-lab)
- [Agentic Commerce Security Lab](https://github.com/Adolfiro17/agentic-commerce-security-lab)

## References

- OWASP Top 10 for LLM Applications (2025) and OWASP agentic security guidance
- OWASP MCP Top 10 (2026)
- MITRE ATLAS
- NIST AI Risk Management Framework
- Australian Voluntary AI Safety Standard (ten guardrails)
- Office of the Australian Information Commissioner, Notifiable Data Breach
  reports
- Simon Willison's writing on prompt injection and the "lethal trifecta"

Wazuh, Slack, Jira, Salesforce and other named technologies are trademarks of
their respective owners. This lab simulates them and is not affiliated with or
endorsed by any of them.

## Licence

The lab is released under the MIT licence. See [LICENSE](LICENSE).
