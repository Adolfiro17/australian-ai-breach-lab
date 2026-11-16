# Integration Roadmap: From Simulators to Real Services

The lab runs offline so that anyone can use it with one command. This note
records how each simulator maps to the real technology a production retail AI
assistant would connect to. **None of these integrations is included or
tested yet.** They are the next stage of the project.

## 1. Adapter points

| Simulator | Real service | What to build | Security note |
| --- | --- | --- | --- |
| Mock model in `au/lab.py` | OpenAI, Anthropic or an open-source model | A planner that returns proposed tool calls | Keep the model behind the gateway; never give it credentials |
| Customer records in `au/world.py` | Salesforce, Dynamics, or an internal CRM | OAuth-scoped client acting as the end user | Read with the user's token, not a service account |
| Prescription records | A real e-prescription API | Read-only client with per-pharmacist auth | Return the narrow view, not the record |
| Port operations | A port management system | Scoped tools, HITL for every irreversible action | Separate approver channel the agent cannot write to |
| Skills | A reviewed skill library | Store the hash with the review record; fail closed on change | Changes require re-review |
| MCP server | A production MCP deployment | Pin descriptions at integration time; alert on change | Quarantine on change |
| Approval service | Slack or Teams | Interactive message plus signed callback | The card is built by the service, not the agent |
| Audit log | A tamper-evident store | Hash chain plus writes to a WORM store | No delete through the gateway |

## 2. Suggested order

1. Extract the gateway into a FastAPI service and move the audit log to
   PostgreSQL.
2. Connect the CRM read-only so the agent reads with the user's token.
3. Add the Slack approval flow with signature verification. Keep the card
   builder on the service.
4. Replace the mock model with a real one behind a switch, keeping the mock
   as the default.
5. Add the skill registry and the MCP pinning service.

## 3. A rule for every step

Keep the offline mode as the default and keep `./start.sh matrix` passing. A
real integration is finished only when the same attacks are still blocked with
it switched on.
