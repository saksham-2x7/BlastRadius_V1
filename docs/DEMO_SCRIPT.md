# Demo video script (about 2:30)

Record the live site, one take, with the advisor panel open.

1. **0:00 The problem (15s).** "Teams have thousands of CVEs and time to fix a few dozen. CVSS says what is severe, not what an attacker can actually reach."
2. **0:15 Scan (20s).** Open the dashboard, click Run scan. "FalkorDB holds the network as a graph. One Cypher query finds every route from the internet to the customer database: 4 paths."
3. **0:35 The decoy (15s).** Point at `legacy-ftp` (CVSS 10.0) and `batch-legacy` (9.8): "Both are on 0 paths. Loud, but unreachable."
4. **0:50 Algorithms (25s).** Ask the advisor: **"Where is the choke point?"** Show the `get_choke_points` step. "That is FalkorDB's own betweenness-centrality algorithm, called by the agent through MCP. `api-gateway` carries 3 of 4 paths."
5. **1:15 Explain (15s).** Ask: **"Show the shortest route an attacker could take."** Show `explain_attack_path`. "Shortest-path algorithm: the answer cites the exact route."
6. **1:30 Act (35s).** Ask: **"Fix everything that is safe, and escalate the rest."** Show simulate, then apply. "It applied the low-risk fixes and the dashboard updated. For the choke point it refused: the graph decides the tier, not the model, so a human has to approve."
7. **2:05 Ticket (15s).** Ask: **"Draft a Jira ticket for the top finding."** "A ready-to-file ticket with the graph evidence, simulated impact and rollback note."
8. **2:20 Memory + close (10s).** Ask: **"What did you do earlier?"** "Every decision is stored in FalkorDB and survives sessions. Live CISA KEV and EPSS feeds, MIT licensed, self-hostable."

Tips: run "Restore demo for everyone" first so you start at 4 paths; keep the dashboard visible behind the panel.
