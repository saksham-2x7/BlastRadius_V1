# Why the scariest CVE is often the least dangerous: an agent that reasons over attack paths with FalkorDB

Security teams drown in findings. A typical scanner report lists thousands of CVEs, and the default way to sort them is CVSS. But CVSS measures how bad a bug is in isolation, not whether an attacker can reach it. In our sample network, a CVSS 10.0 Log4Shell sits on a legacy FTP host that leads nowhere. A modest 7.5 sits on the one gateway that three of the four routes to the customer database pass through.

BlastRadius is an agent that works from the connections, not the scores.

## The graph does the work
We model hosts, network reachability, data stores and findings in FalkorDB:

```
(:Internet)-[:CAN_REACH]->(:Host)-[:CAN_REACH]->(:DataStore {crown})
(:Host)-[:HAS_FINDING]->(:Finding {cve, epss, kev, ...})
```

"Which routes can an attacker take from the internet to the database?" is a bounded multi-hop traversal, one Cypher query. "Which host matters most?" is FalkorDB's `algo.betweenness`. "What is the shortest route?" is `algo.SPpaths`. "What if I patch this?" is the same path query with one finding treated as patched. In a relational database each of these would be a pile of recursive joins; here they are a few lines each.

## An agent that acts, with limits
The advisor reaches the graph through a real MCP server. It can rank choke points, explain a route, simulate a fix, draft a Jira or GitHub ticket, and apply a fix. The important design decision is who decides what is safe. The model does not. A deterministic rule over graph facts assigns each finding a tier: a leaf host on a single path is `auto`; a choke point or a neighbour of the crown jewel is `approval`. `apply_safe_fix` applies only `auto` findings. If the model asks for more, the tool refuses and tells it to hand the finding to a human. This is covered by unit tests.

## Memory in the graph
Every action, including refusals, is written back as `(:Agent)-[:DID]->(:AgentAction)`. Ask "what did you do earlier?" and the agent recalls it from FalkorDB, across sessions.

## Real data
KEV and EPSS come from the live CISA and FIRST feeds, refreshed in the background with a built-in snapshot as fallback. CVSS is still a snapshot, and the topology is synthetic; we say so in every answer.

## What we would do next
Import real inventory (Trivy or cloud exports), one graph per tenant (FalkorDB makes this cheap), and push tickets straight into Jira. The architecture already fits: the graph decides, the agent explains and acts inside hard limits.
