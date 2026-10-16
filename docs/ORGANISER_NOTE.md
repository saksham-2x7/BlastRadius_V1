# Message for the WeMakeDevs / FalkorDB organisers (post in the FalkorDB Discord)

Hi! We're entering Track 1 (Agents That Act on Connected Data) with BlastRadius, an agent that finds the fixes that cut real attack paths in a FalkorDB graph and acts on them within graph-decided limits.

Transparency about the timeline: we started a first prototype (a sample graph, one attack-path query, three read-only MCP tools) on Oct 13-14, before the event opened on Oct 15. Everything that makes it an *agent that acts* was built during the event: algorithm tools (betweenness, PageRank, shortest paths), the tier-guarded `apply_safe_fix`, graph memory per tenant, one FalkorDB graph per user with data import (inventory and Trivy), live CISA KEV and EPSS feeds, ticket drafting and GitHub filing, the whole UI and the tests. The README lists what existed before and what was built during the event, and the git history shows it.

Is that acceptable under Rule 8 ("main coding and design work must begin after the hackathon starts")? If you would prefer we restructure the submission (for example, mark the pre-event commits as the reused scaffold), tell us and we will.

Repo: https://github.com/saksham-2x7/blastradius
Live: https://blastradius-ashy.vercel.app
