"""Network segmentation: the fewest connections to cut so no route from the internet reaches a crown jewel.

Patching removes a weakness; segmentation removes a connection. This is a minimum edge cut over the LIVE attack paths (unit
capacity per connection), found with Edmonds-Karp. It is the plan a network team can execute with firewall or security-group
changes while patches wait for approval. Pure functions, no database.
"""
from collections import defaultdict, deque

SOURCE = "internet"


def min_cut(paths: list[list[str]]) -> list[tuple[str, str]]:
    """Smallest set of directed edges (u, v) whose removal disconnects SOURCE from the end of every given path.

    The cut is the one closest to the source side among equally small cuts, and the output is sorted, so it is deterministic."""
    cap: dict[tuple[str, str], int] = {}
    adj: dict[str, set[str]] = defaultdict(set)
    sinks = {p[-1] for p in paths if len(p) > 1}
    for p in paths:
        for a, b in zip(p, p[1:]):
            cap[(a, b)] = 1
            cap.setdefault((b, a), 0)
            adj[a].add(b)
            adj[b].add(a)
    sink = "\0sink"
    for s in sinks:
        cap[(s, sink)] = 10**6
        cap.setdefault((sink, s), 0)
        adj[s].add(sink)
        adj[sink].add(s)

    def augment() -> bool:
        parent = {SOURCE: None}
        q = deque([SOURCE])
        while q and sink not in parent:
            u = q.popleft()
            for v in sorted(adj[u]):
                if v not in parent and cap[(u, v)] > 0:
                    parent[v] = u
                    q.append(v)
        if sink not in parent:
            return False
        v = sink
        while parent[v] is not None:
            u = parent[v]
            cap[(u, v)] -= 1
            cap[(v, u)] += 1
            v = u
        return True

    if SOURCE not in adj:
        return []
    while augment():
        pass
    seen, q = {SOURCE}, deque([SOURCE])  # nodes still reachable in the residual graph
    while q:
        u = q.popleft()
        for v in adj[u]:
            if v not in seen and cap[(u, v)] > 0:
                seen.add(v)
                q.append(v)
    original = {(a, b) for p in paths for a, b in zip(p, p[1:])}
    return sorted((a, b) for a, b in original if a in seen and b not in seen)
