"""Test environment: throwaway graph names, no network feeds, no GitHub. Set BEFORE the app modules are imported."""
import os
import sys

os.environ.setdefault("FALKORDB_GRAPH", "blastradius_it")
os.environ.setdefault("FALKORDB_ACCOUNTS_GRAPH", "blastradius_it_accounts")
os.environ["LIVE_FEEDS"] = "0"
os.environ.pop("GITHUB_TOKEN", None)
os.environ.pop("GITHUB_REPO", None)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
