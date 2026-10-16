"""Loads backend/.env into the process environment (real environment variables always win).

Import this FIRST in any entry point, so settings are in place before the database package reads them.
"""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")
