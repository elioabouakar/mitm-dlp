"""
Ensures the repo root is on sys.path so `from dlp import pipeline` resolves
when running `pytest` from the repo root, regardless of current working
directory or how pytest was invoked. Pytest doesn't do this automatically
unless a conftest.py exists at the root it should treat as the base.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
