# src/tic/api/__init__.py
"""Local-only FastAPI surface that exposes the existing sweep workflow.

The frontend (e.g. a v0/Next.js app on http://127.0.0.1:3000) consumes this
API. All security-sensitive logic is delegated to tic.ui.adapter and the
existing core modules — this package only translates HTTP <-> adapter calls.
"""
