"""Forensic Explorer: a read-only web view over the store and the ledger."""

from .server import build_server, serve

__all__ = ["build_server", "serve"]
