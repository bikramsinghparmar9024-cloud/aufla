"""Live collection: from the local host, and from files on disk."""

from .live import CollectorStatus, LiveCollector, collect_once
from .tail import FileTailer, TailState, WatchSpec, default_specs

__all__ = [
    "CollectorStatus",
    "FileTailer",
    "LiveCollector",
    "TailState",
    "WatchSpec",
    "collect_once",
    "default_specs",
]
