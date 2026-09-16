"""Loading mappings from disk, with hot reload.

Onboarding a source must not require a restart, a code change or a deploy.
A YAML file appears in ``sources/``, the registry notices, and the next event
from that source normalises. That is what "plug-and-play onboarding" has to
mean for an operator who is not going to rebuild a container at 3am.

Reload is deliberately explicit rather than threaded. The ingest loop calls
:meth:`MappingRegistry.refresh` between batches, so a mapping never changes
underneath a batch that is halfway through being normalised.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .schema import Mapping, MappingError

__all__ = ["MappingRegistry", "LoadReport"]

log = logging.getLogger(__name__)

_SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True, slots=True)
class LoadReport:
    """What changed during a load or refresh."""

    loaded: tuple[str, ...] = ()
    updated: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    failed: tuple[tuple[str, str], ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.loaded or self.updated or self.removed)

    @property
    def ok(self) -> bool:
        return not self.failed


class MappingRegistry:
    """In-memory set of mappings, backed by a directory of YAML files."""

    def __init__(
        self,
        directory: str | Path,
        *,
        require_approval: bool = False,
    ) -> None:
        self.directory = Path(directory)
        self.require_approval = require_approval
        self._mappings: dict[str, Mapping] = {}
        self._by_path: dict[Path, str] = {}
        self._stamps: dict[Path, tuple[int, int]] = {}

    # ---- loading ----------------------------------------------------------

    def _files(self) -> list[Path]:
        if not self.directory.is_dir():
            return []
        return sorted(
            p
            for p in self.directory.iterdir()
            if p.is_file() and p.suffix.lower() in _SUFFIXES
        )

    @staticmethod
    def _stamp(path: Path) -> tuple[int, int]:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)

    def _load_file(self, path: Path) -> Mapping:
        mapping = Mapping.from_yaml(
            path.read_text(encoding="utf-8"), path=str(path)
        )
        if self.require_approval and not mapping.is_approved:
            raise MappingError(
                f"{mapping.source}: not approved. A mapping takes effect only "
                "once 'approved_by' names the person who signed it off."
            )
        return mapping

    def refresh(self) -> LoadReport:
        """Load new files, reload changed ones, drop deleted ones.

        A file that fails to parse leaves the previously loaded version in
        place. A broken edit therefore degrades to "no change", never to a
        source silently losing its mapping mid-flight.
        """
        loaded: list[str] = []
        updated: list[str] = []
        removed: list[str] = []
        failed: list[tuple[str, str]] = []

        seen: set[Path] = set()

        for path in self._files():
            seen.add(path)
            try:
                stamp = self._stamp(path)
            except OSError as exc:  # pragma: no cover - race with deletion
                failed.append((str(path), str(exc)))
                continue

            if self._stamps.get(path) == stamp:
                continue

            try:
                mapping = self._load_file(path)
            except (MappingError, OSError, UnicodeDecodeError) as exc:
                failed.append((str(path), str(exc)))
                log.warning("mapping %s failed to load: %s", path, exc)
                continue

            clash = self._mappings.get(mapping.source)
            if clash is not None and clash.path not in (None, str(path)):
                failed.append(
                    (
                        str(path),
                        f"source {mapping.source!r} is already defined by "
                        f"{clash.path}",
                    )
                )
                continue

            was_present = mapping.source in self._mappings
            self._mappings[mapping.source] = mapping
            self._by_path[path] = mapping.source
            self._stamps[path] = stamp
            (updated if was_present else loaded).append(mapping.source)

        for path in list(self._by_path):
            if path not in seen:
                source = self._by_path.pop(path)
                self._stamps.pop(path, None)
                # Only drop the source if this file still owns it.
                current = self._mappings.get(source)
                if current is not None and current.path == str(path):
                    del self._mappings[source]
                    removed.append(source)

        return LoadReport(
            loaded=tuple(loaded),
            updated=tuple(updated),
            removed=tuple(removed),
            failed=tuple(failed),
        )

    # Kept as an alias so call sites read naturally on first use.
    load = refresh

    def add(self, mapping: Mapping) -> None:
        """Register a mapping directly, without a file. Used by tests and by
        the discovery lane before a proposal has been written to disk."""
        self._mappings[mapping.source] = mapping

    # ---- access -----------------------------------------------------------

    def get(self, source: str) -> Mapping | None:
        return self._mappings.get(source)

    def __contains__(self, source: object) -> bool:
        return source in self._mappings

    def __len__(self) -> int:
        return len(self._mappings)

    def __iter__(self) -> Iterator[Mapping]:
        return iter(self._mappings.values())

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(sorted(self._mappings))

    def hashes(self) -> dict[str, str]:
        """Content hash per source, for commitment to the integrity ledger."""
        return {s: m.content_hash() for s, m in sorted(self._mappings.items())}
