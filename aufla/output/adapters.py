"""Adapters that render normalised records for downstream platforms.

PS 26156 asks for a *pre-processing framework*: the output has to feed other
systems rather than terminate in a dashboard. These adapters are what make
that true. Grafana is a reference consumer, not the product.

Every adapter preserves lineage. A record arriving in Splunk still carries its
``event_uid`` and ``raw_hash``, so an investigator can walk back from the SIEM
to the exact original bytes.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Iterable

from ..normalize.engine import NormalizedRecord

__all__ = [
    "OutputAdapter",
    "OCSFJSONAdapter",
    "JSONLAdapter",
    "CEFAdapter",
    "LEEFAdapter",
    "ADAPTERS",
    "get_adapter",
]

# Characters that terminate or confuse a CEF/LEEF field if left unescaped.
_CEF_HEADER_ESCAPES = str.maketrans({"\\": r"\\", "|": r"\|", "\n": " ", "\r": " "})


def _cef_extension_escape(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", " ")
        .replace("\r", " ")
    )


class OutputAdapter(ABC):
    """Renders one record into a downstream format."""

    name: str = "abstract"
    content_type: str = "text/plain"

    @abstractmethod
    def render(self, record: NormalizedRecord) -> str:
        """Render one record."""

    def render_many(self, records: Iterable[NormalizedRecord]) -> list[str]:
        return [self.render(r) for r in records]


class OCSFJSONAdapter(OutputAdapter):
    """OCSF JSON, the native form.

    Consumed directly by Amazon Security Lake, Splunk, Elastic and Snowflake,
    which is the whole argument for normalising to OCSF: a legacy device ends
    up speaking a schema the industry already ingests.
    """

    name = "ocsf-json"
    content_type = "application/json"

    def __init__(self, *, indent: int | None = None) -> None:
        self.indent = indent

    def render(self, record: NormalizedRecord) -> str:
        return json.dumps(record.to_dict(), sort_keys=True, indent=self.indent)


class JSONLAdapter(OCSFJSONAdapter):
    """Newline-delimited OCSF JSON, for bulk load and data-lake staging."""

    name = "jsonl"
    content_type = "application/x-ndjson"

    def __init__(self) -> None:
        super().__init__(indent=None)


class CEFAdapter(OutputAdapter):
    """ArcSight CEF, also accepted by QRadar and many legacy collectors."""

    name = "cef"
    content_type = "text/plain"

    # OCSF severity_id (0-6) to the CEF 0-10 scale.
    SEVERITY = {0: 0, 1: 2, 2: 3, 3: 5, 4: 7, 5: 9, 6: 10}

    def __init__(self, vendor: str = "AUFLA", product: str = "ULPF") -> None:
        self.vendor = vendor
        self.product = product

    def render(self, record: NormalizedRecord) -> str:
        from ..ocsf.classes import CATALOG

        class_name = (
            CATALOG[record.ocsf_class].name
            if record.ocsf_class in CATALOG
            else "Unmapped"
        )
        severity = self.SEVERITY.get(int(record.fields.get("severity_id", 0) or 0), 0)

        header = "|".join(
            str(part).translate(_CEF_HEADER_ESCAPES)
            for part in (
                "CEF:0",
                self.vendor,
                self.product,
                record.mapping_version or 0,
                record.ocsf_class or 0,
                class_name,
                severity,
            )
        )

        extensions = {
            "src": record.fields.get("src_endpoint.ip"),
            "dst": record.fields.get("dst_endpoint.ip"),
            "spt": record.fields.get("src_endpoint.port"),
            "dpt": record.fields.get("dst_endpoint.port"),
            "rt": record.fields.get("time"),
            "in": record.fields.get("traffic.bytes_in"),
            "out": record.fields.get("traffic.bytes_out"),
            "msg": record.fields.get("message")
            or record.fields.get("finding_info.title"),
            # Lineage survives the hop, so an analyst in the SIEM can walk
            # back to the original bytes.
            "cs1": str(record.event_uid),
            "cs1Label": "eventUid",
            "cs2": record.raw_hash,
            "cs2Label": "rawHash",
            "cs3": record.mapping_id,
            "cs3Label": "mappingId",
        }

        rendered = " ".join(
            f"{k}={_cef_extension_escape(v)}"
            for k, v in extensions.items()
            if v is not None
        )
        return f"{header}|{rendered}"


class LEEFAdapter(OutputAdapter):
    """IBM QRadar LEEF 2.0, tab-delimited attributes."""

    name = "leef"
    content_type = "text/plain"

    def __init__(self, vendor: str = "AUFLA", product: str = "ULPF") -> None:
        self.vendor = vendor
        self.product = product

    def render(self, record: NormalizedRecord) -> str:
        header = "|".join(
            str(p).translate(_CEF_HEADER_ESCAPES)
            for p in (
                "LEEF:2.0",
                self.vendor,
                self.product,
                record.mapping_version or 0,
                record.ocsf_class or 0,
            )
        )
        attributes = {
            "devTime": record.fields.get("time"),
            "src": record.fields.get("src_endpoint.ip"),
            "dst": record.fields.get("dst_endpoint.ip"),
            "srcPort": record.fields.get("src_endpoint.port"),
            "dstPort": record.fields.get("dst_endpoint.port"),
            "sev": record.fields.get("severity_id"),
            "eventUid": str(record.event_uid),
            "rawHash": record.raw_hash,
            "mappingId": record.mapping_id,
        }
        body = "\t".join(
            f"{k}={str(v).replace(chr(9), ' ')}"
            for k, v in attributes.items()
            if v is not None
        )
        return f"{header}|{body}"


ADAPTERS: dict[str, type[OutputAdapter]] = {
    "ocsf-json": OCSFJSONAdapter,
    "jsonl": JSONLAdapter,
    "cef": CEFAdapter,
    "leef": LEEFAdapter,
}


def get_adapter(name: str, **kwargs: Any) -> OutputAdapter:
    try:
        return ADAPTERS[name.lower()](**kwargs)
    except KeyError:
        raise KeyError(
            f"unknown adapter {name!r}; known: {', '.join(sorted(ADAPTERS))}"
        ) from None
