"""The OCSF class catalogue.

Pinned to **OCSF 1.5.0**. Pinning matters: "we normalise to OCSF" invites the
question "which version?", and an unversioned answer costs marks for free.

Four classes cover the perimeter scope of PS 26156:

===== ======================= ==========================================
uid   class                   typical source
===== ======================= ==========================================
4001  Network Activity        firewalls, NetFlow, VPN concentrators
4002  HTTP Activity           proxies, web servers, WAFs
3002  Authentication          VPN, SSH, IAM, Windows security
2004  Detection Finding       IDS/IPS, antivirus, EDR
===== ======================= ==========================================

The catalogue is deliberately a subset. A field absent from it is not a
failure of the source -- it routes to ``unmapped``, and the proportion that
lands there is reported as ``mapping_coverage`` so the gap stays visible
rather than silent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from .types import FieldType

__all__ = [
    "FieldDef",
    "OCSFClass",
    "CATALOG",
    "OCSF_VERSION",
    "get_class",
    "lookup_field",
    "UNMAPPED_FIELD",
]

OCSF_VERSION = "1.5.0"
UNMAPPED_FIELD = "unmapped"


@dataclass(frozen=True, slots=True)
class FieldDef:
    """One field in an OCSF class."""

    name: str
    type: FieldType
    required: bool = False
    description: str = ""


def _f(name: str, type_: FieldType, required: bool = False, desc: str = "") -> FieldDef:
    return FieldDef(name=name, type=type_, required=required, description=desc)


# Fields every class carries. `time` is the device's claim; `observed_time` is
# our receipt clock. Keeping both is what makes a forensic timeline defensible
# when a device's clock has drifted.
_BASE_FIELDS: tuple[FieldDef, ...] = (
    _f("time", FieldType.TIMESTAMP, True, "Event time claimed by the source"),
    _f("observed_time", FieldType.TIMESTAMP, False, "Receipt time; trusted"),
    _f("severity_id", FieldType.INTEGER, False, "OCSF severity, 0-6"),
    _f("status_id", FieldType.INTEGER, False, "OCSF status"),
    _f("activity_id", FieldType.INTEGER, False, "Class-specific activity"),
    _f("message", FieldType.STRING, False, "Human-readable summary"),
    _f("metadata.product.name", FieldType.STRING, False, "Emitting product"),
    _f("metadata.product.vendor_name", FieldType.STRING, False, "Vendor"),
    _f("metadata.log_name", FieldType.STRING, False, "Source log name"),
)

_ENDPOINT_FIELDS: tuple[FieldDef, ...] = (
    _f("src_endpoint.ip", FieldType.IP, False, "Source address"),
    _f("src_endpoint.port", FieldType.PORT, False, "Source port"),
    _f("src_endpoint.hostname", FieldType.HOSTNAME, False, "Source hostname"),
    _f("src_endpoint.mac", FieldType.MAC, False, "Source MAC"),
    _f("dst_endpoint.ip", FieldType.IP, False, "Destination address"),
    _f("dst_endpoint.port", FieldType.PORT, False, "Destination port"),
    _f("dst_endpoint.hostname", FieldType.HOSTNAME, False, "Destination hostname"),
    _f("dst_endpoint.mac", FieldType.MAC, False, "Destination MAC"),
)


@dataclass(frozen=True, slots=True)
class OCSFClass:
    """An OCSF event class and the fields a mapping may target."""

    uid: int
    name: str
    category_uid: int
    category_name: str
    fields: dict[str, FieldDef]

    def has(self, field_name: str) -> bool:
        return field_name in self.fields

    def get(self, field_name: str) -> FieldDef | None:
        return self.fields.get(field_name)

    @property
    def required_fields(self) -> tuple[str, ...]:
        return tuple(n for n, d in self.fields.items() if d.required)

    def __iter__(self) -> Iterator[FieldDef]:
        return iter(self.fields.values())


def _build(
    uid: int,
    name: str,
    category_uid: int,
    category_name: str,
    extra: tuple[FieldDef, ...],
    *,
    endpoints: bool = True,
) -> OCSFClass:
    defs: list[FieldDef] = list(_BASE_FIELDS)
    if endpoints:
        defs.extend(_ENDPOINT_FIELDS)
    defs.extend(extra)
    return OCSFClass(
        uid=uid,
        name=name,
        category_uid=category_uid,
        category_name=category_name,
        fields={d.name: d for d in defs},
    )


NETWORK_ACTIVITY = _build(
    4001,
    "Network Activity",
    4,
    "Network Activity",
    (
        _f("connection_info.protocol_num", FieldType.INTEGER, False, "IP protocol"),
        _f("connection_info.direction_id", FieldType.INTEGER, False, "Direction"),
        _f("connection_info.boundary_id", FieldType.INTEGER, False, "Boundary"),
        _f("traffic.bytes", FieldType.LONG, False, "Total bytes"),
        _f("traffic.bytes_in", FieldType.LONG, False, "Inbound bytes"),
        _f("traffic.bytes_out", FieldType.LONG, False, "Outbound bytes"),
        _f("traffic.packets", FieldType.LONG, False, "Total packets"),
        _f("duration", FieldType.LONG, False, "Duration in milliseconds"),
        _f("disposition_id", FieldType.INTEGER, False, "Allowed, blocked, etc."),
    ),
)

HTTP_ACTIVITY = _build(
    4002,
    "HTTP Activity",
    4,
    "Network Activity",
    (
        _f("http_request.url.text", FieldType.URL, False, "Full request URL"),
        _f("http_request.url.path", FieldType.STRING, False, "Request path"),
        _f("http_request.http_method", FieldType.STRING, False, "GET, POST, ..."),
        _f("http_request.user_agent", FieldType.STRING, False, "User agent"),
        _f("http_request.referrer", FieldType.STRING, False, "Referrer"),
        _f("http_response.code", FieldType.INTEGER, False, "Status code"),
        _f("http_response.length", FieldType.LONG, False, "Response bytes"),
    ),
)

AUTHENTICATION = _build(
    3002,
    "Authentication",
    3,
    "Identity & Access Management",
    (
        _f("user.name", FieldType.STRING, False, "Account name"),
        _f("user.uid", FieldType.STRING, False, "Account identifier"),
        _f("user.domain", FieldType.STRING, False, "Account domain"),
        _f("user.email_addr", FieldType.EMAIL, False, "Account email"),
        _f("auth_protocol_id", FieldType.INTEGER, False, "Auth protocol"),
        _f("logon_type_id", FieldType.INTEGER, False, "Logon type"),
        _f("is_mfa", FieldType.BOOLEAN, False, "MFA used"),
        _f("session.uid", FieldType.STRING, False, "Session identifier"),
    ),
)

DETECTION_FINDING = _build(
    2004,
    "Detection Finding",
    2,
    "Findings",
    (
        _f("finding_info.title", FieldType.STRING, False, "Finding title"),
        _f("finding_info.uid", FieldType.STRING, False, "Finding identifier"),
        _f("finding_info.desc", FieldType.STRING, False, "Description"),
        _f("risk_level_id", FieldType.INTEGER, False, "Risk level"),
        _f("confidence_id", FieldType.INTEGER, False, "Detection confidence"),
        _f("impact_id", FieldType.INTEGER, False, "Impact"),
        _f("malware.name", FieldType.STRING, False, "Malware name"),
    ),
)


CATALOG: dict[int, OCSFClass] = {
    c.uid: c
    for c in (NETWORK_ACTIVITY, HTTP_ACTIVITY, AUTHENTICATION, DETECTION_FINDING)
}


def get_class(class_uid: int) -> OCSFClass:
    """Return the class for ``class_uid``.

    Raises :class:`KeyError` with the supported set listed, because a mapping
    naming an unsupported class is a configuration bug worth failing loudly on.
    """
    try:
        return CATALOG[class_uid]
    except KeyError:
        supported = ", ".join(str(u) for u in sorted(CATALOG))
        raise KeyError(
            f"unknown OCSF class_uid {class_uid}; supported: {supported}"
        ) from None


def lookup_field(class_uid: int, field_name: str) -> FieldDef | None:
    """Return the definition of ``field_name`` within a class, if it exists."""
    return get_class(class_uid).get(field_name)
