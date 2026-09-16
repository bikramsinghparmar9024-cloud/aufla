"""Source mappings: the YAML artifact that turns raw bytes into OCSF."""

from .schema import (
    Condition,
    FieldRef,
    FieldSpec,
    Mapping,
    MappingError,
    RefKind,
    Rule,
)
from .loader import MappingRegistry
from .router import Detection, DiscoveryStrategy, LogFormat, detect_format

__all__ = [
    "Condition",
    "Detection",
    "DiscoveryStrategy",
    "FieldRef",
    "FieldSpec",
    "LogFormat",
    "Mapping",
    "MappingError",
    "MappingRegistry",
    "RefKind",
    "Rule",
    "detect_format",
]
