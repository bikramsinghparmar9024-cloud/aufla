"""Section 63 BSA 2023 certificate preparation.

One point of accuracy that is easy to get wrong and expensive to overclaim:
**software cannot self-certify.** Section 63 of the Bharatiya Sakshya
Adhiniyam 2023 (successor to Section 65B of the Indian Evidence Act) requires
the certificate to be signed by the person in charge of the device or another
responsible official.

So AUFLA prepares the certificate -- device particulars, hash values, batch
roots, verification outcome, all filled in -- and leaves a signature block for
the custodian. It does not claim automatic admissibility, because no software
can deliver that.

Timestamps cite ``observed_time``, the receipt clock, because that is the only
clock the system can attest to. A device's own claimed time is reproduced as
supplied and labelled untrusted.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .. import __version__

__all__ = ["Certificate", "build_certificate"]


@dataclass(slots=True)
class Certificate:
    """A prepared, unsigned Section 63 certificate."""

    generated_at: str
    period_start: str
    period_end: str
    event_count: int
    batch_count: int
    first_batch: int | None
    last_batch: int | None
    chain_head: str
    verification: str
    verification_detail: str
    sources: tuple[str, ...] = ()
    checkpoints: tuple[dict[str, Any], ...] = ()
    system: dict[str, str] = field(default_factory=dict)
    custodian: str | None = None

    @property
    def is_admissible_as_prepared(self) -> bool:
        """Always False. A custodian's signature is required by statute."""
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "period": {"start": self.period_start, "end": self.period_end},
            "event_count": self.event_count,
            "batch_count": self.batch_count,
            "batch_range": [self.first_batch, self.last_batch],
            "chain_head": self.chain_head,
            "verification": self.verification,
            "verification_detail": self.verification_detail,
            "sources": list(self.sources),
            "checkpoints": [dict(c) for c in self.checkpoints],
            "system": dict(self.system),
            "signature_required": True,
        }

    def render(self) -> str:
        """Human-readable certificate text, ready for the custodian to sign."""
        lines = [
            "CERTIFICATE UNDER SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023",
            "(Electronic evidence produced by a computer system)",
            "",
            "PREPARED BY AUFLA - Universal Log Pre-processing Framework "
            f"v{self.system.get('aufla_version', __version__)}",
            f"Prepared at: {self.generated_at}",
            "",
            "1. PARTICULARS OF THE COMPUTER SYSTEM",
            f"   Host              : {self.system.get('host', 'unknown')}",
            f"   Platform          : {self.system.get('platform', 'unknown')}",
            f"   Software          : AUFLA {self.system.get('aufla_version', __version__)}",
            f"   Network mode      : {self.system.get('network', 'air-gapped')}",
            "",
            "2. PERIOD AND SCOPE OF THE RECORDS",
            f"   Period start      : {self.period_start}",
            f"   Period end        : {self.period_end}",
            f"   Events covered    : {self.event_count}",
            f"   Sealed batches    : {self.batch_count} "
            f"(ids {self.first_batch}-{self.last_batch})",
            f"   Sources           : {', '.join(self.sources) or 'n/a'}",
            "",
            "3. INTEGRITY",
            "   Each event was hashed with SHA-256 on arrival, before any parsing",
            "   or interpretation. Events were sealed into Merkle batches whose",
            "   roots form an unbroken chain, each root signed on sealing.",
            "",
            f"   Chain head        : {self.chain_head}",
            f"   Verification      : {self.verification}",
            f"   Detail            : {self.verification_detail}",
            "",
            "4. TIME",
            "   Timestamps cited are the receipt clock of the recording system,",
            "   which is the only clock this system can attest to. Timestamps",
            "   claimed by the originating devices are retained separately and",
            "   are not relied upon in this certificate.",
            "",
        ]

        if self.checkpoints:
            lines.append("5. OFFLINE CHECKPOINTS")
            for c in self.checkpoints:
                lines.append(
                    f"   {c['day']}: batches {c['first_batch']}-{c['last_batch']}, "
                    f"head {str(c['chain_head'])[:16]}..."
                )
            lines.append("")

        lines += [
            "DECLARATION",
            "",
            "   I, the undersigned, being the person in charge of the above",
            "   computer system, certify that the contents described above were",
            "   produced by that system in the ordinary course of its activities,",
            "   and that the particulars stated are true to the best of my",
            "   knowledge and belief.",
            "",
            f"   Name      : {self.custodian or '_' * 40}",
            "   Designation: " + "_" * 40,
            "   Signature : " + "_" * 40,
            "   Date      : " + "_" * 40,
            "",
            "   NOTE: This certificate is prepared by software and is not valid",
            "   until signed by the custodian named above. No software can",
            "   self-certify under Section 63.",
        ]
        return "\n".join(lines)


def build_certificate(
    ledger,
    *,
    store=None,
    sources: tuple[str, ...] = (),
    custodian: str | None = None,
) -> Certificate:
    """Prepare a certificate covering everything currently in the ledger."""
    batches = list(ledger.iter_batches())
    verify_result = ledger.verify(store=store)

    def iso(ns: int) -> str:
        return (
            datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )

    return Certificate(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        period_start=iso(batches[0].sealed_at_ns) if batches else "n/a",
        period_end=iso(batches[-1].sealed_at_ns) if batches else "n/a",
        event_count=ledger.event_count,
        batch_count=len(batches),
        first_batch=batches[0].batch_id if batches else None,
        last_batch=batches[-1].batch_id if batches else None,
        chain_head=ledger.head,
        verification="PASS" if verify_result.ok else "FAIL",
        verification_detail=str(verify_result),
        sources=tuple(sources),
        checkpoints=tuple(
            {
                "day": c.day,
                "first_batch": c.first_batch,
                "last_batch": c.last_batch,
                "chain_head": c.chain_head,
            }
            for c in ledger.checkpoints()
        ),
        system={
            "host": platform.node(),
            "platform": f"{platform.system()} {platform.release()}",
            "aufla_version": __version__,
            "network": "air-gapped (no external network dependency)",
        },
        custodian=custodian,
    )
