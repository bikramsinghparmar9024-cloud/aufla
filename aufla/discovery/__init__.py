"""The discovery lane: propose mappings for unknown formats, gate them, and
route anything below the bar to a human."""

from .confidence import CONFIDENCE_BAR, Check, ConfidenceReport, score_proposal
from .proposer import Proposal, propose_mapping
from .runner import DiscoveryResult, approve_proposal, run_discovery
from .store import ProposalStore, StoredProposal

__all__ = [
    "CONFIDENCE_BAR",
    "Check",
    "ConfidenceReport",
    "DiscoveryResult",
    "Proposal",
    "ProposalStore",
    "StoredProposal",
    "approve_proposal",
    "propose_mapping",
    "run_discovery",
    "score_proposal",
]
