"""
HABTS: Hierarchical Accountable Birkhoff Threshold Signatures.

A practical threshold Schnorr signature scheme combining:

- **Birkhoff interpolation** for hierarchical access control
  [Tassa, J. Cryptology 2007]
- **FROST-style two-round signing** [Komlo & Goldberg, SAC 2020]
- **Configurable accountability** via hash-based tags

Security: EUF-CMA under OMDL in the Random Oracle Model
(selective corruption, up to t-1 corruptions).

Quick start
-----------
::

    from habts import HABTSProtocol, DisclosureLevel

    proto = HABTSProtocol.setup(
        level_sizes=[2, 3, 5],
        thresholds=[1, 3, 7],
        disclosure=DisclosureLevel.FULL,
    )

    bundle = proto.sign(b"transfer 1 BTC to Alice")
    assert proto.verify(b"transfer 1 BTC to Alice", bundle)

    signers = proto.trace(b"transfer 1 BTC to Alice", bundle)
    print(f"Signed by: {signers}")
"""

__version__ = "0.3.0"

# ── core types ──────────────────────────────────────────────────────────
from .curve import Scalar, Point, G, H, ORDER

# ── access structure ────────────────────────────────────────────────────
from .access import HierarchicalAccess, LevelConfig

# ── protocol ────────────────────────────────────────────────────────────
from .protocol import HABTSProtocol, SignatureBundle

# ── signing primitives (for advanced usage / benchmarking) ──────────────
from .signing import (
    Signer,
    Aggregator,
    NonceCommitment,
    PartialSignature,
    ThresholdSignature,
    verify_signature,
)

# ── accountability ──────────────────────────────────────────────────────
from .accountability import (
    DisclosureLevel,
    AccountabilityProver,
    AccountabilityTracer,
    AccountabilityProof,
    AccountabilityTag,
)

# ── DKG ─────────────────────────────────────────────────────────────────
from .dkg import DKGResult, run_dkg

# ── cryptographic building blocks ───────────────────────────────────────
from .polynomial import (
    sample_polynomial,
    evaluate,
    evaluate_derivative,
    birkhoff_coefficients,
    all_birkhoff_coefficients,
    lagrange_coefficient,
    check_polya_conditions,
)
from .commitment import PedersenCommitment, PolynomialCommitment
from .proofs import SchnorrProof, DLEQProof
from .hash import (
    hash_to_scalar,
    hash_binding,
    hash_sig,
    hash_accountability,
)

__all__ = [
    # version
    "__version__",
    # core
    "Scalar", "Point", "G", "H", "ORDER",
    # access
    "HierarchicalAccess", "LevelConfig",
    # protocol
    "HABTSProtocol", "SignatureBundle",
    # signing
    "Signer", "Aggregator", "NonceCommitment", "PartialSignature",
    "ThresholdSignature", "verify_signature",
    # accountability
    "DisclosureLevel", "AccountabilityProver", "AccountabilityTracer",
    "AccountabilityProof", "AccountabilityTag",
    # dkg
    "DKGResult", "run_dkg",
    # polynomials
    "sample_polynomial", "evaluate", "evaluate_derivative",
    "birkhoff_coefficients", "all_birkhoff_coefficients",
    "lagrange_coefficient", "check_polya_conditions",
    # commitments & proofs
    "PedersenCommitment", "PolynomialCommitment",
    "SchnorrProof", "DLEQProof",
    # hashing
    "hash_to_scalar", "hash_binding", "hash_sig", "hash_accountability",
]
