"""
Domain-separated hash functions for HABTS.

Every hash call includes a unique domain tag so that outputs for
different protocol roles (binding, challenge, nonce, accountability)
are cryptographically independent — even when fed identical data.

Convention follows BIP-340 tagged hashes:

    H_tag(x) = SHA-256( SHA-256(tag) ‖ SHA-256(tag) ‖ x )

This prevents cross-protocol attacks with negligible overhead.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Sequence

from .curve import Scalar, Point, ORDER, SCALAR_BYTES


# ── domain tags ─────────────────────────────────────────────────────────
_TAG_BIND    = b"HABTS/v1/binding"
_TAG_SIG     = b"HABTS/v1/challenge"
_TAG_NONCE   = b"HABTS/v1/nonce"
_TAG_TAG     = b"HABTS/v1/accountability"
_TAG_COM     = b"HABTS/v1/commitment"
_TAG_SCHNORR = b"HABTS/v1/schnorr_proof"
_TAG_DLEQ    = b"HABTS/v1/dleq_proof"
_TAG_POLY    = b"HABTS/v1/polynomial"
_TAG_DKG     = b"HABTS/v1/dkg"
_TAG_SCALAR  = b"HABTS/v1/hash_to_scalar"


# ── internal helpers ────────────────────────────────────────────────────
def _tagged_hasher(tag: bytes) -> hashlib._Hash:
    """Return a SHA-256 context pre-loaded with the BIP-340 tag prefix."""
    tag_hash = hashlib.sha256(tag).digest()
    h = hashlib.sha256()
    h.update(tag_hash)
    h.update(tag_hash)
    return h


def _encode_item(item: Any) -> bytes:
    """
    Canonical encoding of a protocol element for hashing.

    Length-prefixing is used for variable-length items (bytes, lists)
    to ensure unambiguous parsing.
    """
    if isinstance(item, bytes):
        return len(item).to_bytes(4, "big") + item
    if isinstance(item, int):
        return item.to_bytes(SCALAR_BYTES, "big")
    if isinstance(item, Scalar):
        return item.to_bytes()
    if isinstance(item, Point):
        return item.to_bytes_compressed()
    if isinstance(item, (list, tuple)):
        parts = b"".join(_encode_item(x) for x in item)
        return len(item).to_bytes(4, "big") + parts
    return str(item).encode("utf-8")


def _tagged_hash(tag: bytes, *args: Any) -> bytes:
    """Compute BIP-340 tagged hash over arbitrary protocol elements."""
    h = _tagged_hasher(tag)
    for a in args:
        h.update(_encode_item(a))
    return h.digest()


def _tagged_scalar(tag: bytes, *args: Any) -> Scalar:
    """Hash to scalar: H_tag(*args) → Z_q."""
    return Scalar.from_bytes_reduce(_tagged_hash(tag, *args))


# ── public hash functions ───────────────────────────────────────────────

def hash_to_scalar(*args: Any) -> Scalar:
    """General-purpose hash to scalar with default domain."""
    return _tagged_scalar(_TAG_SCALAR, *args)


def hash_binding(signer_id: int, message: bytes, binding_data: bytes) -> Scalar:
    r"""
    Binding factor  ρ_i  = H₁(i, m, B)  from FROST §4.

    Binds each signer's nonce share to the message and signer set,
    preventing Drijvers-style multi-session forgery.
    """
    return _tagged_scalar(_TAG_BIND, signer_id, message, binding_data)


def hash_sig(R: Point, pk: Point, message: bytes) -> Scalar:
    r"""
    Schnorr challenge  c = H₂(R, Y, m).

    Output is the Fiat-Shamir challenge used in both single and
    threshold Schnorr verification.
    """
    return _tagged_scalar(_TAG_SIG, R, pk, message)


def hash_nonce(
    secret: Scalar,
    message: bytes,
    extra: bytes = b"",
) -> Scalar:
    """
    Deterministic nonce derivation  (RFC 6979 style, simplified).

    In production use a proper RFC 6979 implementation or hedged
    randomness.  Here we combine the secret with fresh randomness
    for robustness against VM snapshot reuse.
    """
    import secrets as _sec
    aux = _sec.token_bytes(32)
    return _tagged_scalar(
        _TAG_NONCE, secret, message, aux, extra,
    )


def hash_accountability(
    signer_id: int,
    level: int,
    R_i: Point,
    z_i: Scalar,
    message: bytes,
    session_id: bytes,
) -> bytes:
    """
    Accountability tag  τ_i = H_tag(i ‖ ℓ ‖ R_i ‖ z_i ‖ m ‖ sid).

    This tag is included in the accountability proof and allows the
    tracer to identify which participants signed a given message.
    """
    return _tagged_hash(
        _TAG_TAG, signer_id, level, R_i, z_i, message, session_id,
    )


def hash_schnorr_proof(R: Point, Y: Point, context: bytes = b"") -> Scalar:
    """Fiat-Shamir challenge for a Schnorr PoK:  c = H(R, Y, ctx)."""
    return _tagged_scalar(_TAG_SCHNORR, R, Y, context)


def hash_dleq(
    A1: Point, B1: Point, A2: Point, B2: Point, context: bytes = b"",
) -> Scalar:
    """Fiat-Shamir challenge for a DLEQ proof."""
    return _tagged_scalar(_TAG_DLEQ, A1, B1, A2, B2, context)


def hash_commitment(*parts: Any) -> bytes:
    """Hash used inside Pedersen polynomial commitment verification."""
    return _tagged_hash(_TAG_COM, *parts)


def hash_dkg_context(
    participant_id: int,
    num_participants: int,
    num_levels: int,
) -> bytes:
    """Context string for DKG proofs of knowledge."""
    return _tagged_hash(_TAG_DKG, participant_id, num_participants, num_levels)
