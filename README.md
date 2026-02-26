# HABTS: Hierarchical Accountable Birkhoff Threshold Signatures

A threshold Schnorr signature scheme combining hierarchical access control with configurable public accountability, built on Birkhoff interpolation over a single polynomial within the FROST two-round signing framework.

**Paper:** *HABTS: Hierarchical Accountable Birkhoff Threshold Signatures* — submitted to ACISP 2026.

---

## Overview

HABTS enables organisations to enforce stratified signing authority (e.g., "any 2 executives, or 1 executive and 6 staff") while providing configurable accountability that identifies which subset participated in signing. The protocol produces standard 65-byte BIP-340 Schnorr signatures indistinguishable from single-signer output, with verification constant at ~87 μs regardless of threshold, hierarchy depth, or signer count.

### Key Properties

- **Hierarchical access:** Birkhoff interpolation over a single degree-$d$ polynomial encodes $L$ authority levels with cumulative thresholds, achieving $O(1)$ overhead in hierarchy depth.
- **Configurable accountability:** Three disclosure tiers — threshold validity (32 B), per-level counts ($L \times 8$ B), and full signer identification ($|S| \times 105$ B) — calibrate transparency against privacy.
- **Two-round signing:** Extends FROST with Birkhoff coefficients replacing Lagrange coefficients; no additional rounds required.
- **Negligible accountability cost:** Hash-based per-signer tags add < 0.1% to signing time (~2 μs per signer via SHA-256).
- **Standard output:** 65-byte BIP-340 signatures on secp256k1, compatible with existing Schnorr verification infrastructure.

### Security Model

- **Unforgeability:** EUF-CMA under the One-More Discrete Logarithm (OMDL) assumption in the Random Oracle Model (ROM) with selective corruption.
- **Accountability soundness:** Under SHA-256 collision resistance.
- **Accountability completeness:** Unconditional for honest signers.

---

## Project Structure

```
habts/
├── __init__.py            # Package initialisation
├── access.py              # Hierarchical access structure (Definition 2, Eq. 4)
├── accountability.py      # Hash-based accountability tags and disclosure tiers
├── commitment.py          # Pedersen commitments and polynomial commitments
├── curve.py               # secp256k1 elliptic curve operations (via libsecp256k1)
├── dkg.py                 # Distributed Key Generation (Algorithm 2)
├── field.py               # Scalar field arithmetic (Z_q with GMP-backed integers)
├── hash.py                # Tagged hash oracles (H_sig, H_bind, H_nonce, H_dkg, H_tag)
├── polynomial.py          # Polynomial operations and Birkhoff interpolation
├── proofs.py              # Schnorr proofs of knowledge (DKG verification)
├── protocol.py            # Top-level protocol orchestration
├── signing.py             # Two-round signing and aggregation (Algorithms 3–4)
└── Figures/               # Paper figures
```

---

## Installation

### Requirements

- Python ≥ 3.11
- `libsecp256k1` (v0.4.1+)
- `coincurve` (v20.0.0+)
- GMP-backed integers (via `gmpy2` or Python built-in)

### Setup

```bash
# Clone the repository
git clone https://github.com/<org>/habts.git
cd habts

# Install dependencies
pip install coincurve>=20.0.0 gmpy2

# Verify installation
python -c "from habts import protocol; print('HABTS ready')"
```

---

## Usage

### 1. Setup and Key Generation

```python
from habts.protocol import HABTSProtocol

# Define a 2-level hierarchy:
#   Level 0: 3 executives (higher authority)
#   Level 1: 7 staff
#   Thresholds: t = [2, 7] → any 2 executives, or 1 executive + 6 staff, or all 7 staff
protocol = HABTSProtocol(
    levels=2,
    participants_per_level=[3, 7],    # n_0=3, n_1=7
    thresholds=[2, 7]                  # t_0=2, t_1=7 → degree d=6
)
```

### 2. Distributed Key Generation (Algorithm 2)

```python
# Each participant runs DKG; shares are Birkhoff derivative shares:
#   Level-ℓ participant i receives s_i = f^(ℓ)(α_i) / ℓ!
dkg_output = protocol.run_dkg()

# Output includes:
#   - Group public key Y = s · G
#   - Per-participant public shares Y_i = s_i · G
#   - Polynomial commitments C_k for share verification
```

### 3. Two-Round Signing (Algorithm 3)

```python
# Select an authorised signer set S ∈ AS
signer_set = [0, 1, 3, 5, 6, 7, 8]  # 2 executives + 5 staff

# Round 1: Each signer generates and broadcasts nonce commitments (D_i, E_i)
# Round 2: Each signer computes partial signature z_i with accountability tag τ_i
signature, proof = protocol.sign(
    message=b"Transfer 10 BTC to treasury",
    signer_set=signer_set,
    disclosure="full"  # "threshold", "level_only", or "full"
)

# Output: σ = (R, z) — standard 65-byte Schnorr signature
assert len(signature.to_bytes()) == 65
```

### 4. Verification

```python
# Standard BIP-340 Schnorr verification — O(1), no knowledge of signers required
is_valid = protocol.verify(
    message=b"Transfer 10 BTC to treasury",
    signature=signature,
    public_key=dkg_output.group_public_key
)
```

### 5. Accountability / Tracing (Algorithm 5)

```python
# Trace: identify signers from the accountability proof
trace_result = protocol.trace(proof, disclosure="full")

# Disclosure tiers:
#   "threshold"  → 32 B proof: confirms a valid subset signed
#   "level_only" → L×8 B proof: reveals per-level signer counts
#   "full"       → |S|×105 B proof: identifies each signer with verification data
```

---

## Algorithms

| # | Algorithm | Description |
|---|-----------|-------------|
| 1 | **Setup** | Parameter generation, Birkhoff point assignment $(\alpha_i, \beta_i) = (i, \ell)$ |
| 2 | **DKG** | Pedersen DKG with derivative shares and polynomial commitments |
| 3 | **Sign + Aggregate** | Two-round partial signing with Birkhoff coefficients; aggregation into $(R, z)$ |
| 4 | **Verify** | Standard BIP-340 Schnorr verification |
| 5 | **Trace** | Accountability proof parsing and signer identification |

---

## Performance

All benchmarks measured on Intel Xeon Silver 4314 (2.40 GHz), single core, Python 3.11 with `libsecp256k1`.

### Signing Performance

| Configuration | Type | $n$ | $|S|$ | Sign (ms) | Verify (ms) | Sig (B) |
|---------------|------|-----|-------|-----------|-------------|---------|
| 3-of-5 | Flat | 5 | 3 | 2.48 | 0.087 | 65 |
| 5-of-10 | Flat | 10 | 5 | 5.92 | 0.086 | 65 |
| 7-of-15 | Flat | 15 | 7 | 11.23 | 0.088 | 65 |
| 10-of-20 | Flat | 20 | 10 | 23.47 | 0.087 | 65 |
| t=[2,7] | 2-Level | 10 | 7 | 12.88 | 0.088 | 65 |
| t=[2,5,10] | 3-Level | 15 | 10 | 44.80 | 0.087 | 65 |
| t=[3,8,17] | 3-Level | 25 | 17 | 251.60 | 0.087 | 65 |

### Accountability Overhead

| Disclosure | Extra per sign | Extra per signer | Proof size |
|------------|---------------|-----------------|------------|
| Full | < 0.1 ms | ~2 μs | $|S| \times 105$ B |
| Level Only | < 0.1 ms | ~2 μs | $L \times 8$ B |
| Threshold | < 0.1 ms | ~2 μs | 32 B |

### Birkhoff vs. Lagrange

Birkhoff coefficient computation is faster than Lagrange for $|S| \leq 8$ (up to 45% faster), with a crossover near $|S| \approx 9$. For the recommended range $|S| \leq 15$, Birkhoff overhead remains at most +40%.

---

## Deployment Scenarios

| Scenario | Configuration | DKG (ms) | Sign (ms) | Verify (ms) |
|----------|---------------|----------|-----------|-------------|
| Small organisation | Flat 3-of-5 | 8.3 | 2.5 | 0.087 |
| Corporate treasury | 2-Level: [3 exec, 7 staff], t=[2,7] | 46.3 | 12.2 | 0.087 |
| DAO governance | 3-Level: [3 core, 4 dev, 8 mem], t=[2,5,10] | 340.0 | 47.2 | 0.087 |
| Institutional custody | 3-Level: [4 sr, 6 mid, 15 ops], t=[3,8,17] | 1,848 | 252.4 | 0.087 |

---

## Cryptographic Primitives

| Primitive | Implementation |
|-----------|---------------|
| Elliptic curve | secp256k1 via `libsecp256k1` (v0.4.1) / `coincurve` (v20.0.0) |
| Hash function | SHA-256 with BIP-340 tagged hashing |
| Commitments | Pedersen commitments with NUMS second generator |
| Secret sharing | Birkhoff interpolation (generalised Shamir) |
| Proofs of knowledge | Schnorr PoK for DKG share verification |
| Nonce generation | Deterministic with binding (FROST-compatible) |

---

## Comparison with Related Work

| Scheme | Rounds | Hierarchy | Accountability | Security |
|--------|--------|-----------|----------------|----------|
| FROST | 2 | ✗ | ✗ | OMDL/ROM/Selective |
| ROAST | 2+ | ✗ | ✗ | OMDL/ROM/Selective |
| FlexHi | 2 | ✓ ($L$ polynomials) | ✗ | OMDL/ROM/Selective |
| Boneh–Komlo | 2 | ✗ | Private (judge†) | OMDL/ROM/Selective |
| HARTS | 3 | ✗ | ✗ | OMDL+AGM/Adaptive |
| **HABTS** | **2** | **✓ (single poly)** | **Public (configurable)** | **OMDL/ROM/Selective** |

---
