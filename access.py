"""
Hierarchical access structure for HABTS.

Defines how *n* participants are partitioned into *L* authority levels,
each with cumulative thresholds.  Higher-level participants (e.g.,
executives) are assigned lower derivative orders in the Birkhoff
scheme, meaning fewer of them suffice for signing.

Model
-----
Participants are partitioned into levels  L_0, L_1, …, L_{ℓ-1}:

- Level 0 is **highest** authority (fewest needed).
- Level ℓ-1 is **lowest** authority.

Cumulative thresholds  t_0 ≤ t_1 ≤ … ≤ t_{ℓ-1}  define the access
structure Γ:

    S ∈ Γ  iff  ∀ℓ:  |S ∩ (L_0 ∪ … ∪ L_ℓ)| ≥ t_ℓ

Birkhoff point assignment:

    Participant  i  at level  ℓ  gets  (α_i, β_i) = (i, ℓ)

where  α_i > 0  (participant IDs start at 1)  and  β_i  is the
derivative order.  The polynomial degree is  t_{ℓ-1} - 1  (overall
threshold minus one).

References
----------
- Tassa (2007). "Hierarchical Threshold Secret Sharing."
  Journal of Cryptology 20(2), pp. 237-264.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .polynomial import BirkhoffPoint, check_polya_conditions


@dataclass
class LevelConfig:
    """Configuration for a single hierarchy level."""

    level: int               # 0 = highest authority
    member_ids: List[int]    # participant IDs in this level
    threshold: int           # cumulative threshold at this level

    @property
    def size(self) -> int:
        return len(self.member_ids)


@dataclass
class HierarchicalAccess:
    """
    Complete hierarchical access structure.

    Attributes
    ----------
    num_participants : int
        Total number of participants *n*.
    levels : list[LevelConfig]
        Level configurations sorted by authority (0 = highest).
    polynomial_degree : int
        Degree of the shared polynomial = t_{ℓ-1} - 1.
    """

    num_participants: int
    levels: List[LevelConfig]
    polynomial_degree: int

    # internal lookup: participant_id → level
    _id_to_level: Dict[int, int] = field(
        default_factory=dict, repr=False, init=False,
    )

    def __post_init__(self) -> None:
        self._id_to_level = {}
        for lc in self.levels:
            for pid in lc.member_ids:
                if pid in self._id_to_level:
                    raise ValueError(
                        f"participant {pid} assigned to multiple levels"
                    )
                self._id_to_level[pid] = lc.level

    # ── factories ──────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        level_sizes: List[int],
        thresholds: List[int],
        *,
        start_id: int = 1,
    ) -> HierarchicalAccess:
        """
        Build an access structure from level sizes and thresholds.

        Parameters
        ----------
        level_sizes : list[int]
            Number of participants per level, e.g. [2, 3, 5].
        thresholds : list[int]
            Cumulative thresholds, e.g. [1, 3, 7].
            Must be non-decreasing and len == len(level_sizes).
        start_id : int
            First participant ID (default 1; IDs must be > 0).
        """
        L = len(level_sizes)
        if len(thresholds) != L:
            raise ValueError("level_sizes and thresholds must be same length")
        if L == 0:
            raise ValueError("must have at least one level")
        for i in range(1, L):
            if thresholds[i] < thresholds[i - 1]:
                raise ValueError("thresholds must be non-decreasing")
        if any(s <= 0 for s in level_sizes):
            raise ValueError("each level must have ≥ 1 participant")
        if any(t <= 0 for t in thresholds):
            raise ValueError("each threshold must be ≥ 1")
        if start_id < 1:
            raise ValueError("start_id must be ≥ 1 (Birkhoff requires α > 0)")

        # Validate that thresholds are achievable
        cumulative_size = 0
        for i in range(L):
            cumulative_size += level_sizes[i]
            if thresholds[i] > cumulative_size:
                raise ValueError(
                    f"threshold[{i}]={thresholds[i]} exceeds cumulative "
                    f"participants={cumulative_size} at levels 0..{i}"
                )

        pid = start_id
        levels: List[LevelConfig] = []
        for ell in range(L):
            ids = list(range(pid, pid + level_sizes[ell]))
            levels.append(LevelConfig(
                level=ell,
                member_ids=ids,
                threshold=thresholds[ell],
            ))
            pid += level_sizes[ell]

        n = sum(level_sizes)
        degree = thresholds[-1] - 1

        return cls(
            num_participants=n,
            levels=levels,
            polynomial_degree=degree,
        )

    @classmethod
    def flat(cls, n: int, t: int) -> HierarchicalAccess:
        """
        Flat (non-hierarchical) threshold:  t-of-n.

        Equivalent to a single level with all participants at level 0
        and Birkhoff degenerating to Lagrange.
        """
        if t > n:
            raise ValueError(f"threshold {t} exceeds participants {n}")
        if t < 1:
            raise ValueError("threshold must be ≥ 1")
        return cls.create(level_sizes=[n], thresholds=[t])

    # ── queries ────────────────────────────────────────────────────────

    def get_level(self, participant_id: int) -> int:
        """Return the authority level of a participant."""
        try:
            return self._id_to_level[participant_id]
        except KeyError:
            raise ValueError(f"unknown participant {participant_id}")

    def get_birkhoff_point(self, participant_id: int) -> BirkhoffPoint:
        """
        Return (α, β) for participant — the evaluation point and
        derivative order used for share generation and reconstruction.
        """
        level = self.get_level(participant_id)
        # α = participant_id (must be > 0)
        # β = level (derivative order)
        return (participant_id, level)

    def get_birkhoff_points(
        self, signer_ids: List[int],
    ) -> List[BirkhoffPoint]:
        """Birkhoff points for a set of signers."""
        return [self.get_birkhoff_point(pid) for pid in signer_ids]

    def all_participant_ids(self) -> List[int]:
        """All participant IDs across all levels, sorted."""
        ids: List[int] = []
        for lc in self.levels:
            ids.extend(lc.member_ids)
        return sorted(ids)

    @property
    def num_levels(self) -> int:
        return len(self.levels)

    @property
    def overall_threshold(self) -> int:
        """Number of signers required (= t_{L-1})."""
        return self.levels[-1].threshold

    # ── authorisation ──────────────────────────────────────────────────

    def is_authorised(self, signer_ids: Set[int]) -> bool:
        """
        Check whether a signer set satisfies the hierarchical access
        structure.

        The set S is authorised iff for every level ℓ:
            |S ∩ (L_0 ∪ … ∪ L_ℓ)| ≥ t_ℓ
        """
        cumulative_count = 0
        for lc in self.levels:
            cumulative_count += sum(
                1 for pid in lc.member_ids if pid in signer_ids
            )
            if cumulative_count < lc.threshold:
                return False
        return True

    def check_signer_set_valid(self, signer_ids: List[int]) -> bool:
        """
        Check both authorisation AND Pólya conditions for reconstruction.

        An authorised set might still fail Birkhoff interpolation if
        the Pólya conditions are violated (though for Tassa's scheme
        with distinct evaluation points, authorisation implies Pólya).
        """
        if not self.is_authorised(set(signer_ids)):
            return False
        points = self.get_birkhoff_points(signer_ids)
        return check_polya_conditions(points)

    def minimal_sets_description(self) -> str:
        """Human-readable description of the access structure."""
        parts = []
        for lc in self.levels:
            parts.append(
                f"Level {lc.level}: {lc.size} members, "
                f"cumulative threshold ≥ {lc.threshold}"
            )
        return "\n".join(parts)

    def __repr__(self) -> str:
        sizes = [lc.size for lc in self.levels]
        thresh = [lc.threshold for lc in self.levels]
        return (
            f"HierarchicalAccess(n={self.num_participants}, "
            f"sizes={sizes}, thresholds={thresh})"
        )
