"""Serializable capture profile: which processes carry an app's TLS traffic."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

PROFILE_SCHEMA = "tlslibhunter.profile/1"

ROLE_TARGET = "target"
ROLE_SIBLING = "sibling"
ROLE_DELEGATE = "delegate"
ROLE_SDK_SANDBOX = "sdk_sandbox"
ROLE_SHARED_SYSTEM = "shared_system"

ROLES = (ROLE_TARGET, ROLE_SIBLING, ROLE_DELEGATE, ROLE_SDK_SANDBOX, ROLE_SHARED_SYSTEM)


@dataclass
class Candidate:
    """A process that may carry the target's traffic, with the evidence for it."""

    pid: int
    process: str
    package: str
    uid: int
    role: str
    evidence: list[str] = field(default_factory=list)
    # A mapped TLS library backs the socket/hand-off evidence (see discovery.tls_libs).
    confirmed: bool = False

    @property
    def is_attributable(self) -> bool:
        """False for shared system processes whose traffic mixes many apps."""
        return self.role != ROLE_SHARED_SYSTEM


def gate_packages_from(candidates: list[Candidate]) -> list[str]:
    """Sorted unique packages of attributable candidates; target packages come first."""
    attributable = [cand for cand in candidates if cand.is_attributable]
    targets = sorted({cand.package for cand in attributable if cand.role == ROLE_TARGET})
    others = sorted({cand.package for cand in attributable} - set(targets))
    return targets + others


@dataclass
class Profile:
    """Discovery result for one target, persisted as JSON (schema ``tlslibhunter.profile/1``)."""

    target: str
    target_package: str
    gate_packages: list[str] = field(default_factory=list)
    process_patterns: list[str] = field(default_factory=list)
    device_fingerprint: str | None = None
    version_code: int | None = None
    candidates: list[Candidate] = field(default_factory=list)
    # ``discover --probe``: binder interfaces the target called that map to no
    # known package (escaped, capped); optional, absent in older profiles.
    binder_descriptors: list[str] = field(default_factory=list)
    schema: str = PROFILE_SCHEMA

    def attributable_candidates(self) -> list[Candidate]:
        """Candidates except shared system processes."""
        return [cand for cand in self.candidates if cand.is_attributable]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Profile:
        """Build a profile; raises ValueError if ``schema`` is not ``tlslibhunter.profile/1``."""
        schema = data.get("schema")
        if schema != PROFILE_SCHEMA:
            raise ValueError(f"unsupported profile schema: {schema!r} (expected {PROFILE_SCHEMA!r})")
        fields = dict(data)
        fields["candidates"] = [Candidate(**cand) for cand in data.get("candidates", [])]
        return cls(**fields)

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, text: str) -> Profile:
        return cls.from_dict(json.loads(text))
