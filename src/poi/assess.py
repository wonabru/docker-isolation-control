"""Dashboard verdict: a pure function of a status snapshot and the current time."""
from __future__ import annotations

from dataclasses import dataclass, field

VERIFIED, ATTENTION, BROKEN = "verified", "attention", "broken"
STALE_TICKS = 3


@dataclass
class Snapshot:
    error: str | None                     # VerifyError text, if verification failed
    allowed_hits: list[int]               # egress seqs with user data in ALLOWED traffic
    blocked_hits: list[int]               # egress seqs with user data in blocked attempts
    acked: set[int]
    last_received: float | None           # local monotonic time of the last new checkpoint
    started: float                        # local monotonic time the dashboard started
    source_down_since: float | None
    tick_seconds: float
    unbounded_channel: bool
    run_finished: bool = False            # set when operator declares the workload exited


@dataclass
class Verdict:
    level: str
    reasons: list[str] = field(default_factory=list)


def assess(s: Snapshot, now: float) -> Verdict:
    broken = []
    if s.error:
        broken.append(f"Verification failed: {s.error}")
    if s.allowed_hits:
        broken.append(f"Your data was found in ALLOWED outbound traffic (events {s.allowed_hits})")
    if broken:
        return Verdict(BROKEN, broken)

    attention = []
    pending = [q for q in s.blocked_hits if q not in s.acked]
    if pending:
        attention.append(f"Blocked exfiltration attempt containing your data (events {pending})")
    limit = STALE_TICKS * s.tick_seconds
    if s.source_down_since is not None and now - s.source_down_since > limit:
        attention.append(f"Operator feed unreachable for {now - s.source_down_since:.0f} s")
    elif not s.run_finished and now - (s.last_received or s.started) > limit:
        attention.append(f"No new checkpoint for {now - (s.last_received or s.started):.0f} s")
    if s.unbounded_channel:
        attention.append("Policy allows free-form values: covert channel is unbounded")
    return Verdict(ATTENTION, attention) if attention else Verdict(VERIFIED, [])
