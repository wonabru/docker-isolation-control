import pytest

from poi.assess import ATTENTION, BROKEN, VERIFIED, Snapshot, assess


def snap(**kw):
    base = dict(error=None, allowed_hits=[], blocked_hits=[], acked=set(), last_received=100.0, started=0.0,
                source_down_since=None, tick_seconds=2.0, unbounded_channel=False)
    base.update(kw)
    return Snapshot(**base)


@pytest.mark.parametrize("kw,now,level,phrase", [
    ({}, 101.0, VERIFIED, None),
    ({"error": "[12] checkpoint 3: delta"}, 101.0, BROKEN, "Verification failed"),
    ({"allowed_hits": [7]}, 101.0, BROKEN, "ALLOWED"),
    ({"allowed_hits": [7], "error": "x"}, 101.0, BROKEN, "ALLOWED"),
    ({"blocked_hits": [4]}, 101.0, ATTENTION, "Blocked exfiltration"),
    ({"blocked_hits": [4], "acked": {4}}, 101.0, VERIFIED, None),
    ({}, 107.0, ATTENTION, "No new checkpoint"),
    ({"run_finished": True}, 500.0, VERIFIED, None),
    ({"last_received": None, "started": 0.0}, 7.0, ATTENTION, "No new checkpoint"),
    ({"source_down_since": 101.0}, 103.0, VERIFIED, None),
    ({"source_down_since": 101.0}, 108.0, ATTENTION, "unreachable"),
    ({"unbounded_channel": True}, 101.0, ATTENTION, "unbounded"),
])
def test_assess(kw, now, level, phrase):
    v = assess(snap(**kw), now)
    assert v.level == level
    if phrase:
        assert any(phrase in r for r in v.reasons)
    else:
        assert v.reasons == []
