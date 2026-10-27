import math

from poi.fingerprint import FingerprintSet
from poi.ledger import pubkey_hex
from poi.policy import parse
from poi.report import build_report, render_text
from poi.verify import verify_chain

from helpers import DASH_SECRET, POLICY, make_sealed_run


def test_report_locked_then_opened(tmp_path, key):
    run, s, _ = make_sealed_run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    policy = parse(POLICY)
    locked = build_report(res, run, policy)
    assert locked["sealed_locked"] == 3 and locked["allowed_requests"] == 1
    assert math.isinf(locked["capacity_bits_upper_bound"])
    assert all("85010112345" not in b["target"] and "evil" not in b["target"] for b in locked["blocked"])
    assert "🔒" in render_text(locked)
    fps = FingerprintSet(b"k" * 32)
    fps.add(DASH_SECRET, "patients.csv")
    opened = build_report(res, run, policy, fps, sealer=s)
    assert opened["sealed_locked"] == 0 and not math.isinf(opened["capacity_bits_upper_bound"])
    targets = {b["target"] for b in opened["blocked"]}
    assert {"POST evil.test/c/85010112345", "85010112345.evil.test"} <= targets
    assert opened["fingerprint_hits"] and opened["fingerprint_hits_in_allowed_traffic"] == 0
