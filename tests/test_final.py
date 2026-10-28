"""Signed end of run: the last checkpoint is `final`, nothing may follow it, the dashboard stops expecting more."""
import json

import pytest

from poi import cli
from poi.assess import ATTENTION, VERIFIED
from poi.ledger import Ledger, pubkey_hex
from poi.lthash import LtHash
from poi.mirror import Mirror
from poi.source import LocalSource
from poi.verify import E_CHAIN, VerifyError, verify_chain, verify_policy
from poi.policy import parse

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, POLICY, FakeFS, make_engine, make_run


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _engine_run(tmp_path, key, final: bool):
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS))
    (tmp_path / "run").mkdir(exist_ok=True)
    (tmp_path / "run" / "policy.yaml").write_bytes(POLICY)
    eng.genesis()
    eng.tick(final=final)
    return tmp_path / "run"


def _append_after(run, key):
    led = Ledger(run, key)
    last = led.last()
    led.append(t=last["t"], container=last["container"], policy_digest=last["policy"],
               accs={a: LtHash.from_b64(last[a]["vec"]) for a in ("state", "egress", "ingress")},
               counts={"egress": last["egress"]["count"], "ingress": last["ingress"]["count"]}, ops=[])


def test_final_tick_is_signed_and_closes_the_chain(tmp_path, key):
    run = _engine_run(tmp_path, key, final=True)
    res = verify_chain(run, pubkey_hex(key))
    verify_policy(res, run, parse(POLICY))
    assert res.finished and res.last["final"] is True
    _append_after(run, key)                         # a checkpoint after the end of the run
    with pytest.raises(VerifyError) as ei:
        verify_chain(run, pubkey_hex(key))
    assert ei.value.code == E_CHAIN and "after the final" in str(ei.value)


def test_final_flag_is_covered_by_the_signature(tmp_path, key):
    run = _engine_run(tmp_path, key, final=True)
    p = sorted((run / "ledger").glob("*.json"))[-1]
    cp = json.loads(p.read_bytes())
    del cp["final"]                                 # operator (or anyone) tries to reopen the run
    from poi import canonical as c
    p.write_bytes(c.canonical_json(cp))
    with pytest.raises(VerifyError):
        verify_chain(run, pubkey_hex(key))


def test_dashboard_does_not_flag_a_finished_run_as_stale(tmp_path, key):
    """A finished run whose container is gone (operator runtime 'unknown') must stay Verified."""
    for final, expected in ((False, ATTENTION), (True, VERIFIED)):
        d = tmp_path / str(final)
        d.mkdir()
        run = _engine_run(d, key, final=final)
        clock = Clock()
        m = Mirror(d / "mirror", LocalSource(run, runtime=lambda: {"status": "unknown"}), pubkey_hex(key), None,
                   sleep=lambda s: None, monotonic=clock)
        m.sync_once(wait=0)
        m.refresh_runtime()
        clock.t += 3600                             # an hour without new checkpoints
        v = m.verdict()
        assert v.level == expected, v.reasons


def test_finalize_command_closes_an_old_run(tmp_path, key):
    make_run(tmp_path, key)                         # run without a final checkpoint (pre-`final` POI)
    kp = tmp_path / "op.key"
    kp.write_bytes(key.private_bytes_raw())
    assert not verify_chain(tmp_path, pubkey_hex(key)).finished
    assert cli.main(["finalize", str(tmp_path), "--key", str(kp), "--force"]) == 0
    res = verify_chain(tmp_path, pubkey_hex(key))
    assert res.finished and len(res.checkpoints) == 4
    assert res.accs["state"].digest() == res.last["state"]["digest"]   # no state change in the final checkpoint
    assert cli.main(["finalize", str(tmp_path), "--key", str(kp), "--force"]) == 0   # idempotent
    assert len(verify_chain(tmp_path, pubkey_hex(key)).checkpoints) == 4


def test_finalize_refuses_without_docker_check(tmp_path, key, monkeypatch):
    make_run(tmp_path, key)
    kp = tmp_path / "op.key"
    kp.write_bytes(key.private_bytes_raw())
    assert cli.main(["finalize", str(tmp_path), "--key", str(kp)]) == 2      # no runtime.json: must use --force
    assert not verify_chain(tmp_path, pubkey_hex(key)).finished
