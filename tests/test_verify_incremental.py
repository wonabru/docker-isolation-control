import json

import pytest

from poi import evidence
from poi.ledger import pubkey_hex
from poi.policy import parse
from poi.verify import (E_CHAIN, E_DELTA, E_EVIDENCE, ChainVerifier, VerifyError, verify_chain,
                        verify_policy, verify_run)

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, POLICY, FakeFS, make_engine, make_run


def _cps(run):
    return [json.loads(p.read_bytes()) for p in sorted((run / "ledger").glob("*.json"))]


def _delta(run, seq):
    return (run / "delta" / f"{seq:06d}.jsonl").read_bytes()


def test_feed_matches_batch_verify(tmp_path, key):
    make_run(tmp_path, key)
    v = ChainVerifier(pubkey_hex(key))
    new = [v.feed(cp, _delta(tmp_path, cp["seq"])) for cp in _cps(tmp_path)]
    batch = verify_chain(tmp_path, pubkey_hex(key))
    assert [len(n) for n in new] == [0, 4, 2]
    assert v.res.accs == batch.accs
    assert [e.seq for e in v.res.egress] == [e.seq for e in batch.egress]
    assert v.next_checkpoint == 3


def test_failed_feed_does_not_change_state(tmp_path, key):
    make_run(tmp_path, key)
    cps = _cps(tmp_path)
    v = ChainVerifier(pubkey_hex(key))
    v.feed(cps[0], _delta(tmp_path, 0))
    with pytest.raises(VerifyError) as ei:
        v.feed(cps[1], _delta(tmp_path, 1) + b"\n")
    assert ei.value.code == E_DELTA
    v.feed(cps[1], _delta(tmp_path, 1))      # the honest file still verifies afterwards
    assert v.next_checkpoint == 2


def test_out_of_order_rejected(tmp_path, key):
    make_run(tmp_path, key)
    cps = _cps(tmp_path)
    v = ChainVerifier(pubkey_hex(key))
    with pytest.raises(VerifyError) as ei:
        v.feed(cps[1], _delta(tmp_path, 1))
    assert ei.value.code == E_CHAIN


def _engine_run(tmp_path, key):
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS))
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [], b"{}")
    gate.on_request("evil.com", "POST", "/", [], b"x")
    eng.tick()
    return tmp_path / "run"


def test_verify_run_equals_chain_plus_policy(tmp_path, key):
    run = _engine_run(tmp_path, key)
    v = verify_run(run, pubkey_hex(key), parse(POLICY))
    res = verify_chain(run, pubkey_hex(key))
    verify_policy(res, run, parse(POLICY))
    assert v.res.accs == res.accs and len(v.res.egress) == len(res.egress) == 2


def test_incremental_policy_check_needs_evidence(tmp_path, key):
    run = _engine_run(tmp_path, key)
    v = ChainVerifier(pubkey_hex(key), parse(POLICY))
    cps = _cps(run)
    v.feed(cps[0], _delta(run, 0), lambda d: evidence.get(run / "evidence", d))
    with pytest.raises(VerifyError) as ei:
        v.feed(cps[1], _delta(run, 1), lambda d: None)
    assert ei.value.code == E_EVIDENCE
