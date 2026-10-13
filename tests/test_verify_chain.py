import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from poi import canonical as c
from poi.ledger import DeltaOp, pubkey_hex
from poi.verify import (E_CHAIN, E_DELTA, E_SEQ, E_SIGNATURE, VerifyError, verify_chain)

from helpers import egress, make_run


def _rewrite(path, mutate):
    cp = json.loads(path.read_bytes())
    mutate(cp)
    path.write_bytes(c.canonical_json(cp))


def _expect(tmp_path, key, code):
    with pytest.raises(VerifyError) as ei:
        verify_chain(tmp_path, pubkey_hex(key))
    assert ei.value.code == code, str(ei.value)


def test_valid_run_verifies(tmp_path, key):
    make_run(tmp_path, key)
    res = verify_chain(tmp_path, pubkey_hex(key))
    assert len(res.checkpoints) == 3
    assert [e.seq for e in res.egress] == [1, 2, 3]
    assert res.accs["state"].digest() == res.last["state"]["digest"]
    assert res.config_digests == [(0, "c" * 64)]


def test_wrong_key_fails_signature(tmp_path, key):
    make_run(tmp_path, key)
    with pytest.raises(VerifyError) as ei:
        verify_chain(tmp_path, pubkey_hex(Ed25519PrivateKey.generate()))
    assert ei.value.code == E_SIGNATURE


def test_modified_checkpoint_field_fails_signature(tmp_path, key):
    make_run(tmp_path, key)
    _rewrite(tmp_path / "ledger" / "000001.json", lambda cp: cp.update(t="2026-10-13T18:00:05Z"))
    _expect(tmp_path, key, E_SIGNATURE)


def test_resigned_tampered_vector_fails_delta(tmp_path, key):
    make_run(tmp_path, key)

    def mutate(cp):
        cp["state"]["vec"] = cp["state"]["vec"][:-4] + ("AAA=" if cp["state"]["vec"][-4:] != "AAA=" else "AQA=")
        cp["sig"] = key.sign(c.checkpoint_signing_bytes(cp)).hex()

    _rewrite(tmp_path / "ledger" / "000002.json", mutate)
    _expect(tmp_path, key, E_DELTA)


def test_modified_delta_byte_fails(tmp_path, key):
    make_run(tmp_path, key)
    p = tmp_path / "delta" / "000001.jsonl"
    raw = bytearray(p.read_bytes())
    raw[-3] ^= 1
    p.write_bytes(bytes(raw))
    _expect(tmp_path, key, E_DELTA)


def test_deleted_checkpoint_fails_chain(tmp_path, key):
    make_run(tmp_path, key)
    (tmp_path / "ledger" / "000001.json").unlink()
    _expect(tmp_path, key, E_CHAIN)


def test_swapped_checkpoints_fail_chain(tmp_path, key):
    make_run(tmp_path, key)
    a, b = tmp_path / "ledger" / "000001.json", tmp_path / "ledger" / "000002.json"
    da, db = a.read_bytes(), b.read_bytes()
    a.write_bytes(db)
    b.write_bytes(da)
    _expect(tmp_path, key, E_CHAIN)


def test_seq_gap_fails(tmp_path, key):
    led = make_run(tmp_path, key, n_egress=(1,))
    res = verify_chain(tmp_path, pubkey_hex(key))
    accs = {k: v.copy() for k, v in res.accs.items()}
    e = egress(3)  # skips seq 2
    accs["egress"].add(e)
    led.append(t="2026-10-13T18:00:09Z", container=res.last["container"], policy_digest="p" * 64,
               accs=accs, counts={"egress": 2, "ingress": 1}, ops=[DeltaOp("add", "egress", e)])
    _expect(tmp_path, key, E_SEQ)


def test_egress_sub_rejected(tmp_path, key):
    led = make_run(tmp_path, key, n_egress=(1,))
    res = verify_chain(tmp_path, pubkey_hex(key))
    e = egress(1)
    accs = {k: v.copy() for k, v in res.accs.items()}
    accs["egress"].sub(e)
    led.append(t="2026-10-13T18:00:09Z", container=res.last["container"], policy_digest="p" * 64,
               accs=accs, counts={"egress": 1, "ingress": 1}, ops=[DeltaOp("sub", "egress", e)])
    _expect(tmp_path, key, E_SEQ)


def test_key_rotation(tmp_path, key):
    led = make_run(tmp_path, key, n_egress=(1,))
    new = Ed25519PrivateKey.generate()
    res = verify_chain(tmp_path, pubkey_hex(key))
    kw = dict(container=res.last["container"], policy_digest="p" * 64, accs=res.accs,
              counts={"egress": 1, "ingress": 1}, ops=[])
    led.append(t="2026-10-13T18:00:09Z", rotate_to=new, **kw)
    led.append(t="2026-10-13T18:00:10Z", **kw)
    assert len(verify_chain(tmp_path, pubkey_hex(key)).checkpoints) == 4
