import pytest

from poi.ledger import pubkey_hex
from poi.policy import parse
from poi.seal.sealer import Sealer
from poi.verify import E_EVIDENCE, E_SEALED, VerifyError, verify_chain, verify_policy, verify_run

from helpers import POLICY, make_sealed_run


def test_without_key_chain_ok_and_schema_skipped(tmp_path, key):
    run, _, _ = make_sealed_run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    verify_policy(res, run, parse(POLICY))
    assert res.sealed_unchecked == 3            # allowed egress, blocked egress, blocked dns


def test_with_key_everything_checked(tmp_path, key):
    run, s, _ = make_sealed_run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    verify_policy(res, run, parse(POLICY), s)
    assert res.sealed_unchecked == 0
    v = verify_run(run, pubkey_hex(key), parse(POLICY), s)
    assert v.res.sealed_unchecked == 0
    assert verify_run(run, pubkey_hex(key), parse(POLICY)).res.sealed_unchecked == 3


def test_wrong_run_key_is_e_sealed(tmp_path, key):
    run, _, _ = make_sealed_run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    with pytest.raises(VerifyError) as e:
        verify_policy(res, run, parse(POLICY), Sealer(b"x" * 32))
    assert e.value.code == E_SEALED


def test_missing_sealed_evidence_detected_without_key(tmp_path, key):
    run, _, _ = make_sealed_run(tmp_path, key)
    for p in (run / "evidence").glob("*.bin"):
        if p.read_bytes().startswith(b"POIEV1"):
            p.unlink()
    res = verify_chain(run, pubkey_hex(key))
    with pytest.raises(VerifyError) as e:
        verify_policy(res, run, parse(POLICY))
    assert e.value.code == E_EVIDENCE
