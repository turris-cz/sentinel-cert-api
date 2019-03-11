import pytest

import certapi.crypto as c
import certapi.validators as v
import certapi.exceptions as ex


def test_valid_sn_atsha(good_sn_atsha):
    v.validate_sn_atsha(good_sn_atsha)


def test_invalid_sn_atsha(bad_sn_atsha):
    with pytest.raises(ex.RequestConsistencyError):
        v.validate_sn_atsha(bad_sn_atsha)


def test_valid_csr_common_name(valid_csr_sn_sets):
    csr = c.csr_from_str(valid_csr_sn_sets[0])
    v.validate_csr_common_name(csr, valid_csr_sn_sets[1])


def test_valid_csr_hash(good_csr):
    csr = c.csr_from_str(good_csr)
    v.validate_csr_hash(csr)


def test_valid_csr_signature(good_csr):
    csr = c.csr_from_str(good_csr)
    v.validate_csr_signature(csr)


def test_valid_csr(good_csr, good_sn_atsha):
    v.validate_csr(good_csr, good_sn_atsha)


def test_invalid_csr(bad_csr, bad_sn_atsha):
    with pytest.raises(ex.RequestConsistencyError):
        v.validate_csr(bad_csr, bad_sn_atsha)


def test_valid_flags(good_certs_flags):
    v.validate_certs_flags(good_certs_flags)


def test_invalid_flags(bad_certs_flags):
    with pytest.raises(ex.RequestConsistencyError):
        v.validate_certs_flags(bad_certs_flags)


def test_valid_auth_type(good_auth_types):
    v.validate_auth_type(good_auth_types)


def test_invalid_auth_type(bad_auth_types):
    with pytest.raises(ex.RequestConsistencyError):
        v.validate_auth_type(bad_auth_types)


def test_valid_sn(good_sid):
    v.validate_sid(good_sid)


def test_invalid_sn(bad_sid):
    with pytest.raises(ex.RequestConsistencyError):
        v.validate_sid(bad_sid)


def test_valid_session(good_sessions):
    v.check_session(good_sessions)


def test_invalid_session(bad_sessions):
    with pytest.raises(ex.InvalidRedisDataError):
        v.check_session(bad_sessions)


def test_valid_auth_state(good_auth_state):
    v.validate_auth_state(good_auth_state)


def test_invalid_auth_state(bad_auth_state):
    with pytest.raises(ex.InvalidRedisDataError):
        v.validate_auth_state(bad_auth_state)
