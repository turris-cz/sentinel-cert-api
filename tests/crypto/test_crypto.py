import pytest

import certapi.crypto as c
import certapi.exceptions as ex
import certapi.validators as v


def test_get_common_names(good_pem_csr, good_common_names):
    csr = c.csr_from_str(good_pem_csr)
    cname = c.get_common_names(csr)
    assert cname[0].value == good_common_names


def test_valid_csr_loading(good_pem_csr, good_public_numbers):
    csr = c.csr_from_str(good_pem_csr)
    assert csr.public_key().public_numbers() == good_public_numbers


def test_invalid_csr_loading(bad_pem_csr, good_public_numbers):
    with pytest.raises(ex.InvalidParamError):
        c.csr_from_str(bad_pem_csr)


def test_create_random_nonce():
    nonce = c.create_random_nonce()
    assert nonce != ""
    v.validate_sid(nonce)


def test_create_random_sid():
    sid = c.create_random_sid()
    assert sid != ""
    v.validate_sid(sid)


def test_valid_key_match(good_cert_bytes, good_csr_bytes):
    assert c.key_match(good_cert_bytes, good_csr_bytes)


def test_different_key_match(good_cert_bytes, swapped_csr_bytes):
    assert not c.key_match(good_cert_bytes, swapped_csr_bytes)


def test_invalid_key_match(invalid_cert_bytes, good_csr_bytes):
    with pytest.raises(ValueError):
        c.key_match(invalid_cert_bytes, good_csr_bytes)


def test_badlytyped_key_match(bad_format_cert_bytes, good_csr_bytes):
    with pytest.raises(TypeError):
        c.key_match(bad_format_cert_bytes, good_csr_bytes)
