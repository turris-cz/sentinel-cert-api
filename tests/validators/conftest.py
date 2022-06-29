import pytest


@pytest.fixture(
    params=[
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAAQo+Cq6N6QAu99pDw3GJGQ0NZIDnT/P9fU2FePZJVjU\n"
        "o2obmdqZ/uRY8IeQOk3JvpoHM2o0621QIYvpjxxbOQSwoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNJADBGAiEA9uJbjUc8CI2BAt7IO6LI6han20G2Ix9T\n"
        "4mw2hEu3feECIQCb1yBuPIykwP896qq5ngESgDOi+AWUzcdVZpOMfVlIlg==\n"
        "-----END CERTIFICATE REQUEST-----\n",
    ]
)
def good_csr(request):
    return request.param


@pytest.fixture(params=[""])
def bad_csr(request):
    return request.param


@pytest.fixture(
    params=[
        (
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
            "PQIBBggqhkjOPQMBBwNCAAQo+Cq6N6QAu99pDw3GJGQ0NZIDnT/P9fU2FePZJVjU\n"
            "o2obmdqZ/uRY8IeQOk3JvpoHM2o0621QIYvpjxxbOQSwoBEwDwYJKoZIhvcNAQkO\n"
            "MQIwADAKBggqhkjOPQQDAgNJADBGAiEA9uJbjUc8CI2BAt7IO6LI6han20G2Ix9T\n"
            "4mw2hEu3feECIQCb1yBuPIykwP896qq5ngESgDOi+AWUzcdVZpOMfVlIlg==\n"
            "-----END CERTIFICATE REQUEST-----\n",
            "0000000A000001F3",
        ),
    ]
)
def valid_csr_sn_sets(request):
    return request.param


@pytest.fixture(params=["get_key", "0000000A000001F4", "1000000000000000", ""])
def bad_sn_atsha(request):
    return request.param


@pytest.fixture(
    params=[
        "0000000A000001F3",
    ]
)
def good_sn_atsha(request):
    return request.param


@pytest.fixture(params=["B2B9521346857593"])
def good_sn_b2b(request):
    return request.param


@pytest.fixture(
    params=[
        "B2B7561456746521562148",  # wrong sn len
        "1234567891234567",  # missing B2B prefix
    ]
)
def wrong_sn_b2b(request):
    return request.param


@pytest.fixture(
    params=[
        "get",
        "auth",
    ]
)
def good_req_types(request):
    return request.param


@pytest.fixture(
    params=[
        "get_cert",
        "",
        " ",
        None,
    ]
)
def bad_req_types(request):
    return request.param


@pytest.fixture(
    params=[
        ["renew"],
        [],
    ]
)
def good_certs_flags(request):
    return request.param


@pytest.fixture(
    params=[
        ["renw"],
        [""],
        [" "],
        [None],
    ]
)
def bad_certs_flags(request):
    return request.param


@pytest.fixture(params=["atsha", "otp", "b2b"])
def good_auth_types(request):
    return request.param


@pytest.fixture(
    params=[
        "atsha204",
        "",
        " ",
        None,
        #  TODO: improve cert-api so these lines can be added to tests
        #  ["atsha"],
        #  ["atsha204"],
        #  [],
    ]
)
def bad_auth_types(request):
    return request.param


@pytest.fixture(
    params=[
        "06d2bce6a9a1423629e93d451e51f156c6f9c556e495ce6506b2f93ba7e9a5c0",
        "adc619eeb5f1d98873c42d19d69e9cf85e84080b54d8b565dc7e789ce9542772",
        "",
    ]
)
def good_sid(request):
    return request.param


@pytest.fixture(
    params=[
        "atsha",
        "Adc619eeb5f1d98873c42d19d69e9cf85e84080b54d8b565dc7e789ce9542772",
        "dc619eeb5f1d98873c42d19d69e9cf85e84080b54d8b565dc7e789ce9542772",
        "adc619eeb5f1d98873c42d19d69e9cf85e84080b54d8b565dc7e789ce954277",
        " ",
        #  TODO: improve cert-spi so these lines can ba added to tests
        #  ["adc619eeb5f1d98873c42d19d69e9cf85e84080b54d8b565dc7e789ce9542772"],
        #  None,
        #  [],
    ]
)
def bad_sid(request):
    return request.param


@pytest.fixture(
    params=[
        {
            "auth_type": "",
            "nonce": "",
            "signature": "",
            "csr_str": "",
            "flags": "",
            "action": "certs",
        },
        {
            "auth_type": "",
            "nonce": "",
            "signature": "",
            "flags": "",
            "action": "mailpass",
        },
    ]
)
def good_sessions(request):
    return request.param


@pytest.fixture(
    params=[
        {
            "auth_type",
            "nonce",
            "signature",
            "csr_str",
            "",
        },
        {
            "auth_type",
            "nonce",
            "signature",
            "csr_str",
            "flagss",
        },
        {
            "auth_type",
            "nonce",
            "signature",
            "csr_str",
        },
        {},
    ]
)
def bad_sessions(request):
    return request.param


@pytest.fixture(
    params=[
        {
            "status": "ok",
            "message": None,
        },
    ]
)
def good_auth_state(request):
    return request.param


@pytest.fixture(
    params=[
        ("statu", "echo"),
        ("", "echo"),
        #  ( #  TODO: improve cert-spi so these lines can ba added to tests
        #     "status",
        #     "echo"
        #  ),
        #  (
        #     "status",
        #     "status"
        #  ),
        ("",),
        (),
    ]
)
def bad_auth_state(request):
    return request.param
