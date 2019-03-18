from certapi.validators import validate_digest, validate_sid, DIGEST_LEN


def good_req_sid_useless_cert_broken(client, good_data, redis_mock, bad_cert):
    redis_mock().exists.return_value = False  # Auth Session not in Redis
    redis_mock().get.return_value = bad_cert.encode("utf-8")  # BAd cert in redis
    rv = client.post("/v1", json=good_data[0])
    assert redis_mock().exists.call_count == 1  # Session exists?
    assert redis_mock().get.call_count == 1  # Get cert
    assert redis_mock().setex.call_count == 1  # Create auth session

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "authenticate"
    validate_digest(resp_data["nonce"], DIGEST_LEN[good_data[0]["auth_type"]])
    validate_sid(resp_data["sid"])


def test_good_req_sid_set_session_expired_cert_broken(client, good_data, redis_mock, bad_cert):
    good_req_sid_useless_cert_broken(client, good_data, redis_mock, bad_cert)


def test_good_req_sid_empty_cert_broken(client, good_data, redis_mock, bad_cert):
    backup_sid = good_data[0]["sid"]
    good_req_sid_useless_cert_broken(client, good_data, redis_mock, bad_cert)
    good_data[0]["sid"] = backup_sid


def test_good_req_sid_set_auth_broken(client, good_data, redis_mock, bad_auth_state):
    redis_mock().exists.return_value = True  # Session exists
    redis_mock().get.return_value = bad_auth_state.encode("utf-8")  # Auth failed

    rv = client.post("/v1", json=good_data[0])
    assert redis_mock().exists.call_count == 1  # Session exists?
    assert redis_mock().get.call_count == 1  # Get auth state
    assert not redis_mock().setex.called  # Do not set anything

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "error"
