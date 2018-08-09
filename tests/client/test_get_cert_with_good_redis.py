from certapi.validators import validate_digest, validate_sid


def test_good_renew(client, good_req_get_cert_renew, redis_mock):
    rv = client.post("/v1", json=good_req_get_cert_renew)
    assert not redis_mock().exists.called  # Do not look for anything
    assert not redis_mock().get.called  # Do not look fo anything
    assert redis_mock().setex.call_count == 1  # Create auth session

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "authenticate"
    validate_digest(resp_data["nonce"])
    validate_sid(resp_data["sid"])


def good_sid_useless_cert_missing(client, good_data, redis_mock):
    redis_mock().exists.return_value = False  # Auth Session not in Redis
    redis_mock().get.return_value = None  # Cert not in Redis
    #  Now the client gets response "authenticate"

    rv = client.post("/v1", json=good_data[0])
    assert redis_mock().exists.call_count == 1  # Session exists?
    assert redis_mock().get.call_count == 1  # Get cert
    assert redis_mock().setex.call_count == 1  # Create auth session

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "authenticate"
    validate_digest(resp_data["nonce"])
    validate_sid(resp_data["sid"])


def test_good_sid_set_session_expired_cert_missing(client, good_data, redis_mock):
    good_sid_useless_cert_missing(client, good_data, redis_mock)


def test_good_sid_empty_cert_missing(client, good_data, redis_mock):
    backup_sid = good_data[0]["sid"]
    good_sid_useless_cert_missing(client, good_data, redis_mock)
    good_data[0]["sid"] = backup_sid


def good_sid_useless_cert_ok(client, good_data, redis_mock):
    redis_mock().exists.return_value = False  # Auth Session not in Redis
    redis_mock().get.return_value = good_data[1].encode("utf-8")  # Cert not in Redis
    #  Now the client gets response "ok"
    rv = client.post("/v1", json=good_data[0])
    assert redis_mock().exists.call_count == 1  # Session exists?
    assert redis_mock().get.call_count == 1  # Get cert
    assert not redis_mock().setex.called  # Do not create anything

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "ok"
    assert resp_data["cert"] == good_data[1]


def test_good_sid_set_session_expired_cert_ok(client, good_data, redis_mock):
    good_sid_useless_cert_ok(client, good_data, redis_mock)


def test_good_sid_empty_cert_ok(client, good_data, redis_mock):
    backup_sid = good_data[0]["sid"]
    good_sid_useless_cert_ok(client, good_data, redis_mock)
    good_data[0]["sid"] = backup_sid


def test_good_sid_set_auth_in_progress(client, good_data, redis_mock):
    redis_mock().exists.return_value = True  # Session exists
    redis_mock().get.return_value = None  # Auth state not in redis
    #  Now the client gets response "wait" for authentication process result

    rv = client.post("/v1", json=good_data[0])
    assert redis_mock().exists.call_count == 1  # Session exists?
    assert redis_mock().get.call_count == 1  # Get auth state
    assert not redis_mock().setex.called  # Do not set anything

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "wait"
    assert resp_data["delay"] > 0


def test_good_sid_set_auth_failed(client, good_data, redis_mock):
    redis_mock().exists.return_value = True  # Session exists
    redis_mock().get.return_value = b'{"status": "failed"}'  # Auth failed
    #  Now the client gets response "failed"

    rv = client.post("/v1", json=good_data[0])
    assert redis_mock().exists.call_count == 1  # Session exists?
    assert redis_mock().get.call_count == 1  # Get auth state
    assert not redis_mock().setex.called  # Do not set anything

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "auth_failed"


def test_good_sid_set_auth_ok_cert_missing(client, good_data, redis_mock):
    def redis_get(key):
        if "auth_state:{}:".format(good_data[0]["sn"]) in key:
            return b'{"status": "ok"}'
        if key == "certificate:{}".format(good_data[0]["sn"]):
            return None
        assert False

    redis_mock().exists.return_value = True  # Session exists
    redis_mock().get.side_effect = redis_get  # Auth ok & get cert
    #  Now the client gets response "authenticate"

    rv = client.post("/v1", json=good_data[0])
    assert redis_mock().exists.call_count == 1  # Session exists?
    assert redis_mock().get.call_count == 2  # Get auth state and cert
    assert redis_mock().setex.call_count == 1  # Do not set anything

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "authenticate"
    validate_digest(resp_data["nonce"])
    validate_sid(resp_data["sid"])


def test_good_sid_set_auth_ok_cert_ok(client, good_data, redis_mock):
    def redis_get(key):
        if "auth_state:{}:".format(good_data[0]["sn"]) in key:
            return b'{"status": "ok"}'
        if key == "certificate:{}".format(good_data[0]["sn"]):
            return good_data[1].encode("utf-8")
        assert False

    redis_mock().exists.return_value = True  # Session exists
    redis_mock().get.side_effect = redis_get  # Auth ok & get cert

    rv = client.post("/v1", json=good_data[0])
    assert redis_mock().exists.call_count == 1  # Session exists?
    assert redis_mock().get.call_count == 2  # Get auth state and cert
    assert not redis_mock().setex.called  # Do not set anything

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "ok"
    assert resp_data["cert"] == good_data[1]


def test_bad(client, bad_req_get_cert):
    rv = client.post("/v1", json=bad_req_get_cert)
    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "error"
