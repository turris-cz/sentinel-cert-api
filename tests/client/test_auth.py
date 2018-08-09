import json


def test_good_req_session_expired(client, good_req_auth_data, redis_mock):
    redis_mock().get.return_value = None  # Auth session not in redis
    rv = client.post("/v1", json=good_req_auth_data[0])
    assert not redis_mock().exists.called  # Do not look for anythong
    assert redis_mock().get.call_count == 1  # Get auth session
    assert not redis_mock().setex.called  # Do not create anythibg

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "fail"


def test_good_req_session_ok(client, redis_mock, good_req_auth_data):
    redis_mock().get.return_value = json.dumps(good_req_auth_data[1]).encode("utf-8")  # Auth session ok
    rv = client.post("/v1", json=good_req_auth_data[0])
    assert not redis_mock().exists.called  # Do not look for anything
    assert redis_mock().get.call_count == 1  # Get session
    assert not redis_mock().setex.called  # Do not create anythig

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "accepted"
    assert "delay" in resp_data


def test_bad_req(client, redis_mock, bad_req_auth):
    rv = client.post("/v1", json=bad_req_auth)
    assert not redis_mock().exists.called  # Do not look for anything
    assert not redis_mock().get.called  # Do not get anything
    assert not redis_mock().setex.called  # Do not create anythig

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "error"


def test_good_req_session_broken(client, redis_mock, good_req_auth_data, bad_session):
    redis_mock().get.return_value = json.dumps(bad_session).encode("utf-8")  # Auth seesion
    rv = client.post("/v1", json=good_req_auth_data[0])
    assert not redis_mock().exists.called  # Do not for anything
    assert redis_mock().get.call_count == 1  # Get session
    assert not redis_mock().setex.called  # Do not create anythig

    assert rv.status_code == 200
    resp_data = rv.get_json()
    assert resp_data["status"] == "error"
