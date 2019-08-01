import pytest
from certapi import create_app
from unittest.mock import Mock, patch


@pytest.fixture
def app():
    yield create_app()


@pytest.fixture
def client_rl(app):
    with app.test_client() as client:
        app.config["RLIMIT_WINDOW_TIME"] = 600
        app.config["RLIMIT_MAX_HITS"] = 1
        yield client


@pytest.fixture
def client(app):
    with app.test_client() as client:
        app.config["RLIMIT_MAX_HITS"] = 0
        yield client


@pytest.fixture
def redis_mock():
    redis_inst_mock = Mock()
    with patch("redis.StrictRedis", return_value=redis_inst_mock) as m:
        yield m


@pytest.fixture
def redis_pipe_mock():
    redis_inst_mock = Mock()
    pipe_mock = Mock()
    hits_in_redis = 1
    pipe_mock.execute.return_value = [None, hits_in_redis, None]
    redis_inst_mock.pipeline.return_value = pipe_mock
    with patch("redis.StrictRedis", return_value=redis_inst_mock) as m:
        yield m


@pytest.fixture(params=[
    {
        "sn": "0000000A000001F3",
        "type": "get",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAATZidHnuSVUH647KgxFnvgP74OTAdKdkSgVZEfyoAXy\n"
        "d8iEFj3BYAWXicyX6WEsA0mUn391NO0Z6Tu4PwYLclOUoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNJADBGAiEAy2GDiZGcK9CAg7xpqUrgSb5eQnP2LSI7\n"
        "dKI45BF+g5kCIQCgnRB9mt9ThDSeuFB5fDZ3aGizDDdK8E+rYpuAW7VCpQ==\n"
        "-----END CERTIFICATE REQUEST-----\n",
        "auth_type": "atsha",
        "sid": "",
        "flags": ["renew"]
    },
])
def good_req_get_cert_renew(request):
    return request.param


good_reqs_get_cert = [
    {
        "auth_type": "atsha",
        "sn": "0000000A000001F3",
        "flags": [],
        "sid": "4cca5561cf766855a02ee33f229acf4b144fdb7988abd85fd2bad3cfe2546d9f",
        "type": "get",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHnMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAASCLeKIXMOsIdxYndnySeHcwv+EvJvp6RiXPd2gY/pz\n"
        "kfNBVFzudGJ8tKWo4JPG1U66Crh5GgqaxGoWUPBdw8+BoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNIADBFAiB4Me5+cfwup0tMMeQM/xrHgBYylaTT6ngf\n"
        "GZQpsrmpBAIhAIhxE9+bzUoBDYFRTFHq4lzD/mzCb3s/lFwJy694PqA0\n"
        "-----END CERTIFICATE REQUEST-----\n"
    },
    {
        "type": "get",
        "auth_type": "atsha",
        "sid": "aea13dbed3b576cc8300d4710bdc708e6baff00f2e485ad2d9614fdc378fd4e0",
        "flags": [],
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHmMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAAQGpZBcM/iDdl4+m+fW3NnIOf3epwWZjJQqQY8R0b6+\n"
        "cm9eSHpqIlI6zjUCzBD1jC1BsewZ25Dy7nQMGOmvwrTYoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNHADBEAiBN20doyA17mcy4thRY61WY8njlY6jGTV05\n"
        "olYg6lJlDgIgM7DGv4yRLoj7HZkkKJmXDZ+w2PdKLp2za8Si7xiC+zs=\n"
        "-----END CERTIFICATE REQUEST-----\n",
        "sn": "0000000A000001F3"
    }
]


@pytest.fixture(params=[
    {  # bad sn
        "sn": "0000000A000001F4",
        "type": "get",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAATZidHnuSVUH647KgxFnvgP74OTAdKdkSgVZEfyoAXy\n"
        "d8iEFj3BYAWXicyX6WEsA0mUn391NO0Z6Tu4PwYLclOUoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNJADBGAiEAy2GDiZGcK9CAg7xpqUrgSb5eQnP2LSI7\n"
        "dKI45BF+g5kCIQCgnRB9mt9ThDSeuFB5fDZ3aGizDDdK8E+rYpuAW7VCpQ==\n"
        "-----END CERTIFICATE REQUEST-----\n",
        "auth_type": "atsha",
        "sid": "",
        "flags": ["renew"]
    },
    {  # bad sid
        "sn": "0000000A000001F3",
        "type": "get",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAATZidHnuSVUH647KgxFnvgP74OTAdKdkSgVZEfyoAXy\n"
        "d8iEFj3BYAWXicyX6WEsA0mUn391NO0Z6Tu4PwYLclOUoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNJADBGAiEAy2GDiZGcK9CAg7xpqUrgSb5eQnP2LSI7\n"
        "dKI45BF+g5kCIQCgnRB9mt9ThDSeuFB5fDZ3aGizDDdK8E+rYpuAW7VCpQ==\n"
        "-----END CERTIFICATE REQUEST-----\n",
        "auth_type": "atsha",
        "sid": "4821",
        "flags": ["renew"]
    },
    {  # bad auth_type
        "sn": "0000000A000001F3",
        "type": "get",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAATZidHnuSVUH647KgxFnvgP74OTAdKdkSgVZEfyoAXy\n"
        "d8iEFj3BYAWXicyX6WEsA0mUn391NO0Z6Tu4PwYLclOUoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNJADBGAiEAy2GDiZGcK9CAg7xpqUrgSb5eQnP2LSI7\n"
        "dKI45BF+g5kCIQCgnRB9mt9ThDSeuFB5fDZ3aGizDDdK8E+rYpuAW7VCpQ==\n"
        "-----END CERTIFICATE REQUEST-----\n",
        "auth_type": "atsha204",
        "sid": "",
        "flags": ["renew"]
    },
    {  # bad req type
        "sn": "0000000A000001F3",
        "type": "gett",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAATZidHnuSVUH647KgxFnvgP74OTAdKdkSgVZEfyoAXy\n"
        "d8iEFj3BYAWXicyX6WEsA0mUn391NO0Z6Tu4PwYLclOUoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNJADBGAiEAy2GDiZGcK9CAg7xpqUrgSb5eQnP2LSI7\n"
        "dKI45BF+g5kCIQCgnRB9mt9ThDSeuFB5fDZ3aGizDDdK8E+rYpuAW7VCpQ==\n"
        "-----END CERTIFICATE REQUEST-----\n",
        "auth_type": "atsha",
        "sid": "",
        "flags": ["renew"]
    },
    {  # bad csr
        "sn": "0000000A000001F3",
        "type": "get",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHoMIGOAgEAMBsxGTAXBgNMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAATZidnuSVUH647KgxFnvgP74OTAdKdkSgVZEfyoAXy\n"
        "d8iEFj3BYAWXicyX6WEsA0m91NO0Z6Tu4PwYLclOUoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNJADBGAiEAy2GDiZGcK9CAg7xpqUrgSb5eQnP2LSI7\n"
        "dKI45BF+g5kCIQCgnRB9mt9ThDSeuFB5fDZ3aGizDDdK8E+rYpuAW7VCpQ==\n"
        "-----END CERTIFICATE REQUEST-----\n",
        "auth_type": "atsha",
        "sid": "",
        "flags": ["renew"]
    },
    {  # bad flags
        "sn": "0000000A000001F3",
        "type": "get",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
        "PQIBBggqhkjOPQMBBwNCAATZidHnuSVUH647KgxFnvgP74OTAdKdkSgVZEfyoAXy\n"
        "d8iEFj3BYAWXicyX6WEsA0mUn391NO0Z6Tu4PwYLclOUoBEwDwYJKoZIhvcNAQkO\n"
        "MQIwADAKBggqhkjOPQQDAgNJADBGAiEAy2GDiZGcK9CAg7xpqUrgSb5eQnP2LSI7\n"
        "dKI45BF+g5kCIQCgnRB9mt9ThDSeuFB5fDZ3aGizDDdK8E+rYpuAW7VCpQ==\n"
        "-----END CERTIFICATE REQUEST-----\n",
        "auth_type": "atsha",
        "sid": "",
        "flags": ["new"]
    },
    {},
])
def bad_req_get_cert(request):
    return request.param


good_certs = [
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC/jCB56ADAgECAhRusGdTtbzRr+8HH25wzdwUhBz8RzANBgkqhkiG9w0BAQsF\n"
    "ADARMQ8wDQYDVQQDDAZUdXJyaXMwHhcNMTgwODA4MTMwODMxWhcNMTgxMTA3MTMw\n"
    "ODMxWjAbMRkwFwYDVQQDDBAwMDAwMDAwQTAwMDAwMUYzMFkwEwYHKoZIzj0CAQYI\n"
    "KoZIzj0DAQcDQgAEgi3iiFzDrCHcWJ3Z8knh3ML/hLyb6ekYlz3doGP6c5HzQVRc\n"
    "7nRifLSlqOCTxtVOugq4eRoKmsRqFlDwXcPPgaMQMA4wDAYDVR0TAQH/BAIwADAN\n"
    "BgkqhkiG9w0BAQsFAAOCAgEAyBLvDvrf6zExDJ0NDcQhFQK6afTMzkKuo6Iqr8VW\n"
    "TNXcxvCWC+pBz0QOc4/Fv2A/+n47Kp8N40XMaotwCoIxR4XOc94dEeYlhCZiCUd5\n"
    "qDxeRmygW+wvkXXSMdxAGQzA2EJmn35hFtjqCkF5nhwtBHeIQdLhgiXlFXtUBwyn\n"
    "HnDU75wb50FIjc0Z+yPZWWk122XRy/grW9mB2qHaIZL87Pb/oGYKK8URYIG+r5GT\n"
    "pVhgwtt4/pC7K6yM3S48HqG/Uf/AfaewMvHp9KCuahCClOb45qJSRJJWqcTErejx\n"
    "RXl2LolBovPH632kl/7Jx0KeNIcCC7cMah6UjWn2pAJHlnsSGkNaOo9INl4h7xmr\n"
    "T30zcS4DMoCplnW3DcJA7ezGcQqzr8+6YsnJyt6yRnuR0hpBfVqa4VET/Aga/5bM\n"
    "xzOHUgvkaWJh2ZwxrTzJyXfJEeRjF0fzhxxdxrKgEQhJHqLE5PwJIqT1fhq7mLG5\n"
    "EH5Kz5iGq0HXNK2k6b3yVd1bUyBifSav7IZRpqwaC9+yF4HVYUk5YGsDp4TMnk+K\n"
    "W2s1qBpENGOb2021YyNd3FeDaqdXmteIEk6YXmC6Tpot8vs8XmEQYSVPlt9k6zNj\n"
    "fut3HEKfuXyojEUUkzks8m7XJ2xfi68vSJOv2ICSKodpP0I+oJf6Ev+Jj+dGFgBq\n"
    "G2s=\n"
    "-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC/jCB56ADAgECAhRwsXrT83imJnMt302cGkJxt8WP2zANBgkqhkiG9w0BAQsF\n"
    "ADARMQ8wDQYDVQQDDAZUdXJyaXMwHhcNMTgwODA4MTMzMDQ0WhcNMTgxMTA3MTMz\n"
    "MDQ0WjAbMRkwFwYDVQQDDBAwMDAwMDAwQTAwMDAwMUYzMFkwEwYHKoZIzj0CAQYI\n"
    "KoZIzj0DAQcDQgAEBqWQXDP4g3ZePpvn1tzZyDn93qcFmYyUKkGPEdG+vnJvXkh6\n"
    "aiJSOs41AswQ9YwtQbHsGduQ8u50DBjpr8K02KMQMA4wDAYDVR0TAQH/BAIwADAN\n"
    "BgkqhkiG9w0BAQsFAAOCAgEAOsurd1aZ2Znf6zKvVkcVb8omqWqxguLIaq3QsujA\n"
    "kiOcNoeZgyXWMJN1IQZZGVbXPH2VaiaYx0sQvUTJV6V7YyGmXTT3Lt65PEOIrCwn\n"
    "YwsWpl53TgYcuiMU5N5PapoWpiEK2QPvg2wP/QEnFMQXaKvO2tKT20tMh8srSta8\n"
    "hQ3qEJRc2vty0VYC9EUdmP7tM5JbGRXqT6ZWO6xB0ic9MWoXG76tAGC1UsaP4RCb\n"
    "88HccpabrMPGUA585cuA0GIDWId2BXxfPDOjxGKSlOaVRB9VGArLmJoQZnBKEssP\n"
    "Sk4ISZHAftUfx/uXOrTIVviBD3yVvOw0I7tUmTxlCL3UjrhXZC1xxVqmw1yx4kHK\n"
    "4xpKnCXbh+BiCzQzT6A6DxGYlLHO5C/ipVuyie8SnGmc4x5AWX3r9aWu0lEEvJVA\n"
    "ydJLaozciGdWw2oavyTJJyAkiB38MbgGu2IZ9v9rceDbofjGEiEJdM6ZCvO29gaC\n"
    "8yGzKxNDJh5c0Yke9/CpalQXuZTw+w80hT+iHE4Qr88ji3oEAkgn/ZNKfC3j+FnD\n"
    "LneCkFYK+o98m4nwEQ4cUx155XrzR94Bsew7XnAI59dpSGIFoUI28YL2yf8bVjCR\n"
    "JitJV1IEBLzEp+3nVcJr24OFSJeetHQv7IEsZ1ume34h3ssbPNBXduqsTHviSjQS\n"
    "kDg=\n-----END CERTIFICATE-----\n"
]


@pytest.fixture(params=[
        "-----BEGIN CERTIFICATE-----\n"
        "MIIC/jCB56ADAgECAhQclPgOxagZ6vKjLKa01oiMjPeyCzANBgkqhkiG9w0BAQsF\n"
        "ADARMQ8wDQYDVQQDDAZUdXJyaXMwHhcNMTgwODA4MDkyMTU2WhcNMTgxMTA3MDky\n"
        "MTU2WjAbMRkwFwYDVQQDDBAwMDAwMDAwQTAwMDAwMUYzMFkwEwYHKoZIzj0CAQYI\n"
        "KoZIzj0DAQcDQgAEyjczArRbbFNH95G1yEZvW9+WOF5Ex3sO9TtHm5N/k2nIY4ZZ\n"
        "DSJTlnMeo70JWwjgqyaYqMkpmaJWnWmzMiZj7aMQMA4wDAYDVR0TAQH/BAIwADAN\n"
        "BgkqhkiG9w0BAQsFAAOCAgEAaCcJE5skRhllYg4ZPAjnU6eysQhQIG2LDfVuJhhq\n"
        "XgjQIgtmC5Rc2Ky616QXu4hnMUMFDPeEI7nqaOhZxAgewW8f1o5vnHKmeMI2X94V\n"
        "u0St1tKRKkDPpPGtgQwuOAsZrCjQw6+1DnHN5Wz5oIQNyDJDGyAaOHTRm4xfwZRI\n"
        "FqWY3oullQEk6wiloGK5b9kpg13gJ4RW/j8aIcvYQLf4S2GA7ItPrgbLf0+Bb8jb\n"
        "7hDRZ/0FPuBxmFDkqtyVSwgUhSfSQLV21JEc4JU5eNnFE+RzIFGX2VrzA81f1Aje\n"
        "g71D1OsZPufz5cK4/BM7nCpP0NJ6RU9lq2siSX3+/4Jz4QZ4vmL5TqnoD94Jabwd\n"
        "oCd9LkcTwK1d++V062uxkt9jp3G0l9ia+D0IN+O60346qi2iSCFX5gGUouDMoe9L\n"
        "tnFGpq9qbmIVtU8mwMyT/LZ33psqmkLfWgjzI7ApW3u/wqmKZU88GDZKVT7Uvy90\n"
        "mxw/vBEBrBKQLGn6/KA2N6ZlGti6Qir+pJEnWQNd1Br+Ovm6t0p5O/9BQO8/CF5w\n"
        "pjUHuB71UNYYkZ7joErgxhoNIca1w6RM3fGDw1QROndESogwya2atJuLg2zlBbzb\n"
        "0eR7ttyGXK55tw9Iskq479c104Y8GZCUDY3mXfumWYv57fTbutxa2zljf5BRvtrH\n"
        "M20=\n"
        "-----END CERTIFICATE-----\n"
        #    "-----BEGIN CERTIFICATE-----\n"
        #    "MIIC/jCB56ADAgECAhQP9mDtMV2EPyWYR5sv4u7QKTTEejANBgkqhkiG9w0BAQsF\n"
        #    "ADARMQ8wDQYDVQQDDAASDADASDAdHhcNMTgwODA3MTI0NTIyWhcNMTgxMTA2MTI0\n"
        #    "NTIyWjAbMRkwFwYDVQQDDBAwMDAwMDAwQTAwMDAwMUYzMFkwEwYHKoZIzj0CAQYI\n"
        #    "KoZIzj0DAQcDQgAE2YnR57klVB+uOyASDASDASDAsdASDAsoFWRH8qAF8nfIhBY9\n"
        #    "wWAFl4nMl+lhLANJlJ9/dTTtGek7uD8GC3JTlKMQMA4wDAYDVR0TAQH/BAIwADAN\n"
        #    "BgkqhkiG9w0BAQsFAAOCAgEA43n5G/HjQQv85vzOGpbIC3LQLr/Ubtbn24zV9pKl\n"
        #    "RVyePOrCDQsCziHPAy5mazrje5Iggb7dXNbsZaNyQ7EgEioVvRYS704mJ0BEYJhr\n"
        #    "E1iBLOmrf2EIBd/Ii+wraf9JhASDAsdASDAsdASDAsdASDAMhOgoOjfDbasql4h5\n"
        #    "XNK5HkBzA8QzViTNtsbt4I6vh/WRASDAsdASDAsdASDAsdAbrEeuh/JQw7Fm4dho\n"
        #    "PvDZh8paZeyb9grqcT9jaco+jWhH+z3HTuS3GLaQsC5SAsdASDAsdAVfV1slAa3b\n"
        #    "ikOmRgW00UCSzBxdI59hf2Pvq1DrniAcY/C9rNt0b42MCTNNJ5clozdYsJsY7+Yy\n"
        #    "ldnKlGTDx6KR1hKhqoIXogJXzwfM6unTSX2yYOBPsRnVadTCjqsfjIxyYOkamHd+\n"
        #    "GY5nlbs+4tZjvs/wzeWfPrjDHnnv4O/vzYHRdk6yegh/xSfvKKCqtLbG2QMNjwa0\n"
        #    "dgir1mOXasT9Stb4O1+nJSFAfg5kb1KeIiBCqZQQpK/wB2tlwgCSrAe2I29zDpuD\n"
        #    "BgUgYY+vAZLUGvqt2lR+6tLUkHJOz73AV6V6u1N9+WC7d9RkC8GDcXicizsrOdHh\n"
        #    "Qd/EZQ9YnTC2aWsOufQKpVOWWecclK4IZRjNRFMg78c1Uuxl/k+6Cns57C6ru0Nu\n"
        #    "WDM=\n"
        #    "-----END CERTIFICATE-----\n",
        #    "",
])
def bad_cert(request):
    return request.param


@pytest.fixture(params=zip(good_reqs_get_cert, good_certs))
def good_data(request):
    return request.param


good_reqs_auth = [
    {
        "auth_type": "atsha",
        "sn": "0000000A000001F3",
        "type": "auth",
        "sid": "4cca5561cf766855a02ee33f229acf4b144fdb7988abd85fd2bad3cfe2546d9f",
        "signature": "D9C57EF288673CBC6EBAF6990991C58294521AA46E4FF5A2F49D3326F53E10C0"
    },
    {
        "type": "auth",
        "signature": "8B3DCBE95B151390F0F33AA453D486D748CD836693B46602200565898EB7C3BA",
        "sid": "aea13dbed3b576cc8300d4710bdc708e6baff00f2e485ad2d9614fdc378fd4e0",
        "auth_type": "atsha",
        "sn": "0000000A000001F3"
    },
]


@pytest.fixture(params=[
    {  # bad auth_type
        "auth_type": "atsha204",
        "sn": "0000000A000001F3",
        "type": "auth",
        "sid": "4cca5561cf766855a02ee33f229acf4b144fdb7988abd85fd2bad3cfe2546d9f",
        "signature": "D9C57EF288673CBC6EBAF6990991C58294521AA46E4FF5A2F49D3326F53E10C0"
    },
    {  # bad sn
        "auth_type": "atsha",
        "sn": "0000000A000001F4",
        "type": "auth",
        "sid": "4cca5561cf766855a02ee33f229acf4b144fdb7988abd85fd2bad3cfe2546d9f",
        "signature": "D9C57EF288673CBC6EBAF6990991C58294521AA46E4FF5A2F49D3326F53E10C0"
    },
    {  # bad type
        "auth_type": "atsha",
        "sn": "0000000A000001F3",
        "type": "authenticate",
        "sid": "4cca5561cf766855a02ee33f229acf4b144fdb7988abd85fd2bad3cfe2546d9f",
        "signature": "D9C57EF288673CBC6EBAF6990991C58294521AA46E4FF5A2F49D3326F53E10C0"
    },
    {  # bad sid (short)
        "auth_type": "atsha",
        "sn": "0000000A000001F3",
        "type": "auth",
        "sid": "4cca5561cf766855a02ee33f229acf4b144fdb7988abd85fd2bad3cfe2546d",
        "signature": "D9C57EF288673CBC6EBAF6990991C58294521AA46E4FF5A2F49D3326F53E10C0"
    },
    {  # bad signature (non hexa character)
        "auth_type": "atsha",
        "sn": "0000000A000001F3",
        "type": "auth",
        "sid": "4cca5561cf766855a02ee33f229acf4b144fdb7988abd85fd2bad3cfe2546d9f",
        "signature": "X9C57EF288673CBC6EBAF6990991C58294521AA46E4FF5A2F49D3326F53E10C0"
    },
])
def bad_req_auth(request):
    return request.param


good_sessions = [
    {
        "nonce": "665e12e4db0c1c74a24457327c0456e52b026440766d7bb5da58061bdf58160a",
        "auth_type": "atsha",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----MIHnMIGOAgEAMBsxGTAXBgN\n"
        "VBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASCLeKI\n"
        "XMOsIdxYndnySeHcwv+EvJvp6RiXPd2gY/pzkfNBVFzudGJ8tKWo4JPG1U66Crh5Ggqax\n"
        "GoWUPBdw8+BoBEwDwYJKoZIhvcNAQkOMQIwADAKBggqhkjOPQQDAgNIADBFAiB4Me5+cf\n"
        "wup0tMMeQM/xrHgBYylaTT6ngfGZQpsrmpBAIhAIhxE9+bzUoBDYFRTFHq4lzD/mzCb3s\n"
        "/lFwJy694PqA0-----END CERTIFICATE REQUEST-----",
        "flags": [],
        "signature": "",
        "action": "certs",
    },
    {
        "flags": [],
        "signature": "",
        "nonce": "edd22df680f82d1ed1264a93b4f81ddd735aba22b8a99989b087abb2ea4ca3f0",
        "auth_type": "atsha",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----MIHmMIGOAgEAMBsxGTAXBgN\n"
        "VBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGpZBc\n"
        "M/iDdl4+m+fW3NnIOf3epwWZjJQqQY8R0b6+cm9eSHpqIlI6zjUCzBD1jC1BsewZ25Dy7\n"
        "nQMGOmvwrTYoBEwDwYJKoZIhvcNAQkOMQIwADAKBggqhkjOPQQDAgNHADBEAiBN20doyA\n"
        "17mcy4thRY61WY8njlY6jGTV05olYg6lJlDgIgM7DGv4yRLoj7HZkkKJmXDZ+w2PdKLp2\n"
        "za8Si7xiC+zs=-----END CERTIFICATE REQUEST-----",
        "action": "certs",
    }
]


@pytest.fixture(params=[
    "x",
    # "", # TODO: improve cert-api to this could be added to tests
    {  # missing flags
        "signature": "",
        "nonce": "edd22df680f82d1ed1264a93b4f81ddd735aba22b8a99989b087abb2ea4ca3f0",
        "auth_type": "atsha",
        "csr_str": "-----BEGIN CERTIFICATE REQUEST-----MIHmMIGOAgEAMBsxGTAXBgN\n"
        "VBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGpZBc\n"
        "M/iDdl4+m+fW3NnIOf3epwWZjJQqQY8R0b6+cm9eSHpqIlI6zjUCzBD1jC1BsewZ25Dy7\n"
        "nQMGOmvwrTYoBEwDwYJKoZIhvcNAQkOMQIwADAKBggqhkjOPQQDAgNHADBEAiBN20doyA\n"
        "17mcy4thRY61WY8njlY6jGTV05olYg6lJlDgIgM7DGv4yRLoj7HZkkKJmXDZ+w2PdKLp2\n"
        "za8Si7xiC+zs=-----END CERTIFICATE REQUEST-----"
    },
    {  # missing csr
        "flags": [],
        "signature": "",
        "nonce": "edd22df680f82d1ed1264a93b4f81ddd735aba22b8a99989b087abb2ea4ca3f0",
        "auth_type": "atsha",
    },

    # {  # invalid nonce  TODO: improve cert-api to this could be added to tests
    #     "flags": [],
    #     "signature": "",
    #     "nonce": "XXd22df680f82d1ed1264a93b4f81ddd735aba22b8a99989b087abb2ea4ca3f0",
    #     "auth_type": "atsha",
    #     "csr_str": "-----BEGIN CERTIFICATE REQUEST-----MIHmMIGOAgEAMBsxGTAXBgN\n"
    #     "VBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGpZBc\n"
    #     "M/iDdl4+m+fW3NnIOf3epwWZjJQqQY8R0b6+cm9eSHpqIlI6zjUCzBD1jC1BsewZ25Dy7\n"
    #     "nQMGOmvwrTYoBEwDwYJKoZIhvcNAQkOMQIwADAKBggqhkjOPQQDAgNHADBEAiBN20doyA\n"
    #     "17mcy4thRY61WY8njlY6jGTV05olYg6lJlDgIgM7DGv4yRLoj7HZkkKJmXDZ+w2PdKLp2\n"
    #     "za8Si7xiC+zs=-----END CERTIFICATE REQUEST-----"
    # },
])
def bad_session(request):
    return request.param


@pytest.fixture(params=zip(good_reqs_auth, good_sessions))
def good_req_auth_data(request):
    return request.param


@pytest.fixture(params=[
    "x",
    # "", # TODO: improve cert-api so this could be testable
])
def bad_auth_state(request):
    return request.param
