import pytest

from cryptography.hazmat.primitives.asymmetric import ec


@pytest.fixture(params=[
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC/jCB56ADAgECAhReIfz7MP3K1l+fneTEwSvmcOWZ/TANBgkqhkiG9w0BAQsF\n"
    "ADARMQ8wDQYDVQQDDAZUdXJyaXMwHhcNMTgwNzE4MDgxMDAwWhcNMTgxMDE3MDgx\n"
    "MDAwWjAbMRkwFwYDVQQDDBAwMDAwMDAwQTAwMDAwMUYzMFkwEwYHKoZIzj0CAQYI\n"
    "KoZIzj0DAQcDQgAEKPgqujekALvfaQ8NxiRkNDWSA50/z/X1NhXj2SVY1KNqG5na\n"
    "mf7kWPCHkDpNyb6aBzNqNOttUCGL6Y8cWzkEsKMQMA4wDAYDVR0TAQH/BAIwADAN\n"
    "BgkqhkiG9w0BAQsFAAOCAgEANTYZW3NJ/8o+/uDEj1OlpialgSpDNi1jXgKYIusp\n"
    "nFwXV5shbwFWtA+RrEKBxt2QSHSEyqnteFYnd909n+sjjkGlfxJSqZpkhnt95Gci\n"
    "R2G1Vkl8o/A+g6cP1qMIqihnjo0gA+7iB8tTOncQ5V+UD1l1eEnX2rZhLvI+zCBb\n"
    "rNtYQgmLimPfBki1tgza8jmnSIoee+RxYmamFmQ0QRIWfdOIF0+nfMvgGy3CZ7/K\n"
    "M8GUaMrYKcTdfVUu5Q5SgVebxHbiazYsOptPoDE1U2mrFnoY6J7jPQUaXzxsfOAt\n"
    "J8neZjbYJNsi/nm9SXT8U2irU+PWHuRmqErFoE4puQpTrfNOeR5zR474B4VQ1pBZ\n"
    "ZL4fqPgbS0UDv/+vczcjlt5vLVgMLkISjrZ7H/ey1cFUFCmrvst2mAvy/Z7gffR1\n"
    "s8zzQ58H9sqXW9Xe4qhg4crs8OIaHNikLBJVP6kvxyB7B8dAInREpYjXTEnG2+VT\n"
    "0Fi/VE6BOrGbcsuvbyP9Qmf72iXK8JtQfw1boXRBDFIzd0cNUfX+6TZUTtLMlWaS\n"
    "IztvO9cTmgBPvaxs1IFRca9EGs9y3wxornLHwdFLeyMinLO7Tkc6ugbbaEW5kVmx\n"
    "uCcAyFMmsevX4IzSXQhT1n0JlouvxnS1U/ux7I8RSRmcyW1/R2sVW+MiS1mMxCuB\n"
    "ODA=\n"
    "-----END CERTIFICATE-----\n"
])
def bad_pem_csr(request):
    return request.param


@pytest.fixture(params=[
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIHoMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAAQo+Cq6N6QAu99pDw3GJGQ0NZIDnT/P9fU2FePZJVjU\n"
    "o2obmdqZ/uRY8IeQOk3JvpoHM2o0621QIYvpjxxbOQSwoBEwDwYJKoZIhvcNAQkO\n"
    "MQIwADAKBggqhkjOPQQDAgNJADBGAiEA9uJbjUc8CI2BAt7IO6LI6han20G2Ix9T\n"
    "4mw2hEu3feECIQCb1yBuPIykwP896qq5ngESgDOi+AWUzcdVZpOMfVlIlg==\n"
    "-----END CERTIFICATE REQUEST-----\n"
])
def good_pem_csr(request):
    return request.param


@pytest.fixture(params=[
    ec.EllipticCurvePublicNumbers(curve=ec.SECP256R1(),
                                  x=18530986909151983050284544213119323517767560142198433589936451726052928574627,
                                  y=47993928681252323044406019950063756592017868342485408738553462064909785826480)
])
def good_public_numbers(request):
    return request.param


@pytest.fixture(params=["0000000A000001F3", ])
def good_common_names(request):
    return request.param


@pytest.fixture(params=[
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC/jCB56ADAgECAhQoJZa+P1gWgVGRB+8GStJeNUHvbzANBgkqhkiG9w0BAQsF\n"
    "ADARMQ8wDQYDVQQDDAZUdXJyaXMwHhcNMTgwNzE4MDkzODEzWhcNMTgxMDE3MDkz\n"
    "ODEzWjAbMRkwFwYDVQQDDBAwMDAwMDAwQTAwMDAwMUYzMFkwEwYHKoZIzj0CAQYI\n"
    "KoZIzj0DAQcDQgAEKPgqujekALvfaQ8NxiRkNDWSA50/z/X1NhXj2SVY1KNqG5na\n"
    "mf7kWPCHkDpNyb6aBzNqNOttUCGL6Y8cWzkEsKMQMA4wDAYDVR0TAQH/BAIwADAN\n"
    "BgkqhkiG9w0BAQsFAAOCAgEAXhematRu4z5Usde+3T36M+/VYTLZ6NYJV0PYpNqM\n"
    "BZXvlNS800Fu58s7tpmh2k0p48Pnje16llaeAA+YBWSHlAjt59Vmd8+PfVVdbPgS\n"
    "TY/AS85fQ9fjmv+BndIHhTgtss+d3KLXH443zNis2ySKzoekZWjkUj6EBeVQ8RmQ\n"
    "ugQAkAokI0+r3K6vTe6OW4L5lQWwOknRzn/VFNZeJ30fqX2R6G6stadCrkJFMI9v\n"
    "wgXX1bhmTsWvYl37TXO2LcXGZbsIEjLJuD1/0fNhrZOKk5n+iIz0/y6pgsskPido\n"
    "YPhgDaClLMU7vWUy7B6WqX2iten2B9K4ONVdjRTSyGM1DblwBbUWrplrZuEPgJv6\n"
    "1pWfArup5B4yfGhVpO0y7A05J1nRaHXHstQZCznrhlm4siS3YTW2b/38Ky823L1C\n"
    "oT5iC9FPR0G4dLbM3uxcXlWuw/pb4vwZxqEmqFlqUu3ZtgGEOU5++ybFPW+//pZm\n"
    "V9xY0AnT9kF5U6vGAPn/qAOptV1uLXTyCTV/ZNgooJ3kghZsT66M8TD6ay2PQs5T\n"
    "P/k1oDvS6S9gJfKgWaBKRnkICPQrb6ZePyVv65OroiDsb4U7whxZjHSATrT3bZCq\n"
    "zdbUj/f376wgpffOELGKznSYH//7ghDHDRy6p3aI/LeSGzquJGMyq941FFUX53ci\n"
    "zIQ=\n"
    "-----END CERTIFICATE-----\n".encode("utf-8"),
])
def good_cert_bytes(request):
    return request.param


@pytest.fixture(params=[
      "-----BEGIN CERTIFICATE REQUEST-----\n"
      "MIHnMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
      "PQIBBggqhkjOPQMBBwNCAAQo+Cq6N6QAu99pDw3GJGQ0NZIDnT/P9fU2FePZJVjU\n"
      "o2obmdqZ/uRY8IeQOk3JvpoHM2o0621QIYvpjxxbOQSwoBEwDwYJKoZIhvcNAQkO\n"
      "MQIwADAKBggqhkjOPQQDAgNIADBFAiB6sA9YxXXwmbYwp7+i5e1TpF1mnsps9Xf7\n"
      "TuwVjgJnaAIhAMfRiFdQZLMeNIasJvXu0+E5kABrcE/q9Tt8HVGCgaPc\n"
      "-----END CERTIFICATE REQUEST-----\n".encode("utf-8"),
])
def good_csr_bytes(request):
    return request.param


@pytest.fixture(params=[
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIHnMIGOAgEAMBsxGTAXBgNVBAMMEDAwMDAwMDBBMDAwMDAxRjMwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAATZidHnuSVUH647KgxFnvgP74OTAdKdkSgVZEfyoAXy\n"
    "d8iEFj3BYAWXicyX6WEsA0mUn391NO0Z6Tu4PwYLclOUoBEwDwYJKoZIhvcNAQkO\n"
    "MQIwADAKBggqhkjOPQQDAgNIADBFAiA2oQy0WaU4VUi/AB0qhKYY7I2nRiEI8XZe\n"
    "6XkDmDrPLQIhAIiZoX1lCymEyi/VVFtC5z4IquunasJCY4c4ECCUvf+l\n"
    "-----END CERTIFICATE REQUEST-----\n".encode("utf-8"),
])
def swapped_csr_bytes(request):
    return request.param


@pytest.fixture(params=[
    b"",
    "MIIC/jCB56ADAgECAhQoJZa+P1gWgVGRB+8GStJeNUHvbzANBgkqhkiG9w0BAQsF\n"
    "ADARMQ8wDQYDVQQDDAZUdXJyaXMwHhcNMTgwNzE4MDkzODEzWhcNMTgxMDE3MDkz\n"
    "ODEzWjAbMRkwFwYDVQQDDBAwMDAwMDAwQTAwMDAwMUYzMFkwEwYHKoZIzj0CAQYI\n"
    "KoZIzj0DAQcDQgAEKPgqujekALvfaQ8NxiRkNDWSA50/z/X1NhXj2SVY1KNqG5na\n"
    "mf7kWPCHkDpNyb6aBzNqNOttUCGL6Y8cWzkEsKMQMA4wDAYDVR0TAQH/BAIwADAN\n"
    "BgkqhkiG9w0BAQsFAAOCAgEAXhematRu4z5Usde+3T36M+/VYTLZ6NYJV0PYpNqM\n"
    "BZXvlNS800Fu58s7tpmh2k0p48Pnje16llaeAA+YBWSHlAjt59Vmd8+PfVVdbPgS\n"
    "TY/AS85fQ9fjmv+BndIHhTgtss+d3KLXH443zNis2ySKzoekZWjkUj6EBeVQ8RmQ\n"
    "ugQAkAokI0+r3K6vTe6OW4L5lQWwOknRzn/VFNZeJ30fqX2R6G6stadCrkJFMI9v\n"
    "wgXX1bhmTsWvYl37TXO2LcXGZbsIEjLJuD1/0fNhrZOKk5n+iIz0/y6pgsskPido\n"
    "YPhgDaClLMU7vWUy7B6WqX2iten2B9K4ONVdjRTSyGM1DblwBbUWrplrZuEPgJv6\n"
    "1pWfArup5B4yfGhVpO0y7A05J1nRaHXHstQZCznrhlm4siS3YTW2b/38Ky823L1C\n"
    "oT5iC9FPR0G4dLbM3uxcXlWuw/pb4vwZxqEmqFlqUu3ZtgGEOU5++ybFPW+//pZm\n"
    "V9xY0AnT9kF5U6vGAPn/qAOptV1uLXTyCTV/ZNgooJ3kghZsT66M8TD6ay2PQs5T\n"
    "P/k1oDvS6S9gJfKgWaBKRnkICPQrb6ZePyVv65OroiDsb4U7whxZjHSATrT3bZCq\n"
    "zdbUj/f376wgpffOELGKznSYH//7ghDHDRy6p3aI/LeSGzquJGMyq941FFUX53ci\n"
    "zIQ=\n"
    "-----END CERTIFICATE-----\n".encode("utf-8"),
])
def invalid_cert_bytes(request):
    return request.param


@pytest.fixture(params=[
    "",
    " ",
    "MIIC/jCB56ADAgECAhQoJZa+P1gWgVGRB+8GStJeNUHvbzANBgkqhkiG9w0BAQsF\n"
    "ADARMQ8wDQYDVQQDDAZUdXJyaXMwHhcNMTgwNzE4MDkzODEzWhcNMTgxMDE3MDkz\n"
    "ODEzWjAbMRkwFwYDVQQDDBAwMDAwMDAwQTAwMDAwMUYzMFkwEwYHKoZIzj0CAQYI\n"
    "KoZIzj0DAQcDQgAEKPgqujekALvfaQ8NxiRkNDWSA50/z/X1NhXj2SVY1KNqG5na\n"
    "mf7kWPCHkDpNyb6aBzNqNOttUCGL6Y8cWzkEsKMQMA4wDAYDVR0TAQH/BAIwADAN\n"
    "BgkqhkiG9w0BAQsFAAOCAgEAXhematRu4z5Usde+3T36M+/VYTLZ6NYJV0PYpNqM\n"
    "BZXvlNS800Fu58s7tpmh2k0p48Pnje16llaeAA+YBWSHlAjt59Vmd8+PfVVdbPgS\n"
    "TY/AS85fQ9fjmv+BndIHhTgtss+d3KLXH443zNis2ySKzoekZWjkUj6EBeVQ8RmQ\n"
    "ugQAkAokI0+r3K6vTe6OW4L5lQWwOknRzn/VFNZeJ30fqX2R6G6stadCrkJFMI9v\n"
    "wgXX1bhmTsWvYl37TXO2LcXGZbsIEjLJuD1/0fNhrZOKk5n+iIz0/y6pgsskPido\n"
    "YPhgDaClLMU7vWUy7B6WqX2iten2B9K4ONVdjRTSyGM1DblwBbUWrplrZuEPgJv6\n"
    "1pWfArup5B4yfGhVpO0y7A05J1nRaHXHstQZCznrhlm4siS3YTW2b/38Ky823L1C\n"
    "oT5iC9FPR0G4dLbM3uxcXlWuw/pb4vwZxqEmqFlqUu3ZtgGEOU5++ybFPW+//pZm\n"
    "V9xY0AnT9kF5U6vGAPn/qAOptV1uLXTyCTV/ZNgooJ3kghZsT66M8TD6ay2PQs5T\n"
    "P/k1oDvS6S9gJfKgWaBKRnkICPQrb6ZePyVv65OroiDsb4U7whxZjHSATrT3bZCq\n"
    "zdbUj/f376wgpffOELGKznSYH//7ghDHDRy6p3aI/LeSGzquJGMyq941FFUX53ci\n"
    "zIQ=\n"
    "-----END CERTIFICATE-----\n",
])
def bad_format_cert_bytes(request):
    return request.param
