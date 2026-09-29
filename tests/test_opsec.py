from core.opsec import is_bad_ua, is_private_or_reserved_ip


def test_is_bad_ua_positive():
    assert is_bad_ua("curl/8.0")
    assert is_bad_ua("python-requests/2.31.0")
    assert is_bad_ua("sqlmap/1.5")

def test_is_bad_ua_negative():
    assert not is_bad_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0 Safari/537.36")
    assert not is_bad_ua("Safari/605.1.15")

def test_private_ip_detection():
    assert is_private_or_reserved_ip("127.0.0.1")
    assert is_private_or_reserved_ip("10.0.0.5")
    assert is_private_or_reserved_ip("192.168.1.10")
    assert not is_private_or_reserved_ip("8.8.8.8")
