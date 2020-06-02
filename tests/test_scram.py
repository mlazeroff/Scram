import pytest
from scram.scramsha1 import SCRAMSHA1

plaintext = b'pencil'
salt = 'QSXCR+Q6sek8bf92'
iterations = 4096


def test_non_bytes_plaintext():
    with pytest.raises(TypeError):
        SCRAMSHA1('not bytes', salt, iterations)


def test_non_b64_salt():
    with pytest.raises(ValueError):
        SCRAMSHA1(plaintext, 'im a bad salt', iterations)


def test_negative_iterations():
    with pytest.raises(ValueError):
        SCRAMSHA1(plaintext, salt, -1)


def test_zero_iterations():
    with pytest.raises(ValueError):
        SCRAMSHA1(plaintext, salt, 0)


def test_non_int_iterations():
    with pytest.raises(TypeError):
        SCRAMSHA1(plaintext, salt, .1)


def test_valid_input():
    result = SCRAMSHA1(plaintext, salt, iterations)
    assert result.hex() == 'e9d94660c39d65c38fbad91c358f14da0eef2bd6'


def test_consecutive_hashes():
    result = SCRAMSHA1(plaintext, salt, iterations)
    for i in range(10):
        result2 = SCRAMSHA1(plaintext, salt, iterations)
    assert result == result2
