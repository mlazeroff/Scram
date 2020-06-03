from base64 import b64decode
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def SCRAMSHA1(plaintext: bytes, salt: str, iterations: int):
    """
    Implementation of SCRAM-SHA1
    :param plaintext: plaintext data
    :param salt: base64 encoded string
    :param iterations: # of iterations
    :return: bytes
    """
    # validate args
    if not isinstance(plaintext, bytes):
        raise TypeError('Expected bytes type')

    try:
        salt = b64decode(salt, validate=True)
    except Exception as e:
        raise ValueError('Invalid salt: {}'.format(e))

    if not isinstance(iterations, int):
        raise TypeError('Iterations must be an int.')
    if iterations < 1:
        raise ValueError('Iterations must be > 0')

    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=20,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    salted_password = kdf.derive(plaintext)
    # hmac
    mac = hmac.HMAC(salted_password, hashes.SHA1(), backend=backend)
    mac.update(b'Client Key')
    client_key = mac.finalize()
    # sha1
    digest = hashes.Hash(hashes.SHA1(), backend=backend)
    digest.update(client_key)
    stored_key = digest.finalize()
    return stored_key
