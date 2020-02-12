#!/usr/bin/env python3
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf import pbkdf2

def wcdb_generate_device_salt(serialno: bytes, cpu_serial: bytes):
    serial = serialno + cpu_serial
    return pbkdf2.PBKDF2HMAC(
        hashes.SHA1(),
        16,
        serial,
        1,
        default_backend()
    ).derive(serial)

def wcdb_decrypt_first_page(raw, page_size, device_salt, password):
    salt_mask = 0x3a
    salt_size = 16
    cipher_key_size = 32
    cipher_key_iter = 4000
    cipher_iv_size = algorithms.AES.block_size // 8
    hmac_key_size = cipher_key_size
    hmac_key_iter = 2
    hmac_sig_size = hashes.SHA1.digest_size
    reserved_size = (cipher_iv_size + hmac_sig_size + algorithms.AES.block_size // 8 - 1) // (algorithms.AES.block_size // 8) * (algorithms.AES.block_size // 8)

    page = raw[0:page_size]
    page_salt = page[:salt_size]
    page_content_enc = page[salt_size:-reserved_size]
    page_reserved = page[-reserved_size:]

    cipher_iv = page_reserved[0:cipher_iv_size]
    hmac_sig = page_reserved[cipher_iv_size:cipher_iv_size + hmac_sig_size]

    cipher_key = pbkdf2.PBKDF2HMAC(hashes.SHA1(), cipher_key_size, device_salt, 1, default_backend()).derive(
        pbkdf2.PBKDF2HMAC(
            hashes.SHA1(),
            cipher_key_size,
            page_salt,
            cipher_key_iter,
            default_backend()
        ).derive(password)
    )

    hmac_key = pbkdf2.PBKDF2HMAC(hashes.SHA1(), hmac_key_size, device_salt, 1, default_backend()).derive(
        pbkdf2.PBKDF2HMAC(
            hashes.SHA1(),
            hmac_key_size,
            bytes([ x ^ salt_mask for x in page_salt ]),
            hmac_key_iter,
            default_backend()
        ).derive(cipher_key)
    )

    h = hmac.HMAC(hmac_key, hashes.SHA1(), default_backend())
    h.update(page_content_enc)
    h.update(cipher_iv)
    h.update(int(1).to_bytes(4, 'little'))
    h.verify(hmac_sig)

    decryptor = Cipher(
        algorithms.AES(cipher_key),
        modes.CBC(cipher_iv),
        default_backend()
    ).decryptor()

    page_content_dec = decryptor.update(page_content_enc) + decryptor.finalize()
    assert(page_content_dec[21 - 16] == 64)
    assert(page_content_dec[22 - 16] == 32)
    assert(page_content_dec[23 - 16] == 32)
    assert(all(v == 0 for v in page_content_dec[72 - 16:72 - 16 + 20]))

    return b'SQLite format 3\x00' + page_content_dec

def wcdb_decrypt_left_pages(raw, page_size, device_salt, password):
    salt_mask = 0x3a
    salt_size = 16
    cipher_key_size = 32
    cipher_key_iter = 4000
    cipher_iv_size = algorithms.AES.block_size // 8
    hmac_key_size = cipher_key_size
    hmac_key_iter = 2
    hmac_sig_size = hashes.SHA1.digest_size
    reserved_size = (cipher_iv_size + hmac_sig_size + algorithms.AES.block_size // 8 - 1) // (algorithms.AES.block_size // 8) * (algorithms.AES.block_size // 8)

    salt = raw[0:salt_size]

    cipher_key = pbkdf2.PBKDF2HMAC(hashes.SHA1(), cipher_key_size, device_salt, 1, default_backend()).derive(
        pbkdf2.PBKDF2HMAC(
            hashes.SHA1(),
            cipher_key_size,
            salt,
            cipher_key_iter,
            default_backend()
        ).derive(password)
    )

    hmac_key = pbkdf2.PBKDF2HMAC(hashes.SHA1(), hmac_key_size, device_salt, 1, default_backend()).derive(
        pbkdf2.PBKDF2HMAC(
            hashes.SHA1(),
            hmac_key_size,
            bytes([ x ^ salt_mask for x in salt] ),
            hmac_key_iter,
            default_backend()
        ).derive(cipher_key)
    )

    raw_dec = bytearray()
    for i in range(1, len(raw) // page_size):
        page = raw[i * page_size:i * page_size + page_size]
        page_content_enc = page[:-reserved_size]
        page_reserved = page[-reserved_size:]

        cipher_iv = page_reserved[0:cipher_iv_size]
        hmac_sig = page_reserved[cipher_iv_size:cipher_iv_size + hmac_sig_size]

        h = hmac.HMAC(hmac_key, hashes.SHA1(), default_backend())
        h.update(page_content_enc)
        h.update(cipher_iv)
        h.update((i + 1).to_bytes(4, 'little'))
        h.verify(hmac_sig)

        decryptor = Cipher(
            algorithms.AES(cipher_key),
            modes.CBC(cipher_iv),
            default_backend()
        ).decryptor()

        raw_dec.extend(
            decryptor.update(page_content_enc) + decryptor.finalize()
        )

    return bytes(raw_dec)

g_device_salt = wcdb_generate_device_salt(b'', b'')

with open(sys.argv[1], 'rb') as f:
    raw_enc = f.read()

raw_dec = \
    wcdb_decrypt_first_page(raw_enc, 1024, g_device_salt, b'token') + \
    wcdb_decrypt_left_pages(raw_enc, 1024, g_device_salt, b'token')

new_page_size = int.from_bytes(raw_dec[16:18], 'big')
if new_page_size == 1:
    new_page_size = 0x10000

new_page_reserved_size = raw_dec[20]

new_page_content_size = new_page_size - new_page_reserved_size

with open(sys.argv[1], 'wb') as f:
    for i in range(0, len(raw_dec), new_page_content_size):
        f.write(raw_dec[i:i + new_page_content_size])
        f.write(b'\x00' * new_page_reserved_size)
