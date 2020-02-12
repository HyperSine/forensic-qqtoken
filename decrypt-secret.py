#!/usr/bin/env python3
import os, sys, hashlib

class TencentTEACipher:

    def __init__(self, key: bytes):
        if isinstance(key, bytes) or isinstance(key, bytearray):
            if len(key) == 16:
                self._key = (
                    int.from_bytes(key[0:4], 'big'),
                    int.from_bytes(key[4:8], 'big'),
                    int.from_bytes(key[8:12], 'big'),
                    int.from_bytes(key[12:16], 'big')
                )
            else:
                raise ValueError('Invalid key length.')
        else:
            raise TypeError('key requires a value with bytes type.')

    def encrypt_block(self, plaintext: bytes):
        if isinstance(plaintext, bytes) or isinstance(plaintext, bytearray):
            if len(plaintext) == 8:
                block = [
                    int.from_bytes(plaintext[0:4], 'big'),
                    int.from_bytes(plaintext[4:8], 'big')
                ]

                sum = 0
                for i in range(0, 16):
                    sum += 0x9E3779B9
                    sum &= 0xffffffff
                    block[0] += (block[1] << 4) + self._key[0] ^ block[1] + sum ^ (block[1] >> 5) + self._key[1]
                    block[0] &= 0xffffffff
                    block[1] += (block[0] << 4) + self._key[2] ^ block[0] + sum ^ (block[0] >> 5) + self._key[3]
                    block[1] &= 0xffffffff

                return block[0].to_bytes(4, 'big') + block[1].to_bytes(4, 'big')
            else:
                raise ValueError('Invalid plaintext length.')
        else:
            raise TypeError('plaintext requires a value with bytes type.')

    def decrypt_block(self, ciphertext: bytes):
        if isinstance(ciphertext, bytes) or isinstance(ciphertext, bytearray):
            if len(ciphertext) == 8:
                block = [
                    int.from_bytes(ciphertext[0:4], 'big'),
                    int.from_bytes(ciphertext[4:8], 'big')
                ]

                sum = 0xE3779B90
                for i in range(0, 16):
                    block[1] -= (block[0] << 4) + self._key[2] ^ block[0] + sum ^ (block[0] >> 5) + self._key[3]
                    block[1] &= 0xffffffff
                    block[0] -= (block[1] << 4) + self._key[0] ^ block[1] + sum ^ (block[1] >> 5) + self._key[1]
                    block[0] &= 0xffffffff
                    sum -= 0x9E3779B9
                    sum &= 0xffffffff

                return block[0].to_bytes(4, 'big') + block[1].to_bytes(4, 'big')
            else:
                raise ValueError('Invalid ciphertext length.')
        else:
            raise TypeError('ciphertext requires a value with bytes type.')

class TencentCrypto:

    def __init__(self, key: bytes):
        self._cipher = TencentTEACipher(key)

    def encrypt(self, plaintext: bytes):
        padding = 8 - (len(plaintext) + 10) % 8
        if padding == 8:
            padding = 0

        text = bytearray(1 + padding + 2 + len(plaintext) + 7)

        text[0:1 + padding + 2] = os.urandom(1 + padding + 2)
        text[0] &= 0xf8
        text[0] |= padding

        text[1 + padding + 2:1 + padding + 2 + len(plaintext)] = plaintext[0:len(plaintext)]

        xor_bytes = lambda a_bytes, b_bytes: bytes(x ^ y for x, y in zip(a_bytes, b_bytes))

        vector1 = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        vector2 = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        for i in range(0, len(text), 8):
            next_vector2 = xor_bytes(text[i:i + 8], vector1)
            next_vector1 = xor_bytes(self._cipher.encrypt_block(next_vector2), vector2)
            text[i:i + 8] = next_vector1[0:8]
            vector2 = next_vector2
            vector1 = next_vector1

        return bytes(text)

    def decrypt(self, ciphertext: bytes):
        if isinstance(ciphertext, bytes) or isinstance(ciphertext, bytearray):
            if len(ciphertext) % 8 != 0:
                raise ValueError('ciphertext length is not a multiple of 8.')
            if len(ciphertext) < 16:
                raise ValueError('ciphertext is too short.')

            header = self._cipher.decrypt_block(ciphertext[0:8])
            if len(ciphertext) < header[0] % 8 + 10:
                raise ValueError('ciphertext is corrupted or key is invalid.')
            else:
                padding = header[0] % 8
                plaintext_off = 1 + padding + 2
                plaintext_len = len(ciphertext) - (1 + padding + 2 + 7)

            xor_bytes = lambda a_bytes, b_bytes : bytes(x ^ y for x, y in zip(a_bytes, b_bytes))

            plaintext = bytearray()
            vector1 = b'\x00\x00\x00\x00\x00\x00\x00\x00'
            vector2 = b'\x00\x00\x00\x00\x00\x00\x00\x00'
            for i in range(0, len(ciphertext), 8):
                next_vector1 = ciphertext[i:i + 8]
                next_vector2 = self._cipher.decrypt_block(xor_bytes(vector2, next_vector1))
                plaintext.extend(
                    xor_bytes(vector1, next_vector2)
                )
                vector1 = next_vector1
                vector2 = next_vector2

            if all(plaintext[i] == 0 for i in range(plaintext_off + plaintext_len, len(ciphertext))):
                return bytes(plaintext[plaintext_off:plaintext_off + plaintext_len])
            else:
                raise ValueError('ciphertext is corrupted or key is invalid.')
        else:
            raise TypeError('ciphertext requires a value with bytes type.')

c = bytes.fromhex(sys.argv[1])
k = hashlib.md5(sys.argv[2].encode()).digest()
print(
    TencentCrypto(k).decrypt(c).hex()
)
