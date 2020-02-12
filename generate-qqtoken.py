#!/usr/bin/env python3
import sys
from hashlib import sha256
from datetime import datetime, timezone, timedelta

def GenerateQQTokenSerial(secret: bytes):
    digest = sha256(
        sha256(secret).digest()
    ).digest()

    digest_exp = bytearray()
    for x in digest:
        digest_exp.append(x >> 4)
        digest_exp.append(x & 0x0f)

    serial = []
    for i in range(0, 16):
        t = digest_exp[i]
        t += digest_exp[i + 16 * 1]
        t += digest_exp[i + 16 * 2]
        t += digest_exp[i + 16 * 3]
        serial.append(t % 10)
    if serial[0] == 0:
        serial[0] = 1

    serial = ''.join('%d' % x for x in serial)

    return '%s-%s-%s-%s' % (serial[0:4], serial[4:8], serial[8:12], serial[12:16])

def GenerateQQTokenCode(currentTimeMillis: int, secret: bytes):
    tz_beijing = timezone(timedelta(hours = +8))
    dt_beijing = datetime.fromtimestamp(currentTimeMillis // 1000).replace(tzinfo = tz_beijing)

    digest = sha256(secret + b'%d-%02d-%02d %02d:%02d:%02d' % (
        dt_beijing.year,
        dt_beijing.month,
        dt_beijing.day,
        dt_beijing.hour,
        dt_beijing.minute,
        dt_beijing.second // 30 * 30
    )).digest()

    digest_exp = bytearray()
    for x in digest:
        digest_exp.append(x >> 4)
        digest_exp.append(x & 0x0f)

    code = []
    for i in range(0, 6):
        t = digest_exp[i + 1]
        t += digest_exp[i + 1 + 1 * 7]
        t += digest_exp[i + 1 + 2 * 7]
        t += digest_exp[i + 1 + 3 * 7]
        t += digest_exp[i + 1 + 4 * 7]
        t += digest_exp[i + 1 + 5 * 7]
        t += digest_exp[i + 1 + 6 * 7]
        t += digest_exp[i + 1 + 7 * 7]
        t += digest_exp[i + 1 + 8 * 7]
        code.append(t % 10)

    return ''.join('%d' % x for x in code)

print(
    GenerateQQTokenCode(
        int(datetime.now().timestamp() * 1000), 
        bytes.fromhex(sys.argv[1])
    )
)
