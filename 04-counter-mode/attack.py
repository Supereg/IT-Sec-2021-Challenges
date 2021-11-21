#!/usr/bin/env python3
# coding=utf-8

# Task 4: Der Counter-Mode
# ========================
#
# Im Cookie wird nur in einem JSON-Object unter dem Key "user" gespeichert,
# welcher User hier eingeloggt sein soll. Also ist nur auf dem Client gespeichert, wer
# eingeloggt sein soll und nirgends auf dem Server. Also müssen wir versuchen diesen
# Wert zu manipulieren.
#
# Das ist tatsächlich möglich, da wir im CTR Modus bei der Verschlüsselung der Plaintext
# mit dem Key-Stream ge-XOR-t wird, um den ciphertext zu erhalten.
# Da wir sowohl den Plaintext '{"user": "testuser"}' als auch den ciphertext (hinterer Teil
# vom Cookie-Text nach der nonce, einfach über die Webconsole im Browser ausgelesen) können
# wir den Key-Stream einfach erhalten, indem wir den plaintext und den ciphertext XOR-en.
# Da wir dann den Key-Stream kennen können wir uns einfach einen neuen Plaintext überlegen
# '{"user": "admin"}' und diesen mit den '{"user": "testuser"}' XOR-en um dann einen neuen
# ciphertext zu erhalten, den man dann mit den alten ciphertext im cookie austauscht.
# Dieser neue Cookie Wert muss dann lediglich noch im Browser als Wert für den "session"
# Cookie eingetragen werden.
# Page refresh
# Der Server liest nach den Wert entschlüsselt ihn und liest, dass "admin" der authentifizierte
# User sein soll und gibt uns daraufhin den Text von /bin/flag aus und wir sind happy.




import base64
import json
import os

NONCE_LENGTH = 12  # bytes (of the 16 byte IV, the rest is a automatically generated counter)
SECRET_KEY = os.urandom(32)

COOKIE_NAME = 'session'
COOKIE_LIFETIME = 3600  # seconds


# copyright notice: stolen from https://nitratine.net/blog/post/xor-python-byte-strings/
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def idk():
    testuser_cookie = "qORJyquOwDKC5dl5Mx1PoG6w9fvmA7PkkhVINx1KPVQ="
    username = "testuser"
    data = base64.b64decode(testuser_cookie)
    nonce, ciphertext = data[:NONCE_LENGTH], data[NONCE_LENGTH:]
    session_data = {
        'user': username,
    }
    plaintext = json.dumps(session_data).encode()
    key_stream = byte_xor(bytes(plaintext), ciphertext)

    # new ciphertext
    session_data = {
        'user': 'admin',
    }
    plaintextADMIN = json.dumps(session_data).encode()

    ciphertext = byte_xor(bytes(plaintextADMIN), key_stream)

    print ("New Plaintext")
    print(byte_xor(ciphertext, key_stream))

    print ("new Cookie text:")
    raw_cookie = base64.b64encode(nonce + ciphertext)
    print(raw_cookie.decode("utf-8"))

# Flag found: flag{99de66135d00b3c2c7c83a2a12a4bca442e8}


idk()
