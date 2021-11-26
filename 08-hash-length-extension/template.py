from fha256 import fha_init, fha_update, fha_final
import binascii
import hashlib
import struct
import math
import sys
import socket


def forge_keyed_hash(orig_msg, orig_hash, append, key_length):
    m = fha_init()

    # key length in bits
    assert key_length % 8 == 0, "Illegal key_length {}".format(key_length)

    # this is the "raw" message lenght (in bytes), meaning the key itself and the message.
    # The padding gets appended to >this< message
    raw_lenght = (key_length // 8) + len(orig_msg)

    # min length without any zeros, meaning raw_length + 1 byte 0x80 + 8 byte length
    min_length = raw_lenght + 9

    blocks = (min_length // 64)
    zero_bytes = 0  # amount of "filler" zero bytes
    if min_length % 64 > 0:
        zero_bytes = 64 - (min_length % 64)
        blocks += 1

    # sanity check (which saved my life, casue apparently I can't do math).
    assert (raw_lenght + 9) < blocks * 64, "min message size {} doesn't fit into {} blocks (= {} bytes)"\
        .format(min_length, blocks, blocks * 64)

    m["count_lo"] = blocks * 64 * 8  # orig message len in bits
    m['digest'] = list(struct.unpack(">IIIIIIII", orig_hash))

    # reconstruct the original padding
    padding = b'\x80' + (zero_bytes * b'\x00') + (raw_lenght * 8).to_bytes(length=8, byteorder="big")

    assert (raw_lenght + len(padding)) % 64 == 0, "len is weird: {}".format(raw_lenght + len(padding))

    # continue hash, appending the "append" message
    fha_update(m, append)
    h = fha_final(m)

    # the new message is the original message, plus the reconstructed padding and our appended message
    new_msg = orig_msg + padding + append
    new_mac = binascii.hexlify(h)

    print("new_msg {}".format(new_msg))
    print("new_mac {}".format(new_mac))

    return new_msg, new_mac


# Beispiel für die Erstellung eines FHA hashes mit fha_init(),
# fha_update() und fha_final()
def hash_using_fha(msg):
    """Create a regular FHA hash of a message"""
    m = fha_init()
    fha_update(m, msg)
    return fha_final(m)


keysize = 8  # SPOILER:  key size is 240

while True:
    print("keysize: {}".format(keysize))
    # Verbindung zum Service herstellen
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7030))
    sf = s.makefile("rw")

    # Message M vom Server holen
    M = sf.readline().strip()
    # MAC(M) vom Server holen
    mac = sf.readline().strip()
    print("Got message from server:", M)
    print("MAC for this message:", mac)

    print("Generating message with is_admin=true...")

    m_f, mac_f = forge_keyed_hash(M.encode(), binascii.unhexlify(mac), b"is_admin=true", keysize)

    # m_f und mac_f zum Server für Prüfung schicken
    sf.write(binascii.hexlify(m_f).decode() + "\n")
    sf.write(mac_f.decode() + "\n")
    sf.flush()

    # Flagge ausgeben
    response = sf.readline()
    # print(response)

    if response != "Sorry, but no :(":
        print(response)
        break

    # we just brute force the key size, byte by byte
    keysize += 8
