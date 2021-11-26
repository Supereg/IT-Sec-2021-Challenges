from fha256 import fha_init, fha_update, fha_final
import binascii
import hashlib
import struct
import math
import sys
import socket

def forge_keyed_hash(orig_msg, orig_hash, append, key_length):
    m = fha_init()
    m["count_lo"] = 0 # TODO: Länge der Nachricht bis hier (in Bits) 
    m['digest'] = list(struct.unpack(">IIIIIIII", orig_hash))

    # TODO: Hier fehlt Code...
    new_msg = b""

    # Beispiel: Mit dem Inhalt von Variable foobar "weiter hashen"
    # fha_update(m, foobar)

    h = fha_final(m)
    return (new_msg, binascii.hexlify(h))

# Beispiel für die Erstellung eines FHA hashes mit fha_init(),
# fha_update() und fha_final()
def hash_using_fha(msg):
    """Create a regular FHA hash of a message"""
    m = fha_init()
    fha_update(m, msg)
    return fha_final(m)

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

# TODO: Message m_f und mac_f erzeugen, sodass M != m_f, aber MAC_f gültig
# TODO: MAC_k(M) := FHA(k || M) -> keysize := len(k). Da k nur auf dem Server
# vorhanden ist, muss keysize anders bestimmt werden
keysize = 0

m_f, mac_f = forge_keyed_hash(M.encode(), binascii.unhexlify(mac), b"is_admin=true", keysize)

# m_f und mac_f zum Server für Prüfung schicken
sf.write(binascii.hexlify(m_f).decode() + "\n")
sf.write(mac_f.decode() + "\n")
sf.flush()

# Flagge ausgeben
print(sf.readline())
