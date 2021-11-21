import asyncio
import logging
import math

from Crypto.Util.number import *
from Crypto.Cipher import AES
import subprocess
import os
import pickle
import binascii

KEYFILE = "claudias-keys.pickle"

def load_or_generate_keys():
    global p, q, N, e, d
    if not os.path.exists(KEYFILE):
        # Generate a pubkey for Claudia if necessary
        # This is done just **once** on server setup and not on every request
        while True:
            p = getStrongPrime(512)
            q = getStrongPrime(512)
            phi = (p-1)*(q-1)
            N = p*q
            e = 3
            if math.gcd(e,p-1) != 1: continue
            if math.gcd(e,q-1) != 1: continue
            break
        d = inverse(e, phi)

        with open(KEYFILE, "wb") as keyfile:
            pickle.dump((p,q,N,e,d), keyfile)
    else:
        with open(KEYFILE, "rb") as keyfile:
            p,q,N,e,d = pickle.load(keyfile)

async def handle_request(reader, writer):
    logging.info("New connection!")

    k = os.getrandom(16)
    padding_bytes = b"\x01" * 100
    knumber = bytes_to_long(k + padding_bytes) # Padding seems to be important!
    enc_k = pow(knumber, e, N)
    cipher = AES.new(key=k, mode=AES.MODE_CTR)

    flag = subprocess.run(["/bin/flag"], capture_output=True).stdout
    enc_msg = cipher.encrypt(flag)

    writer.write(f"***GCHQ Internet Observation Center***\n\nFabian sent the following message to Prof. Eckert:\nenc_k = {enc_k:x}\niv = {cipher.nonce.hex()}\nenc_msg = {enc_msg.hex()}\n\nProf. Eckert's public key is:\nN = {N:x}\ne = {e:x}\n\nUnfortunatly our quantum computer and spies are too busy right now.\nGive me enc_key (hex encoded) terminated by a newline!\n".encode())

    await writer.drain()

    while True:
        enc_key = await reader.readline()

        enc_key = int(enc_key.strip(), 16)

        k = pow(enc_key, d, N)
        kb = k.to_bytes(128, byteorder="big")
        print("kb", kb.hex())
        if kb[-1] & 0x1 == 0x1: # Check for correct padding
            writer.write(b"Padding okay!\n")
        else:
            writer.write(b"Bad padding!\n")

        await writer.drain()
    writer.transport.abort()

if __name__ == "__main__":
    load_or_generate_keys()

    logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_request, "0.0.0.0", 1024, loop=loop)
    server = loop.run_until_complete(coro)

    print("Serving on {}".format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Quitting server")
