#!/usr/bin/env python3

import hashlib
import subprocess
import os
import binascii
import asyncio
from fha256 import fha_init, fha_update, fha_final

def create_keyed_hash(secret, msg):
    h = fha_init()
    fha_update(h, secret)
    fha_update(h,msg)
    digest = fha_final(h)
    return digest

mhex = lambda x: binascii.hexlify(x).decode()

with open("secret-key.bin", "rb") as keyfile:
    secret = keyfile.read()
msg = b"http://www.bank.de/onlinebanking.html?lang=deutsch&is_admin=false"

async def handle_request(reader, writer):
    print("New connection")
    mac = create_keyed_hash(secret, msg)
    writer.write("{}\n{}\n".format(msg.decode(), mhex(mac)).encode())
    await writer.drain()

    new_msg = await reader.readline()
    new_msg = new_msg.strip() # unhexlify will cut off the newline anyways (it's not a hex character)
    print("Message:           ", new_msg.decode(errors='ignore')) # Just for logging, we don't care about Unicode.
    new_mac = await reader.readline()
    new_hash = new_mac.strip()
    print("User-supplied MAC: ", new_hash.decode(errors='ignore'))

    new_msg = binascii.unhexlify(new_msg)
    check_hash = binascii.hexlify(create_keyed_hash(secret, new_msg))
    print("Expected MAC:      ", check_hash.decode())

    if b"is_admin=true" in new_msg and new_msg.startswith(msg) and check_hash == new_hash:
        flag = subprocess.check_output("/bin/flag")
        writer.write(flag)
    else:
        print("Nope...")
        writer.write(b"Sorry, but no :(")
    await writer.drain()
    writer.close()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_request, "0.0.0.0", 1024, loop=loop)
    server = loop.run_until_complete(coro)

    print("Serving on {}".format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Quitting server")
