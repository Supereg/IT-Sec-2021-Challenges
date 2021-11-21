import asyncio
import logging
import os
import pickle
import subprocess

from Crypto.Util.number import *

KEYFILE = "keys.pickle"

def load_or_generate_keys():
    global p, q, N, e, d
    if not os.path.exists(KEYFILE):
        # Generate keys for Bob if necessary
        # This is done just **once** on server setup and not on every request
        while True:
            p = getStrongPrime(1024)
            q = getStrongPrime(1024)
            phi = (p-1)*(q-1)
            N = p*q
            e = 65537
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

    # Step 1: Leak a message with the flag
    m = int.from_bytes(subprocess.check_output(["/bin/flag"]), byteorder="little")
    c = pow(m, e, N)

    writer.write("Hey! I am Bob!\nDo you want to send me a message? Feel free to use my public key (N={},e={})!\n\n".format(N, e).encode())

    writer.write("The GCHQ sniffed this RSA-encrypted message from my friend to me today: {}\n".format(c.to_bytes(length=2048//8,byteorder="little").hex()).encode())

    writer.write(b"\nI have no clue why they are doing this... I have nothing to hide! Send me one hex-encoded message, directed at me and encrypted with my public key! I will happily decrypt it and show you what is inside! I am using textbook RSA, this is so much simpler than OEAP! Textbook RSA not being secure is just fake news...\n")

    await writer.drain()

    # Step 2: Read the message the user wants us to decrypt
    user_message = await reader.readline()
    i = bytes.fromhex(user_message.decode().strip())
    c = int.from_bytes(i, byteorder="little")

    mm = pow(c, d, N).to_bytes(length=2048//8, byteorder="little")
    if b"flag" in mm:
        logging.info("Decryption try with flag inside!")
        writer.write(b"Um... Sorry, apparently this message is corrupted. I have nothing to hide, I promise!\n")
    else:
        logging.info("Decryption try without flag inside!")
        writer.write("The decrypted message is (in hex): {}".format(mm.hex()).encode())
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
