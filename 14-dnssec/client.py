import socket
import struct

import binascii
import sys

from dns.dnssec import ValidationFailure
import dns.message
from datetime import datetime

HARDNESS = 100

cert_time = int(datetime(2021, 12, 16, 15).timestamp())

def check_correctness(messages):
    # Please implement me
    return True

def main():
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7071))

    for _ in range(HARDNESS):
        message = s.recv(4)
        datalen = struct.unpack(">I", message)[0]
        message = b""
        while len(message) < datalen:
            x = s.recv(datalen)
            if not x:
                print("Something seems to be wrong with the server")
                sys.exit(-1)
            message += x
        
        assert len(message) == datalen
        print("Received", datalen, "bytes")

        dns_messages = []
        for el in binascii.unhexlify(message).decode().split("\n\n"):
            dns_messages.append(dns.message.from_text(el))

        correctness = check_correctness(dns_messages)
        print("Responding with", correctness)
        s.send(bytes([correctness]))

    # Print f14g
    print(s.recv(1024))
    s.close()

main()
