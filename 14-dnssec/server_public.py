import asyncio
import subprocess
import random
import binascii
import struct

HARDNESS = 100

MESSAGE_FILES = [] # REDACTED

msgs = []
for fn, c in MESSAGE_FILES:
    with open(fn) as f:
        msgs.append((f.read().split("\n\n"), c))

class EchoServerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.state = 0
        self.transport = transport
        self.next_correct = 1
        self.all_correct = True

        self.send_challenge()

    def check_response(self, message):
        return message == self.next_correct

    def generate_challenge(self):
        # REDACTED
        return binascii.hexlify("\n\n".join(random.choice(msgs)).encode())

    def send_challenge(self):
        data = self.generate_challenge()
        datalen = struct.pack(">I", len(data))
        self.transport.write(datalen + data)

    def data_received(self, data):
        message = data
        if not len(message) == 1:
            self.transport.close()
            return
        
        message = message[0]
        if not self.check_response(message):
            self.all_correct = False
        
        self.state += 1
        
        if self.state == HARDNESS:
            if self.all_correct:
                flag = subprocess.check_output("/bin/flag")
                self.transport.write(flag)
            else:
                self.transport.write(b"There must have been an error somewhere :<")
            self.transport.close()
        else:
            self.send_challenge()


async def main():
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: EchoServerProtocol(),
        '0.0.0.0', 7071)

    async with server:
        await server.serve_forever()


asyncio.run(main())
