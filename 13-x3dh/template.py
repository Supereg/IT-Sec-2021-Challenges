import cryptography
import json
import socket
import string
import sys
import typing
import xeddsa

# https://www.signal.org/docs/specifications/x3dh/

NUM_OTKS = 64 # How many OTKs you need to publish (at least!)

# Here are some useful API functions to talk to the server
# Your function will receive a working server_api object
class server_api:
    def __init__(self, sf):
        self._sf = sf
        self._name = 'Alice' # Your name is always Alice, don't change this...

    def _request(self, operation: str, args: typing.Any) -> str:
        self._sf.write((json.dumps({ 'op': operation, 'args': args }) + '\n').encode())
        return self._sf.readline().decode().strip()

    def publish_keys(self, ik: str, spk: str, sig: str, otks: typing.List[str]) -> None:
        '''
        Publish your own keys (as raw hex strings).
        sig should be a hex string containing the appropriate signature of the SPK.
        To make sure you can talk to the server, you should sign the *raw bytes of the SPK*,
        not the hex string (i.e. use `bytes.fromhex` on the SPK you pass here).
        '''
        assert len(otks) == len(set(otks)), 'Your OTKs are not distinct!'
        assert len(otks) >= NUM_OTKS, f'You should publish at least {NUM_OTKS} OTKs'
        response = self._request('publish', { 'name': self._name, 'ik': ik, 'spk': spk, 'sig': sig, 'otks': otks })
        assert response == 'OK', f'Failed to publish keys: {response}'

    def fetch_prekey_bundle(self, user: str):
        '''
        Grab someone's public keys from the server.
        Response will contain
            { 'ik': ik, 'spk': spk, 'sig': sig, 'otk': otk, 'bundle': bundle_index }
        where ik, spk, sig, and otk are raw hex strings, and bundle_index is a number.
        '''
        return json.loads(self._request('keys', user))

    def handle_incoming_request(self):
        '''If someone sent you a message, you'll get the message here (like send_message)'''
        message = self._request('incoming', '')
        try:
            return json.loads(message)
        except json.JSONDecodeError:
            assert False, f'Failed to receive message: {message}'

    def send_message(self, user: str, your_ik: str, your_ek: str, which_prekey_bundle: int, nonce: str, ciphertext: str, tag: str) -> None:
        '''Send a message to establish a connection'''
        response = self._request('message', { 'user': user, 'ik': your_ik, 'ek': your_ek, 'bundle': which_prekey_bundle, 'nonce': nonce, 'ct': ciphertext, 'tag': tag })
        assert response == 'OK', f'Failed to send message: {response}'

class ValidationError(Exception):
    pass

# For this task, you need to perform X3DH both ways.
# Implement the task's individual parts below!

def generate_key():
    # TODO: Return a valid pair of public and private keys. You can then reuse this function below!
    #       We don't check this function, but you'll probably need to use this in multiple places!
    # return public_key, private_key

def publish_keys(server_api: server_api) -> None:
    # TODO: You need to generate your own keys and publish them to the server here!
    #       Make sure to generate enough OTKs (at least NUM_OTKS)
    # server_api.publish_keys(...)

def send_message_to(server_api: server_api, user: str, message: str) -> None:
    # TODO: Send the specified message to the specified user. If someone messed with the key bundle,
    #       raise a ValidationError (`raise ValidationError()`).
    # server_api.send_message(...)

def receive_message(server_api: server_api) -> str:
    incoming = server_api.handle_incoming_request()
    # TODO: Process the incoming message, then decode and return the decrypted ciphertext.
    #       If you cannot validate that the message really is from the user it claims to be from,
    #       raise a ValidationError (`raise ValidationError()`).

# You don't need to change anything below here - this code just repeatedly sends and receives
# messages. Maybe you want to add some calls to print() for more logging though...
if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else 'itsec.sec.in.tum.de'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 7070
    with socket.socket() as so:
        # Connect to the server and publish some keys
        so.connect((host, port))
        api = server_api(so.makefile('rwb', buffering=0))
        publish_keys(api)
        message_count = 0
        send_message_to(api, 'admin', f'Let\'s go!')
        while True:
            message_count += 1
            try:
                result = receive_message(api)
            except ValidationError:
                # Failed to validate, send a message about that to the server to prove correctness
                send_message_to(api, 'admin', f'Incoming message {message_count} failed to validate')
            else:
                next_user, secret = result.split(':', 1)
                if next_user == 'flag': # This is the last message!
                    print(secret)
                    break
                try:
                    send_message_to(api, next_user, secret)
                except ValidationError:
                    send_message_to(api, 'admin', f'Outgoing message {message_count} failed to validate')
