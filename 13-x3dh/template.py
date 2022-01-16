import cryptography
import json
import socket
import string
import sys
import typing
import xeddsa
import binascii
import os

# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# https://www.signal.org/docs/specifications/x3dh/

NUM_OTKS = 64 # How many OTKs you need to publish (at least!)

# Here are some useful API functions to talk to the server
# Your function will receive a working server_api object
class server_api:
    def __init__(self, sf):
        self._sf = sf
        self._name = 'Alice' # Your name is always Alice, don't change this...

    def _request(self, operation: str, args: typing.Any) -> str:
        print("Doing {} with {}".format(operation, args))
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
    priv = xeddsa.implementations.XEdDSA25519.generate_mont_priv()
    pub = xeddsa.implementations.XEdDSA25519.mont_pub_from_mont_priv(priv)
    return pub, priv

def getFirstHex(otk):
    return (otk[0]).hex()

def publish_keys(server_api: server_api) -> None:
    # TODO: You need to generate your own keys and publish them to the server here!
    #       Make sure to generate enough OTKs (at least NUM_OTKS)
    # server_api.publish_keys(ik: str, spk: str, sig: str, otks: typing.List[str])

    # First generate a identity key pair
    global IK_B
    global IK_B_priv
    (IK_B, IK_B_priv) = generate_key()

    # and now use that for key material to init a XEdDSA25519 Object, in order to use the signing function
    IK = xeddsa.implementations.XEdDSA25519(IK_B_priv, IK_B)

    # generate the SPK pair
    global SPK_B
    global SPK_B_priv
    (SPK_B, SPK_B_priv) = generate_key()

    # and now sign that public SPK with the private IK_B_priv using the IK object we initialized above
    sig = IK.sign(SPK_B)

    # Generate a bunch of these One-time PreKeys...
    otks = []
    for i in range(NUM_OTKS):
        otks.append(generate_key())
    
    # ...and map their public keys to a hexed string list for publishing
    otks_strs = list(map(getFirstHex, otks))

    server_api.publish_keys(ik = IK_B.hex(), spk = SPK_B.hex(), sig = sig.hex(), otks = otks_strs)   

    return None

def send_message_to(server_api: server_api, user: str, message: str) -> None:
    # TODO: Send the specified message to the specified user. If someone messed with the key bundle,
    #       raise a ValidationError (`raise ValidationError()`).
    # server_api.send_message(...)

    # Fetch Prekey bundle from server for `user`
    PK_bundle = server_api.fetch_prekey_bundle(user)

    print("PK bundle for user {}:".format(user))
    print(PK_bundle)

    # Unpack bundle
    IK_admin_str = PK_bundle["ik"]
    SPK_admin_str = PK_bundle["spk"]
    SIG_admin_str = PK_bundle["sig"]
    OTK_admin_str = PK_bundle["otk"]

    # Verify Signature
    IK_obj = xeddsa.implementations.XEdDSA25519(mont_pub = bytes.fromhex(IK_admin_str))

    if IK_obj.verify(bytes.fromhex(SPK_admin_str), bytes.fromhex(SIG_admin_str)):
        print("Successfully verified {}'s signature".format(user))
    else:
        raise ValidationError()

    # TODO: generate EK ?!
    (EK_priv, EK) = generate_key()

    X25519_SPK_admin = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(SPK_admin_str))
    X25519_IK_B_priv = x25519.X25519PrivateKey.from_private_bytes(IK_B_priv)

    shared_DH_1 = X25519_IK_B_priv.exchange(X25519_SPK_admin)

    X25519_EK_priv = x25519.X25519PrivateKey.from_private_bytes(EK_priv)
    X25519_IK_admin = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(IK_admin_str))

    shared_DH_2 = X25519_EK_priv.exchange(X25519_IK_admin)
    shared_DH_3 = X25519_EK_priv.exchange(X25519_SPK_admin)

    X25519_OTK_admin= x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(OTK_admin_str))

    shared_DH_4 = X25519_EK_priv.exchange(X25519_OTK_admin)

    all_DHs = shared_DH_1 + shared_DH_2 + shared_DH_3 + shared_DH_4

    print("Concatenated DH Keys")
    print(all_DHs.hex())

    # according to spec prepend a F with 32 0xFF bytes for X25519
    F_X25519 = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'

    derived_SK = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        info=b'itsec@tum'
    ).derive(F_X25519 + all_DHs)

    print("derived SK: {}".format(derived_SK.hex()))

    # Phase 2b

    # Derive Assiciated Data

    AD = IK_B + bytes.fromhex(IK_admin_str)

    aesgcm = AESGCM(derived_SK)

    nonce = os.urandom(24)
    # TODO: check this line. Maybe the `+AD` is bullshit
    ct_raw = aesgcm.encrypt(nonce, bytes(message, "utf-8"), bytes(AD.hex(), "utf-8"))

    print("ct_raw = {}".format(ct_raw.hex()))

    ct = ct_raw[:-16]
    tag = ct_raw[-16:]

    print("ct = {}".format(ct.hex()))
    print("tag = {}".format(tag.hex()))

    print(aesgcm.decrypt(nonce, ct_raw, bytes(AD.hex(), "utf-8")))

    # msg = IK_B + EK + ct + bytes.fromhex(SPK_admin_str) + bytes.fromhex(OTK_admin_str)
    # print("msg = {}".format(msg.hex()))

    # send_message(self, user: str, your_ik: str, your_ek: str, which_prekey_bundle: int, nonce: str, ciphertext: str, tag: str)
    server_api.send_message(user = user, your_ik = IK_B.hex(), your_ek =  EK.hex(), which_prekey_bundle = PK_bundle["bundle"], 
                                nonce = nonce.hex(), ciphertext = ct.hex(), tag = tag.hex())

    return None

def receive_message(server_api: server_api) -> str:
    incoming = server_api.handle_incoming_request()
    # TODO: Process the incoming message, then decode and return the decrypted ciphertext.
    #       If you cannot validate that the message really is from the user it claims to be from,
    #       raise a ValidationError (`raise ValidationError()`).
    return ""

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
