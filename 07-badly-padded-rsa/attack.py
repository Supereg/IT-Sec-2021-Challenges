from Crypto.Util.number import *
import socket

from Crypto.Cipher import AES

# claudia_pub
N_hex = "cc274dcdd17573e3889aa66cbe9cff77f7c63cb85162634796c7a4789b3fec4784787e74a8ded41adc7e12a2e979c3546e3ae09331bcba894ec99d20366df22e9636ee2a94b9aa0b246732ebbe2f9fd5bd628c5ad6f918a170cf15d34f150a4cb6ae142965631b73dee4aad7b3d638c37245fba6196fecde3248a3a3070c2337"
e = 3

# enc_k = RSA_e(k + 0x01*100)
enc_k = "67e49068753a308477cd9613ed99a8fcca6a505b42512673f0c3eef5b9d8abd7075755611248367fedea5f4246986c28ac824104645c58126ffcfdbcbd48e43abaada5dcd418dfc935c691ce76be7c86fd447a37e80e6cec52d774df6b71132efd90ad168d520443d8a80c422820eb68e18480d71b27fcee8f868508f4c0e540"
iv = "27466b3b8ef45f92"
# AES-CTR_k(flag)
enc_msg = "f530aafc6d7f584fce2817cd01926f43ebfac1654dbffb350e3d0d14818a91b074a44ae143a03a0296ff74"

# Reading through the linked paper http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
# we again (like in task 6) rely on the fact, that the decryption of C'=C*s^e yields a message M'=M*s.
# So we can construct ciphertexts which are similar to the leaked one above.
# Further we have a Orclae which tells us if the least significant bit is 1 or not.
# While I took some hours to study the paper, I coulnd't quite wrap my head around how the attack is to be implemented.
# Also it seemed that the attack didn't quite fit 1:1 to our scenario.
#
# One line caught my eye: "Another well-known result is that the least significant bit of RSA encryption is as secure as the whole message [8] (see also [1])."
# This brought be to the Google Search "rsa least significant bit oracle attack"
# and the write up https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-LSBit-Oracle
# which explained a very similar scneario were we can exploit weaknesses of RSA by only knowing the value of the least significatn bit.

# First, turn N into an integer
N_bytes = bytes.fromhex(N_hex)
N = int.from_bytes(N_bytes, byteorder="big")
k = len(N_bytes)
print(k)


# Inspired from https://stackoverflow.com/questions/23056805/how-to-continuously-read-data-from-socket-in-python
def buffered_readLine(socket):
    line = bytes()
    while True:
        part = socket.recv(1)
        if part != b'\n':
            line += part
        elif part == b'\n':
            break
    return line.decode("utf-8")

def byte_length(c):
    bits = c.bit_length()
    bytes = bits // 8
    if bits % 8 > 0:
        bytes += 1
    return bytes

# Return value "True" indicates that the LSB was set to 1 (aka the padding check succeeded)
def check_cipher(socket, c):
    hex_c_bytes = c.to_bytes(length=byte_length(c), byteorder="big").hex().encode("utf-8")
    s.sendall(hex_c_bytes + b'\n')

    response = buffered_readLine(socket)
    if response == "Bad padding!":
        return False
    elif response == "Padding okay!":
        return True
    else:
        print("FATAL!")
        exit(1)

# open the socket to the server
s = socket.socket()
s.connect(("itsec.sec.in.tum.de", 7022))

while True:
    line = buffered_readLine(s)
    print(line)
    if line == "Give me enc_key (hex encoded) terminated by a newline!":
        break


print("Starting algo now!")

upper_limit = N
lower_limit = 0

# turn the ciphertext enc_k into an integer
c = int.from_bytes(bytes.fromhex(enc_k), byteorder="big")

i = 1
while i <= 500: # 500 iterations is enough to reconstruct the AES key, might not reconstruct the full padding!
    # we construct a C'=(C*r^e) mod N  with M'=r*M
    c_modified = (c * pow(2 ** i, e, N)) % N
    result = check_cipher(s, c_modified)

    if result:
        lower_limit = (lower_limit + upper_limit) // 2
    else:
        upper_limit = (upper_limit + lower_limit) // 2

    i += 1
    test = upper_limit.to_bytes(length=byte_length(c), byteorder="big").hex()
    print(i)
    print(test)


plaintext = upper_limit.to_bytes(length=byte_length(c), byteorder="big").hex()
print(plaintext)
prefix = len("000000000000000000000000")
AES_KEY = plaintext[prefix:(prefix + 16*2)] # d9eced2b1c3ac29b5d4d6860f68af08e
print(AES_KEY)
result = AES.new(bytes.fromhex(AES_KEY), AES.MODE_CTR, nonce=bytes.fromhex(iv)).decrypt(bytes.fromhex(enc_msg))
print(result.decode("utf-8"))

s.close()

# In THEORY, AES_KEY should hold our AES_KEY (and our padding). so 116 bytes with 100 bytes bein 0x01
# However we get some rubish, and a total of 128 bytes ://



# Please ignore everything from below. This were my attempts when looking at the paper.
# Just wanted to keep it for reference!

# First of all, we calculate B = 2^(8(k-2)) with k being the byte length of N
# print(n)
# B = pow(2, 8 * (k - 2))

# According to the paper 2B <= m*s mod N < 3B
# print(k)
# print(B)

# c = int.from_bytes(bytes.fromhex(enc_k), byteorder="little")
# First interval with s=1: [2B, 3B - 1]

# print(n // (3 * B))
# s_1_base = (n // 3 * B) + 2  # +1 as its most likely not a rest free integer division
# c_next = (c * pow(s_1_base, e)) % n
# print(c_next.to_bytes(length=2048 // 8, byteorder="little").hex())
# M_0 = [(2 * B, 3 * B - 1)]
# print(M_0)
# for (a, b) in M_0:
#    r_lower = (a * s_1_base - 3 * B + 1) // n
#     r_upper = (b * s_1_base - 2 * B) // n
#     print(r_lower)
#     print(r_upper)
#     print(r_upper - r_lower)
# M_u =


# i = b'\x01' + b'\x00' * 100
# print(i)
# print(bytes_to_long(i))
