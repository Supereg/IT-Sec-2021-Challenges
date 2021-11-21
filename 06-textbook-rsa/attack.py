# We know that the server uses textbook rsa.
# We know that the server will decrypt anything we send them as long as it doesn't start with "flag"
# We have the encrypted flag C=RSA_e(M) with M="flag{...}".
#
# According to https://www.uni-weimar.de/fileadmin/user/fak/medien/professuren/Mediensicherheit/Teaching/WS1516/Kryptographie__Mosbach_/krypto08.pdf
# (this is also explained in http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf; linked in task 07)
# we can construct a M'=(M*r) mod N (with r \in Z_N) by just knowing C
# C'=RSA_e(M') is constructed as follows:
#   =(r * M)^e mod N
#   =(r^e * M^e) mod N
#   =(r^e * C) mod N
#
# Using this techniue we can modify the ciphertext, therefore circumvent the "flag-check" and reconstruct the
# original message afterwards.

# We can manually connect via `telnet itsec.sec.in.tum.de 7025`

# Constants retrieve from a manual connect!
N = 31511564540733510745119160555849790586658736078995926138938535802938687308372270495817783933340060681773033322388651205126697332436106943823768892885824384816616707561073010507264693221167953982741722947421173352096779833391716248640759214437975808719610239896720756762152382233956921377862900844373271271633441224605191962708005539801818821038150900437910524787374195607458725771735840356530155558119951348786334434374051473655235808803885460360983745083039054245376435787478073833501446705665139014671301534356862915478678476632672633176304226010163232805220740485841258380224994639873580833185794681663032400599777
e = 65537

# The encrypted flag in hex retrieved from the server
flag_hex = "0461d0fd3e6310ee888490ee27656e2f24ef654d53c52a05c20ac494bb6c09c1bb09e60787830e834cc883e56f1576046b9baf36afc55e8e11da82630141fb7bca78c7af398f67c62d5adab880c52ec04b48b981030cde2af08528c81cd0ef74bfa25e69b2a2366ec3aff3582b2ddcd54da0d6de899fa1bec6788b314870790028e37bac52cc81f2a1f94f1a2e523d6b6b3aaea93078952e940b573dd69f3eb749ca06ee00fbad3e2dea9d99a7176439c60c31090bd943a01fa5d79cd65246ef0d0f8071a6e268ee6c475a888ffb6a6c66928b5d1301de099a3f76219fd3cbfa72c647c3ccdd3ac178cb09f27f348bae1bc13ef6852245c02d8e6ef4486c11aa"
c = int.from_bytes(bytes.fromhex(flag_hex), byteorder="little")

# Construct C'=(r^e * C) mod N
# We instantiate r=2
r = 2
c_modified = (pow(r, e) * c) % N
c_modified_hex = c_modified.to_bytes(length=2048//8, byteorder="little").hex()
# We print the modified c such that we can copy it and send it to the server!
print("Here is C'. Please send it to the server and paste response below:")
print(c_modified_hex)

# exit(0)

# Below is M' in hex, as returned from the server
m_modified_hex = "ccd8c2cef672c4c66672c86070c86e70c66aca726ac86c6470cac86070c8666ecc667262606aca72c2fa14000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
m_modified = int.from_bytes(bytes.fromhex(m_modified_hex), byteorder="little")
# We know M'=(r*M) mod N
# We know M'<<N
# Therfore we can derrive M=M'/r
m = m_modified // r
print("The plaintext is:")
print(m.to_bytes(length=43, byteorder="little").decode("utf-8"))
