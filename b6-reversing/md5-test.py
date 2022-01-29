import hashlib
import struct

data = bytes.fromhex("0bee9ec062c42bc198570bf4cde591f45b45101bed8fb1c730d0657a")

print(data)

print(hashlib.md5(data).digest().hex())

header = None
content = None
md5sum = None

with open("./current", "rb") as file:
    file_data = file.read()

    header = file_data[0:0x20]
    content = file_data[0x20: 0x20+0x1c]
    md5sum = file_data[-0x10:]
    print(len(file_data))

#header = b"\xff"*0x20
#content = b"\xff"*0x1c
#md5sum = bytes.fromhex("4c35dce565fd713eaf1c9cf2a81c3772")

print(header.hex())
print(content.hex())
print(md5sum.hex())

tmp_buf = bytearray(272)
# those two vars basically map to the last 8 (+2) bytes in the buffer above!


def process_header(length=0x20):
    for i in range(0x100):  # iterates over the first 256 bytes
        tmp_buf[i] = i

    print(tmp_buf.hex())

    last_j = 0
    for j in range(0x100):
        value = tmp_buf[j]
        last_j = (header[j % length] + value + last_j) & 0xFF

        tmp_buf[j] = tmp_buf[last_j]
        tmp_buf[last_j] = value

    var1 = 0
    var2 = 0

    print(tmp_buf.hex())

    return (var1, var2)


var1, var2 = process_header()

new_content = []
xor_parameters = []

def unwrapContent(var1, var2, length=0x1c):
    if length == 0:
        return

    asdf1 = var1
    asdf2 = var2

    for i in range(length):
        base_var1 = (asdf1 + 1) & 0xFF
        asdf1 = base_var1

        var1_hdr = tmp_buf[base_var1]

        base_var2 = (asdf2 + var1_hdr) & 0xFF
        asdf2 = base_var2

        var2_hdr = tmp_buf[base_var2]

        tmp_buf[base_var2] = var1_hdr
        tmp_buf[base_var1] = var2_hdr

        xor_param = tmp_buf[(var2_hdr + var1_hdr) & 0xff]
        new_content.append(
            content[i] ^ xor_param
        )
        xor_parameters.append(xor_param)


unwrapContent(var1, var2)

print(new_content)
new_content_bytes = bytearray(new_content)
print(new_content_bytes.hex())
print(bytearray(xor_parameters).hex())
print("""
mana {}
maxMana {}
health {}
gold {}
maxHealth {}
attackStat {}
manaRegen{}
""".format(
    struct.unpack_from("f", new_content_bytes, 0x00),
    struct.unpack_from("i", new_content_bytes, 0x04),
    struct.unpack_from("i", new_content_bytes, 0x08),
    struct.unpack_from("i", new_content_bytes, 0x0c), # gold
    struct.unpack_from("i", new_content_bytes, 0x10),
    struct.unpack_from("i", new_content_bytes, 0x14),
    struct.unpack_from("i", new_content_bytes, 0x18),
))

print("")
new_hash = hashlib.md5(new_content_bytes).digest().hex()
print(new_hash)
print(md5sum.hex())
print(md5sum.hex() == new_hash)


struct.pack_into("i", new_content_bytes, 0x0c, 13371337)
print(f"asdf {bytearray(new_content).hex()}")
print(f"asdf {new_content_bytes.hex()}")

modified_content = []

for i in range(0x1c):
    modified_content.append(new_content_bytes[i] ^ xor_parameters[i])

modified_content_bytes = bytearray(modified_content)
modified_hash = hashlib.md5(new_content_bytes).digest()
print(modified_hash.hex())

with open("./new_file", "wb") as new_file:
    new_file.write(header + modified_content_bytes + modified_hash)

print("flag{5ffd1d7ff045b356b361c018c297b49804f3}")
