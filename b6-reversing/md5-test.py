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

print(header.hex())
print(content.hex())
print(md5sum.hex())

tmp_buf = bytearray(272)
# those two vars basically map to the last 8 (+2) bytes in the buffer above!
var1 = 0
var2 = 0


def process_header(length=0x20):
    for i in range(0x100):  # iterates over the first 256 bytes
        tmp_buf[i] = i

    print(tmp_buf.hex())

    last_j = 0
    for j in range(0x100):
        value = tmp_buf[j]
        new_index = (header[j % length] + value + last_j) & 0xFF

        tmp_buf[j] = tmp_buf[new_index]
        tmp_buf[last_j] = value

    var1 = 0
    var2 = 0

    print(tmp_buf.hex())


process_header()

new_content = []

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

        new_content.append(
            content[i] ^ tmp_buf[(var2_hdr + var1_hdr) & 0xff]
        )

        """"
        (asdf,) = struct.unpack_from("i", tmp_buf, 0x100)
        iVar4 = asdf + 1
        asdf = struct.pack("i", iVar4 >> 0x1f)
        (asdf,) = struct.unpack("I", asdf)
        uVar3 = asdf >> 0x18
        iVar6 = ((iVar4 + uVar3) & 0xff) - uVar3
        struct.pack_into("i", tmp_buf, 0x100, iVar6)

        bVar1 = tmp_buf[iVar6]
        (asdf,) = struct.unpack_from("i", tmp_buf, 0x104)
        iVar4 = bVar1 + asdf
        asdf = struct.pack("i", iVar4 >> 0x1f)
        (asdf,) = struct.unpack("I", asdf)
        uVar3 = asdf >> 0x18
        iVar4 = ((iVar4 + uVar3) & 0xFF) - uVar3
        struct.pack_into("i", tmp_buf, 0x104, iVar4)

        # asdf = struct.pack("i", iVar4)
        # (asdf,) = struct.unpack("l", asdf)
        lVar5 = iVar4
        cVar2 = tmp_buf[lVar5]
        tmp_buf[lVar5] = bVar1
        tmp_buf[iVar6] = cVar2

        value_x = content[i] ^ \
                  tmp_buf[cVar2 + tmp_buf[lVar5]]
        new_content.append(value_x)
        """


unwrapContent(var1, var2)

print(new_content)
new_content_bytes = bytearray(new_content)
print(new_content_bytes.hex())
print(hashlib.md5(new_content_bytes).digest().hex())
print(md5sum.hex())