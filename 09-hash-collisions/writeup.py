import os.path


# This file was used to create the two grades files. It is a mix between automated code for file assembly
# and at the same time acts as a write up of the whole process.
# The file creation is not a full automated task, and needs some manual steps as described below.


# The TUM grades file can somewhat be considered a tlv8 encoded file.
# It starts with a predefined magic, followed by several tlv8 records.
# Each record consists of one byte <record type> one byte <record length> and then followed by the <record content>.
# The file format differs from the standard tlv8 encoding in the following ways and has the following specialities:
#  - record 0x00 is not allowed
#  - record 0x01 (the name) must be the first record
#  - record 0x02 (the lecture name) is appended with 4 bytes representing the grade for the lecture:
#     3 bytes string representation of the grade, 1 null terminator byte. the 4 bytes for the grade are
#     not considered in the length of the 0x02 record
#  - any other record is ignored with the caveaty that the length byte is parsed differently:
#     for unknown records the lenght byte always counts itself into the length. So e.g. an empty record would need to be
#     encoded as 0x0401 (length of 1)
def tlv_record(type, content):
    return bytes([type]) + bytes([len(content)]) + content


# This method creates the grade (type 0x02) record for a given grade string
def grade(grade_string):
    assert len(grade_string) == 3
    return tlv_record(0x02, b'IT-Sicherheit') +\
        bytes(grade_string, "utf-8") +\
        b'\x00'  # grade protection


# For the collision i primarily considered two resources:
# 1) https://www.mscs.dal.ca/~selinger/md5collision/
# 2) https://github.com/corkami/collisions
#
# 1) was pretty decent to get a climpse of the fundamental concept behind md5 collisions.
# 2) was a good resource for an overview of the possible attack types.
#
# At the beginning, I tried to do the challenge with a chosen-prefix attack, basically having two grade files properly
# formatted (with a unknown record at the end skipping the rest) and feeding them into hashclash.
# Well, this thing ran forever, so it didn't really work out.
#
# Instead I've gone forward with a identical-prefix attack with the aim that the collision blocks in the two resulting
# files point to two different grades.
# So the file layout should look like the following:
# 1st block: <MAGIC><student record><unknown record; padding><record byte><record length byte pointing into block 2>
# 2nd block: The collision block. This block is slightly different in both files. We use those differences as
#   records, such that they point into different spots in the third block.
# 3rd block: Block containing both grades at different offsets.

# One thing to note is, that we don't control the 2nd block at all.
# We just use what the attack gives us and build around that.


# This method creates the 1st block.
# The offset paramter will be encoded in the last byte in the block.
# More on how we choose this value later.
def create_file_prefix_block(offset):
    # magic and name record
    prefix = b'!TUMFile' +\
        tlv_record(0x01, b'Andreas Bauer')

    # the rest bytes in the 64 byte block (MD5 acts on 64 byte blocks).
    # - 1 to accomodate for the type byte.
    rest_len = 64 - (len(prefix)) - 1

    # we reserve 2 bytes at the end for the start of a record.
    # type byte and length byte; lenght byte will be ="offset"
    rest_len -= 2

    # append the padding
    prefix += b'\x03' + bytes([rest_len]) + (rest_len - 1) * b'\xaf'

    offset += 1  # parser is weird and includes the length byte in the length itself for unknown records
    prefix += b'\x04' + bytes([offset])

    return prefix


def write_prefix_file():
    # With several iterations we found, that -- consistently -- the first byte difference occurs
    # at byte offset 0x12 in the collision block.
    file_prefix = create_file_prefix_block(0x12)

    with open("grade_prefix.grade", "wb") as fd:
        fd.write(file_prefix)


# The first step is to construct a common prefix, by abusing that the unknown record types
#  1) point beyond the file
#  2) point to distinct points beyond the file
#
# We then fed this file it into hashclash. More specificall feed it into `bin/md5_fastcoll`.
# `write_prefix_file` will generate `grade_prefix.grade` and after compiling https://github.com/cr-marcstevens/hashclash
# we can execute `./md5_fastcoll -p grade_prefix.grade`. This will create
# the files msg1.bin and msg2.bin with identical md5 hashes.
write_prefix_file()

# Remember from above, the first (random) record type is at byte 18th (0x12) in the collision block.
# We by hand traverse those records now below (hint look at the hex diff representation of both files).
# The goal is to find the byte offset into the file suffix for each of the files such that we can compute the common
# suffix (remember Merkle-Damgard construction, we can append as much data as we want,
# only requirement is that it is identical).
#
# every line below (for the according file) represents a record in the file, while one record always points
# to the record/position written on the next line.

# msg1.bin
# 0x4907  # record type 0x49, 7 bytes long
# 0x83fd  # record type 0x83, 253 bytes long
#   file has a rest length of 0x64 = 100 bytes, therfore 253 - 100 - 1 (-1 due to the weirdness that unknown records
#   include the length byte itself in the length) => 152 byte offset in the suffix
msg_1_offset = 152

# msg2.bin
# 0x4987  # record type 0x49, 135 bytes long
#  file has a rest length of 0x6C = 108 bytes, therefore (analogous to above) 135 - 108 - 1 =>
#  analogous to above: 135-100-1 = 34
msg_2_offset = 26


# Step 3 is now to construct the suffix, which is identical in each file (Markel-Damgard)
suffix = msg_2_offset * b'\x00'
suffix += grade("5.0")
# after one parses bad_grade, once should encounter another record which skips the whole file
suffix += b'\x05\xFF'  # we could calculcate the lenght, but as the parser doesn't check bounds just encode 0xFF

suffix += (msg_1_offset - len(suffix)) * b'\x00' + grade("1.0")

if not os.path.exists("msg1.bin") or not os.path.exists("msg2.bin"):
    print("please execute hashclash, to create msg1.bin and msg2.bin files!")
    # Note, this is not an automatic script, above `msg_1_offset` and `msg_2_offset` are manually calculated
    # for ONE execution of hashclash.
    exit(0)


with open("msg1.bin", "rb") as fd:
    msg1_data = fd.read()

with open("msg2.bin", "rb") as fd:
    msg2_data = fd.read()

new_1_file = msg1_data + suffix
new_2_file = msg2_data + suffix

with open("grade-1.0.grade", "wb") as fd:
    fd.write(new_1_file)
    print("Written the grade file with the good grade.")

with open("grade-5.0.grade", "wb") as fd:
    fd.write(new_2_file)
    print("Written the grade file with the bad grade.")
