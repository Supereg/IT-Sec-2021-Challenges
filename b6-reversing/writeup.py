import hashlib
import struct

# Alright welcome to my writeup for b6 :)
# So we have a couple of hints from the exercise already. We know we can't do a similar approach as in b4,
# and it is also given that we should not waste our time trying to modify any of the binaries.
# So our target is the save file itself.
#
# So the first step is to locate the save file itself. Why the easiest way would have probably been to just read
# the source code of the `SaveManager` (using dotPeek see b5) I just followed my intuition back from my gaming's days.
# Where do programms store their data on Windows (yeah I'm running windows as my daily driver running macOS was
# unsupported :( and that was my only read-to-go alternative)? Exactly `%appdata%` (good old `.minecraft` days).
# Viola we have our save game. 0x4c bytes long! Packaged as `current`.

# Now let's see how the save game is handled.
# We have two libraries `libitsec-game-savefiles.so` and `libanticheat.so` (I know I'm jumping back and worth
# between windows stuff and linux stuff. But that are things I can do on my primary machine.
#
# For context (something I discovered later down the road though): saving the game is handled in `libanticheat`.
# Checking this logic is not really feasible.
#
# Now getting into some static analysis in `libanticheat`. Opened with ghidra and looking at the decompiled code
# we see the `LoadGame` function (we would have also discovered this entry point when looking at the `SaveManager`).
#
# I think to thoroughly present my findings it's best to just copy the decompiled output, combined with my renaming of
# variables into the write-up with some further comments here and there. Otherwise the stuff below won't make sense.
# ```
# FILE * LoadGame(char *fileName)
# {
#   int hashResult;
#   FILE *__stream;
#   FILE *fileContent;
#   long in_FS_OFFSET;
#   MD5_CTX md5_ctx;
#   undefined tmp_buf [272];
#   undefined expectedHash [16];
#   uchar computedHash [16];
#   undefined fileHeader [40];
#   long stack_cookie;
#
#   stack_cookie = *(long *)(in_FS_OFFSET + 0x28);
#   printf("itsec-savefiles: Loading game from %s\n",fileName);
#   __stream = fopen(fileName,"rb");
#   if (__stream == (FILE *)0x0) {
#     fprintf(stderr,"Unable to load save file: %s\n",fileName);
#   }
#   else {
#     fileContent = (FILE *)malloc(0x1c);
#     # at this point we read the file in three steps
#     fread(fileHeader,1,0x20,__stream); # first 0x20 bytes are some magic header
#     fread(fileContent,1,0x1c,__stream); # next 0x1c bytes are the actual file content (returned later in the method)
#     fread(expectedHash,1,0x10,__stream); # last 16 bytes is a md5 hash over the file content (NOTE comments below)
#     fclose(__stream);
#     # here happens some magic stuff. Some bytes scrambled into `tmp_buf` which are later processed
#     # and XORed again the current `fileContent` resulting in the "unwrapped" fileContent.
#     parsedFileHeader(tmp_buf,fileHeader,0x20);
#     parseFileContent(tmp_buf,fileContent,0x1c);
#     # At this point fileContent is fully unpacked and contains the readable data.
#
#     MD5_Init(&md5_ctx);
#     MD5_Update(&md5_ctx,fileContent,0x1c);
#     MD5_Final(computedHash,&md5_ctx);
#     # We use a md5 hash over the unpacked file content to "verify" integrity
#     hashResult = memcmp(computedHash,expectedHash,0x10);
#     __stream = fileContent;
#     if (hashResult != 0) {
#       puts("itsec-savefiles: Invalid save file!");
#       __stream = (FILE *)0x0;
#     }
#   }
#   if (stack_cookie == *(long *)(in_FS_OFFSET + 0x28)) { # check for the stack cookie
#     # Return the file content. This is typeOf `SaveData` (inside the C# module).
#     return __stream;
#   }
#                     /* WARNING: Subroutine does not return */
#   __stack_chk_fail();
# }
# ```

# So now we know roughly how the file is structured.
# 0x20 bytes of "file header"
# 0x1c bytes of content
# 0x10 bytes of md5 hash

def read_savegame(path):
    with open(path, "rb") as file:
        file_data = file.read()

        header = file_data[0:0x20]
        content = file_data[0x20: 0x20 + 0x1c]
        md5sum = file_data[-0x10:]

        return header, content, md5sum


header, content, md5sum = read_savegame("./current")
print("Current SaveGame:")
print(header.hex())
print(content.hex())
print(md5sum.hex())
print("")


# Looking at `parsedFileHeader` and `parseFileContent` this contains weird stuff we can't really calculate ourselves.
# But we notice, the last operation in the loop inside `parseFileContent`, the operation which actually unwraps
# the file content is a XOR operation. So whatever the result of the `header` processing is, if we can reimplement
# it, we can just save the XOR operand and reverse the whole thing!! So that's the plan!

# We also allocate the tmp_buf byte array. Looking at `parsedFileHeader` it has the following structure,
# first 256 bytes are the values which get written around. On position 0x100 and 0x104 we have to ints (4B)
# which are used here and there to store stuff, idk. But instead of handling writing int back and forth
# in python we just use the two variables `var1` and `var2` to handle that.
# Then there are 2 bytes left in the `tmp_buf` which idk what they are for :)
tmp_buf = bytearray(272)
var1 = 0
var2 = 0

# void parsedFileHeader(long param_1,long fileHeader,ulong length_0x20)
# {
#   uint last_j;
#   long i;
#   ulong j;
#   byte value;
#
#   i = 0;
#   # first loop fills the buf with ascending numbers (up to 0x100).
#   do {
#     *(char *)(param_1 + i) = (char)i;
#     i = i + 1;
#   } while (i != 0x100);
#
#   # Then there is this weird stuff were a lot of positions are interchanged with each others and processed.
#   j = 0;
#   last_j = 0;
#   do {
#     value = *(byte *)(param_1 + j);
#     last_j = (uint)*(byte *)(fileHeader + j % length_0x20) + value + last_j & 0xff;
#     *(undefined *)(param_1 + j) = *(undefined *)(param_1 + (int)last_j);
#     *(byte *)(param_1 + (int)last_j) = value;
#     j = j + 1;
#   } while (j != 0x100);
#   *(undefined4 *)(param_1 + 0x104) = 0;
#   *(undefined4 *)(param_1 + 0x100) = 0;
#   return;
# }


def process_header(length=0x20):
    # this is the first loop
    for i in range(0x100):  # iterates over the first 256 bytes
        tmp_buf[i] = i

    print(tmp_buf.hex())

    # this the second one
    last_j = 0
    for j in range(0x100):
        value = tmp_buf[j]
        last_j = (header[j % length] + value + last_j) & 0xFF

        tmp_buf[j] = tmp_buf[last_j]
        tmp_buf[last_j] = value

    print(tmp_buf.hex())


print("Processing header...")
process_header()
print("")

# Now to unwrapping the content:
# void parseFileContent(long tmp_buff,byte *content,long length_0x1c)
# {
#   uint uVar1;
#   int base_var2;
#   long base_var2_2;
#   int base_var1;
#   byte *max_ptr;
#   byte var1_hdr;
#   char var2_hdr;
#
#   if (length_0x1c != 0) {
#     max_ptr = content + length_0x1c;
#     do {
#       # This is base_var1, but they are optimized into the same variable
#       base_var2 = *(int *)(tmp_buff + 0x100) + 1;
#       uVar1 = (uint)(base_var2 >> 0x1f) >> 0x18;
#       base_var1 = (base_var2 + uVar1 & 0xff) - uVar1;
#       *(int *)(tmp_buff + 0x100) = base_var1;
#       var1_hdr = *(byte *)(tmp_buff + base_var1);
#       base_var2 = (uint)var1_hdr + *(int *)(tmp_buff + 0x104);
#       uVar1 = (uint)(base_var2 >> 0x1f) >> 0x18;
#       base_var2 = (base_var2 + uVar1 & 0xff) - uVar1;
#       *(int *)(tmp_buff + 0x104) = base_var2;
#       base_var2_2 = (long)base_var2;
#       var2_hdr = *(char *)(tmp_buff + base_var2_2);
#       *(byte *)(tmp_buff + base_var2_2) = var1_hdr;
#       *(char *)(tmp_buff + base_var1) = var2_hdr;
#
#       # Here is the operation of interest. Something XORed with the content resulting in the actual content! :)
#       *content = *content ^
#                  *(byte *)(tmp_buff + (ulong)(byte)(var2_hdr + *(char *)(tmp_buff + base_var2_2)));
#       content = content + 1;
#     } while (content != max_ptr);
#   }
#   return;
# }


# So let's implement this as well
def unwrap_content(value1, value2, length=0x1c):
    unwrapped_content = []
    xor_parameters = []

    for i in range(length):
        base_var1 = (value1 + 1) & 0xFF
        value1 = base_var1

        var1_hdr = tmp_buf[base_var1]

        base_var2 = (value2 + var1_hdr) & 0xFF
        value2 = base_var2

        var2_hdr = tmp_buf[base_var2]

        tmp_buf[base_var2] = var1_hdr
        tmp_buf[base_var1] = var2_hdr

        xor_param = tmp_buf[(var2_hdr + var1_hdr) & 0xff]
        # save both
        unwrapped_content.append(content[i] ^ xor_param)
        xor_parameters.append(xor_param)

    return unwrapped_content, xor_parameters


unwrapped_content, xor_parameters = unwrap_content(var1, var2)
unwrapped_content_bytes = bytearray(unwrapped_content)
xor_parameters_bytes = bytearray(xor_parameters)
print(f"unwrapped_content: \t{unwrapped_content_bytes.hex()}")
print(f"xor_parameters: \t{xor_parameters_bytes.hex()}")

# Looking into the `SaveManager` source we can get to the type of the unwrapped_content:
# struct SavedData { // 28b
#     public float mana; // 4b
#     public int maxMana; // 4b
#     public int health; // 4b
#     public int gold; // 4b
#     public int maxHealth; // 4b
#     public int attackStat; // 4b
#     public int manaRegen // 4b
# }

# So let's print this
print("""
mana {}
maxMana {}
health {}
gold {}
maxHealth {}
attackStat {}
manaRegen{}
""".format(
    struct.unpack_from("f", unwrapped_content_bytes, 0x00),
    struct.unpack_from("i", unwrapped_content_bytes, 0x04),
    struct.unpack_from("i", unwrapped_content_bytes, 0x08),
    struct.unpack_from("i", unwrapped_content_bytes, 0x0c),
    struct.unpack_from("i", unwrapped_content_bytes, 0x10),
    struct.unpack_from("i", unwrapped_content_bytes, 0x14),
    struct.unpack_from("i", unwrapped_content_bytes, 0x18),
))

print("")
# Let's calculate the has over the content ourselves
computed_hash = hashlib.md5(unwrapped_content_bytes).digest().hex()
print(f"hash: \t\t{computed_hash}")
print(f"expected:\t{md5sum.hex()}")
print(f"same: \t\t{md5sum.hex() == computed_hash}")
print("")

# Now we modify the savegame
struct.pack_into("i", unwrapped_content_bytes, 0x0c, 13371337)
print(f"previous:\t{bytearray(unwrapped_content).hex()}")
print(f"now: \t\t{unwrapped_content_bytes.hex()}")

# Computed the new hash
modified_hash = hashlib.md5(unwrapped_content_bytes).digest()
print(f"new hash: \t{modified_hash.hex()}")

# compute the new, wrapped content field
wrapped_content = []
for i in range(0x1c):
    wrapped_content.append(unwrapped_content_bytes[i] ^ xor_parameters[i])
wrapped_content_bytes = bytearray(wrapped_content)

# write out the modified save game
with open("./modified_savegame", "wb") as modified_savegame:
    modified_savegame.write(header + wrapped_content_bytes + modified_hash)

# play the game...
print("flag{5ffd1d7ff045b356b361c018c297b49804f3}")
