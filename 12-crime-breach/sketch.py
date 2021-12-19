import gzip
import os
import random
import time
from itertools import permutations

host = "131.159.74.85:7043"

hex_alphabet = list("0123456789abcdef")
base_alphabet = list("0123456789abcdeflg{}")
#alphabet_l = list(alphabet)
#random.shuffle(alphabet_l)
#alphabet = "".join(alphabet_l)
print(base_alphabet)

# 5-6 bytes increased
prefix = b'ebb100b259974f49'
suffix = b'd97ecf8dbb24dbbe'
#prefix = os.urandom(8).hex().encode()
#suffix = os.urandom(8).hex().encode()
flag = os.urandom(18).hex().encode()
print(flag)
otherflag = b"flag{9cc4496a75134b20e6d03303b332a8f52583}".strip()
randomflag = (b"flag{" + flag + b"}").strip()
flag = b'flag{70859bc0b71b54b05690dffe284bff415685}'.strip()
#alphabet: ['c', '4', '5', 'b', '7', '6', 'e', 'd', '2', 'f', 'a', '3', '8', '0', '1', '9']
example_flag_text = prefix + flag + suffix
search_text_length = len(example_flag_text)
print(example_flag_text)

# https://datatracker.ietf.org/doc/html/rfc1951

base_length = len(gzip.compress(example_flag_text + b" "))
length_threshold = len(gzip.compress(example_flag_text + b" " + flag))
length_offset = length_threshold - base_length
print("base_length: {}".format(base_length))
print("length_threshold: {}".format(length_threshold))
print("length_offset: {}".format(length_offset))
#exit(0)

#flag{70859bc0b71b54b05690b05690b05690b0d}
#flag{70859bc0b71b54b05690b05690b05690b01}
#flag{70859bc0b71b54b05690b05690b05690b02}
#flag{70859bc0b71b54b05690b05690b05690b02}

def calculate_length(N=10000):
    base_length = 0
    max_extension = 0
    for i in range(N):
        prefix = os.urandom(8).hex().encode()
        suffix = os.urandom(8).hex().encode()
        randomflag = os.urandom(18).hex().encode()
        flag = b"flag{" + randomflag + b"}"

        result_flag = prefix + flag + suffix

        base_len = len(gzip.compress(result_flag))
        if base_len > base_length:
            base_length = base_len

        i = len(gzip.compress(result_flag + b" " + randomflag)) - base_len
        if i > max_extension:
            max_extension = i

    return (base_length, max_extension)

# 84, 10
#print(calculate_length())
#exit(0)

RESULTS = []

def recurse(base = "", print2=False):
    if print2:
        print("trying {}".format(base))
    cmprssd = gzip.compress(example_flag_text + b" " + bytes(base, "utf-8"))
    if len(cmprssd) > (length_threshold + 1):
        #print("aborting {}, to long".format(base))
        return None
    elif len(base) == len(flag):
        return base

    alphabet = None

    l = len(base) + 16
    if l < 16:
        alphabet = hex_alphabet
    elif l == 16:
        alphabet = ["f"]
    elif l == 17:
        alphabet = ["l"]
    elif l == 18:
        alphabet = ["a"]
    elif l == 19:
        alphabet = ["g"]
    elif l == 20:
        alphabet = ["{"]
    elif l > 20 and l < (20+36):
        alphabet = hex_alphabet
    elif l == (20+36):
        alphabet = ["}"]
        return base + "}"
    else:
        alphabet = hex_alphabet

    random.shuffle(alphabet)

    if flag.startswith(base.encode()):
        print("alphabet: {}".format(alphabet))

    for element in alphabet:
        result = recurse(base + element, print2=(print2 or (base == "flag{" and element == "7")))
        if result is not None:
            RESULTS.append(result)
            print("FOOOOOOUUUUUUUNNNNNNNNNNNNNNNNNDDDDDDDD: {} {}".format(result, len(RESULTS)))
            if result.encode() == flag:
                time.sleep(10)
        if base == "flag{" and element == "7":
            print("uff")
            time.sleep(10)


recurse("flag{70859bc0b71b54b05690dffe284bff41", print2=True)
# print(RESULTS)
exit(0)

def calculate_alphabet():
    new_alphabet = []
    for element in base_alphabet:
        byte = bytes(element, "utf-8")

        cmprssd = gzip.compress(example_flag_text + byte)
        if len(cmprssd) == len(gzip.compress(example_flag_text)):
            new_alphabet.append(element)

    return new_alphabet

# print(calculate_alphabet())
print("")
exit(0)


#perms = list(map(lambda x: "{}{}{}".format(x[0], x[1], x[2]), permutations(alphabet, 3)))
#elements = [*alphabet, *perms]
#print(elements)

def next_digit_search(prefix = "", search_letters = "".join(base_alphabet)):
    results = []
    for element in search_letters:
        byte = bytes("flag{" + prefix + element, "utf-8")

        cpm = gzip.compress(example_flag_text + b' ' + byte + b' ' + byte + b' ' + byte)
        results.append((len(cpm), element))

    results.sort(key=lambda y: y[0])
    (count, _) = results[0]
    new_letters = list(map(
        lambda a: a[1],
        filter(lambda a: a[0] == count, results)
    ))

    # print(results)
    # print(new_letters)
    return new_letters

print(next_digit_search(""))

exit(0)

print("it starts")
def some_thing():
    work_set = [("", 0, next_digit_search())]  # array of tuples (search_prefix, sub_result_count)
    next_working_set = []

    i = 0
    while True:
        if i >= 15:
            break
        for (search_prefix, search_prefix_count, suitable_next_chars) in work_set:
            next_char_result = []

            for char in suitable_next_chars:
                # print("checking char: {}".format(char))
                result = next_digit_search(search_prefix + char)
                next_char_result.append(
                    (char, len(result), result)
                )

            # sort nex_char_result ascending by the amount of next digit results
            # and filter out those with the highest count
            next_char_result.sort(key=lambda entry: entry[1])
            # print(next_char_result)
            # (_, highest_count, _) = next_char_result[-1]
            filtered_next_char_result = filter(lambda entry: entry[1] != len(base_alphabet), next_char_result)

            for (char, count, result) in filtered_next_char_result:
                # calculate EWMA
                a = 0.4
                new_count = (1-a) * count + a * search_prefix_count

                next_working_set.append(
                    (search_prefix + char, new_count, result)
                )

        work_set = next_working_set
        work_set.sort(key=lambda entry: entry[1])

        next_working_set = []

        filtered = list(map(lambda entry: (entry[0], entry[1]), work_set))

        print("WORKING SET: {}".format(filtered[0: 100]))
        print("\n\n")

        i += 1
        time.sleep(1)

    return None
    prefix = "70"

    new = next_digit_search(prefix)

    print("")
    out = []

    for n in new:
        print("running {}".format(n))
        results = next_digit_search(prefix+n)
        out.append((len(results), n, results))

    out.sort(key=lambda y: y[0])
    (count, zahl, next) = out[0]
    (last, _ ,_) = out[len(out) -1]
    print(out)
    new = list(map(
        lambda a: (a[1], a[2]),
        filter(lambda a: a[0] != last, out)
    ))
    print("")
    print(new)

    print("")
    print("")
    print(next_digit_search("{}".format(zahl), next))


some_thing()

def find_char(text ="", letters = base_alphabet):
    print("lanuched with '{}'".format(text))

    results = []


    for char in letters:
        # print("trying {}".format(char + text))
        #suffix_bytes = bytes(" ".join([(text + char)] * 5), "utf-8")
        suffix_bytes = bytes(char, "utf-8")

        compressed_0 = gzip.compress(example_flag_text + b' ' + suffix_bytes)
        results.append((len(compressed_0), char))

    results.sort(key=lambda a: a[0])

    lowest_non_same = -1
    #for (count, char) in results:
        #if char !=

    (count, _) = results[0]
    print(results)

    new_letters = list(map(lambda a: a[1], filter(lambda a: a[0] <= count, results)))
    print(new_letters)
    # random.shuffle(new_letters)

    if len(text) > 0:
        previous_char = text[0]
        try:
            char_index = new_letters.index(previous_char)
            # above raises a value error if yielding no results

            del new_letters[char_index]
            new_letters.append(previous_char)
        except ValueError:
            pass

    if len(text) >= len(example_flag_text) - 1:
        if text.find("flag{") >= 0:
            return text, new_letters

        return None

    for next_char in new_letters:
        result = find_char(text + next_char)
        # break
        if result is None:
            continue

        return result

    return None


# print("FOUND: {}".format(find_char()))
