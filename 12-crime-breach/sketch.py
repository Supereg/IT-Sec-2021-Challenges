import gzip
import os
import random
import time
from itertools import permutations

alphabet = "0123456789abcdeflg{}"
alphabet_l = list(alphabet)
random.shuffle(alphabet_l)
alphabet = "".join(alphabet_l)
print(alphabet)

prefix = b'ebb100b259974f49'  # os.urandom(8).hex().encode()
suffix = b'cbbccfe75d9fe449'  # os.urandom(8).hex().encode()
flag = b'flag{70859bc0b71b54b05690dffe284bff415685}'.strip()

example_flag_text = prefix + flag + suffix
print(example_flag_text)

# https://datatracker.ietf.org/doc/html/rfc1951
compressed = gzip.compress(example_flag_text)
print(compressed)
print(len(compressed))
print(len(gzip.compress(example_flag_text + b"")))
print("")


#perms = list(map(lambda x: "{}{}{}".format(x[0], x[1], x[2]), permutations(alphabet, 3)))
#elements = [*alphabet, *perms]
#print(elements)

def next_digit_search(prefix = "", search_letters = alphabet):
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

print(next_digit_search("7085"))

# exit(0)

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
            filtered_next_char_result = filter(lambda entry: entry[1] != len(alphabet), next_char_result)

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

def find_char(text ="", letters = alphabet):
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
