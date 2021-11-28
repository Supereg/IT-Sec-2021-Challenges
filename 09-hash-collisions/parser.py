import hashlib
import sys

MAGIC = b"!TUMFile"

class FileFormatError(Exception):
    def __init__(self, message):
        self.message = message

def get_itsec_grade(content):
    # Check magic
    if not content.startswith(MAGIC):
        raise FileFormatError("Magic wrong or missing")

    idx = len(MAGIC)

    # Student name is mandatory at file start
    if content[idx] != 1:
        raise FileFormatError("File doesn't start with student name")

    idx += 1
    name_size = content[idx]
    idx += 1
    name = content[idx:idx+name_size]
    print("Reading grades of student", name.decode())
    idx += name_size

    lecture_grades = []

    # Parse grades, skip unknown records for max compability
    while idx < len(content):
        if content[idx] == 1 or content[idx] == 0:
            print(idx, content[idx])
            raise FileFormatError("This record type is not allowed here!")
        elif content[idx] == 2:
            print(f"Grade record at pos {idx}!")
            idx += 1
            # Grade record
            lecture_name_size = content[idx]
            idx += 1
            lecture_name = content[idx:idx+lecture_name_size]
            print(lecture_name)
            idx += lecture_name_size
            grade = content[idx:idx+3]
            print(grade)
            idx += 3

            # Check protection byte
            if content[idx] != 0:
                raise FileFormatError("Grade protection byte incorrect!")
            idx += 1

            lecture_grades.append((lecture_name,grade))
        else:
            idx += 1
            unknown_rec_size = content[idx]
            print(f"Unknown record at pos {idx-1}, {unknown_rec_size} bytes long!")
            idx += unknown_rec_size
    return (name, lecture_grades)

def check_files(filename1, filename2, allow_swap=False):
    with open(filename1, "rb") as f:
        c = f.read()
        hash_a = hashlib.md5(c).digest()
        name_a, grades_a = get_itsec_grade(c)

    with open(filename2, "rb") as f:
        c = f.read()
        hash_b = hashlib.md5(c).digest()
        name_b, grades_b = get_itsec_grade(c)

    print('Hash check:', hash_a == hash_b)
    print('Name check:', name_a == name_b)
    if allow_swap and grades_a[0][1] == b'1.0' and grades_b[0][1] == b'5.0':
        grades_a, grades_b = grades_b, grades_a # If you're not sure which is which, still allow manual verification (app.py does not do this!)
    print('Grade check 5.0:', grades_a == [(b"IT-Sicherheit", b"5.0")])
    print('Grade check 1.0:', grades_b == [(b"IT-Sicherheit", b"1.0")])
    return (hash_a == hash_b and name_a == name_b and
            [(b"IT-Sicherheit", b"5.0")] == grades_a and
            [(b"IT-Sicherheit", b"1.0")] == grades_b)

if __name__ == "__main__":
    # When using this as a command line tool, specify --allow-swap if you're not sure
    # which of the files is the 1.0 and which the 5.0 file.
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('grade-5.0', help='File for grade 5.0')
    parser.add_argument('grade-1.0', help='File for grade 1.0')
    parser.add_argument('--allow-swap', help='Not sure which of the files is which, so swap them around if you got it wrong', action='store_true')
    args = parser.parse_args()
    print('Verdict:', 'OK' if check_files(args['grade-5.0'], args['grade-1.0'], allow_swap=args.allow_swap) else 'Wrong')
