#!/usr/bin/env python3

import random
import time

from string import ascii_letters, digits

# colors
GREEN, RESET = "\033[32m", "\033[0m"


def get_chars(i: int) -> str:

    chars = random.sample(ascii_letters + digits, k=i)
    return " ".join(chars).upper()


def shuffle(line: str, name_length: int):

    for _ in range(0, random.randint(4, 8)):
        print(f"\t{get_chars(name_length)}", end="\r")
        time.sleep(0.09)

    print(f"\t{line}")


def print_banner(version, name="Karma", author="decoxviii"):

    # name legnth + four chars
    name_length = len(name) + 4
    # space between letters
    name = " ".join(name.upper())
    name = f"{get_chars(2)}{GREEN} {name} {RESET}{get_chars(2)}"

    print("\n")

    lines = [get_chars(name_length), name, get_chars(name_length)]
    for line in lines:
        shuffle(line, name_length)

    print(f"""
        {author}
        {version}
    """)
