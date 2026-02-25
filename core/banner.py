import sys
import time
import random
import os

GREEN = "\033[92m"
RESET = "\033[0m"

def _type_effect(text: str, delay: float = 0.002):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)

def _glitch(text: str, prob: float = 0.02):
    out = []
    for c in text:
        if random.random() < prob and c.strip():
            out.append(random.choice("!@#$%^&*"))
        else:
            out.append(c)
    return "".join(out)

def print_alex_banner():
    if os.getenv("VANTA_MATRIX_RAIN") == "1":
        _matrix_rain()
    art = [
        "    ██████  ██       ███████ ██  ██ ",
        "    ██   ██ ██       ██      ██  ██ ",
        "    ██████  ██       █████   ██████ ",
        "    ██   ██ ██       ██          ██ ",
        "    ██   ██ ███████  ███████     ██ ",
        "                 A L E X            ",
    ]
    print(GREEN)
    for line in art:
        _type_effect(_glitch(line) + "\n", 0.003)
    print(RESET)

def _matrix_rain():
    g = "\033[32m"
    r = "\033[0m"
    width = 64
    rows = 10
    frames = 15
    print(g)
    for _ in range(frames):
        for _ in range(rows):
            sys.stdout.write("".join(random.choice("01") for _ in range(width)) + "\n")
        sys.stdout.flush()
        time.sleep(0.03)
    print(r)
