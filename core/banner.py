import sys
import time
import random

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
