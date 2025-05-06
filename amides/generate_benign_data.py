import random
from pathlib import Path

# Token pools to simulate benign sequences
TOKEN_POOL = {
    "drives": ["c", "d", "e"],
    "folders": ["windows", "system32", "programdata", "users", "appdata", "logs", "mozilla", "microsoft", "winlogbeat"],
    "executables": ["exe", "dll", "rundll32", "taskhost", "wininit", "explorer", "smss", "sysmon"],
    "services": ["svchost", "services", "trustedinstaller", "spoolsv"],
    "tools": ["ipconfig", "netsh", "powershell", "notepad", "chrome", "firefox"],
    "flags": ["0x0", "0x1", "autoadminlogon", "off", "on", "true", "false"],
    "misc": ["environment", "logging", "setup", "program", "client", "path", "tmp", "foreground", "reader", "updates"],
}

# Combine all tokens
ALL_TOKENS = sum(TOKEN_POOL.values(), [])

# Output config
TARGET_SAMPLES = 74_000_000
CHUNK_SIZE = 100_000
OUT_PATH = Path("data/benign_dataset.txt")
OUT_PATH.parent.mkdir(exist_ok=True)

def generate_sequence(min_len=5, max_len=20):
    length = random.randint(min_len, max_len)
    return ",".join(random.choices(ALL_TOKENS, k=length))

def generate_dataset():
    with OUT_PATH.open("w") as f:
        for chunk_start in range(0, TARGET_SAMPLES, CHUNK_SIZE):
            lines = [generate_sequence() + "\n" for _ in range(CHUNK_SIZE)]
            f.writelines(lines)
            print(f"[+] Written {chunk_start + CHUNK_SIZE:,} samples...")

    print(f"\n[✓] Dataset of {TARGET_SAMPLES:,} benign samples saved to: {OUT_PATH}")

if __name__ == "__main__":
    generate_dataset()
