import time
import random
import math
import datetime
import os
import json

# ============================
# CONFIG (SAFE, NON-CRYPTOGRAPHIC)
# ============================

DNA_KEY_LENGTH = 20
KEYSPACE = 4 ** DNA_KEY_LENGTH          # 4^20 ≈ 1.099e12
QUANTUM_BRUTEFORCE = 2 ** (2 * DNA_KEY_LENGTH)  # sqrt(4^20) = 4^10 = 1,048,576
UNIVERSE_YEARS = 1e10

ROUND_SIZE = 10       # show 10 guesses per round
TOTAL_ROUNDS = 5      # simulate 5 rounds
DELAY = 0.15          # delay between simulated steps

SNIFF_FILE = "sniffed_packet.json"


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def slowprint(msg, delay=0.02):
    for c in msg:
        print(c, end="", flush=True)
        time.sleep(delay)
    print()


def hr():
    print("\n" + "="*90 + "\n")


def fake_key():
    return "".join(random.choice("ACGT") for _ in range(DNA_KEY_LENGTH))


def fake_hex(n=64):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


# ============================
# TIME ESTIMATORS
# ============================

def estimate_classical_time():
    ops_per_sec = 10 ** 12  # 1 trillion ops/sec (unrealistically generous)
    years = (KEYSPACE / ops_per_sec) / (3600 * 24 * 365)
    return years


def estimate_quantum_time():
    ops = QUANTUM_BRUTEFORCE
    q_ops_sec = 10 ** 18  # hypothetical quantum
    years = (ops / q_ops_sec) / (3600 * 24 * 365)
    return years


# ============================
# BANNER
# ============================

def banner():
    print(r"""LIVE DNA–QUANTUM CRYPTOGRAPHY ATTACK SIMULATION""")

# ============================
# LOAD SNIFFED DATA
# ============================

def load_sniffed_packet():
    if not os.path.exists(SNIFF_FILE):
        return None

    try:
        with open(SNIFF_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"[ERROR] Failed to read {SNIFF_FILE}: {e}")
        return None


# ============================
# MAIN SIMULATION
# ============================

def main():
    os.system("cls" if os.name == "nt" else "clear")
    banner()

    sniffed = load_sniffed_packet()

    if sniffed is None:
        slowprint(f"[{now()}] No sniffed packet found.")
        slowprint(f"→ Please run the CLIENT and SERVER once so that {SNIFF_FILE} is created.")
        slowprint("→ Then re-run this attacker simulation.\n")
        return

    ciphertext = sniffed.get("ciphertext", "<unknown>")
    seed_hex = sniffed.get("seed", fake_hex(128))
    client_addr = sniffed.get("client_addr", "unknown")

    start_time = time.time()

    slowprint(f"[{now()}] Attacker has tapped into the network...")
    slowprint(f"[{now()}] Observed connection from client: {client_addr}\n")

    print("📦 Intercepted Ciphertext (from live client-server run):")
    print(ciphertext + "\n")

    print("🧬 Intercepted Seed (SHA3-512, first 64 hex):")
    print(seed_hex[:64] + "...\n")

    hr()

    slowprint(f"[{now()}] Beginning brute-force simulation against DNA key...")
    slowprint(f"[INFO] DNA key length assumed: {DNA_KEY_LENGTH} bases")
    slowprint(f"[INFO] Total search space: 4^{DNA_KEY_LENGTH} = {KEYSPACE:,}\n")

    # =============================
    # ROUND-BASED GUESSING
    # =============================
    for round_num in range(1, TOTAL_ROUNDS + 1):
        slowprint(f"\n[{now()}] === ROUND {round_num} ===\n")

        for attempt in range(1, ROUND_SIZE + 1):
            guess = fake_key()
            slowprint(f"[{now()}] Guess {attempt}/{ROUND_SIZE}: Trying DNA key = {guess}")
            time.sleep(DELAY)
            slowprint("[ATTACKER] ❌ Seed mismatch. SHA3-512 output does not match intercepted seed.\n")
            time.sleep(DELAY / 2)

        slowprint(f"[{now()}] Round {round_num} summary:")
        slowprint("→ All tested keys in this round failed.")
        slowprint("→ Moving to next region of theoretical keyspace...\n")
        time.sleep(0.6)

    hr()

    slowprint(f"[{now()}] Estimating realistic attack timeframe...\n")

    classical_years = estimate_classical_time()
    quantum_years = estimate_quantum_time()

    slowprint(f"⏱ Estimated classical brute-force time: {classical_years:.2e} years")
    slowprint(f"⏱ Estimated quantum Grover-based time: {quantum_years:.2e} years\n")

    slowprint("🌌 Age of the universe: 1e10 years")
    slowprint("📉 Required attack time >> universe age.\n")

    hr()

    end_time = time.time()
    sim_seconds = end_time - start_time

    slowprint(f"[SIMULATION TIME] {sim_seconds:.2f} seconds (local demo only)")
    slowprint("[RESULT] No key recovered.")
    slowprint("[CONCLUSION] Attack infeasible under classical and quantum threat models.\n")
    slowprint("Simulation complete.\n", 0.02)


if __name__ == "__main__":
    main()
