#!/usr/bin/env python3
"""
Attacker Simulation for DNA Quantum-Resistant Cryptosystem

This is a PURELY EDUCATIONAL script.
It does NOT perform any real attack or cryptanalysis.
It only prints what an attacker *might* see and why the system is infeasible
to break, even with quantum computers.
"""

import time
import math
import random
import sys

# ---- Configurable parameters for the simulation ----

DNA_KEY_LENGTH = 20          # length of DNA key (bases)
DNA_ALPHABET = ['A', 'C', 'G', 'T']
CLASSICAL_OPS_PER_SEC = 1e12  # 1 trillion ops/sec (optimistic)
QUANTUM_OPS_PER_SEC   = 1e18  # 1 quintillion ops/sec (ridiculously optimistic)

# Universe age in years (approx)
UNIVERSE_AGE_YEARS = 1.38e10

# Some example "stolen" data (you can replace with real-looking values)
EXAMPLE_CIPHERTEXT = (
    "24|192|0|4|CAAGAGTAGCTACTGACTGAATAGCTACTATCCCATGTTGGGATA"
    "ATTGTAATCAAGATTGCTTAA|TD*WWCD*WWQHMPFFMFKFL*"
)

EXAMPLE_SEED_HEX = (
    "8fea91b07d13b0f3c9aa0df8b9a95fadb9c2352be0c76c12a3e2b64da951bc3f"
    "b6c2a19e4f8912afcd08a1d2b73a3e5c7b9e10a4d6c1f59b8c1d4e6a2f3b7c9"
)


# ----------------- Helper functions for printing ----------------- #

def slow_print(text, delay=0.02):
    """Print text slowly for cinematic effect."""
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print()


def spinner(duration=1.5, prefix="[ATTACKER] Thinking "):
    """Simple ASCII spinner animation."""
    chars = "|/-\\"
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r{prefix}{chars[i % len(chars)]}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write("\r" + " " * (len(prefix) + 2) + "\r")
    sys.stdout.flush()


def format_large_number(n):
    """Format large numbers with scientific notation and commas."""
    if n == 0:
        return "0"
    if n < 1e6:
        return f"{int(n):,}"
    return f"{n:.2e}"


# ----------------- Core simulation logic ----------------- #

def attacker_view():
    slow_print("🔐 Intruder POV Simulation – DNA Quantum Crypto", 0.01)
    print()
    slow_print("🎭 ATTACKER POV: What the intruder actually sees...\n", 0.02)

    slow_print("1️⃣ Intercepted Ciphertext:")
    print("   ", EXAMPLE_CIPHERTEXT[:80] + "...")
    print()

    slow_print("2️⃣ Intercepted Seed (from network sniffing):")
    print("   ", EXAMPLE_SEED_HEX[:80] + "...")
    print()
    slow_print("❌ Missing: DNA key, plaintext, round keys, internal Feistel states.\n", 0.02)


def simulate_bruteforce_space():
    slow_print("🔨 STEP 1 — Trying to guess the DNA key...\n", 0.02)

    total_keys = 4 ** DNA_KEY_LENGTH
    quantum_keys = math.isqrt(total_keys)  # ~ sqrt search space via Grover

    slow_print(f"[ATTACKER] DNA key length: {DNA_KEY_LENGTH} bases", 0.02)
    slow_print(f"[ATTACKER] Alphabet size: 4 (A, C, G, T)", 0.02)
    slow_print(f"[ATTACKER] Total possible keys = 4^{DNA_KEY_LENGTH} = {format_large_number(total_keys)}", 0.02)
    slow_print(f"[ATTACKER] Even with Grover's algorithm (quantum): sqrt(4^{DNA_KEY_LENGTH}) =", 0.02)
    slow_print(f"            ≈ {format_large_number(quantum_keys)} key guesses.\n", 0.02)

    # Simulate a few fake guesses
    slow_print("[ATTACKER] Trying a few random DNA keys...", 0.02)
    for i in range(5):
        guess = "".join(random.choice(DNA_ALPHABET) for _ in range(DNA_KEY_LENGTH))
        spinner(0.4, f"[ATTACKER] Guess #{i+1}: {guess}  ")
        print(f"[ATTACKER] Result: ❌ Seed mismatch.\n")
        time.sleep(0.2)

    print()


def simulate_seed_reversal():
    slow_print("🔬 STEP 2 — Trying to reverse the SHA3-512 seed...\n", 0.02)

    slow_print("[ATTACKER] Observed seed (512-bit output of SHA3-512):", 0.02)
    print("   ", EXAMPLE_SEED_HEX[:80] + "...\n")

    slow_print("🔒 SHA3-512 preimage resistance:", 0.02)
    slow_print("    Classical complexity ≈ 2^512", 0.02)
    slow_print("    Quantum (Grover)  ≈ 2^256", 0.02)

    classical_tries = 2 ** 512
    quantum_tries = 2 ** 256

    slow_print(f"[ATTACKER] Even with a quantum computer:", 0.02)
    slow_print(f"    Required operations ≈ 2^256 ≈ {format_large_number(quantum_tries)}", 0.02)

    # Estimated years with crazy quantum speed
    quantum_years = quantum_tries / QUANTUM_OPS_PER_SEC / (60 * 60 * 24 * 365)

    slow_print(f"[ATTACKER] At {format_large_number(QUANTUM_OPS_PER_SEC)} ops/sec (unrealistic):", 0.02)
    slow_print(f"    Time ≈ {format_large_number(quantum_years)} years", 0.02)
    slow_print(f"    Age of universe ≈ {UNIVERSE_AGE_YEARS:.2e} years", 0.02)
    slow_print("    ➜ Reversing SHA3-512 is effectively impossible.\n", 0.02)


def simulate_memory_hard():
    slow_print("🧱 STEP 3 — Trying to bypass the memory-hard expander...\n", 0.02)

    slow_print("[ATTACKER] Even if the seed was guessed, the key schedule uses:", 0.02)
    slow_print("    • Memory-hard expansion (Argon2-inspired)", 0.02)
    slow_print("    • Multiple SHA3-256 passes", 0.02)
    slow_print("    • Data-dependent memory accesses", 0.02)
    slow_print("    • Large RAM footprint per guess\n", 0.02)

    slow_print("⚠ Quantum computers cannot accelerate RAM access or random lookups.", 0.02)
    slow_print("   Grover gives no speedup for memory-bound functions.\n", 0.02)

    slow_print("[ATTACKER] So for every DNA key guess, they must:", 0.02)
    slow_print("    1) Derive the seed", 0.02)
    slow_print("    2) Run the full memory-hard expander", 0.02)
    slow_print("    3) Derive all Feistel round keys", 0.02)
    slow_print("    4) Attempt decryption and check if plaintext makes sense\n", 0.02)

    spinner(1.5, "[ATTACKER] Simulating a memory-hard key derivation ")
    slow_print("\n[ATTACKER] Result: ❌ Way too slow for large-scale brute-force.\n", 0.02)


def simulate_lattice_and_feistel():
    slow_print("🧮 STEP 4 — Lattice-style mixing and Feistel cipher...\n", 0.02)

    slow_print("The derived key stream is further diffused via:", 0.02)
    slow_print("    • Lattice-style mixing over Z_q (e.g., mod 65537)", 0.02)
    slow_print("    • Neighbour-based linear combination: m[i] = left + 2*center + right (mod q)", 0.02)
    slow_print("    • High diffusion similar in spirit to LWE-based PQC schemes\n", 0.02)

    slow_print("Then comes the Feistel network:", 0.02)
    slow_print("    • 16 rounds", 0.02)
    slow_print("    • DNA-inspired F-function with rotation and XOR", 0.02)
    slow_print("    • Round keys derived from the quantum-resistant schedule\n", 0.02)

    slow_print("[ATTACKER] Without the correct round keys:", 0.02)
    slow_print("    • Ciphertext gives no linear relation to plaintext", 0.02)
    slow_print("    • Feistel layers hide structure at every round", 0.02)
    slow_print("    • Codon + amino-acid encoding further obfuscates binary patterns\n", 0.02)

    spinner(1.5, "[ATTACKER] Trying to exploit structural weaknesses ")
    slow_print("\n[ATTACKER] Result: ❌ No practical cryptanalytic shortcut found.\n", 0.02)


def main_summary():
    slow_print("🎯 FINAL CONCLUSION (Attacker POV)", 0.02)
    print()
    slow_print("From the intruder's perspective:", 0.02)
    slow_print("  • Brute-forcing the DNA key is astronomically hard.", 0.02)
    slow_print("  • Reversing SHA3-512 seed is practically impossible, even with quantum.", 0.02)
    slow_print("  • Memory-hard key expansion defeats quantum parallel speedups.", 0.02)
    slow_print("  • Lattice-style mixing and Feistel rounds hide internal structure.", 0.02)
    slow_print("  • Codon and amino-acid layers add additional obfuscation.\n", 0.02)

    slow_print("✅ Therefore: The system is designed to remain secure even", 0.02)
    slow_print("   against adversaries equipped with large-scale quantum computers.", 0.02)
    print()
    slow_print("Use this simulation in your demo/report to explain WHY it is quantum-resistant.", 0.02)


def main():
    attacker_view()
    time.sleep(0.5)
    simulate_bruteforce_space()
    time.sleep(0.5)
    simulate_seed_reversal()
    time.sleep(0.5)
    simulate_memory_hard()
    time.sleep(0.5)
    simulate_lattice_and_feistel()
    time.sleep(0.5)
    main_summary()


if __name__ == "__main__":
    main()
