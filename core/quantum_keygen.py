import hashlib
from typing import List

DEBUG_MODE = True


class QuantumResistantKeyGen:
    """
    DNA-based, PQC-flavoured key schedule.

    Pipeline:
      DNA key (A/C/G/T)
        → DNA->binary mapping (2 bits/base)
        → SHA3-512 base seed
        → Memory-hard expansion (Argon2-inspired)
        → Lattice-style Z_q mixing
        → Per-round Feistel keys
    """

    MEM_BLOCKS = 512       # number of memory blocks
    BLOCK_SIZE = 32        # bytes per block (SHA3-256 output)
    MOD_Q = 65537          # modulus for lattice-style mixing

    # ---------- Low-level helpers ----------

    @staticmethod
    def dna_to_binary(dna_key: str) -> str:
        """
        Map DNA string (A/C/G/T) to a binary string using 2 bits per base.
        A->00, C->01, G->10, T->11
        """
        dna_to_bin = {
            'A': '00',
            'C': '01',
            'G': '10',
            'T': '11'
        }
        return ''.join(dna_to_bin[b] for b in dna_key)

    @staticmethod
    def generate_seed_from_dna(dna_key: str) -> bytes:
        """
        Backward-compatible API name.
        Internally calls base_seed_from_dna.
        """
        return QuantumResistantKeyGen.base_seed_from_dna(dna_key)

    @staticmethod
    def base_seed_from_dna(dna_key: str) -> bytes:
        """
        Combine DNA-derived binary with a fixed context string and hash
        with SHA3-512 to produce a strong base seed (64 bytes).
        Deterministic: same DNA key => same seed.
        """
        bin_str = QuantumResistantKeyGen.dna_to_binary(dna_key)

        hasher = hashlib.sha3_512()
        hasher.update(b"DNA_FEISTEL_KEY_SCHEDULE_V1")
        hasher.update(bin_str.encode('utf-8'))
        seed = hasher.digest()

        if DEBUG_MODE:
            print("\n[KEYGEN] === DNA → Seed ===")
            print("[KEYGEN] DNA key:", dna_key)
            print("[KEYGEN] DNA→bin (first 64 bits):",
                  bin_str[:64] + ("..." if len(bin_str) > 64 else ""))
            print("[KEYGEN] SHA3-512 seed (64B, first 64 hex):",
                  seed.hex()[:64], "...")

        return seed

    @staticmethod
    def memory_hard_expand(seed: bytes, total_bytes: int) -> bytes:
        """
        Lightweight memory-hard expansion inspired by Argon2.
        """
        blocks = QuantumResistantKeyGen.MEM_BLOCKS
        bsize = QuantumResistantKeyGen.BLOCK_SIZE

        mem = [b'\x00' * bsize for _ in range(blocks)]
        mem[0] = hashlib.sha3_256(seed).digest()
        for i in range(1, blocks):
            h = hashlib.sha3_256()
            h.update(mem[i - 1])
            h.update(seed)
            h.update(i.to_bytes(4, 'big'))
            mem[i] = h.digest()

        # Mixing passes
        for i in range(blocks * 2):
            idx1 = i % blocks
            idx2 = int.from_bytes(mem[idx1][:2], 'big') % blocks
            h = hashlib.sha3_256()
            h.update(mem[idx1])
            h.update(mem[idx2])
            h.update(i.to_bytes(4, 'big'))
            mem[idx1] = h.digest()

        # Squeeze bytes
        out = b""
        ctr = 0
        while len(out) < total_bytes:
            h = hashlib.sha3_256()
            h.update(mem[ctr % blocks])
            h.update(ctr.to_bytes(4, 'big'))
            out += h.digest()
            ctr += 1

        expanded = out[:total_bytes]

        if DEBUG_MODE:
            print("\n[KEYGEN] === Memory-hard Expansion ===")
            print(f"[KEYGEN] Requested bytes: {total_bytes}")
            print("[KEYGEN] Expanded stream (first 64B):", expanded[:64].hex(), "...")

        return expanded

    @staticmethod
    def lattice_style_mix(stream: bytes) -> bytes:
        """
        Lattice-inspired diffusion over Z_q.
        """
        q = QuantumResistantKeyGen.MOD_Q

        ints = []
        for i in range(0, len(stream), 2):
            if i + 1 < len(stream):
                val = int.from_bytes(stream[i:i+2], 'big')
            else:
                val = stream[i] << 8
            ints.append(val % q)

        n = len(ints)
        mixed = []
        for i in range(n):
            left = ints[(i - 1) % n]
            center = ints[i]
            right = ints[(i + 1) % n]
            m = (2 * center + left + right) % q
            mixed.append(m)

        out = b''.join(x.to_bytes(2, 'big') for x in mixed)
        out = out[:len(stream)]

        if DEBUG_MODE:
            print("\n[KEYGEN] === Lattice-style Mixing ===")
            print("[KEYGEN] Mixed stream (first 64B):", out[:64].hex(), "...")

        return out

    @staticmethod
    def generate_round_keys(dna_key: str, rounds: int, round_key_size: int) -> List[bytes]:
        base_seed = QuantumResistantKeyGen.base_seed_from_dna(dna_key)
        return QuantumResistantKeyGen.generate_round_keys_from_seed(base_seed, rounds, round_key_size)

    @staticmethod
    def generate_round_keys_from_seed(seed: bytes, rounds: int, round_key_size: int) -> List[bytes]:
        """
        Same pipeline as generate_round_keys, but starts from a seed directly.
        This is used on the SERVER side, which never sees the DNA key, only the seed.
        """
        total_len = rounds * round_key_size

        if DEBUG_MODE:
            print("\n[KEYGEN] === Seed → Round Keys (Server side) ===")
            print("[KEYGEN] Input seed (first 64 hex):", seed.hex()[:64], "...")

        expanded = QuantumResistantKeyGen.memory_hard_expand(seed, total_len)
        mixed = QuantumResistantKeyGen.lattice_style_mix(expanded)

        round_keys = [
            mixed[i * round_key_size:(i + 1) * round_key_size]
            for i in range(rounds)
        ]

        if DEBUG_MODE:
            print("\n[KEYGEN] === Final Round Keys (from seed) ===")
            for i, rk in enumerate(round_keys[:min(4, rounds)]):
                print(f"[KEYGEN] Round {i} key (first 32 hex): {rk.hex()[:32]}...")

        return round_keys
