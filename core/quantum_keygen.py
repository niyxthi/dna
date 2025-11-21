import hashlib
from typing import List

class QuantumResistantKeyGen:
    """
    DNA-based, PQC-flavoured key schedule.

    Pipeline:
      DNA key (A/C/G/T)
        → DNA->binary mapping (2 bits/base)
        → SHA3-512 base seed (256-bit classical, ~128-bit quantum security)
        → Memory-hard expansion (Argon2-inspired)
        → Lattice-style Z_q mixing for extra diffusion
        → Per-round Feistel keys
    """

    # Tunable parameters (for cost vs speed trade-off)
    MEM_BLOCKS = 512       # number of memory blocks (increase for more hardness)
    BLOCK_SIZE = 32        # bytes per block (SHA3-256 output size)
    MOD_Q = 65537          # modulus for lattice-style integer mixing

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
        # You can add validation if needed
        return ''.join(dna_to_bin[b] for b in dna_key)

    @staticmethod
    def generate_seed_from_dna(dna_key: str) -> bytes:
        """
        Backward-compatible entry point name.

        Internally:
          - DNA -> binary string
          - Context-tagged SHA3-512 over that binary
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
        # Domain separation / context tag to avoid cross-protocol reuse
        hasher.update(b"DNA_FEISTEL_KEY_SCHEDULE_V1")
        hasher.update(bin_str.encode('utf-8'))
        return hasher.digest()  # 64 bytes

    @staticmethod
    def memory_hard_expand(seed: bytes, total_bytes: int) -> bytes:
        """
        Lightweight memory-hard expansion inspired by Argon2:
          - Allocate MEM_BLOCKS of BLOCK_SIZE bytes.
          - Initialize them with chained SHA3-256.
          - Do several mixing passes where each block depends on another,
            selected by its current contents (data-dependent access).
          - Squeeze out 'total_bytes' bytes via further hashing.

        This makes brute-force of the DNA key more expensive (time+memory).
        Deterministic for a given seed.
        """
        blocks = QuantumResistantKeyGen.MEM_BLOCKS
        bsize = QuantumResistantKeyGen.BLOCK_SIZE

        # 1) Initialize memory blocks
        mem = [b'\x00' * bsize for _ in range(blocks)]
        mem[0] = hashlib.sha3_256(seed).digest()
        for i in range(1, blocks):
            h = hashlib.sha3_256()
            h.update(mem[i - 1])
            h.update(seed)
            h.update(i.to_bytes(4, 'big'))
            mem[i] = h.digest()

        # 2) Mixing passes (data-dependent indexing)
        #    Number of passes can be tuned; 2 * blocks is modest but non-trivial.
        for i in range(blocks * 2):
            idx1 = i % blocks
            # derive a second index from the current contents
            idx2 = int.from_bytes(mem[idx1][:2], 'big') % blocks
            h = hashlib.sha3_256()
            h.update(mem[idx1])
            h.update(mem[idx2])
            h.update(i.to_bytes(4, 'big'))
            mem[idx1] = h.digest()

        # 3) Squeeze a stream of bytes from the memory
        out = b""
        ctr = 0
        while len(out) < total_bytes:
            h = hashlib.sha3_256()
            h.update(mem[ctr % blocks])
            h.update(ctr.to_bytes(4, 'big'))
            out += h.digest()
            ctr += 1

        return out[:total_bytes]

    @staticmethod
    def lattice_style_mix(stream: bytes) -> bytes:
        """
        Lattice-inspired diffusion:
          - Interpret stream as 16-bit integers modulo q.
          - For each position i, set:
                m[i] = (2*center + left + right) mod q
            where left/right are neighbours in the ring.
          - Convert back to bytes.

        This is not a full LWE scheme, but gives strong local diffusion
        and a 'Z_q^n' flavour to the key schedule.
        """
        q = QuantumResistantKeyGen.MOD_Q

        # bytes -> list of 16-bit ints
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

        # back to bytes
        out = b''.join(x.to_bytes(2, 'big') for x in mixed)
        return out[:len(stream)]

    # ---------- Public API used by your Feistel cipher ----------

    @staticmethod
    def generate_round_keys(dna_key: str, rounds: int, round_key_size: int) -> List[bytes]:
        """
        Main API used in your cipher.

        Given:
          - dna_key      : string over {A,C,G,T}
          - rounds       : number of Feistel rounds
          - round_key_size : bytes per round key

        Returns:
          List[bytes] of length 'rounds', each one 'round_key_size' bytes.

        Deterministic:
          Same dna_key + same parameters => same key schedule.

        PQC-flavoured:
          - SHA3-512 seed
          - memory-hard expansion
          - lattice-style diffusion
        """
        total_len = rounds * round_key_size

        # 1) Seed from DNA (SHA3-512 over DNA-binary + context)
        base_seed = QuantumResistantKeyGen.base_seed_from_dna(dna_key)

        # 2) Memory-hard expansion to required total length
        expanded = QuantumResistantKeyGen.memory_hard_expand(base_seed, total_len)

        # 3) Lattice-style diffusion for extra mixing
        mixed = QuantumResistantKeyGen.lattice_style_mix(expanded)

        # 4) Slice into per-round keys
        round_keys = [
            mixed[i * round_key_size:(i + 1) * round_key_size]
            for i in range(rounds)
        ]
        
        return round_keys
