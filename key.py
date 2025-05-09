import json
from multiprocessing import Pool, cpu_count
from random import randint
from pathlib import Path
import time

class ECPoint:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity

    def __eq__(self, other):
        if self.infinity and other.infinity:
            return True
        if self.infinity or other.infinity:
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        return "∞" if self.infinity else f"({hex(self.x)}, {hex(self.y)})"

class Secp256k1:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    G = ECPoint(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )

    @staticmethod
    def point_add(p1, p2):
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1
        if p1.x == p2.x and p1.y != p2.y:
            return ECPoint(None, None, True)
        if p1.x == p2.x:
            if p1.y == 0:
                return ECPoint(None, None, True)
            l = (3 * p1.x * p1.x) * pow(2 * p1.y, -1, Secp256k1.p) % Secp256k1.p
        else:
            l = (p2.y - p1.y) * pow(p2.x - p1.x, -1, Secp256k1.p) % Secp256k1.p
        x3 = (l * l - p1.x - p2.x) % Secp256k1.p
        y3 = (l * (p1.x - x3) - p1.y) % Secp256k1.p
        return ECPoint(x3, y3)

    @staticmethod
    def scalar_mult(k, store_trace=False, known_x_set=None):
        result = ECPoint(None, None, True)
        addend = Secp256k1.G
        bit_index = 0
        trace = []

        while k:
            if store_trace:
                step = {
                    "bit": k & 1,
                    "addend_x": addend.x,
                    "result_x": result.x if not result.infinity else None
                }
                if known_x_set:
                    if addend.x in known_x_set or (not result.infinity and result.x in known_x_set):
                        step["match"] = True
                trace.append(step)

            if k & 1:
                result = Secp256k1.point_add(result, addend)
            addend = Secp256k1.point_add(addend, addend)
            k >>= 1
            bit_index += 1

        return result, trace

# === Load known public x-coordinates (compressed pubkeys)
def load_known_x(filename="allpubs.txt"):
    with open(filename, "r") as f:
        return set(int(line[2:66], 16) for line in f if len(line) > 70)

# === Worker for multiprocessing
def process_private_key(key_and_known):
    priv_key, known_x_set = key_and_known
    pub, trace = Secp256k1.scalar_mult(priv_key, store_trace=True, known_x_set=known_x_set)

    matches = []
    for step in trace:
        if step.get("match"):
            matches.append({
                "priv": priv_key,
                "bit": step["bit"],
                "addend_x": hex(step["addend_x"]),
                "result_x": hex(step["result_x"]) if step["result_x"] else "∞"
            })

    return matches

# === Main function
def run_parallel_trace(num_keys=100, key_bits=64, known_file="allpubs.txt"):
    print(f"🧠 Loading known x-values from: {known_file}")
    known_x = load_known_x(known_file)

    print(f"🔑 Generating {num_keys} random keys of {key_bits} bits...")
    keys = [randint(1, 2**key_bits) for _ in range(num_keys)]

    with Pool(cpu_count()) as pool:
        results = pool.map(process_private_key, [(k, known_x) for k in keys])

    all_matches = [m for sub in results for m in sub]
    print(f"\n✅ Found {len(all_matches)} matches")

    if all_matches:
        with open("matches.txt", "w") as f:
            for match in all_matches:
                f.write(json.dumps(match) + "\n")
        print("📁 Matches saved to matches.txt")

# === Run
if __name__ == "__main__":
    start = time.time()
    run_parallel_trace(num_keys=10000, key_bits=256, known_file="allpubs.txt")
    end = time.time() - start

    print(start)
    print(end)
