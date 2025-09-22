import hashlib
from generate_combinations import generate_combinations
from multiprocessing import Pool, cpu_count
import time

FILES = [
    "md5_30_passwords-pt1.txt",
    "md5_30_passwords-pt2.txt",
    "md5_30_passwords-pt3.txt"
]

def check_password(args):
    password, target_hashes = args
    hashed_candidate = hashlib.md5(password.encode()).hexdigest()
    if hashed_candidate in target_hashes:
        return (hashed_candidate, password)
    return None

if __name__ == "__main__":
    start_time = time.time()

    # Read all target hashes
    hashed_passwords = set()
    for filename in FILES:
        with open(filename, "r") as f:
            for line in f:
                hashed_passwords.add(line.strip())

    cracked_passwords = {}

    # Prepare generator of argument tuples
    def candidate_args(length, target_hashes):
        for pw in generate_combinations(length):
            yield (pw, target_hashes)

    for length in range(3,6):
        with Pool(cpu_count()) as pool:
            for result in pool.imap_unordered(check_password, candidate_args(length, hashed_passwords), chunksize=1000):
                if result:
                    h, pw = result
                    cracked_passwords[h] = pw
                    print(f"Found: {h} -> {pw}")

    # Save results
    with open("cracked_passwords.txt", "w") as f:
        for h, pw in cracked_passwords.items():
            f.write(f"{h} -> {pw}\n")

    # End timer and print elapsed time
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"\nTotal time elapsed: {elapsed:.2f} seconds")