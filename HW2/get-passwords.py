# Function to brute-force passwords from 3 files
import hashlib
from generate_combinations import generate_combinations

# Declare file names
FILE1 = "md5_30_passwords-pt1.txt"
FILE2 = "md5_30_passwords-pt2.txt"
FILE3 = "md5_30_passwords-pt3.txt"
files = [FILE1, FILE2, FILE3]

count = 0

# Add all passwords to a dictionary for faster look-up
passwords = {}
hashed_passwords = set()
for filename in files:
    with open(filename, "r") as f:
        for line in f:
            pw = line.strip()
            hashed_passwords.add(pw)

# Loop through each candidate and check for it in candidate passwords
for length in range(3, 6):
    for password in generate_combinations(length):
        hashed_candidate = hashlib.md5(password.encode()).hexdigest()
        if hashed_candidate in hashed_passwords:
            count += 1
            print(f"Found: {hashed_candidate} -> {password} #{count}")
            passwords[hashed_candidate] = password

# Output all found passwords to a file
output_file = "cracked_passwords.txt"

with open(output_file, "w") as f:
    for hash_value, plain_text in passwords.items():
        if plain_text is not None:
            f.write(f"{hash_value} -> {plain_text}\n")
