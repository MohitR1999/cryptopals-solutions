from sys import stdin
from CryptoTools.tools import xor_bruteforce_guesser

max_score = -1
max_map = {}

for line in stdin:
    line = line.strip()
    str_map = xor_bruteforce_guesser(line)
    if (str_map['score'] > max_score):
        max_score = str_map['score']
        max_map = str_map
        
print(max_map['decrypted_string'])