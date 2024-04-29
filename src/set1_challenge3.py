from CryptoTools.tools import xor_bruteforce_guesser
inp = input()
decrypted_string_map = xor_bruteforce_guesser(inp)
print(decrypted_string_map['decrypted_string'].decode('utf-8'))