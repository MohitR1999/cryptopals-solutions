from sys import stdin
from CryptoTools.tools import encrypt_repeating_key_xor

plaintext = ""
for line in stdin:
    plaintext += line

encrypted_text = encrypt_repeating_key_xor(plaintext, "ICE")
print(encrypted_text)
print(encrypted_text == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
