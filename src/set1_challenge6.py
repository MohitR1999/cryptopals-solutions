from CryptoTools.tools import get_hamming_distance

str1 = "this is a test"
str2 = "wokka wokka!!!"

b1 = bytes(str1, 'utf-8')
b2 = bytes(str2, 'utf-8')

hamming_distance = get_hamming_distance(b1, b2)
print(hamming_distance)