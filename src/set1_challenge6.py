from subprocess import check_output as run
from base64 import b64decode

def key_sizes():
    """
        Returns a list of specified key sizes
    """
    start = 2
    end = 40
    return list(range(start, end + 1))

def ascii_to_bytes(text : str):
    return bytearray.fromhex(text.encode('utf-8').hex())

def xor_matching(a : bytes, b : bytes) -> list :
    """
        XORs two sets of bytes with same length
    """
    assert len(a) == len(b)
    return [a[i] ^ b[i] for i, x in enumerate(a)]

def hamming_distance(a : bytes, b : bytes) -> int :
    """
        Computes hamming distance between two input strings
    """
    xor_bytes = xor_matching(a, b)
    binary_bytes_count = [bin(i)[2:].count("1") for i in xor_bytes]
    count = sum(binary_bytes_count)
    return count

def split_chunks(iterable, chunk_size) : 
    """
        Split an iterable in chunks of specified size
    """
    chunks = [
        iterable[i : i + chunk_size]
        for i in range(0, len(iterable), chunk_size)
        if i < len(iterable) - chunk_size
    ]
    
    return chunks

def normalized_hamming_distance(text, key_size):
    assert key_size < len(text) / 2
    bytelist = b64decode(text)
    assert isinstance(bytelist, (bytes, bytearray))
    # break cipher into chunks
    
    chunks = split_chunks(bytelist, key_size)
    blocks = [
        bytelist[0 : key_size],
        bytelist[key_size : key_size * 2]
    ]
    
    hamming_distances = [
        [hamming_distance(block, chunk) for chunk in chunks]
        for block in blocks
    ][0]
    
    mean = sum(hamming_distances) / len(hamming_distances)
    normalized = mean / key_size
    return normalized

def smallest(values):
    sorted_values = sorted(values, key=lambda x : x.get('distance'))
    return sorted_values[0].get('key_size')

def remote():
    url = "https://cryptopals.com/static/challenge-data/6.txt"
    return run(['curl', '--silent', url]).decode('ascii')

def find_key_size(text):
    normalized_hamming_distances = [
        {
            'key_size' : key_size,
            'distance' : normalized_hamming_distance(text, key_size)
        }
        
        for key_size in key_sizes()
    ]
    
    keys = smallest(normalized_hamming_distances)
    return keys

def transpose(text, size):
    bytelist = b64decode(text)
    chunks = split_chunks(bytelist, size)
    transposed = list(zip(*chunks))
    return transposed

def xor_single(bytelist, key):
    return [b ^ key for b in bytelist]

def ascii():
    return [chr(x) for x in range(128)]

def detect_key(strings : list):
    common = list('etaoin shrdlu')
    counts = [
        sum([ string.count(character) for character in common ])
        for string in strings
    ]
    maxium = max(counts)
    index = counts.index(maxium)
    return chr(index)

def find_xor_key(bytelist):
  """For a set of XOR encrypted input bytes, statistically determine the single most likely key."""
  xor_bytes = [xor_single(bytelist, ord(character)) for character in ascii()]
  xor_strings = [''.join(list(map(chr, integer))) for integer in xor_bytes]
  key = detect_key(xor_strings)
  return key

def find_vignere_key(text):
  """Statistically determine the Vignere cipher key that was used to XOR encrypt an input text."""
  key_size = find_key_size(text)
  transposed_bytes = transpose(text, key_size)
  vignere_key = ''.join([find_xor_key(x) for x in transposed_bytes])
  return vignere_key

def decrypt_vignere(ciphertext, key):
  """Given a ciphertext and a key as input, decrypt with a Vignere cipher."""
  bytes_text = b64decode(ciphertext)
  bytes_key = ascii_to_bytes(key)
  decrypted_bytes = [b ^ bytes_key[i % len(bytes_key)] for i, b in enumerate(bytes_text)]
  decrypted_characters = [chr(b) for b in decrypted_bytes]
  decrypted_text = ''.join(decrypted_characters)
  return decrypted_text

def test():
  """Test challenge 6."""
  print('Challenge 6')
  ciphertext = remote()
  key = find_vignere_key(ciphertext)
  assert key == 'Terminator X: Bring the noise', 'incorrect key'
  message = decrypt_vignere(ciphertext, key)
  print(key)
  print(message)
  return (key, message)

test()