BASE64_TABLE = {
        '000000' :	'A',  '010000' : 'Q' ,	'100000' :	'g' ,	'110000' : 	'w',
        '000001' :	'B',  '010001' : 'R' ,	'100001' :	'h' ,	'110001' : 	'x',
        '000010' :	'C',  '010010' : 'S' ,	'100010' :	'i' ,	'110010' : 	'y',
        '000011' :	'D',  '010011' : 'T' ,	'100011' :	'j' ,	'110011' : 	'z',
        '000100' :	'E',  '010100' : 'U' ,	'100100' :	'k' ,	'110100' : 	'0',
        '000101' :	'F',  '010101' : 'V' ,	'100101' :	'l' ,	'110101' : 	'1',
        '000110' :	'G',  '010110' : 'W' ,	'100110' :	'm' ,	'110110' : 	'2',
        '000111' :	'H',  '010111' : 'X' ,	'100111' :	'n' ,	'110111' : 	'3',
        '001000' :	'I',  '011000' : 'Y' ,	'101000' :	'o' ,	'111000' : 	'4',
        '001001' :	'J',  '011001' : 'Z' ,	'101001' :	'p' ,	'111001' : 	'5',
        '001010' :	'K',  '011010' : 'a' ,	'101010' :	'q' ,	'111010' : 	'6',
        '001011' :	'L',  '011011' : 'b' ,	'101011' :	'r' ,	'111011' : 	'7',
        '001100' :	'M',  '011100' : 'c' ,	'101100' :	's' ,	'111100' : 	'8',
        '001101' :	'N',  '011101' : 'd' ,	'101101' :	't' ,	'111101' : 	'9',
        '001110' :	'O',  '011110' : 'e' ,	'101110' :	'u' ,	'111110' : 	'+',
        '001111' :	'P',  '011111' : 'f' ,	'101111' :	'v' ,	'111111' : 	'/',
}

REVERSE_BASE64_TABLE = {
    'A' : '000000',  'Q' : '010000', 'g' : '100000', 'w': '110000',
    'B' : '000001',  'R' : '010001', 'h' : '100001', 'x': '110001',
    'C' : '000010',  'S' : '010010', 'i' : '100010', 'y': '110010',
    'D' : '000011',  'T' : '010011', 'j' : '100011', 'z': '110011',
    'E' : '000100',  'U' : '010100', 'k' : '100100', '0': '110100',
    'F' : '000101',  'V' : '010101', 'l' : '100101', '1': '110101',
    'G' : '000110',  'W' : '010110', 'm' : '100110', '2': '110110',
    'H' : '000111',  'X' : '010111', 'n' : '100111', '3': '110111',
    'I' : '001000',  'Y' : '011000', 'o' : '101000', '4': '111000',
    'J' : '001001',  'Z' : '011001', 'p' : '101001', '5': '111001',
    'K' : '001010',  'a' : '011010', 'q' : '101010', '6': '111010',
    'L' : '001011',  'b' : '011011', 'r' : '101011', '7': '111011',
    'M' : '001100',  'c' : '011100', 's' : '101100', '8': '111100',
    'N' : '001101',  'd' : '011101', 't' : '101101', '9': '111101',
    'O' : '001110',  'e' : '011110', 'u' : '101110', '+': '111110',
    'P' : '001111',  'f' : '011111', 'v' : '101111', '/': '111111',
}

CHAR_LIST = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
]

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

def hexToBase64Encode(input_string):
    """
        Encodes an input string (already in hex) to Base64 format
    """
    processed_str = ""
    encoded_str = ""
    for character in input_string:
        processed_str += str(bin(int(character, 16)))[2:].zfill(4)
    
    index = 0
    while (index < len(processed_str)):
        binary = processed_str[index : index + 6]
        binary_val = binary + ((6 - (len(binary) % 6)) % 6) * '0'
        encoded_str += BASE64_TABLE[binary_val]
        index += 6
    
    return encoded_str

def base64ToHexDecode(encoded_string : str) -> bytes:
    """
        Decodes an input string to bytes array
    """
    processed_str = ""
    for ch in encoded_string:
        if (ch != '='):
            processed_str += REVERSE_BASE64_TABLE[ch]
    
    hex_str = ""
    index = 0
    while (index < len(processed_str)):
        binary = processed_str[index : index + 4]
        hex_str += str(hex(int(binary, 2)))[2:]
        index += 4
    
    return hex_str.encode()
    
def get_string_score(string : str) -> int:
    total_score = 0
    for byte in string:
        total_score += CHARACTER_FREQ.get(chr(byte).lower(), 0)
    
    return total_score
    

def decryptor(encrypted_string : str, key : int) -> str :
    output_string = b""
    for char in encrypted_string :
        output_string += bytes([char ^ key])
    return output_string

def xor_bruteforce_guesser(encrypted_hex_string : str, guess_list : list = CHAR_LIST) -> dict:
    cipher = bytes.fromhex(encrypted_hex_string)
    guesses = []
    for key in range(256):
        guesses.append({
                'guess' : decryptor(cipher, key),
                'key' : key
        })
        
    guess_scores = {}
    for guess_obj in guesses:
        score = get_string_score(guess_obj['guess'])
        guess_scores[guess_obj['guess']] = {
            'guess' : guess_obj['guess'],
            'score' : score,
            'key' : guess_obj['key']
        }
        
    decrypted_string = ""
    max_score = -1
    encryption_key = ""
    
    for guess_obj in guess_scores.values():
        if (guess_obj['score'] > max_score):
            max_score = guess_obj['score']
            decrypted_string = guess_obj['guess']
            encryption_key = guess_obj['key']
            
    return {
        'encrypted_string' : encrypted_hex_string,
        'decrypted_string' : decrypted_string,
        'score' : max_score,
        'encryption_key' : encryption_key
    }

def encrypt_repeating_key_xor(plaintext: str, key: str) -> str:
    bytes_string = bytes(plaintext, 'utf-8')
    bytes_key = bytes(key, 'utf-8')
    
    while(len(bytes_key) < len(bytes_string)):
        bytes_key += bytes_key
    
    bytes_key = bytes_key[0:len(bytes_string)]
    encrypted_key = b''
    
    for i in range(len(bytes_string)):
        plain_byte = bytes_string[i]
        key_byte = bytes_key[i]
        encrypted_key += bytes([plain_byte ^ key_byte])
        
    return encrypted_key.hex()

def get_hamming_distance(string1 : bytes, string2 : bytes):
    distance = 0
    if (len(string1) != len(string2)) :
        return -1
    
    for i in range(len(string1)):
        distance += bin(int.from_bytes(bytes([string1[i] ^ string2[i]]))).count("1")
    
    return distance