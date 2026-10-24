import des_tables as t

# Test data (hexadecimal)

message = "0011223344556677"
cle = "0123456789ABCDEF"
ciphertext_reference = "CADB6782EE2B4823"

# Convert the hex strings into lists of 64 bits.
message_test = [int(b) for b in format(int(message, 16), '064b')]
cle_test = [int(b) for b in format(int(cle, 16), '064b')]

ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
S_BOXES = [t.S_1, t.S_2, t.S_3, t.S_4, t.S_5, t.S_6, t.S_7, t.S_8]

# FUNCTIONS

def permute(bits, table):
    return [bits[i - 1] for i in table]


def xor_bits(a, b):
    return [x ^ y for x, y in zip(a, b)]


def bits_to_hex(bits):
    return format(int("".join(str(x) for x in bits), 2), f'0{len(bits) // 4}X')


# Key schedule (generation of the 16 subkeys)


def rotate_left(bits, n):
    return bits[n:] + bits[:n]


def generate_halves(half):
    """Take one 28-bit key half (C0 or D0) and return its 16 states [C1, ..., C16].

    Shifts are cumulative: each state is the shift of the PREVIOUS one.
    """
    states = []
    current = half
    for shift in ROTATIONS:
        current = rotate_left(current, shift)
        states.append(current)
    return states


def generate_subkeys(lk, rk):
    """Build the 16 subkeys of 48 bits"""
    c_states = generate_halves(lk)
    d_states = generate_halves(rk)
    return [permute(c + d, t.PC_2) for c, d in zip(c_states, d_states)]


# Cipher function f


def expansion(right_half):
    """Expansion E: 32 -> 48 bits"""
    return permute(right_half, t.E)


def sbox_substitution(bits48):
    """Pass 48 bits through the 8 S-boxes -> 32 bits"""
    result = []
    for j in range(8):
        block = bits48[6 * j : 6 * j + 6]          # j-th 6 bit block

        # Binary to decimal, each bit is multiplied by the weight of its position
        row = block[0] * 2 + block[5]
        col = (block[1] * 8 + block[2] * 4
               + block[3] * 2 + block[4])

        value = S_BOXES[j][row][col]               # value 0-15 from S box j

        # Convert the value to 4 bits
        result += [int(b) for b in format(value, '04b')]
    return result


def cipher_function(right_half, subkey):
    """Cipher for XOR operation"""
    expanded = expansion(right_half)               # 32 -> 48 bits
    mixed = xor_bits(expanded, subkey)             # XOR with the subkey (48 bits)
    substituted = sbox_substitution(mixed)         # 8 S-boxes: 48 -> 32 bits
    return permute(substituted, t.P)               # permutation P


# Feistel network


def left_xor_f(left, right, subkey):
    """Generating new R part"""
    return xor_bits(left, cipher_function(right, subkey))


def feistel_round(left, right, subkey):
    """Managing keys and messaging components within a single cycle"""
    new_left = right
    new_right = left_xor_f(left, right, subkey)
    return new_left, new_right


def feistel_rounds(left, right, keys):
    """Management of keys and messaging components throughout the entire encryption system"""
    for key in keys:                               # each round uses its own subkey
        left, right = feistel_round(left, right, key)
    return left, right


def final_permutation(left, right):
    """R16 + L16 and apply FP = IP^-1"""
    return permute(right + left, t.IP_Inverse)

# Main cycle program

# Key permutation

cle_clear = permute(cle_test, t.PC_1)

cle_left_half = cle_clear[:28]
cle_right_half = cle_clear[28:]

subkeys = generate_subkeys(cle_left_half, cle_right_half)

# Encryption


# Initial permutation
message_ip = permute(message_test, t.IP)
message_left_half = message_ip[:32]
message_right_half = message_ip[32:]

# 16 rounds, then final permutation
left_16, right_16 = feistel_rounds(message_left_half, message_right_half, subkeys)
ciphertext = final_permutation(left_16, right_16)
cipher_lisible = bits_to_hex(ciphertext)


# Decryption

# Same algorithm: input = ciphertext, subkeys in reverse order

cipher_ip = permute(ciphertext, t.IP)
cipher_left_half = cipher_ip[:32]
cipher_right_half = cipher_ip[32:]

left_16, right_16 = feistel_rounds(cipher_left_half, cipher_right_half, subkeys[::-1])
plaintext = final_permutation(left_16, right_16)
plaintext_lisible = bits_to_hex(plaintext)


print(f"{'Message (plaintext):':<24}{message}")
print(f"{'Key:':<24}{cle}")
print(f"{'Ciphertext reference:':<24}{ciphertext_reference}")

print(f"\n{'Ciphertext calculated:':<24}{cipher_lisible}")
print(f"{'Plaintext decrypted:':<24}{plaintext_lisible}")