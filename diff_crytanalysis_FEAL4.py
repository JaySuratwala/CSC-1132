# Differential Cryptanalysis on FEAL-4 in Python
# Cracking K3 using fixed plaintext/ciphertext pairs

def rot2(x):
    return ((x << 2) & 0xFF) | ((x >> 6) & 0x03)

def g0(a, b):
    return rot2((a + b) & 0xFF)

def g1(a, b):
    return rot2((a + b + 1) & 0xFF)

def unpack(val):
    # Ensure val is treated as a 32-bit integer for unpacking
    val = val & 0xFFFFFFFF
    return [(val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]

def pack(b):
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]

def F(input_word):
    x = unpack(input_word)
    y = [0] * 4
    y[1] = g1(x[0] ^ x[1], x[2] ^ x[3])
    y[0] = g0(x[0], y[1])
    y[2] = g0(y[1], x[2] ^ x[3])
    y[3] = g1(y[2], x[3])
    return pack(y)

def M(A):
    # Extract bytes a0, a1, a2, and a3 from the 32-bit integer A
    a0 = (A >> 24) & 0xFF
    a1 = (A >> 16) & 0xFF
    a2 = (A >> 8) & 0xFF
    a3 = A & 0xFF

    # Compute M(A) = (z, a0 ^ a1, a2 ^ a3, z) where z is 0x00
    z = 0x00
    b1 = a0 ^ a1
    b2 = a2 ^ a3

    # Construct the result as a 32-bit integer
    result = (z << 24) | (b1 << 16) | (b2 << 8) | z
    return result

def xor32(a, b):
    return (a ^ b) & 0xFFFFFFFF # Ensure 32-bit XOR

def split64(val):
    return (val >> 32) & 0xFFFFFFFF, val & 0xFFFFFFFF

# Global dictionary for memoization, mimicking Java's globalKeys
global_keys = {}

def global_dict_constructor(check_value):
    if check_value in global_keys:
        return global_keys[check_value]
    else:
        temp = F(check_value)
        global_keys[check_value] = temp
        return temp

def primary_phase(c0, c1):
    l0, r0 = split64(c0)
    l1, r1 = split64(c1)

    y0 = xor32(l0, r0)
    y1 = xor32(l1, r1)

    l_dash = xor32(l0, l1)
    z_dash = xor32(l_dash, 0x02000000) # The constant 0x02000000 from the diagram [cite: 38]

    matching_pairs = []
    for a0 in range(256):
        for a1 in range(256):
            A = (0x00 << 24) | (a0 << 16) | (a1 << 8) | 0x00 # A = (0x00, a0, a1, 0x00)

            temp1 = M(xor32(y0, A))
            temp2 = M(xor32(y1, A))

            Q0 = global_dict_constructor(temp1)
            Q1 = global_dict_constructor(temp2)

            xor_result = xor32(Q0, Q1)
            
            # Extract middle 16 bits: (xor_result >> 8) & 0xFFFF
            extracted_bits = (xor_result >> 8) & 0xFFFF
            Z_dash_bits = (z_dash >> 8) & 0xFFFF

            if extracted_bits == Z_dash_bits:
                value = A # A is already in the desired format (0x00, a0, a1, 0x00)
                matching_pairs.append(value)
    return matching_pairs, z_dash, y0, y1 # Return z_dash, y0, y1 for secondary phase

def secondary_phase(primary_survivors, y0, y1, z_dash):
    k3_candidates_for_pair = {} # Use a dictionary to count occurrences for this pair
    for survivor_A in primary_survivors:
        # survivor_A is already in the format (0x00, a0, a1, 0x00)
        # We need a0 and a1 from survivor_A
        a0 = (survivor_A >> 16) & 0xFF
        a1 = (survivor_A >> 8) & 0xFF

        for c0 in range(256):
            for c1 in range(256):
                # Compute D as (c0, a0^c0, a1^c1, c1)
                D = (c0 << 24) | ((a0 ^ c0) << 16) | ((a1 ^ c1) << 8) | c1

                Z0 = global_dict_constructor(xor32(y0, D))
                Z1 = global_dict_constructor(xor32(y1, D))

                if xor32(Z0, Z1) == z_dash:
                    k3_candidates_for_pair[D] = k3_candidates_for_pair.get(D, 0) + 1
    return k3_candidates_for_pair

def intersect_keys(list_of_k3_dicts, required_count):
    final_candidates = {}
    for k3_dict in list_of_k3_dicts:
        for key, count in k3_dict.items():
            final_candidates[key] = final_candidates.get(key, 0) + 1
    
    # Filter keys that appeared in all 'required_count' dictionaries
    return {k: v for k, v in final_candidates.items() if v == required_count}


def main():
    # Ciphertext pairs corresponding to plaintext pairs with difference 0x8080000080800000
    # c0 is C(p0), c1 is C(p1) where p1 = p0 ^ 0x8080000080800000
    cipher_text_pairs = [
        (0xbfa68902044c5bfa, 0x2d3617760aa5b93d), # (c0, c1) from original Java
        (0x928d09abd2735506, 0xf8f7462224726e7c), # (c2, c3)
        (0xb07ba785f5707028, 0x42b70825af44ff09), # (c4, c5)
        (0x885a2c1be73ed79f, 0xbb9e58774c72c372)  # (c6, c7)
    ]

    all_k3_candidates_from_pairs = []

    for c0, c1 in cipher_text_pairs:
        # Step 1: Primary Phase (finding A candidates)
        primary_survivors, z_dash, y0, y1 = primary_phase(c0, c1)
        
        # Step 2: Secondary Phase (using A candidates to find K3)
        k3_dict_for_this_pair = secondary_phase(primary_survivors, y0, y1, z_dash)
        all_k3_candidates_from_pairs.append(k3_dict_for_this_pair)

    # Find keys that are common across all pairs
    final_k3_candidates = intersect_keys(all_k3_candidates_from_pairs, len(cipher_text_pairs))

    print("\nFinal K3 Candidate Keys (Matched in all pairs):")
    if final_k3_candidates:
        for k, count in final_k3_candidates.items():
            print(f"K3 = {k:08X}, Count = {count}")
    else:
        print("No K3 candidates found that match across all ciphertext pairs.")


if __name__ == "__main__":
    main()