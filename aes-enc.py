from pwn import log

sbox = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]
r_con = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
mul_matrix = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
] 

key = "sirjameelthegoat"
log.info(f"Original Key  => {key}")
hex_key = "".join(f"{ord(c):02x}" for c in key)  
log.info(f"Key in hex => {hex_key}")
matrix = [
    [hex_key[i:i+2] for i in range(0, 8, 2)],	
    [hex_key[i:i+2] for i in range(8, 16, 2)],
    [hex_key[i:i+2] for i in range(16, 24, 2)],
    [hex_key[i:i+2] for i in range(24, 32, 2)]
]

def sub_col(rot):
    s_list = []
    for i in range(4):
        row = int(rot[i][:1], 16) 
        col = int(rot[i][1:], 16)
        s_list.append(f"{sbox[row][col]:02x}")
    return s_list
def rot_col(col):
	rot_last = col[1:] + col[:1]
	return rot_last
def get_column(mat, idx):
	col = []
	for i in range(4):
		col += [mat[i][idx]]
	return col
def xorr(sub_col, matrix, idx):
	xor_result = []
	for i in range(4):
		prev_col_val = int(matrix[i][idx - 3], 16)
		sub_col_val = int(sub_col[i], 16)
		xor_result.append(f"{prev_col_val ^ sub_col_val:02x}")
	return xor_result
def rc(xo, i):
    return f"{int(xo[0], 16) ^ r_con[i]:02x}"

def get_round_keys(matrix):
    round_keys = []
    for i in range(0, 44, 4):
        round_key = [matrix[j][i:i+4] for j in range(4)]
        round_keys.append(round_key)
    return round_keys
def sub_mat(matrix):
    substituted_matrix = []
    for i in range(4):
        row = []
        for j in range(4):
            row_idx = int(matrix[i][j][:1], 16)
            col_idx = int(matrix[i][j][1:], 16)
            substituted_value = f"{sbox[row_idx][col_idx]:02x}"
            row.append(substituted_value)
        substituted_matrix.append(row)
    return substituted_matrix
def rot_mat(matrix):
    for i in range(4):
        for _ in range(i):
            matrix[i] = matrix[i][1:] + matrix[i][:1]
    return matrix
def multiply_matrix(mat):
    result_matrix = []
    for col in range(4):
        result_col = []
        for row in range(4):
            result_val = (int(mat[row][col], 16) * mul_matrix[row][col]) % 256
            result_col.append(f"{result_val:02x}")
        result_matrix.append(result_col)
    return result_matrix
def xor_matrices(mat1, mat2):
    result_matrix = []
    for row in range(4):
        result_row = []
        for col in range(4):
            xor_val = int(mat1[row][col], 16) ^ int(mat2[row][col], 16)
            result_row.append(f"{xor_val:02x}")
        result_matrix.append(result_row)
    return result_matrix
'''
Key Scheduling
'''
log.info("Key in matrix:")
log.info("--------------------")
for row in matrix:
	print(row)
for i in range(4, 44):
    if i % 4 == 0:
        col = get_column(matrix, i - 1)
        rot = rot_col(col)
        sub = sub_col(rot)
        xor_result = xorr(sub, matrix, i - 1)
        xor_result[0] = rc(xor_result, (i // 4) - 1)
    else:
        col1 = get_column(matrix, i - 1)
        col2 = get_column(matrix, i - 4)
        xor_result = [f"{int(col1[j], 16) ^ int(col2[j], 16):02x}" for j in range(4)]
    
    for j in range(4):
        matrix[j].append(xor_result[j])
round_keys = get_round_keys(matrix)
log.info("--------------------")
log.info("Round Keys:")
log.info("--------------------")
for i, round_key in enumerate(round_keys):
    if(i+1==10 or i+1==11):
        log.info(f"Round {i+1} Key => {round_key}")
    else:
        log.info(f"Round {i+1} Key  => {round_key}")
log.info("--------------------")
'''
Encryption
'''
plain_text = "lab4-aes-crypter"
bin_plain = "".join(f"{ord(c):02x}"for c in plain_text)
pt_mat = [
    [bin_plain[i:i+2] for i in range(0, 8, 2)],   
    [bin_plain[i:i+2] for i in range(8, 16, 2)],
    [bin_plain[i:i+2] for i in range(16, 24, 2)],
    [bin_plain[i:i+2] for i in range(24, 32, 2)]
]
log.info(f"Plain text to encode => {plain_text}")
log.info(f"Plain text in hex    => {bin_plain}")
log.info(f"Hex in matrix:")
log.info("--------------------")
for row in pt_mat:
    print(row)
for i in range(11):
    if i != 10:  
        sub_mat_res = sub_mat(pt_mat)
        rot_matrix = rot_mat(sub_mat_res)
        mix_mat = multiply_matrix(rot_matrix)
        ff = xor_matrices(mix_mat, round_keys[i])
    else:
        sub_mat_res = sub_mat(pt_mat)
        rot_matrix = rot_mat(sub_mat_res)
        ff = xor_matrices(rot_matrix, round_keys[i])

    pt_mat = ff
log.info("--------------------")
log.info(f"Encoded hex in matrix:")
log.info("--------------------")
for row in pt_mat:
    print(row)
log.info("--------------------")

enc_hex = "".join("".join(pt_mat[i][j] for j in range(4)) for i in range(4))
enc_string = bytes.fromhex(enc_hex)
enc_string = enc_string.decode('latin-1', errors='ignore')
log.info(f"Encoded Text => {enc_string}")