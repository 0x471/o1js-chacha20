hex_array = [
    b'61707865', b'3320646e', b'79622d32', b'6b206574',  # ChaCha constants
    b'03020100', b'07060504', b'0b0a0908', b'0f0e0d0c',  # Key
    b'13121110', b'17161514', b'1b1a1918', b'1f1e1d1c',  # Key
    b'00000001',  # Block count
    b'09000000', b'4a000000', b'00000000'  # Nonce
]

def process_hex(hex_num):
    big = bytearray.fromhex(hex_num.decode('utf-8'))
    big.reverse()
    little = ''.join(f"{n:02X}" for n in big)
    return little

for hex_num in hex_array:
    result = process_hex(hex_num)
    print("0x"+result)
