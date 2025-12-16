KEY = b"whisper-udt-final-key"

def crypt(data, seq):
    key = KEY + seq.to_bytes(4, 'big')
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)
