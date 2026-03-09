# see: https://www.jonaslieb.de/blog/nltest-ntowfpassword/

import click
from Cryptodome.Cipher import DES


def toggle_endianness(data: bytes) -> bytes:
    result = bytearray(len(data))
    assert len(data) % 4 == 0
    for i in range(0, len(data), 4):
        chunk = data[i : i + 4]
        chunk = chunk[::-1]
        result[i : i + 4] = chunk
    return bytes(result)


# see [MS-SAMR] 2.2.11.1.1: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/a5252e8c-25e7-4616-a375-55ced086b19b
def encrypt(plaintext: bytes, rid: int):
    key = derive_key(rid)

    assert len(plaintext) % 8 == 0

    ciphertext = []
    for i in range(len(plaintext) // 8):
        subkey = stretch_key(key[7 * i : 7 * (i + 1)])
        subplaintext = plaintext[8 * i : 8 * (i + 1)]
        subciphertext = DES.new(key=subkey, mode=DES.MODE_ECB).encrypt(subplaintext)
        ciphertext.append(subciphertext)

    return b"".join(ciphertext)


# see [MS-SAMR] 2.2.11.1.3: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b1b0094f-2546-431f-b06d-582158a9f2bb
def derive_key(rid: int) -> bytes:
    return rid.to_bytes(4, "little") * 4


# see [MS-SAMR] 2.2.11.1.2 : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ebdb15df-8d0d-4347-9d62-082e6eccac40
def stretch_key(InputKey: bytes) -> bytes:
    assert len(InputKey) == 7
    InputKey = bytearray(InputKey)
    OutputKey = bytearray(8)

    OutputKey[0] = InputKey[0] >> 0x01
    OutputKey[1] = ((InputKey[0] & 0x01) << 6) | (InputKey[1] >> 2)
    OutputKey[2] = ((InputKey[1] & 0x03) << 5) | (InputKey[2] >> 3)
    OutputKey[3] = ((InputKey[2] & 0x07) << 4) | (InputKey[3] >> 4)
    OutputKey[4] = ((InputKey[3] & 0x0F) << 3) | (InputKey[4] >> 5)
    OutputKey[5] = ((InputKey[4] & 0x1F) << 2) | (InputKey[5] >> 6)
    OutputKey[6] = ((InputKey[5] & 0x3F) << 1) | (InputKey[6] >> 7)
    OutputKey[7] = InputKey[6] & 0x7F

    for i in range(8):
        OutputKey[i] = (OutputKey[i] << 1) & 0xFE

    return bytes(OutputKey)


@click.command()
@click.option("-r", "--hexrid", type=str, required=True)
@click.argument("NtOwfPassword")
def main(hexrid: str, ntowfpassword: str):
    rid = int(hexrid, 16) 
    nt_owf_password = bytes.fromhex(ntowfpassword)

    plaintext = toggle_endianness(nt_owf_password)
    ciphertext = encrypt(plaintext, rid)

    print(ciphertext.hex(" ").upper())


if __name__ == "__main__":
    main()
