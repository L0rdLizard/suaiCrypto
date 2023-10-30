import base64
import binascii
import secrets
from loguru import logger

import numpy as np

from PIL import Image
from io import BytesIO


class IDEA:
    def __init__(self, key, iv):
        self._iv = iv
        self._keys = None
        self.gen_keys(key)

    def mul_mod(self, a, b):
        assert 0 <= a <= 0xFFFF
        assert 0 <= b <= 0xFFFF

        if a == 0:
            a = 0x10000
        if b == 0:
            b = 0x10000

        r = (a * b) % 0x10001

        if r == 0x10000:
            r = 0

        assert 0 <= r <= 0xFFFF
        return r

    def add_mod(self, a, b):
        return (a + b) % 0x10000

    def add_inv(self, key):
        u = (0x10000 - key) % 0xFFFF
        assert 0 <= u <= 0x10000 - 1
        return u

    def mul_inv(self, key):
        a = 0x10000 + 1
        if key == 0:
            return 0
        else:
            x = 0
            y = 0
            x1 = 0
            x2 = 1
            y1 = 1
            y2 = 0
            while key > 0:
                q = a // key
                r = a - q * key
                x = x2 - q * x1
                y = y2 - q * y1
                a = key
                key = r
                x2 = x1
                x1 = x
                y2 = y1
                y1 = y
            d = a
            x = x2
            y = y2
            return y

    def round(self, p1, p2, p3, p4, keys):
        k1, k2, k3, k4, k5, k6 = keys

        p1 = self.mul_mod(p1, k1)  # 1
        p2 = self.add_mod(p2, k2)  # 2
        p3 = self.add_mod(p3, k3)  # 3
        p4 = self.mul_mod(p4, k4)  # 4

        x = p1 ^ p3  # 5
        t0 = self.mul_mod(k5, x)  # 7
        x = p2 ^ p4  # 6

        x = self.add_mod(t0, x)  # 8

        t1 = self.mul_mod(k6, x)  # 9
        t2 = self.add_mod(t0, t1)  # 10

        r1 = p1 ^ t1  # 11
        r2 = p3 ^ t1  # 12
        r3 = p2 ^ t2  # 13
        r4 = p4 ^ t2  # 14

        # return p1, p2, p3, p4
        return r1, r2, r3, r4

    def gen_keys(self, key):
        assert 0 <= key < (1 << 128)
        modulus = 1 << 128

        sub_keys = []
        for i in range(9 * 6):
            sub_keys.append((key >> (112 - 16 * (i % 8))) % 0x10000)
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % modulus

        keys = []
        for i in range(9):
            round_keys = sub_keys[6 * i: 6 * (i + 1)]
            keys.append(tuple(round_keys))
        self._keys = tuple(keys)

    def encrypt(self, plain: bytes):
        plain_int = int.from_bytes(plain, 'big')
        p1 = (plain_int >> 48) & 0xFFFF
        p2 = (plain_int >> 32) & 0xFFFF
        p3 = (plain_int >> 16) & 0xFFFF
        p4 = plain_int & 0xFFFF
        # p1 = (plain >> 48) & 0xFFFF
        # p2 = (plain >> 32) & 0xFFFF
        # p3 = (plain >> 16) & 0xFFFF
        # p4 = plain & 0xFFFF

        # 8 циклов
        for i in range(8):
            keys = self._keys[i]
            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

        # окончательное преобразование
        k1, k2, k3, k4, k5, k6 = self._keys[8]
        y1 = self.mul_mod(p1, k1)
        y2 = self.add_mod(p3, k2)
        y3 = self.add_mod(p2, k3)
        y4 = self.mul_mod(p4, k4)

        encrypted = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return encrypted

    def decrypt(self, encrypted : bytes):
        encrypted_int = int.from_bytes(encrypted, 'big')
        p1 = (encrypted_int >> 48) & 0xFFFF
        p2 = (encrypted_int >> 32) & 0xFFFF
        p3 = (encrypted_int >> 16) & 0xFFFF
        p4 = encrypted_int & 0xFFFF
        # p1 = (encrypted >> 48) & 0xFFFF
        # p2 = (encrypted >> 32) & 0xFFFF
        # p3 = (encrypted >> 16) & 0xFFFF
        # p4 = encrypted & 0xFFFF

        # Round 1
        keys = self._keys[8]
        k1 = self.mul_inv(keys[0])
        if k1 < 0:
            k1 = 0x10000 + 1 + k1
        k2 = self.add_inv(keys[1])
        k3 = self.add_inv(keys[2])
        k4 = self.mul_inv(keys[3])
        if k4 < 0:
            k4 = 0x10000 + 1 + k4
        keys = self._keys[7]
        k5 = keys[4]
        k6 = keys[5]
        keys = [k1, k2, k3, k4, k5, k6]
        p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

        # Other rounds
        for i in range(1, 8):
            keys = self._keys[8 - i]
            k1 = self.mul_inv(keys[0])
            if k1 < 0:
                k1 = 0x10000 + 1 + k1
            k2 = self.add_inv(keys[2])
            k3 = self.add_inv(keys[1])
            k4 = self.mul_inv(keys[3])
            if k4 < 0:
                k4 = 0x10000 + 1 + k4
            keys = self._keys[7 - i]
            k5 = keys[4]
            k6 = keys[5]
            keys = [k1, k2, k3, k4, k5, k6]
            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

        # Final output transformation
        keys = self._keys[0]
        k1 = self.mul_inv(keys[0])
        if k1 < 0:
            k1 = 0x10000 + 1 + k1
        k2 = self.add_inv(keys[1])
        k3 = self.add_inv(keys[2])
        k4 = self.mul_inv(keys[3])
        if k4 < 0:
            k4 = 0x10000 + 1 + k4
        y1 = self.mul_mod(p1, k1)
        y2 = self.add_mod(p3, k2)
        y3 = self.add_mod(p2, k3)
        y4 = self.mul_mod(p4, k4)
        decrypted = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return decrypted

    def encrypt_message(self, message):
        encrypted_message = b''
        previous = self._iv
        for i in range(0, len(message), 8):
            # block = message[i:i + 8]
            block = xor_bytes(message[i:i + 8], previous, 8)

            encrypted_block = self.encrypt(block)

            encrypted_block_str = encrypted_block.to_bytes(8, 'big')
            if len(encrypted_block_str) != 16:
                encrypted_block_str = b'0' * (16 - len(encrypted_block_str)) + encrypted_block_str

            previous = encrypted_block_str

            encrypted_message += encrypted_block_str
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        decrypted_message = ''
        previous = self._iv
        for i in range(0, len(encrypted_message), 16):
            block = encrypted_message[i:i + 16]
            # block = int(block, 16)

            decrypted_block = self.decrypt(block)

            decrypted_block_xor = xor_bytes(decrypted_block.to_bytes(8, 'big'), previous, 16)

            # decrypted_block_str = hex_to_string(decrypted_block)
            decrypted_block_str = decrypted_block_xor.decode('cp1251')
            decrypted_message += decrypted_block_str
        return decrypted_message

    #

    # def encrypt_cbc(self, plaintext, iv):
    #     """
    #     Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
    #     initialization vector (iv).
    #     """
    #     assert len(iv) == 16
    #
    #     plaintext = pad(plaintext)
    #
    #     blocks = []
    #     previous = iv
    #     for plaintext_block in split_blocks(plaintext):
    #         # CBC mode encrypt: encrypt(plaintext_block XOR previous)
    #         block = self.encrypt_block(xor_bytes(plaintext_block, previous))
    #         blocks.append(block)
    #         previous = block
    #
    #     return b''.join(blocks)
    #
    # def decrypt_cbc(self, ciphertext, iv):
    #     """
    #     Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
    #     initialization vector (iv).
    #     """
    #     assert len(iv) == 16
    #
    #     blocks = []
    #     previous = iv
    #     for ciphertext_block in split_blocks(ciphertext):
    #         # CBC mode decrypt: previous XOR decrypt(ciphertext)
    #         blocks.append(
    #             xor_bytes(previous, self.decrypt_block(ciphertext_block)))
    #         previous = ciphertext_block
    #
    #     return unpad(b''.join(blocks))



    def encrypt_image(self, input_filename, output_filename):
        header_size = 14 + 40
        # header_size = 64

        with open(input_filename, 'rb') as input_file:
            bmp_header = input_file.read(header_size)

            pixel_data = input_file.read()

        # encrypted_pixel_data = self.encrypt_message(pixel_data).encode('cp1251')
        encrypted_pixel_data = b''
        for i in range(0, len(pixel_data), 8):
            block = pixel_data[i:i + 8]

            encrypted_block = self.encrypt(block)

            encrypted_block_bytes = encrypted_block.to_bytes(8, 'big')
            # encrypted_pixel_data = pixel_data[:i] + encrypted_block_bytes + pixel_data[i + 8:]
            encrypted_pixel_data += encrypted_block_bytes

        # print(len(encrypted_pixel_data))

        # new_bmp_content = bmp_header + replace_pixel_data
        new_bmp_content = bmp_header + encrypted_pixel_data

        # Write the new BMP content to the output file
        with open(output_filename, 'wb') as output_file:
            output_file.write(new_bmp_content)


    def decrypt_image(self, input_filename, output_filename):
        # Define the size of the BMP header (14 bytes) and the DIB header (40 bytes)
        header_size = 14 + 40
        # header_size = 64
        bmp_header, pixel_data = None, None

        # Open the input BMP file in binary mode
        with open(input_filename, 'rb') as input_file:
            # Read the BMP header
            bmp_header = input_file.read(header_size)

            # Read the pixel data
            pixel_data = input_file.read()
            # print(len(pixel_data))

        # тут мы типа шифруем картинку
        decrypted_pixel_data = b''
        for i in range(0, len(pixel_data), 8):
            block = pixel_data[i:i + 8]

            decrypted_block = self.decrypt(block)

            decrypted_block_bytes = decrypted_block.to_bytes(8, 'big')
            # encrypted_pixel_data = pixel_data[:i] + encrypted_block_bytes + pixel_data[i + 8:]
            decrypted_pixel_data += decrypted_block_bytes

        # print(len(decrypted_pixel_data))

        # new_bmp_content = bmp_header + replace_pixel_data
        new_bmp_content = bmp_header + decrypted_pixel_data

        # Write the new BMP content to the output file
        with open(output_filename, 'wb') as output_file:
            output_file.write(new_bmp_content)



def string_to_hex(string):
    return int(string.encode("cp1251").hex(), 16)

@logger.catch
def xor_bytes(ba1, ba2, length):
    print(len(ba1), len(ba2))
    # return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
    # assume ba1 and ba2 is 64 bytes, convert to int
    int1 = int.from_bytes(ba1, 'big')
    int2 = int.from_bytes(ba2, 'big')
    # xor
    int3 = int1 ^ int2
    # convert back to bytes
    return int3.to_bytes(length, 'big')


def hex_to_string(hex_value):
    hex_str = hex(hex_value)[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str).decode("cp1251")


def image_to_string(image_path):
    with open(image_path, 'rb') as image_file:
        encoded_string = base64.b64encode(image_file.read())
        return encoded_string.decode('cp1251')


def string_to_image(image_string, image_path):
    decoded_string = base64.b64decode(image_string)
    image = Image.open(BytesIO(decoded_string))
    image.save(image_path)


def save_encrypted_image(encrypted_image_data, output_path):
    with open(output_path, 'wb') as image_file:
        image_file.write(encrypted_image_data)

def decode_base64(encoded_data):
    header = encoded_data[:64]  # Extract the header (first 54 bytes) of the encrypted image
    encoded_data_without_header = encoded_data[64:]
    decoded_data_temp = base64.b64decode(encoded_data_without_header)
    decoded_data_result = header + decoded_data_temp
    return decoded_data_result

def main():
    key = 0x2BD6459F82C5B300952C49104881FF48
    image_path = 'smile.bmp'
    iv = secrets.token_bytes(16)
    print('key\t\t', hex(key))

    my_IDEA = IDEA(key, iv)

    # plainStr = "To Sherlock Holmes she is always the woman. I have seldom heard him mention her under any other name. In his eyes she eclipses and predominates the whole of her sex. It was not that he felt any emotion akin to love for Irene Adler. All emotions, and that one particularly, were abhorrent to his cold, precise but admirably balanced mind. He was, I take it, the most perfect reasoning and observing machine that the world has seen, but as a lover he would have placed himself in a false position. He never spoke of the softer passions, save with a gibe and a sneer. They were admirable things for the observer--excellent for drawing the veil from men's motives and actions. But for the trained reasoner to admit such intrusions into his own delicate and finely adjusted temperament was to introduce a distracting factor which might throw a doubt upon all his mental results. Grit in a sensitive instrument, or a crack in one of his own high-power lenses, would not be more disturbing than a strong emotion in a nature such as his. And yet there was but one woman to him, and that woman was the late Irene Adler, of dubious and questionable memory."
    plainStr = "To Sherlock Holmes she is always fgv"
    print(len(plainStr))
    print('plainStr_hex\t', hex(string_to_hex(plainStr)))
    print('plaintext\t', plainStr)
    print()


    encrypted_message = my_IDEA.encrypt_message(plainStr.encode('cp1251'))
    print('encrypted_message_hex\t', encrypted_message)

    decrypted_message = my_IDEA.decrypt_message(encrypted_message)
    print('decrypted_message\t', decrypted_message)


    my_IDEA.encrypt_image(image_path, 'encrypted_image.bmp')

    my_IDEA.decrypt_image('encrypted_image.bmp', 'decrypted_image.bmp')


if __name__ == '__main__':
    main()
