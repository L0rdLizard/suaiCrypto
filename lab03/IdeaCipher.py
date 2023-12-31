import base64
import binascii

import numpy as np

from PIL import Image
from io import BytesIO


class IDEA:
    def __init__(self, key):
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

    def invert_bits_second(self, number):
        # Function to invert every second bit
        return number ^ 0b1010101010101010101010101010101010101010101010101010101010101010

    def invert_bits_forth(self, number):
        # Function to invert every second bit
        return number ^ 0b1000100010001000100010001000100010001000100010001000100010001000

    def bytes_to_bits_str(self, b):
        return ''.join(format(x, '08b') for x in b)

    def int_to_bits_str(self, i):
        # use bytes_to_bits_str
        return self.bytes_to_bits_str(i.to_bytes(8, byteorder='big'))

    def encrypt_second(self, plain: bytes):
        changes = [0] * 64
        plain_int = int.from_bytes(plain, 'big')

        print(self.int_to_bits_str(plain_int))
        plain_int = self.invert_bits_second(plain_int)
        print(self.int_to_bits_str(plain_int))

        p1 = (plain_int >> 48) & 0xFFFF
        p2 = (plain_int >> 32) & 0xFFFF
        p3 = (plain_int >> 16) & 0xFFFF
        p4 = plain_int & 0xFFFF

        # 8 циклов
        for i in range(8):
            keys = self._keys[i]
            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

            new_block = (p1 << 48) | (p2 << 32) | (p3 << 16) | p4
            new_block = self.int_to_bits_str(new_block)
            block = self.int_to_bits_str(plain_int)
            for j in range(len(block)):
                if block[j] != new_block[j]:
                    changes[j] += 1

        print(changes)
        # окончательное преобразование
        k1, k2, k3, k4, k5, k6 = self._keys[8]
        y1 = self.mul_mod(p1, k1)
        y2 = self.add_mod(p3, k2)
        y3 = self.add_mod(p2, k3)
        y4 = self.mul_mod(p4, k4)

        encrypted = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return encrypted

    def encrypt_forth(self, plain: bytes):
        changes = [0] * 64
        plain_int = int.from_bytes(plain, 'big')

        print(self.int_to_bits_str(plain_int))
        plain_int = self.invert_bits_forth(plain_int)
        print(self.int_to_bits_str(plain_int))

        p1 = (plain_int >> 48) & 0xFFFF
        p2 = (plain_int >> 32) & 0xFFFF
        p3 = (plain_int >> 16) & 0xFFFF
        p4 = plain_int & 0xFFFF

        # 8 циклов
        for i in range(8):
            keys = self._keys[i]
            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

            new_block = (p1 << 48) | (p2 << 32) | (p3 << 16) | p4
            new_block = self.int_to_bits_str(new_block)
            block = self.int_to_bits_str(plain_int)
            for j in range(len(block)):
                if block[j] != new_block[j]:
                    changes[j] += 1

        print(changes)
        # окончательное преобразование
        k1, k2, k3, k4, k5, k6 = self._keys[8]
        y1 = self.mul_mod(p1, k1)
        y2 = self.add_mod(p3, k2)
        y3 = self.add_mod(p2, k3)
        y4 = self.mul_mod(p4, k4)

        encrypted = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return encrypted

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

    def decrypt(self, encrypted: bytes):
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

    def auto_corr_test(self, data):
        print("Автокорреляционный тест")
        bits = int.from_bytes(data, byteorder='big')
        entry_bytes = [1 if bits & (1 << k) else -1 for k in range(63, -1, -1)]

        for D in range(1, 33):
            A = 0
            for i in range(64 - D):
                A += entry_bytes[i] * entry_bytes[i + D]

            X = A / (64 - D)
            print(f"для D = {D}: {X}")

    def series_test(self, data):
        print("Последовательностей разрывов")
        bits = int.from_bytes(data, byteorder='big')
        entry_nul = ""
        nul = ""
        one = ""

        for k in range(63, -1, -1):
            nul += "0"
            one += "1"
            entry_nul += "1" if bits & (1 << k) else "0"

        entry_one = entry_nul
        X = 0

        for i in range(63, -1, -1):
            count = entry_nul.count(nul)
            entry_nul = entry_nul.replace(nul, "")
            nul = nul[:-1]

            if count != 0:
                print(f"длиной {i + 1} = {count}")
                e = (64 - i + 4) / (2 ** (i + 3))
                X += (count - e) ** 2 / e

        print("Последовательностей блоков")
        for i in range(63, -1, -1):
            count = entry_one.count(one)
            entry_one = entry_one.replace(one, "")
            one = one[:-1]

            if count != 0:
                print(f"длиной {i + 1} = {count}")
                e = (64 - i + 4) / (2 ** (i + 4))
                X += (count - e) ** 2 / e

        print(f"Статистика Х = {X}")

    def frequency_test(self, data):
        test = data
        sum0 = 0
        sum1 = 0
        bites = int.from_bytes(test, byteorder='big')

        for k in range(63, -1, -1):
            if bites & (1 << k):
                sum1 += 1
            else:
                sum0 += 1

        res0 = sum0 / 64
        res1 = sum1 / 64
        print(f"Частотный тест 0: {res0}\nЧастотный тест 1: {res1}")

def string_to_hex(string):
    return int(string.encode("cp1251").hex(), 16)


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
    print('key\t\t', hex(key))

    # voice:.idea/1701179216437.wav

    my_IDEA = IDEA(key)

    # plainStr = "To Sherlock Holmes she is always the woman. I have seldom heard him mention her under any other name. In his eyes she eclipses and predominates the whole of her sex. It was not that he felt any emotion akin to love for Irene Adler. All emotions, and that one particularly, were abhorrent to his cold, precise but admirably balanced mind. He was, I take it, the most perfect reasoning and observing machine that the world has seen, but as a lover he would have placed himself in a false position. He never spoke of the softer passions, save with a gibe and a sneer. They were admirable things for the observer--excellent for drawing the veil from men's motives and actions. But for the trained reasoner to admit such intrusions into his own delicate and finely adjusted temperament was to introduce a distracting factor which might throw a doubt upon all his mental results. Grit in a sensitive instrument, or a crack in one of his own high-power lenses, would not be more disturbing than a strong emotion in a nature such as his. And yet there was but one woman to him, and that woman was the late Irene Adler, of dubious and questionable memory."
    # plainStr = "To Sherlock Holmes she is always fgv"
    plainStr = "loveguap"
    print(len(plainStr))
    print('plainStr_hex\t', hex(string_to_hex(plainStr)))
    print('plaintext\t', plainStr)
    print()

    encrypted_block_second = my_IDEA.encrypt_second(plainStr.encode('cp1251'))
    print('encrypted_block_second\t', encrypted_block_second)

    print()
    my_IDEA.auto_corr_test(encrypted_block_second.to_bytes(8, byteorder='big'))
    print()
    my_IDEA.series_test(encrypted_block_second.to_bytes(8, byteorder='big'))
    print()
    my_IDEA.frequency_test(encrypted_block_second.to_bytes(8, byteorder='big'))

    print()

    encrypted_block_forth = my_IDEA.encrypt_forth(plainStr.encode('cp1251'))
    print('encrypted_block_forth\t', encrypted_block_forth)


if __name__ == '__main__':
    main()
