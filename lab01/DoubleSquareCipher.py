import random

class DoubleSquareCipher:

    alphabet_normal = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя ,."
    def __init__(self, key1, key2):
        self.key1 = key1
        self.key2 = key2
        self.square1 = self.generate_square(key1)
        self.square2 = self.generate_square(key2)


    def generate_square(self, key):

        alist = list(self.alphabet_normal)
        random.shuffle(alist)
        alphabet = ''.join(alist)

        key = key.lower()
        key_set = set(key)
        square = []
        for letter in key:
            if letter not in square:
                square.append(letter)
        for letter in alphabet:
            if letter not in key_set and letter not in square:
                square.append(letter)
        print(square)
        print()
        return square

    @staticmethod
    def filter_string(input_string, allowed_chars):
        return ''.join(c for c in input_string if c in allowed_chars)

    def encode(self, address):

        with open(address, 'r', encoding='utf-8') as f:
            plaintext = f.readline()

        plaintext = plaintext.lower()

        plaintext = self.filter_string(plaintext, self.alphabet_normal)

        if len(plaintext) % 2 == 1:
            plaintext += " "
        ciphertext = ""
        for i in range(0, len(plaintext), 2):
            a = plaintext[i]
            b = plaintext[i+1]
            a_row = self.square1.index(a) // 6
            a_col = self.square1.index(a) % 6
            b_row = self.square2.index(b) // 6
            b_col = self.square2.index(b) % 6
            if a_row == b_row:
                a_col = (a_col + 1) % 6
                b_col = (b_col + 1) % 6
            elif a_col == b_col:
                a_row = (a_row + 1) % 6
                b_row = (b_row + 1) % 6
            else:
                a_col, b_col = b_col, a_col
            ciphertext += self.square1[a_row*6 + a_col]

            ciphertext += self.square2[b_row*6 + b_col]
        return ciphertext

    def decode(self, ciphertext):
        plaintext = ""
        for i in range(0, len(ciphertext), 2):
            a = ciphertext[i]
            b = ciphertext[i+1]
            a_row = self.square1.index(a) // 6
            a_col = self.square1.index(a) % 6
            b_row = self.square2.index(b) // 6
            b_col = self.square2.index(b) % 6
            if a_row == b_row:
                a_col = (a_col - 1) % 6
                b_col = (b_col - 1) % 6
            elif a_col == b_col:
                a_row = (a_row - 1) % 6
                b_row = (b_row - 1) % 6
            else:
                a_col, b_col = b_col, a_col
            plaintext += self.square1[a_row*6 + a_col]

            plaintext += self.square2[b_row*6 + b_col]
        return plaintext


    def frequency_analysis(text):
        frequencies = dict()
        total_chars = 0

        for char in text:
            if char.isalpha():
                char = char.lower()
                frequencies[char] = frequencies.get(char, 0) + 1
                total_chars += 1

        items = frequencies.items()
        for char, count in sorted(items, key=lambda i: i[0]):
            frequency = count / total_chars * 100
            print(f"{char}: {frequency:.2f}%")