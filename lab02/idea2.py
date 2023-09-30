import codecs
class IDEA:
    def __init__(self, key):
        self.key_schedule = self.generate_key_schedule(key)

    def generate_key_schedule(self, key):
        key_schedule = [[0] * 16 for _ in range(17)]
        key_length = len(key)

        for i in range(key_length):
            key_schedule[i // 8][i % 8] = ord(key[i])

        for i in range(key_length // 8, 8):
            key_schedule[i // 8][i % 8] = 0

        for i in range(8, 56):
            if i % 8 == 0:
                for j in range(8):
                    key_schedule[i // 8][j] = (key_schedule[(i - 8) // 8][j] << 9) % 65536
            elif i % 8 == 7:
                for j in range(8):
                    key_schedule[i // 8][j] = (key_schedule[(i - 8) // 8][j] >> 7) % 65536
            else:
                for j in range(8):
                    key_schedule[i // 8][j] = (key_schedule[(i - 8) // 8][j] >> 9) % 65536

        return key_schedule

    def multiply(self, a, b):
        if a == 0:
            a = 65536
        if b == 0:
            b = 65536
        return (a * b) % 65537

    def encrypt(self, plaintext):
        plaintext_length = len(plaintext)
        ciphertext = []

        for i in range(0, plaintext_length, 8):
            block = [0] * 8
            for j in range(8):
                if i + j < plaintext_length:
                    block[j] = ord(plaintext[i + j])

            x1 = (block[0] << 8) + block[1]
            x2 = (block[2] << 8) + block[3]
            x3 = (block[4] << 8) + block[5]
            x4 = (block[6] << 8) + block[7]

            for round in range(8):
                x1 = self.multiply(x1, self.key_schedule[round][0])
                x2 = (x2 + self.key_schedule[round][1]) % 65536
                x3 = (x3 + self.key_schedule[round][2]) % 65536
                x4 = self.multiply(x4, self.key_schedule[round][3])

                t1 = self.multiply(x1 ^ x3, self.key_schedule[round][4])
                t2 = self.multiply((x2 ^ x4 + t1) % 65536, self.key_schedule[round][5])
                t3 = (t1 + t2) % 65536

                x1 = x1 ^ t2
                x3 = x3 ^ t2
                x2 = x2 ^ t3
                x4 = x4 ^ t3

                x2, x3 = x3, x2

            x1 = self.multiply(x1, self.key_schedule[8][0])
            x2 = (x2 + self.key_schedule[8][1]) % 65536
            x3 = (x3 + self.key_schedule[8][2]) % 65536
            x4 = self.multiply(x4, self.key_schedule[8][3])

            ciphertext.extend([x1 >> 8, x1 & 255, x2 >> 8, x2 & 255, x3 >> 8, x3 & 255, x4 >> 8, x4 & 255])

        return ''.join([chr(byte) for byte in ciphertext])

    def decrypt(self, ciphertext):
        ciphertext_length = len(ciphertext)
        plaintext = []

        for i in range(0, ciphertext_length, 8):
            block = [0] * 8
            for j in range(8):
                if i + j < ciphertext_length:
                    block[j] = ord(ciphertext[i + j])

            x1 = (block[0] << 8) + block[1]
            x2 = (block[2] << 8) + block[3]
            x3 = (block[4] << 8) + block[5]
            x4 = (block[6] << 8) + block[7]

            for round in range(8, 0, -1):
                x1 = self.multiply(x1, self.key_schedule[round][0])
                x2 = (x2 + self.key_schedule[round][1]) % 65536
                x3 = (x3 + self.key_schedule[round][2]) % 65536
                x4 = self.multiply(x4, self.key_schedule[round][3])

                t1 = self.multiply(x1 ^ x3, self.key_schedule[round][4])
                t2 = self.multiply((x2 ^ x4 + t1) % 65536, self.key_schedule[round][5])
                t3 = (t1 + t2) % 65536

                x1 = x1 ^ t2
                x3 = x3 ^ t2
                x2 = x2 ^ t3
                x4 = x4 ^ t3

                x2, x3 = x3, x2

            x1 = self.multiply(x1, self.key_schedule[0][0])
            x2 = (x2 + self.key_schedule[0][1]) % 65536
            x3 = (x3 + self.key_schedule[0][2]) % 65536
            x4 = self.multiply(x4, self.key_schedule[0][3])

            plaintext.extend([x1 >> 8, x1 & 255, x2 >> 8, x2 & 255, x3 >> 8, x3 & 255, x4 >> 8, x4 & 255])

        return ''.join([chr(byte) for byte in plaintext])


plaintext = "Hello, World!"
key = "mysecretkey"

cipher = IDEA(key)
encrypted_text = cipher.encrypt(plaintext)
decrypted_text = cipher.decrypt(encrypted_text)

encrypted_text_bytes = encrypted_text.encode('utf-8')
decrypted_text_bytes = decrypted_text.encode('utf-8')
plaintext_bytes = plaintext.encode('utf-8')

plaintext_text_hex = plaintext_bytes.hex()
encrypted_text_hex = encrypted_text_bytes.hex()
decrypted_text_hex = decrypted_text_bytes.hex()

print("plaintext (hex):", plaintext_text_hex)
print("Encrypted text (hex):", encrypted_text_hex)
print("Decrypted text (hex):", decrypted_text_hex)
