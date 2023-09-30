class IDEA:
    def __init__(self, key):
        self.key = key

    def _multiply(self, a, b):
        if a == 0:
            a = 0x10001
        if b == 0:
            b = 0x10001
        p = (a * b) % 0x10001
        return p

    def _add(self, a, b):
        return (a + b) & 0xffff

    def _subtract(self, a, b):
        return (a - b) & 0xffff

    def _multiply_inverse(self, a):
        if a <= 1:
            return a
        t1 = 0x10001
        t2 = a
        t3 = 0
        t4 = 1
        while t2 != 1:
            q = t1 // t2
            t3, t1 = t1, t2
            t4, t2 = t2, self._subtract(t3, self._multiply(q, t2))
        if t4 < 0:
            t4 = self._add(t4, 0x10001)
        return t4

    def _expand_key(self, key):
        expanded_key = []
        for i in range(8):
            expanded_key.append((key >> (16 * (7 - i))) & 0xffff)
        for i in range(8, 52):
            expanded_key.append((expanded_key[i - 7] << 9) | (expanded_key[i - 6] >> 7))
        return expanded_key

    def _encrypt_block(self, block, expanded_key):
        x1 = (block >> 48) & 0xffff
        x2 = (block >> 32) & 0xffff
        x3 = (block >> 16) & 0xffff
        x4 = block & 0xffff

        for round in range(8):
            round_key_index = round * 6
            round_key = expanded_key[round_key_index:round_key_index + 6]

            x1 = self._multiply(x1, round_key[0])
            x2 = self._add(x2, round_key[1])
            x3 = self._add(x3, round_key[2])
            x4 = self._multiply(x4, round_key[3])

            t2 = self._multiply(x1 ^ x3, round_key[4])
            t1 = self._add(x2 ^ x4, t2)
            t1 = self._multiply(t1, round_key[5])
            t2 = self._add(t2, t1)

            x1 = x1 ^ t1
            x4 = x4 ^ t2

            x1, x2, x3, x4 = x2, x3, x4, x1

        x1 = self._multiply(x1, expanded_key[48])
        x2 = self._add(x2, expanded_key[49])
        x3 = self._add(x3, expanded_key[50])
        x4 = self._multiply(x4, expanded_key[51])

        return (x1 << 48) | (x2 << 32) | (x3 << 16) | x4

    def _decrypt_block(self, block, expanded_key):
        x1 = (block >> 48) & 0xffff
        x2 = (block >> 32) & 0xffff
        x3 = (block >> 16) & 0xffff
        x4 = block & 0xffff

        for round in range(8):
            round_key_index = (7 - round) * 6
            round_key = expanded_key[round_key_index:round_key_index + 6]

            x1 = self._multiply(x1, round_key[0])
            x2 = self._add(x2, round_key[1])
            x3 = self._add(x3, round_key[2])
            x4 = self._multiply(x4, round_key[3])

            t2 = self._multiply(x1 ^ x3, round_key[4])
            t1 = self._add(x2 ^ x4, t2)
            t1 = self._multiply(t1, round_key[5])
            t2 = self._add(t2, t1)

            x1 = x1 ^ t1
            x4 = x4 ^ t2

            x1, x2, x3, x4 = x2 & 0xffff, x3 & 0xffff, x4 & 0xffff, x1 & 0xffff

        x1 = self._multiply(x1, self._multiply_inverse(expanded_key[48]))
        x2 = self._subtract(x2, expanded_key[49])
        x3 = self._subtract(x3, expanded_key[50])
        x4 = self._multiply(x4, self._multiply_inverse(expanded_key[51]))

        return (x1 << 48) | (x2 << 32) | (x3 << 16) | x4

    def encrypt(self, plaintext):
        expanded_key = self._expand_key(self.key)
        ciphertext = []
        for block in plaintext:
            ciphertext.append(self._encrypt_block(block, expanded_key))
        return ciphertext

    def decrypt(self, ciphertext):
        expanded_key = self._expand_key(self.key)
        plaintext = []
        for block in ciphertext:
            plaintext.append(self._decrypt_block(block, expanded_key))
        return plaintext