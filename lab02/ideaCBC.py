class IDEA_CBC:
    def __init__(self, key, iv):
        self._keys = None
        self._iv = iv
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

        # Step 1
        p1 = self.mul_mod(p1, k1)
        p4 = self.mul_mod(p4, k4)
        p2 = self.add_mod(p2, k2)
        p3 = self.add_mod(p3, k3)
        # Step 2
        x = p1 ^ p3
        t0 = self.mul_mod(k5, x)
        x = p2 ^ p4
        x = self.add_mod(t0, x)
        t1 = self.mul_mod(k6, x)
        t2 = self.add_mod(t0, t1)
        # Step 3
        p1 = p1 ^ t1
        p4 = p4 ^ t2
        a = p2 ^ t2
        p2 = p3 ^ t1
        p3 = a

        return p1, p2, p3, p4

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

    def encrypt(self, plain):
        p1 = (plain >> 48) & 0xFFFF
        p2 = (plain >> 32) & 0xFFFF
        p3 = (plain >> 16) & 0xFFFF
        p4 = plain & 0xFFFF

        encrypted = 0
        for i in range(8):
            keys = self._keys[i]

            # Apply XOR with previous ciphertext (or IV in the first round)
            if i == 0:
                p1 ^= self._iv >> 48
                p2 ^= self._iv >> 32
                p3 ^= self._iv >> 16
                p4 ^= self._iv
            else:
                p1 ^= (encrypted >> 48) & 0xFFFF
                p2 ^= (encrypted >> 32) & 0xFFFF
                p3 ^= (encrypted >> 16) & 0xFFFF
                p4 ^= encrypted & 0xFFFF

            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

            # Update previous ciphertext
            encrypted = (encrypted << 64) | ((p1 << 48) | (p2 << 32) | (p3 << 16) | p4)

        return encrypted

    def decrypt(self, encrypted):
        p1 = (encrypted >> 48) & 0xFFFF
        p2 = (encrypted >> 32) & 0xFFFF
        p3 = (encrypted >> 16) & 0xFFFF
        p4 = encrypted & 0xFFFF

        decrypted = 0
        for i in range(8):
            keys = self._keys[7 - i]

            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

            # Apply XOR with previous ciphertext (or IV in the last round)
            if i == 7:
                p1 ^= self._iv >> 48
                p2 ^= self._iv >> 32
                p3 ^= self._iv >> 16
                p4 ^= self._iv
            else:
                p1 ^= (encrypted >> 48) & 0xFFFF
                p2 ^= (encrypted >> 32) & 0xFFFF
                p3 ^= (encrypted >> 16) & 0xFFFF
                p4 ^= encrypted & 0xFFFF

            # Update previous ciphertext
            decrypted = (decrypted << 64) | ((p1 << 48) | (p2 << 32) | (p3 << 16) | p4)

        return decrypted


def main():
    key = 0x2BD6459F82C5B300952C49104881FF48
    iv = 0x1234567890ABCDEF
    plain = 0xF129A6601EF62A47

    my_IDEA = IDEA_CBC(key, iv)
    encrypted = my_IDEA.encrypt(plain)
    print('encrypted\t', hex(encrypted))

    decrypted = my_IDEA.decrypt(encrypted)
    print('decrypted\t', hex(decrypted))

if __name__ == '__main__':
    main()
