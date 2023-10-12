def _mul(x, y):
    assert 0 <= x <= 0xFFFF
    assert 0 <= y <= 0xFFFF

    if x == 0:
        x = 0x10000
    if y == 0:
        y = 0x10000

    r = (x * y) % 0x10001

    if r == 0x10000:
        r = 0

    assert 0 <= r <= 0xFFFF
    return r
def _inv_mul(x):
    assert 0 <= x <= 0xFFFF

    if x <= 1:
        return x

    y = 0x10001
    t0 = 1
    t1 = 0

    while True:
        t0, t1 = t1, t0 - (x // y) * t1
        x, y = y, x % y

        if y == 1:
            return (1 - t1) & 0xFFFF


def _KA_layer(x1, x2, x3, x4, round_keys):
    assert 0 <= x1 <= 0xFFFF
    assert 0 <= x2 <= 0xFFFF
    assert 0 <= x3 <= 0xFFFF
    assert 0 <= x4 <= 0xFFFF
    z1, z2, z3, z4 = round_keys[0:4]
    assert 0 <= z1 <= 0xFFFF
    assert 0 <= z2 <= 0xFFFF
    assert 0 <= z3 <= 0xFFFF
    assert 0 <= z4 <= 0xFFFF

    y1 = _mul(x1, z1)
    y2 = (x2 + z2) % 0x10000
    y3 = (x3 + z3) % 0x10000
    y4 = _mul(x4, z4)

    return y1, y2, y3, y4
def _inv_KA_layer(y1, y2, y3, y4, round_keys):
    assert 0 <= y1 <= 0xFFFF
    assert 0 <= y2 <= 0xFFFF
    assert 0 <= y3 <= 0xFFFF
    assert 0 <= y4 <= 0xFFFF
    z1, z2, z3, z4 = round_keys[0:4]
    assert 0 <= z1 <= 0xFFFF
    assert 0 <= z2 <= 0xFFFF
    assert 0 <= z3 <= 0xFFFF
    assert 0 <= z4 <= 0xFFFF

    x1 = _inv_mul(y1)
    x2 = (y2 - z2) % 0x10000
    x3 = (y3 - z3) % 0x10000
    x4 = _inv_mul(y4)

    return x1, x2, x3, x4

def _MA_layer(y1, y2, y3, y4, round_keys):
    assert 0 <= y1 <= 0xFFFF
    assert 0 <= y2 <= 0xFFFF
    assert 0 <= y3 <= 0xFFFF
    assert 0 <= y4 <= 0xFFFF
    z5, z6 = round_keys[4:6]
    assert 0 <= z5 <= 0xFFFF
    assert 0 <= z6 <= 0xFFFF

    p = y1 ^ y3
    q = y2 ^ y4

    s = _mul(p, z5)
    t = _mul((q + s) % 0x10000, z6)
    u = (s + t) % 0x10000

    x1 = y1 ^ t
    x2 = y2 ^ u
    x3 = y3 ^ t
    x4 = y4 ^ u

    return x1, x2, x3, x4

def _inv_MA_layer(x1, x2, x3, x4, round_keys):
    assert 0 <= x1 <= 0xFFFF
    assert 0 <= x2 <= 0xFFFF
    assert 0 <= x3 <= 0xFFFF
    assert 0 <= x4 <= 0xFFFF
    z5, z6 = round_keys[4:6]
    assert 0 <= z5 <= 0xFFFF
    assert 0 <= z6 <= 0xFFFF

    t = _inv_mul(x1 ^ x3)
    u = (x2 ^ x4) ^ t

    y1 = x1 ^ _inv_mul((x3 ^ u) % 0x10000)
    y2 = u
    y3 = x3 ^ _inv_mul((x1 ^ t) % 0x10000)
    y4 = x4 ^ _inv_mul(u)

    return y1, y2, y3, y4


class IDEA:
    def __init__(self, key):
        self._keys = None
        self.change_key(key)

    def change_key(self, key):
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

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << 64)
        x1 = (plaintext >> 48) & 0xFFFF
        x2 = (plaintext >> 32) & 0xFFFF
        x3 = (plaintext >> 16) & 0xFFFF
        x4 = plaintext & 0xFFFF

        for i in range(8):
            round_keys = self._keys[i]

            y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, round_keys)
            x1, x2, x3, x4 = _MA_layer(y1, y2, y3, y4, round_keys)

            x2, x3 = x3, x2

        y1, y2, y3, y4 = _KA_layer(x1, x3, x2, x4, self._keys[8])

        ciphertext = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return ciphertext

    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << 64)
        y1 = (ciphertext >> 48) & 0xFFFF
        y2 = (ciphertext >> 32) & 0xFFFF
        y3 = (ciphertext >> 16) & 0xFFFF
        y4 = ciphertext & 0xFFFF

        y2, y3 = y3, y2

        x1, x2, x3, x4 = _inv_KA_layer(y1, y3, y2, y4, self._keys[8])

        for i in range(7, -1, -1):
            round_keys = self._keys[i]

            y1, y2, y3, y4 = _inv_MA_layer(x1, x2, x3, x4, round_keys)
            x1, x2, x3, x4 = _inv_KA_layer(y1, y2, y3, y4, round_keys)

            x2, x3 = x3, x2

        plaintext = (x1 << 48) | (x2 << 32) | (x3 << 16) | x4
        return plaintext


def main():
    key = 0x2BD6459F82C5B300952C49104881FF48
    plain = 0xF129A6601EF62A47
    cipher = 0xEA024714AD5C4D84

    print('key\t\t', hex(key))
    print('plaintext\t', hex(plain))

    my_IDEA = IDEA(key)
    encrypted = my_IDEA.encrypt(plain)
    assert encrypted == cipher

    decrypted = my_IDEA.decrypt(encrypted)
    # assert decrypted == plain

    print('ciphertext\t', hex(cipher))
    print('decrypted\t', hex(decrypted))


if __name__ == '__main__':
    main()
