def mul_inv(a, m):
    """
    Вычисляет обратный элемент a по модулю m
    с использованием расширенного алгоритма Евклида.
    """
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % m


def encrypt_block(block, key):
    """
    Шифрует один блок данных (64 бита) с использованием ключа.
    """
    keys = generate_round_keys(key)
    x1, x2, x3, x4 = block[:16], block[16:32], block[32:48], block[48:]
    for i in range(8):
        x1 = multiply(x1, keys[i])
        x2 = add(x2, keys[i + 1])
        x3 = add(x3, keys[i + 2])
        x4 = multiply(x4, keys[i + 3])
        t1 = xor(x1, x3)
        t2 = xor(x2, x4)
        t1 = multiply(t1, keys[i + 4])
        t2 = add(t1, t2)
        t2 = multiply(t2, keys[i + 5])
        t1 = add(t1, t2)
        x1 = xor(x1, t2)
        x2 = xor(x2, t1)
        x3 = xor(x3, t2)
        x4 = xor(x4, t1)
    x1 = multiply(x1, keys[8])
    x3 = add(x3, keys[9])
    x2 = add(x2, keys[10])
    x4 = multiply(x4, keys[11])
    return x1 + x2 + x3 + x4


def decrypt_block(block, key):
    """
    Расшифровывает один блок данных (64 бита) с использованием ключа.
    """
    keys = generate_round_keys(key)
    x1, x2, x3, x4 = block[:16], block[16:32], block[32:48], block[48:]
    for i in range(8, 0, -1):
        x1 = multiply(x1, keys[i + 3])
        x2 = add(x2, keys[i + 2])
        x3 = add(x3, keys[i + 1])
        x4 = multiply(x4, keys[i])
        t1 = xor(x1, x3)
        t2 = xor(x2, x4)
        t1 = multiply(t1, keys[i + 5])
        t2 = add(t1, t2)
        t2 = multiply(t2, keys[i + 4])
        t1 = add(t1, t2)
        x1 = xor(x1, t2)
        x2 = xor(x2, t1)
        x3 = xor(x3, t2)
        x4 = xor(x4, t1)
    x1 = multiply(x1, keys[3])
    x3 = add(x3, keys[2])
    x2 = add(x2, keys[1])
    x4 = multiply(x4, keys[0])
    return x1 + x2 + x3 + x4


def generate_round_keys(key):
    """
    Генерирует раундовые ключи для шифрования/расшифрования.
    """
    round_keys = []
    for i in range(8):
        round_keys.append((key >> (112 - 16 * i)) & 0xFFFF)
    for i in range(8, 52):
        round_keys.append((round_keys[i - 8] << 9) | (round_keys[i - 7] >> 7))
    return round_keys



def multiply(a, b):
    """
    Умножает два числа в поле GF(2^16 + 1).
    """
    a = int.from_bytes(a, byteorder='big')
    p = 0
    while a and b:
        if b & 1:
            p ^= a
        if a & 0x8000:
            a = (a << 1) ^ 0x1100B
        else:
            a <<= 1
        b >>= 1

    # Apply 16-bit mask
    p &= 0xFFFF

    return p.to_bytes(2, byteorder='big')


def add(a, b):
    """
    Выполняет операцию сложения двух чисел в поле GF(2^16 + 1).
    """
    return (a + b) & 0xFFFF


def xor(a, b):
    """
    Выполняет операцию побитового XOR двух чисел.
    """
    return a ^ b


def pad_message(message):
    """
    Дополняет сообщение до кратности 8 байт нулевыми байтами.
    """
    padding = 8 - (len(message) % 8)
    return message + b'\x00' * padding


def remove_padding(padded_message):
    """
    Удаляет дополнение из сообщения.
    """
    padding = padded_message[-1]
    return padded_message[:-padding]


def encrypt_message(message, key):
    """
    Шифрует сообщение с использованием ключа.
    """
    padded_message = pad_message(message)
    encrypted_blocks = []
    for i in range(0, len(padded_message), 8):
        block = padded_message[i:i + 8]
        encrypted_block = encrypt_block(block, key)
        encrypted_blocks.append(encrypted_block)
    encrypted_message = b''.join(encrypted_blocks)
    return encrypted_message


def decrypt_message(encrypted_message, key):
    """
    Расшифровывает сообщение с использованием ключа.
    """
    decrypted_blocks = []
    for i in range(0, len(encrypted_message), 8):
        block = encrypted_message[i:i + 8]
        decrypted_block = decrypt_block(block, key)
        decrypted_blocks.append(decrypted_block)
    decrypted_message = b''.join(decrypted_blocks)
    return remove_padding(decrypted_message)


# Пример использования:

key = 0x2BD6459F82C5B300952C49104881FF48
message = b"Hello, World!"

encrypted_message = encrypt_message(message, key)
print("Encrypted message:", encrypted_message.hex())

decrypted_message = decrypt_message(encrypted_message, key)
print("Decrypted message:", decrypted_message.decode())
