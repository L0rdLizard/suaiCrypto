from PIL import Image

# Ключевая последовательность (128 бит)
key_sequence = b'0123456789abcdef'

# Функция для разделения блока на подблоки
def split_block(block):
    subblocks = []
    for i in range(4):
        subblock = int.from_bytes(block[i * 2 : i * 2 + 2], 'big')
        subblocks.append(subblock)
    return subblocks

# Функция для объединения подблоков в блок
def combine_subblocks(subblocks):
    block = 0
    for i, subblock in enumerate(subblocks):
        block |= subblock << (i * 16)
    return block

# Функция для выполнения шагов алгоритма IDEA над подблоками
def process_subblocks(subblocks, round_keys):
    for i in range(8):
        subblock = subblocks[i % 4]
        round_key = round_keys[i]

        # Шаги алгоритма IDEA
        subblock = multiply(subblock, round_key)
        subblock = add(subblock, round_keys[i + 1])
        subblock = xor(subblock, round_keys[i + 2])

        subblocks[i % 4] = subblock

    return subblocks

def xor(a, b):
    result = a ^ b
    return result

def add(a, b):
    result = (a + b) & 0xFFFF
    return result

def multiply(a, b):
    if a == 0:
        a = 0x10000
    if b == 0:
        b = 0x10000

    result = (a * b) % 0x10001
    if result == 0x10000:
        result = 0

    return result

def split_data_into_blocks(data, block_size=8):
    blocks = []
    num_blocks = len(data) // block_size

    for i in range(num_blocks):
        block = data[i * block_size : (i + 1) * block_size]
        blocks.append(block)

    return blocks


# Функция для шифрования блока данных
def encrypt_block(block, key):
    subblocks = split_block(block)
    processed_subblocks = process_subblocks(subblocks, key)
    encrypted_block = combine_subblocks(processed_subblocks)

    return encrypted_block

# Функция для дешифрации блока данных
def decrypt_block(block, key):
    subblocks = split_block(block)
    processed_subblocks = process_subblocks(subblocks, key)
    decrypted_block = combine_subblocks(processed_subblocks)

    return decrypted_block

# Функция для шифрования файла
def encrypt_file(input_file, output_file, key):
    # Чтение данных из входного файла
    with open(input_file, 'rb') as file:
        data = file.read()

    # Разделение данных на блоки
    blocks = split_data_into_blocks(data)

    # Шифрование и объединение блоков
    encrypted_data = b""
    for block in blocks:
        encrypted_block = encrypt_block(block, key)
        encrypted_data += encrypted_block.to_bytes(8, 'big')

    # Запись зашифрованных данных в выходной файл
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)


# Функция для дешифрации файла
def decrypt_file(input_file, output_file, key):
    # Read encrypted data from the input file with the correct encoding
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    # Split encrypted data into blocks
    blocks = split_data_into_blocks(encrypted_data)

    # Decrypt and combine blocks
    decrypted_data = b""
    for block in blocks:
        decrypted_block = decrypt_block(block, key)
        decrypted_data += decrypted_block.to_bytes(8, 'big')

    # Write decrypted data to the output file with the correct encoding
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)



# Пример использования функций для шифрования и дешифрации файла
input_file = 'input.txt'
encrypted_file = 'encrypted.bin'
decrypted_file = 'decrypted.txt'

encrypt_file(input_file, encrypted_file, key_sequence)
decrypt_file(encrypted_file, decrypted_file, key_sequence)
