from lab01.DoubleSquareCipher import DoubleSquareCipher

cipher = DoubleSquareCipher("гуап", "люблю")

address = "bigText.txt"
ciphertext = cipher.encode(address)
decoded_plaintext = cipher.decode(ciphertext)

with open(address, 'r', encoding='utf-8') as f:
    plaintext = f.readline()

print("Address:", address)
print("plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decoded plaintext:", decoded_plaintext)

