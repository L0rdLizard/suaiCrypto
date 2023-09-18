from lab01.DoubleSquareCipher import DoubleSquareCipher

cipher = DoubleSquareCipher("гуап", "люблю")

address = "bigText.txt"
ciphertext = cipher.encode(address)
decoded_plaintext = cipher.decode(ciphertext)

print("Address:", address)
print("Ciphertext:", ciphertext)
print("Decoded plaintext:", decoded_plaintext)

