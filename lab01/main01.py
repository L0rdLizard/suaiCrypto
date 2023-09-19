import alphabet as alphabet

from lab01.DoubleSquareCipher import DoubleSquareCipher
from lab01.DoubleSquare import DoubleSquare
from lab01.analys import frequency_analysis
from alphabetRus.rusAlphabet import alphabet_frequencies

alphabet_normal = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя .,"

cipher = DoubleSquareCipher("секрет", "птица")

# address = "voyna-i-mir.txt"
address = "bigText.txt"

ciphertext = cipher.encode(address)
decoded_plaintext = cipher.decode(ciphertext)

with open(address, 'r', encoding='utf-8') as f:
    plaintext = f.read()

print("Address:", address)
print("plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decoded plaintext:", decoded_plaintext)

print()


print("Частотный анализ:")
frequencies = frequency_analysis(ciphertext, alphabet_normal)

for char, frequency in frequencies.items():
    print(f"{char}: {frequency:.2f}%")

# founded_shift = find_shift(ciphertext, alphabet_normal, alphabet_frequencies)
# print("Вычисленный сдвиг:", founded_shift)
