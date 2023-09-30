import math

alphabet_normal = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя .,"


def frequency_analysis(text: str, alphabet: str) -> dict:
    frequencies = {c: 0 for c in alphabet}
    total_chars = 0

    for char in text:
        c = char.lower()
        if c in alphabet:
            frequencies[c] = frequencies.get(c, 0) + 1
            total_chars += 1

    for char, count in frequencies.items():
        frequency = count / total_chars * 100
        frequencies[char] = frequency

    return frequencies

