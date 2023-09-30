from lab02.idea import IDEA


# key = 0x2BD6459F82C5B300952C49104881FF48  # 128-bit key
# plaintext = b'privet'

key = 0x2BD6459F82C5B300952C49104881FF48  # 128-bit key
plaintext = [0x0123, 0x4567, 0x89AB, 0xCDEF]  # 64-bit blocks

idea = IDEA(key)
ciphertext = idea.encrypt(plaintext)
decrypted_plaintext = idea.decrypt(ciphertext)

print("plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted plaintext:", decrypted_plaintext)
