
import maes_optimized
import maes_padding

# Crear una instancia de cifrado AES en modo CBC
key = b'0123456789abcdef'  # Llave de 16 bytes (AES-128)
iv = b'abcdefghijklmnop'  # Vector de inicialización para CBC
cipher = maes_optimized.new(key, maes_optimized.MODE_CBC, iv)

# Texto original
plaintext = b'This is a secret phrase'

# Aplicar padding para asegurar que la longitud sea múltiplo de 16
padded_plaintext = maes_padding.pad(plaintext)

# Cifrar datos
encrypted = cipher.encrypt(padded_plaintext) # texto ya cifrado
print(f"encrypted: {encrypted}")

# Descifrar datos
cipher = maes_optimized.new(key, maes_optimized.MODE_CBC, iv)
decrypted = cipher.decrypt(encrypted)

# Eliminar el padding para obtener el texto original
original = maes_padding.unpad(decrypted)

print(original)  # Debería imprimir b'This is a secret'

print(maes_padding.decode(original))  # Convertirá a texto legible

