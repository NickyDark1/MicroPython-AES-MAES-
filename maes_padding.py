# aes_padding.py
"""
Funciones de padding para complementar maes_optimized.py
"""

def pad(data, block_size=16):
    """
    Aplicar padding PKCS#7 a los datos para que sean múltiplo del tamaño de bloque
    
    Args:
        data (bytes): Datos a los que aplicar padding
        block_size (int): Tamaño de bloque (por defecto 16 bytes)
        
    Returns:
        bytes: Datos con padding aplicado
    """
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data):
    """
    Eliminar padding PKCS#7 de los datos
    
    Args:
        data (bytes): Datos con padding
        
    Returns:
        bytes: Datos sin padding
    """
    padding_len = data[-1]
    if padding_len > 16:  # máximo es el tamaño del bloque
        return data  # No es un padding válido
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            return data  # No es un padding válido
    return data[:-padding_len]

def decode(data):
    """
    Convertir bytes a texto legible
    
    Args:
        data (bytes): Datos a convertir
    
    Returns:
        str: Texto legible
    """
    return bytes(data).decode('utf-8')