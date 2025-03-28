# maes_optimized.py

"""
Implementación de AES optimizada para MicroPython siguiendo la API PEP-272
Basado en: https://bitbucket.org/intgr/pyaes/ pero con optimizaciones para MicroPython

https://github.com/piaca/micropython-aes/blob/master/maes.py
"""

import ubinascii
from array import array
from micropython import const

# Constantes para mejorar la eficiencia de memoria
MODE_ECB = const(1)
MODE_CBC = const(2)

# Tamaños de bloque estándar
BLOCK_SIZE = const(16)

# Clase para manejar las tablas y constantes para AES
class AESConstants:
    # Las tablas se cargan una sola vez cuando se inicializa la clase
    __slots__ = ()
    
    # S-boxes precalculadas
    sbox = None
    inv_sbox = None
    
    # Tablas de multiplicación para GF(2^8)
    mul_2 = None
    mul_3 = None
    mul_9 = None
    mul_11 = None
    mul_13 = None
    mul_14 = None
    
    # Constantes Rcon
    Rcon = None
    
    @staticmethod
    def init_tables():
        """Inicializar todas las tablas necesarias para AES"""
        if AESConstants.sbox is not None:
            return  # Ya fueron inicializadas
            
        # Inicializar S-boxes
        AESConstants.sbox = array(
            'B',
            ubinascii.unhexlify(
                '637c777bf26b6fc53001672bfed7ab76'
                'ca82c97dfa5947f0add4a2af9ca472c0'
                'b7fd9326363ff7cc34a5e5f171d83115'
                '04c723c31896059a071280e2eb27b275'
                '09832c1a1b6e5aa0523bd6b329e32f84'
                '53d100ed20fcb15b6acbbe394a4c58cf'
                'd0efaafb434d338545f9027f503c9fa8'
                '51a3408f929d38f5bcb6da2110fff3d2'
                'cd0c13ec5f974417c4a77e3d645d1973'
                '60814fdc222a908846eeb814de5e0bdb'
                'e0323a0a4906245cc2d3ac629195e479'
                'e7c8376d8dd54ea96c56f4ea657aae08'
                'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
                '703eb5664803f60e613557b986c11d9e'
                'e1f8981169d98e949b1e87e9ce5528df'
                '8ca1890dbfe6426841992d0fb054bb16'
            )
        )
        
        AESConstants.inv_sbox = array(
            'B',
            ubinascii.unhexlify(
                '52096ad53036a538bf40a39e81f3d7fb'
                '7ce339829b2fff87348e4344c4dee9cb'
                '547b9432a6c2233dee4c950b42fac34e'
                '082ea16628d924b2765ba2496d8bd125'
                '72f8f66486689816d4a45ccc5d65b692'
                '6c704850fdedb9da5e154657a78d9d84'
                '90d8ab008cbcd30af7e45805b8b34506'
                'd02c1e8fca3f0f02c1afbd0301138a6b'
                '3a9111414f67dcea97f2cfcef0b4e673'
                '96ac7422e7ad3585e2f937e81c75df6e'
                '47f11a711d29c5896fb7620eaa18be1b'
                'fc563e4bc6d279209adbc0fe78cd5af4'
                '1fdda8338807c731b11210592780ec5f'
                '60517fa919b54a0d2de57a9f93c99cef'
                'a0e03b4dae2af5b0c8ebbb3c83539961'
                '172b047eba77d626e169146355210c7d'
            )
        )
        
        # Inicializar Rcon
        AESConstants.Rcon = array(
            'B',
            ubinascii.unhexlify(
                '8d01020408102040801b366cd8ab4d9a'
                '2f5ebc63c697356ad4b37dfaefc59139'
                '72e4d3bd61c29f254a943366cc831d3a'
                '74e8cb8d01020408102040801b366cd8'
                'ab4d9a2f5ebc63c697356ad4b37dfaef'
                'c5913972e4d3bd61c29f254a943366cc'
                '831d3a74e8cb8d01020408102040801b'
                '366cd8ab4d9a2f5ebc63c697356ad4b3'
                '7dfaefc5913972e4d3bd61c29f254a94'
                '3366cc831d3a74e8cb8d010204081020'
                '40801b366cd8ab4d9a2f5ebc63c69735'
                '6ad4b37dfaefc5913972e4d3bd61c29f'
                '254a943366cc831d3a74e8cb8d010204'
                '08102040801b366cd8ab4d9a2f5ebc63'
                'c697356ad4b37dfaefc5913972e4d3bd'
                '61c29f254a943366cc831d3a74e8cb'
            )
        )
        
        # Cálculo de las tablas de multiplicación Galois Field para AES
        def galois_multiply(a, b):
            p = 0
            while b:
                if b & 1:
                    p ^= a
                a <<= 1
                if a & 0x100:
                    a ^= 0x1b
                b >>= 1
            return p & 0xff
        
        # Precalcular las tablas de multiplicación
        AESConstants.mul_2 = array('B', [galois_multiply(x, 2) for x in range(256)])
        AESConstants.mul_3 = array('B', [galois_multiply(x, 3) for x in range(256)])
        AESConstants.mul_9 = array('B', [galois_multiply(x, 9) for x in range(256)])
        AESConstants.mul_11 = array('B', [galois_multiply(x, 11) for x in range(256)])
        AESConstants.mul_13 = array('B', [galois_multiply(x, 13) for x in range(256)])
        AESConstants.mul_14 = array('B', [galois_multiply(x, 14) for x in range(256)])

# Inicializar todas las tablas
def init():
    """Inicializar el módulo AES"""
    AESConstants.init_tables()

# Función para crear nuevas instancias de cifrado
def new(key, mode, IV=None):
    """
    Crear una nueva instancia de cifrado AES
    
    Args:
        key (bytes): Llave de 16, 24 o 32 bytes
        mode (int): Modo de cifrado (MODE_ECB, MODE_CBC)
        IV (bytes, opcional): Vector de inicialización para CBC
        
    Returns:
        Objeto cifrador con métodos encrypt y decrypt
    """
    # Asegurar que las tablas estén inicializadas
    AESConstants.init_tables()
    
    if mode == MODE_ECB:
        return ECBMode(AES(key))
    elif mode == MODE_CBC:
        if IV is None:
            raise ValueError("El modo CBC necesita un valor IV")
        return CBCMode(AES(key), IV)
    else:
        raise NotImplementedError("Modo no soportado")

class AES:
    """Implementación del cifrado AES (Advanced Encryption Standard)"""
    
    __slots__ = ('key', 'key_size', 'rounds', 'exkey')
    
    def __init__(self, key):
        """
        Inicializar con una llave específica
        
        Args:
            key (bytes): Llave de 16, 24 o 32 bytes
        """
        self.setkey(key)
    
    def setkey(self, key):
        """
        Establecer la llave y realizar la expansión de la llave
        
        Args:
            key (bytes): Llave de 16, 24 o 32 bytes
        """
        self.key = key
        self.key_size = len(key)
        
        if self.key_size == 16:
            self.rounds = 10
        elif self.key_size == 24:
            self.rounds = 12
        elif self.key_size == 32:
            self.rounds = 14
        else:
            raise ValueError("La longitud de la llave debe ser 16, 24 o 32 bytes")
        
        self.expand_key()
    
    def expand_key(self):
        """Realizar la expansión de la llave AES y almacenarla en self.exkey"""
        # La llave expandida comienza con la llave actual
        exkey = array('B', self.key)
        
        # Pasos adicionales de expansión de la llave
        if self.key_size == 16:
            extra_cnt = 0
        elif self.key_size == 24:
            extra_cnt = 2
        else:
            extra_cnt = 3
        
        # Variable temporal de 4 bytes para la expansión de la llave
        word = exkey[-4:]
        # Cada ciclo de expansión usa 'i' una vez para la búsqueda en la tabla Rcon
        for i in range(1, 11):
            # Rotación a la izquierda por 1 byte
            word = word[1:4] + word[0:1]
            
            # Aplicar S-box a todos los bytes
            for j in range(4):
                word[j] = AESConstants.sbox[word[j]]
            
            # Aplicar la tabla Rcon al byte más a la izquierda
            word[0] ^= AESConstants.Rcon[i]
            
            for z in range(4):
                for j in range(4):
                    # Mezclar bytes de la última subclave
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)
            
            # El último ciclo de expansión de la llave siempre termina aquí
            if len(exkey) >= (self.rounds + 1) * BLOCK_SIZE:
                break
            
            # Paso de sustitución especial para llave de 256 bits
            if self.key_size == 32:
                for j in range(4):
                    # Mezclar bytes de la última subclave XOR con S-box
                    word[j] = AESConstants.sbox[word[j]] ^ exkey[-self.key_size + j]
                exkey.extend(word)
            
            # Dos veces para llave de 192 bits, tres veces para llave de 256 bits
            for z in range(extra_cnt):
                for j in range(4):
                    # Mezclar bytes de la última subclave
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)
        
        self.exkey = exkey
    
    def add_round_key(self, block, round):
        """
        Paso AddRoundKey. Aquí es donde la llave se mezcla con el texto plano
        
        Args:
            block (array): Bloque a procesar
            round (int): Ronda actual
        """
        offset = round * 16
        exkey = self.exkey
        
        for i in range(16):
            block[i] ^= exkey[offset + i]
    
    def sub_bytes(self, block, sbox):
        """
        Paso SubBytes, aplicar S-box a todos los bytes
        
        Args:
            block (array): Bloque a procesar
            sbox (array): S-box a utilizar (normal o inversa)
        """
        for i in range(16):
            block[i] = sbox[block[i]]
    
    def shift_rows(self, b):
        """
        Paso ShiftRows en AES
        Desplaza la 2da fila a la izquierda por 1, 3ra fila por 2, 4ta fila por 3
        """
        b[1], b[5], b[9], b[13] = b[5], b[9], b[13], b[1]
        b[2], b[6], b[10], b[14] = b[10], b[14], b[2], b[6]
        b[3], b[7], b[11], b[15] = b[15], b[3], b[7], b[11]
    
    def shift_rows_inv(self, b):
        """
        Similar a shift_rows, pero realizado de forma inversa para descifrado
        """
        b[5], b[9], b[13], b[1] = b[1], b[5], b[9], b[13]
        b[10], b[14], b[2], b[6] = b[2], b[6], b[10], b[14]
        b[15], b[3], b[7], b[11] = b[3], b[7], b[11], b[15]
    
    def mix_columns(self, block):
        """Paso MixColumns. Mezcla los valores en cada columna"""
        # Usar las tablas de multiplicación precalculadas
        mul_2 = AESConstants.mul_2
        mul_3 = AESConstants.mul_3
        
        # Como estamos tratando con una matriz transpuesta, las columnas ya son secuenciales
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col:col + 4]
            
            block[col] = mul_2[v0] ^ v3 ^ v2 ^ mul_3[v1]
            block[col + 1] = mul_2[v1] ^ v0 ^ v3 ^ mul_3[v2]
            block[col + 2] = mul_2[v2] ^ v1 ^ v0 ^ mul_3[v3]
            block[col + 3] = mul_2[v3] ^ v2 ^ v1 ^ mul_3[v0]
    
    def mix_columns_inv(self, block):
        """
        Similar a mix_columns, pero realizado de forma inversa para descifrado
        """
        # Usar las tablas de multiplicación precalculadas
        mul_9 = AESConstants.mul_9
        mul_11 = AESConstants.mul_11
        mul_13 = AESConstants.mul_13
        mul_14 = AESConstants.mul_14
        
        # Como estamos tratando con una matriz transpuesta, las columnas ya son secuenciales
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col:col + 4]
            
            block[col] = mul_14[v0] ^ mul_9[v3] ^ mul_13[v2] ^ mul_11[v1]
            block[col + 1] = mul_14[v1] ^ mul_9[v0] ^ mul_13[v3] ^ mul_11[v2]
            block[col + 2] = mul_14[v2] ^ mul_9[v1] ^ mul_13[v0] ^ mul_11[v3]
            block[col + 3] = mul_14[v3] ^ mul_9[v2] ^ mul_13[v1] ^ mul_11[v0]
    
    def encrypt_block(self, block):
        """
        Cifra un solo bloque. Esta es la función principal de AES
        
        Args:
            block (array): Bloque a cifrar
        """
        self.add_round_key(block, 0)
        
        for round in range(1, self.rounds):
            self.sub_bytes(block, AESConstants.sbox)
            self.shift_rows(block)
            self.mix_columns(block)
            self.add_round_key(block, round)
        
        self.sub_bytes(block, AESConstants.sbox)
        self.shift_rows(block)
        # No hay paso mix_columns en la última ronda
        self.add_round_key(block, self.rounds)
    
    def decrypt_block(self, block):
        """
        Descifra un solo bloque. Esta es la función principal de descifrado AES
        
        Args:
            block (array): Bloque a descifrar
        """
        self.add_round_key(block, self.rounds)
        
        # Contar rondas hacia abajo desde (self.rounds) ... 1
        for round in range(self.rounds - 1, 0, -1):
            self.shift_rows_inv(block)
            self.sub_bytes(block, AESConstants.inv_sbox)
            self.add_round_key(block, round)
            self.mix_columns_inv(block)
        
        self.shift_rows_inv(block)
        self.sub_bytes(block, AESConstants.inv_sbox)
        self.add_round_key(block, 0)

class CipherMode:
    """Clase base para diferentes modos de cifrado"""
    
    __slots__ = ('cipher', 'block_size')
    
    def __init__(self, cipher):
        """
        Inicializar modo de cifrado
        
        Args:
            cipher (AES): Instancia de cifrado AES
        """
        self.cipher = cipher
        self.block_size = BLOCK_SIZE

class ECBMode(CipherMode):
    """
    Modo Electronic CodeBook (ECB)
    
    Este modo aplica la función de cifrado a cada bloque individualmente;
    no hay retroalimentación. ¡ADVERTENCIA! Es inseguro para casi todos los propósitos.
    """
    
    def ecb(self, data, block_func):
        """
        Realizar modo ECB con la función dada
        
        Args:
            data (bytes): Datos a procesar
            block_func (function): Función de cifrado o descifrado
            
        Returns:
            array: Datos procesados
        """
        if len(data) % self.block_size != 0:
            raise ValueError("La longitud de entrada debe ser múltiplo de 16")
        
        block_size = self.block_size
        data = array('B', data)
        
        for offset in range(0, len(data), block_size):
            block = data[offset:offset + block_size]
            block_func(block)
            data[offset:offset + block_size] = block
        
        return data
    
    def encrypt(self, data):
        """
        Cifrar datos en modo ECB
        
        Args:
            data (bytes): Datos a cifrar
            
        Returns:
            array: Datos cifrados
        """
        return self.ecb(data, self.cipher.encrypt_block)
    
    def decrypt(self, data):
        """
        Descifrar datos en modo ECB
        
        Args:
            data (bytes): Datos a descifrar
            
        Returns:
            array: Datos descifrados
        """
        return self.ecb(data, self.cipher.decrypt_block)

class CBCMode(CipherMode):
    """
    Modo Cipher Block Chaining (CBC). Este modo evita fugas de contenido.
    
    En el cifrado CBC, cada bloque de texto plano se XOR con el bloque de texto cifrado
    que lo precede; el descifrado es simplemente lo inverso.
    """
    
    __slots__ = ('cipher', 'block_size', 'IV')
    
    def __init__(self, cipher, IV):
        """
        Inicializar modo CBC
        
        Args:
            cipher (AES): Instancia de cifrado AES
            IV (bytes): Vector de inicialización
        """
        super().__init__(cipher)
        self.IV = array('B', IV)
    
    def encrypt(self, data):
        """
        Cifrar datos en modo CBC
        
        Args:
            data (bytes): Datos a cifrar
            
        Returns:
            array: Datos cifrados
        """
        block_size = self.block_size
        if len(data) % block_size != 0:
            raise ValueError("La longitud del texto plano debe ser múltiplo de 16")
        
        data = array('B', data)
        IV = self.IV
        
        for offset in range(0, len(data), block_size):
            block = data[offset:offset + block_size]
            
            # Realizar encadenamiento CBC
            for i in range(block_size):
                block[i] ^= IV[i]
            
            self.cipher.encrypt_block(block)
            data[offset:offset + block_size] = block
            IV = block
        
        self.IV = IV
        return data
    
    def decrypt(self, data):
        """
        Descifrar datos en modo CBC
        
        Args:
            data (bytes): Datos a descifrar
            
        Returns:
            array: Datos descifrados
        """
        block_size = self.block_size
        if len(data) % block_size != 0:
            raise ValueError("La longitud del texto cifrado debe ser múltiplo de 16")
        
        data = array('B', data)
        IV = self.IV
        
        for offset in range(0, len(data), block_size):
            ctext = data[offset:offset + block_size]
            block = ctext[:]
            self.cipher.decrypt_block(block)
            
            # Realizar encadenamiento CBC
            for i in range(block_size):
                block[i] ^= IV[i]
            
            data[offset:offset + block_size] = block
            IV = ctext
        
        self.IV = IV
        return data

# Compatibilidad con la API PEP-272
block_size = BLOCK_SIZE
key_size = None  # Variable según llave: 16, 24 o 32 bytes

# Inicializar las tablas al importar el módulo
init()