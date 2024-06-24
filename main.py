import hashlib
from sympy import mod_inverse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii

# PARTE 1 ------------------------------------------------------------------
# dados fornecidos
p = 62948365567077381076785749437466289389
a = 12345678901234567890123456789
B_x = 19283739880924114996531797216199530358
B_y = 40955782276983534261924476760645212500

# função para adicionar dois pontos na curva elíptica
def elliptic_curve_addition(x1, y1, x2, y2, a, p):
    if x1 == x2 and y1 == y2:
        # adição de um ponto consigo mesmo (dobrar o ponto)
        m = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p)
    else:
        # adição de dois pontos diferentes
        m = (y2 - y1) * mod_inverse(x2 - x1, p)
    
    m = m % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    
    return x3, y3

# função para multiplicar um ponto na curva elíptica por um escalar
def elliptic_curve_multiplication(x, y, k, a, p):
    k_bin = bin(k)[2:]
    Q_x, Q_y = x, y
    
    for i in range(1, len(k_bin)):
        Q_x, Q_y = elliptic_curve_addition(Q_x, Q_y, Q_x, Q_y, a, p)
        if k_bin[i] == '1':
            Q_x, Q_y = elliptic_curve_addition(Q_x, Q_y, x, y, a, p)
    
    return Q_x, Q_y

# multiplicação do ponto B pelo valor a
V_x, V_y = elliptic_curve_multiplication(B_x, B_y, a, 2, p)

print(f"Ponto V: ({V_x},{V_y})")

# PARTE 2 ------------------------------------------------------------------
# concatenar as coordenadas do ponto V em uma string
V_str = f"{V_x}{V_y}\n"

# calcular o hash SHA-256 da string e pegar os primeiros 128 bits
hash_obj = hashlib.sha256(V_str.encode())
hash_hex = hash_obj.hexdigest()
k = hash_hex[:32]  # pegar os primeiros 128 bits (32 caracteres hexadecimais)

print(f"Chave k: {k}")

# PARTE 3 ------------------------------------------------------------------
# dados fornecidos
c_hex = "D59D64D83AA6C17BAD5B7386978962B6B21AA267354BE5AA29C4"
iv_hex = "01010101010101010101010101010101"

# converter hex para bytes
k_bytes = binascii.unhexlify(k)
c_bytes = binascii.unhexlify(c_hex)
iv_bytes = binascii.unhexlify(iv_hex)

# configurar o algoritmo AES em modo CTR
cipher = Cipher(algorithms.AES(k_bytes), modes.CTR(iv_bytes), backend=default_backend())
decryptor = cipher.decryptor()

# decriptar a mensagem
m_bytes = decryptor.update(c_bytes) + decryptor.finalize()

# converter a mensagem de bytes para string
m_str = m_bytes.decode('utf-8')

print(f"Mensagem decifrada: {m_str}")
