import asn1
from math import gcd
from random import randint
from Crypto.Cipher import AES
from hashlib import sha256 as SHA256
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse


# парсинг ASN1 файла: просто достать все числовые значения
def parse(decoder, integers):
    while not decoder.eof():
        try:
            tag = decoder.peek()
            if tag.nr == asn1.Numbers.Null:
                break
            if tag.typ == asn1.Types.Primitive:
                tag, value = decoder.read()
                if tag.nr == asn1.Numbers.Integer:
                    integers.append(value)
            else:
                decoder.enter()
                integers = parse(decoder, integers)
                decoder.leave()
        except asn1.Error:
            break
    return integers


# шифртекст в ASN1
def cipher_to_asn(n, e, c, len, encrypted):
    encoder = asn1.Encoder()
    encoder.start()

    encoder.enter(asn1.Numbers.Sequence)  # заголовок
    encoder.enter(asn1.Numbers.Set)  # множество ключей
    encoder.enter(asn1.Numbers.Sequence)  # первый ключ (RSA)

    encoder.write(b'\x00\x01', asn1.Numbers.OctetString)  # идентификатор RSA
    encoder.write(b'\x0C\x00', asn1.Numbers.UTF8String)  # идентификатор ключа

    encoder.enter(asn1.Numbers.Sequence)  # значение открытого ключа
    encoder.write(n, asn1.Numbers.Integer)  # модуль, число n
    encoder.write(e, asn1.Numbers.Integer)  # открытая экспонента, число e
    encoder.leave()  # выход из значения открытого ключа

    encoder.enter(asn1.Numbers.Sequence)  # параметры криптосистемы (пусто)
    encoder.leave()  # выход из параметров криптосистемы

    encoder.enter(asn1.Numbers.Sequence)  # зашифрованные данные RSA
    encoder.write(c, asn1.Numbers.Integer)  # ключ AES256CBC
    encoder.leave()  # выход из зашифрованных данных RSA

    encoder.leave()  # выход из первого ключа (RSA)
    encoder.leave()  # выход из множества ключей

    encoder.enter(asn1.Numbers.Sequence)  # последовательность дополнительных данных
    encoder.write(b'\x10\x82', asn1.Numbers.OctetString)  # идентификатор алгоритма шифрования AES256CBC
    encoder.write(len, asn1.Numbers.Integer)  # длина шифртекста
    encoder.leave()  # выход из последовательности дополнительных данных
    encoder.leave()  # выход из заголовка

    encoder.write(encrypted)  # запись зашифрованных данных AES256CBC

    return encoder.output()


# шифртекст из файла ASN1
def cipher_from_asn(filename):
    integers = []
    with open(filename, "rb") as file:
        data = file.read()
        decoder = asn1.Decoder()
        decoder.start(data)
        integers = parse(decoder, integers)
        cipher = data[-integers[-1]:]
    return integers[0], integers[1], integers[2], cipher #  n, e, cipher_key, cipher_text


# подпись в ASN1
def sign_to_asn(n, e, sign):
    encoder = asn1.Encoder()
    encoder.start()

    encoder.enter(asn1.Numbers.Sequence)  # заголовок
    encoder.enter(asn1.Numbers.Set)  # множество ключей (обычно только 1)
    encoder.enter(asn1.Numbers.Sequence)  # ключ и подпись

    encoder.write(b'\x00\x40', asn1.Numbers.OctetString)  # идентификатор подписи RSA-SHA
    encoder.write(b'\x0C\x00', asn1.Numbers.UTF8String)  # строковый идентификатор ключа

    encoder.enter(asn1.Numbers.Sequence)  # значение открытого ключа
    encoder.write(n, asn1.Numbers.Integer)  # модуль, число n
    encoder.write(e, asn1.Numbers.Integer)  # открытая экспонента, число e
    encoder.leave()  # выход из значения открытого ключа

    encoder.enter(asn1.Numbers.Sequence)  # параметры криптосистемы (пусто)
    encoder.leave()  # выход их параметров криптосистемы

    encoder.enter(asn1.Numbers.Sequence)  # подпись сообщения
    encoder.write(sign, asn1.Numbers.Integer)  # число s (сама подпись)
    encoder.leave()  # выход из подписи сообщения
    encoder.leave()  # выход из ключа и подписи
    encoder.leave()  # выход из множества ключей

    encoder.enter(asn1.Numbers.Sequence)  # дополнительные данные (пусто)
    encoder.leave()  # выход из дополнительных данных
    encoder.leave()  # выход из заголовка

    return encoder.output()


# подпись из файла ASN1
def sign_from_asn(filename):
    integers = []
    with open(filename, "rb") as file:
        data = file.read()
        decoder = asn1.Decoder()
        decoder.start(data)
        integers = parse(decoder, integers)
    return integers[0], integers[2]


# зашифровать: AES-256 CBC
def encrypt_AES256CBC(plain_text, key):
    # синхропосылка
    iv = b'\x00' * AES.block_size
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plain_text, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    return ct


# расшифровать: AES-256 CBC
def decrypt_AES256CBC(cipher_text, key):
    # синхропосылка
    iv = b'\x00' * AES.block_size
    ct = b64decode(cipher_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt


# зашифровать файл
def encrypt_file(file_name, e, n):
    input_file = open(file_name, 'rb')
    plain_text = input_file.read()
    key = get_random_bytes(32) # Случайный ключ шифрования алгоритма AES
    cipher_text = encrypt_AES256CBC(plain_text, key)

    key_as_number = int.from_bytes(key, byteorder='big') # представить как число для шифрования
    cipher_key = pow(key_as_number, e, n)
    print(hex(cipher_key))
    asn1_encoded = cipher_to_asn(n, e, cipher_key, len(cipher_text), cipher_text)

    output_file = open(file_name + '.asn1', 'wb')
    output_file.write(asn1_encoded)
    print('file encrypted! result:' + file_name + '.asn1')


# расшифровать файл
def decrypt_file(file_name, d):
    n, e, cipher_key, cipher_text = cipher_from_asn(file_name + '.asn1')
    key_as_number = pow(cipher_key, d, n)
    key = key_as_number.to_bytes(32, byteorder='big')
    plain_text = decrypt_AES256CBC(cipher_text, key)

    output_file = open(file_name[:len(file_name) - 4] + '_decrypted' + file_name[len(file_name) - 4:], 'wb')
    output_file.write(plain_text)
    print('file decrypted! result:' + file_name[:len(file_name) - 4] + '_decrypted' + file_name[len(file_name) - 4:])


# подписать файл
def sign_file(file_name, e, d, n):
    input_file = open(file_name, 'rb')
    sign_as_number = int.from_bytes(SHA256(input_file.read()).digest(), byteorder='big')
    sign = pow(sign_as_number, d, n) # на закрытом ключе
    asn1_sign = sign_to_asn(n, e, sign)

    output_file = open(file_name + '.sign', 'wb')
    output_file.write(asn1_sign)
    print('file signed: result:' + file_name + '.sign')


# проверить подпись
def check_sign(file_name, e):
    n, sign_as_number = sign_from_asn(file_name + '.sign')
    sign_as_number = pow(sign_as_number, e, n)
    input_file = open(file_name[:len(file_name) - 4] + '_decrypted' + file_name[len(file_name) - 4:], 'rb')
    sign_as_number_true = int.from_bytes(SHA256(input_file.read()).digest(), byteorder='big')

    if sign_as_number == sign_as_number_true:
        print('Подпись принимается!')
    else:
        print('Подпись неверна!')


# генерация параметров криптосистемы RSA
def RSA_init():
    p = getPrime(1024, randfunc=get_random_bytes)
    q = getPrime(1024, randfunc=get_random_bytes)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    while True:
        e = randint(1, phi_n - 1)
        gcd_ = gcd(e, phi_n)
        if gcd_ == 1:
            break
    d = inverse(e, phi_n)
    if d < 0:
        d += n
    return e, d, n, p, q


# параметры криптосистемы (генерация или статичные)
e, d, n, p, q = RSA_init()

# путь к файлу
input_file = r'1.png'
print('RSA with AES-256 CBC\n e = {}\n d = {}\n n = {}\n p = {}\n q = {}\n'.format(hex(e), hex(d), hex(n), hex(p), hex(q)))

while True:
    mode = int(input(' chose mode:\n 0 - encryption, 1 - signature, 2 - exit\n '))
    if mode == 0:
        mode = int(input(' encryption:\n 0 - encrypt file, 1 - decrypt file\n '))
        if mode == 0:
            encrypt_file(input_file, e, n)
        elif mode == 1:
            decrypt_file(input_file, d)

    elif mode == 1:
        mode = int(input(' signature:\n 0 - sign file, 1 - check signature\n '))
        if mode == 0:
            sign_file(input_file, e, d, n)
        elif mode == 1:
            check_sign(input_file, e)
    elif mode == 2:
        exit()
