##Вариант 2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from tqdm import tqdm
import json
import argparse
import os

settings = {
    'initial_file': "file.txt",  # Файл с текстом
    'encrypted_file': 'encrypted_file.txt',  # Зашифрованный текст
    'decrypted_file': 'decrypted_file.txt',  # Дешиврованный текст
    'symmetric_key': 'symmetric_key.txt',  # Симметричный ключ Camellia
    'public_key': 'public_key.pem',  # Открытый ключ RSA
    'secret_key': 'secret_key.pem',  # закрытый ключ RSA
}


def input_len_key() -> int:
    """
        Функция возвращает длину ключа для алгоритма Camellia
    """
    while 1:
        os.system('CLS')
        print("Выберите длину ключа\n"
              "1.128\n"
              "2. 192\n"
              "3. 256\n"
              "Ваш выбор:")
        alternative = input()
        if int(alternative) == 1:
            return int(128)
        if int(alternative) == 2:
            return int(192)
        if int(alternative) == 3:
            return int(256)


def generate_key(encrypted_symmetric_key: str, public_key_path: str, secret_key_path: str) -> None:
    symmetrical_key = algorithms.Camellia(os.urandom(int(input_len_key() / 8)))
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    with open(public_key_path, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(secret_key_path, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    encrypt_symmetrical_key = public_key.encrypt(symmetrical_key.key,
                                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(),
                                                              label=None))

    with open(encrypted_symmetric_key, 'wb') as summetric_out:
        summetric_out.write(encrypt_symmetrical_key)


parser = argparse.ArgumentParser(description="main")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
args = parser.parse_args()
# пишем в файл
with open('settings.json', 'w') as fp:
    json.dump(settings, fp)
# читаем из файла
with open('settings.json') as json_file:
    json_data = json.load(json_file)

args = parser.parse_args()
if args.generation is not None:
    generate_key(json_data['symmetric_key'], json_data['public_key'], json_data['secret_key'])

