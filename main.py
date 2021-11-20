##Вариант 2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import Camellia
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from tqdm import tqdm
import json
import argparse
import os
import pickle

settings = {
    'initial_file': "C://Users//matro//OneDrive//Рабочий стол//Учебники//ОИБ//Лаба 3//file.txt",
    'encrypted_file': 'C://Users//matro//OneDrive//Рабочий стол//Учебники//ОИБ//Лаба 3//encrypted_file.txt',
    'decrypted_file': 'C://Users//matro//OneDrive//Рабочий стол//Учебники//ОИБ//Лаба 3//decrypted_file.txt',
    'symmetric_key': 'C://Users//matro//OneDrive//Рабочий стол//Учебники//ОИБ//Лаба 3//symmetric_key.txt',
    'public_key': 'C://Users//matro//OneDrive//Рабочий стол//Учебники//ОИБ//Лаба 3//public_key.pem',
    'secret_key': 'C://Users//matro//OneDrive//Рабочий стол//Учебники//ОИБ//Лаба 3//secret_key.pem',
}


def generate_keys(encrypted_symmetrical_key_path: str, open_asymmetric_key_path: str,
                  private_asymmetric_key_path: str) -> None:
    """
    :param encrypted_symmetrical_key_path:
        путь, по которому сохранить зашифрованный ключ симметричного алгоритма
    :param open_asymmetric_key_path:
        путь, по которому сохранить открытый ключ ассиметричного алгоритма
    :param private_asymmetric_key_path:
        путь, по которому сохранить закрытый ключ ассиметричного алгоритма
    """
    # генерация ключа симметричного шифрования
    symmetrical_key = Camellia.generate_key()

    # генерация ключей асимметричного шифрование
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys

    # сериализация ключей асимметричного шифрования:
    # закрытый ключ
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_asymmetric_key_path, 'wb') as key_file:
        key_file.write(pem_private)

    # открытый ключ
    public_key = keys.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(open_asymmetric_key_path, 'wb') as key_file:
        key_file.write(pem_public)

    # шифрование ключа симметричного алгоритма
    encrypted_symmetrical_key = public_key.encrypt(
        symmetrical_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # сериализация ключа симмеричного алгоритма в файл
    with open(encrypted_symmetrical_key_path, 'wb') as key_file:
        key_file.write(encrypted_symmetrical_key)


# читаем из файла


parser = argparse.ArgumentParser(description='main.py')

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
args = parser.parse_args()
with open('settings.json') as json_file:
    json_data = json.load(json_file)
path_data = os.path.realpath()
generate_keys(json_data['symmetric_key'],)
