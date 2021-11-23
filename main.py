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


