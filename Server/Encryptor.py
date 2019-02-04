import base64
from Crypto.Cipher import AES
import configparser
from Crypto import Random
import io
import hashlib


class AES_MD5:
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('remote.ini')
        self.key = config.get('crypto', 'key')

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # 返回bytes

    # 英文字符串加密方法
    def encrypt_str(self, str_text):
        # 初始化加密器
        aes = AES.new(self.add_to_16(self.key), AES.MODE_ECB)
        # 先进行aes加密
        encrypt_aes = aes.encrypt(self.add_to_16(str_text))
        # 用base64转成字符串形式
        encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
        return encrypted_text

    # 英文字符串解密方法
    def decrypt_str(self, cipher_text):
        # 初始化加密器
        aes = AES.new(self.add_to_16(self.key), AES.MODE_ECB)
        # 优先逆向解密base64成bytes
        base64_decrypted = base64.decodebytes(cipher_text.encode(encoding='utf-8'))
        # 执行解密密并转码返回str
        decrypted_text = str(aes.decrypt(base64_decrypted), encoding='utf-8').replace('\0', '')
        return decrypted_text

    def encrypt_bin(self, b_text):
        # 初始化加密器
        iv = Random.new().read(AES.block_size)
        aes = AES.new(self.add_to_16(self.key), AES.MODE_CFB, iv)
        # 先进行aes加密
        encrypt_aes = iv + aes.encrypt(b_text)

        return encrypt_aes

    def decrypt_bin(self, cipher_bin):
        decryptor = AES.new(self.add_to_16(self.key), AES.MODE_CFB, cipher_bin[:16])
        plain = decryptor.decrypt(cipher_bin)
        return plain[16:]

    def getMd5(self, filename):
        m = hashlib.md5()
        file = io.FileIO(filename, 'r')
        block = file.read(1024)
        while block != b'':
            m.update(block)
            block = file.read(1024)
        file.close()
        return m.hexdigest()


if __name__ == '__main__':
    pass