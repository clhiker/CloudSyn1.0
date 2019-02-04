#!/usr/bin/python
# encoding=utf-8

import socket
import configparser
import time

import Encryptor
import filetree
import load


# 客户端
class Client:
    def __init__(self):
        self.address = ()
        self.local_path = ''
        self.home_path = ''
        self.buff = 1024
        self.block_size = 1024
        self.getConfig()
        # 连接选项
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.client_socket.connect(self.address)

        self.file_tree = filetree.FileTree()
        self.file_tree.storeFilesLocal()

        # 初始化加密器
        self.encryptor_generator = Encryptor.AES_MD5()

        self.load_generator = load.Load(self.buff)
        self.load_generator.setClient(self.client_socket)

    def getConfig(self):
        config = configparser.ConfigParser()
        config.read('local.ini')
        ip = config.get('address', 'ip')
        port = int(config.get('address', 'port'))
        self.address = (ip, port)
        self.local_path = config.get('path', 'store_path')
        self.home_path = config.get('path', 'home_path')
        
        self.buff = int(config.get('spilt', 'buff'))
        self.block_size = int(config.get('spilt', 'block_size'))

    def sendFilesInfo(self):
        # self.client_socket.send(self.encryptor_generator.encrypt_str('file_struct').encode())
        # time.sleep(0.005)
        self.load_generator.sendInfo('file_struct')

        self.load_generator.upload(self.local_path)

    def waitCheck(self):
        print('check')
        # check_info = self.encryptor_generator.decrypt_str(self.client_socket.recv(self.buff).decode())
        check_info = self.load_generator.receiveInfo()

        if check_info == 'syn':
            self.load_generator.download(self.local_path)
            self.synFiles()

    def synFiles(self):
        download_list = []
        try:            
            with open(self.local_path, 'r') as f:
                for line in f:
                    part_path = line.replace('\n', '')                    
                    download_list.append(part_path)
        except IOError:
            print('文件打开失败')
        
        for item in download_list:
            real_path = self.home_path + item

            self.load_generator.sendInfo('continue')
            self.load_generator.sendInfo(item)

            print(real_path)

            self.load_generator.upload(real_path)

            time.sleep(1)

        self.load_generator.sendInfo('stop')
            

def main():
    client = Client()
    client.sendFilesInfo()
    client.waitCheck()

if __name__ == '__main__':

    config = configparser.ConfigParser()
    config.read('local.ini')
    time_stamp = int(config.get('config', 'time_stamp'))

    old_time = time.time()
    new_time = time.time()
    while True:
        new_time = time.time()
        if new_time - old_time > time_stamp:
            main()
            old_time = time.time()
        else:
            pass
