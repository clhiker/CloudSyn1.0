# -*- coding: utf-8 -*-
import socket
import configparser
import threading
import time

import load
import Encryptor
import filetree


class Server:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.server_socket.settimeout(3)
        self.address = ()
        self.max_supported_devices = 3
        self.buff = 1024
        self.home_path = ''
        self.store_path = ''
        self.client = None

        # 读取配置文件
        self.readConfig()

        # 绑定地址
        self.server_socket.bind(self.address)
        # 最多三台设备
        self.server_socket.listen(int(self.max_supported_devices))

        # 初始化加密器
        self.encryptor_generator = Encryptor.AES_MD5()

        self.file_tree = filetree.FileTree()
        self.file_tree.setStorePath(self.store_path)
        self.file_tree.setHomePath(self.home_path)

        self.download_list = []

        self.load_gerenator = load.Load(self.buff)

    # 读取配置信息
    def readConfig(self):
        config = configparser.ConfigParser()
        config.read('remote.ini')
        ip = config.get('socket_config', 'ip')
        port = config.get('socket_config', 'port')
        
        self.address = (ip, int(port))
        self.max_supported_devices = config.get('socket_config', 'max_supported_devices')

        self.buff = int(config.get('socket_config', 'buff'))
        
        self.home_path = config.get('path', 'home_path')

        self.store_path = config.get('path', 'store_path')

    def receiveFilesInfo(self):
        self.load_gerenator.download(self.store_path)
        self.transDifference()

    # 同步接口
    def transDifference(self):
        # 清楚服务器端缓存
        self.file_tree.clearDownloadList()
        # 对比本地文件，生成下载列表
        self.file_tree.setDownloadList()
        # 移除多余的文件
        self.file_tree.removeRecursiveFiles()
        # 存储需要下载的文件
        self.file_tree.storeFilesRemote()

        self.download_list = self.file_tree.getDownLoadList()

        if len(self.download_list) != 0:
            self.load_gerenator.sendInfo('syn')
            # self.client.send(self.encryptor_generator.encrypt_str('syn').encode())
            # time.sleep(0.005)
            self.load_gerenator.upload(self.store_path)

            self.synFiles()

    # 同步文件
    def synFiles(self):

        while True:
            stop_info = self.load_gerenator.receiveInfo()

            if stop_info == 'stop':
                break
            part_path = self.load_gerenator.receiveInfo()

            file_path = self.home_path + part_path
            print(file_path)
            self.load_gerenator.download(file_path)

            time.sleep(1)

    def receiveState(self, receive_info):
        # 目录信息
        if receive_info == 'file_struct':
            self.receiveFilesInfo()

    def beginInterface(self):
        while True:
            self.client, address = self.server_socket.accept()
            self.load_gerenator.setClient(self.client)

            choice = self.load_gerenator.receiveInfo()

            print(choice)

            t = threading.Thread(target=self.receiveState, args=(choice,))
            t.start()


if __name__ == '__main__':
    server_start = Server()
    print('begin connecting...')
    server_start.beginInterface()