import Encryptor
import os
import shutil


class FileTree:
    def __init__(self):
        self.store_path = ''
        self.home_path = ''
        self.download_list = []
        self.local_files_list = []
        self.remove_list = []
        
        # 初始化加密器
        self.encryptor_generator = Encryptor.AES_MD5()

    def clearDownloadList(self):
        self.download_list = []

    def setStorePath(self, store_path):
        self.store_path = store_path

    def setHomePath(self, home_path):
        self.home_path = home_path

    def getDownLoadList(self):
        return self.download_list

    def clearLocalFilesList(self):
        self.local_files_list = []

    def clearRemoveList(self):
        self.remove_list = []

    # 检查文件目录结构信息
    def setDownloadList(self):

        self.clearLocalFilesList()

        count = 0
        part_path = ''
        real_path = ''
        with open(self.store_path, 'r') as f:
            for line in f:
                if count == 0:
                    part_path = line[:line.rfind('\n')]
                    part_path = self.transPath(part_path)
                    real_path = self.home_path + part_path

                if count == 1:
                    item_type = line[:line.rfind('\n')]

                    if item_type == 'dir':
                        self.checkDir(real_path)
                        self.local_files_list.append(part_path)
                    else:
                        self.local_files_list.append(part_path)

                        self.checkFile(real_path, part_path, item_type)

                    count = -1

                count += 1

    def checkFile(self, real_path, part_path, md5):
        if not os.path.exists(real_path):
            self.download_list.append(part_path)

        else:
            if self.encryptor_generator.getMd5(real_path) != md5:
                self.download_list.append(part_path)

    def checkDir(self, real_path):
        if not os.path.exists(real_path):
            # os.makedirs(real_path)
            os.mkdir(real_path)

    # 存储要上传的文件
    def storeFilesRemote(self):
        if os.path.exists(self.store_path):
            os.remove(self.store_path)
        try:
            with open(self.store_path, 'w') as f:
                for item in self.download_list:
                    f.write(item)
                    f.write('\n')
        except IOError:
            print('文件打开失败')

    # 移除多余的文件
    def removeRecursiveFiles(self):
        self.clearRemoveList()
        self.recursiveTraversal(self.home_path)

        print('移除文件目录')
        print(self.remove_list)

        for item in self.remove_list:
            if os.path.exists(item):
                os.remove(item)

    def recursiveTraversal(self, file_path):
        files_list = os.listdir(file_path)
        for item in files_list:
            real_path = file_path + os.sep + item
            if os.path.isdir(real_path):
                part_path = real_path.replace(self.home_path, '')
                if part_path not in self.local_files_list:
                    shutil.rmtree(real_path)  # 递归删除文件夹
                else:
                    self.recursiveTraversal(real_path)
            else:
                part_path = real_path.replace(self.home_path, '')
                if part_path not in self.local_files_list:
                    self.remove_list.append(real_path)

    # 本地文件系统修改
    def transPath(self, path):
        if path.find('\\') != -1:
            path_list = path.split('\\')
            new_path = path_list[0]
            for index in range(1, len(path_list)):
                new_path += (os.sep + path_list[index])
        else:
            path_list = path.split('/')
            new_path = path_list[0]
            for index in range(1, len(path_list)):
                new_path += os.sep + path_list[index]

        return new_path