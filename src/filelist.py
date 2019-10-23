import argparse
import os
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dir", help="directory of data")
args = parser.parse_args()
dirpath = args.dir
for root, dirs, files in os.walk(dirpath):  # 循环读取每个文件名
    print(root)
    print(files)