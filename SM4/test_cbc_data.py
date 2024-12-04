import os

# 定义文件大小（字节）
file_sizes = {
    "test1.bin": 64,          # 64 Bytes
    "test2.bin": 2048,        # 2 KB
    "test3.bin": 10 * 1024 * 1024  # 10 MB
}

# 创建随机数据文件
for file_name, size in file_sizes.items():
    with open(file_name, "wb") as f:
        f.write(os.urandom(size))

# 列出生成的文件及其大小
for file_name, size in file_sizes.items():
    print(f"{file_name}: {size} Bytes generated.")
