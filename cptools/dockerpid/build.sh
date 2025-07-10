#!/bin/bash

# 设置交叉编译环境变量
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

echo "正在交叉编译Linux二进制文件..."
go build -o dockerpid-linux-amd64 .

echo "编译完成！生成的文件: dockerpid-linux-amd64"

# 可选：生成其他架构的二进制文件
echo "正在编译ARM64版本..."
export GOARCH=arm64
go build -o dockerpid-linux-arm64 .

echo "编译完成！生成的文件: dockerpid-linux-arm64"