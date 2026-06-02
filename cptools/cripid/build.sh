#!/bin/bash

# 交叉编译 Linux 二进制文件 (CRI 仅存在于 Linux)
export CGO_ENABLED=0
export GOOS=linux

echo "正在交叉编译 Linux amd64 版本..."
export GOARCH=amd64
go build -o cripid-linux-amd64 .

echo "正在编译 Linux arm64 版本..."
export GOARCH=arm64
go build -o cripid-linux-arm64 .

echo "编译完成！生成的文件: cripid-linux-amd64, cripid-linux-arm64"
