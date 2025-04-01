#!/bin/bash
pkill client  
pkill sfu
# 创建日志文件夹
mkdir -p logs

# 进入build目录
cd build

make

# 运行SFU并保存日志
./sfu ../config/sfu_config3.txt > ../logs/sfu.log 2>&1 &

sleep 1

# 运行Client 1并保存日志
./client ../config/client1_config.txt > ../logs/client1.log 2>&1 &

sleep 1

# 运行Client 2并保存日志
./client ../config/client2_config.txt > ../logs/client2.log 2>&1 &

sleep 1
# 运行Client 3并保存日志
./client ../config/client3_config.txt > ../logs/client3.log 2>&1 &

# 等待所有后台进程完成（可选）
wait
