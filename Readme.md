# 多人3D视频会议系统

1. 使用方法

    ```shell
    # build
    mkdir build
    cd build
    cmake ..
    make
    ```

    以两个客户端为例,开三个终端，按顺序执行运行

   ```shell
    # 开启sfu
   ./sfu ../config/sfu_config2.txt

    #开启client1
   ./client ../config/client1_config.txt

    #开启client2
   ./client ../config/client1_config.txt

