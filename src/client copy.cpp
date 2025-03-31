#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>

#include <cstring>  // 添加该头文件来使用 memcpy

#include <iomanip>

// #include "quic/quiche.h"
#include "quic/newQUIC.h"  // newQUIC.h 内包含了你实现的 QUIC 类


// Client class
class Client {
private:
    std::string clientId;
    std::string sfuIp;
    int sfuPort;
    QUIC* quicConnection;  // Use QUIC for connection handling
    std::queue<std::vector<char>> fifo;  // 用于存放解析后的参数码流
    std::mutex fifoMutex;

public:
    Client() : quicConnection(nullptr) {}

    // 从配置文件中加载客户端自身的 id、SFU 服务器的 IP 和端口
    void loadConfig(const std::string& configFile) {
        std::ifstream infile(configFile);
        if (!infile) {
            std::cerr << "Client: 无法打开配置文件: " << configFile << std::endl;
            return;
        }
        infile >> clientId >> sfuIp >> sfuPort;
        infile.close();
        std::cout << "Client " << clientId << ": 配置加载完毕，SFU 地址为 " << sfuIp << ":" << sfuPort << std::endl;
    }

    // 连接到 SFU（使用 QUIC 建立连接）
    void connectToSFU() {
        std::cout << "Client " << clientId << ": 正在连接 SFU..." << std::endl;
        quicConnection = new QUIC();

        // 以client
        // Initialize QUIC connection (client-side)
        quicConnection->client_init(const_cast<char*>(sfuIp.c_str()), const_cast<char*>(std::to_string(sfuPort).c_str()));
        
         // 尝试连接 SFU
        int connect_status = quicConnection->client_connect(const_cast<char*>(sfuIp.c_str()));


        // quicConnection->server_init(const_cast<char*>(sfuIp.c_str()), const_cast<char*>(std::to_string(sfuPort).c_str()));
        
        //  // 尝试连接 SFU
        // int connect_status = quicConnection->server_connect();


        if (connect_status < 0) {
            std::cerr << "Client " << clientId << ": 连接 SFU 失败，错误码: " << connect_status << std::endl;
            delete quicConnection;  // 释放已分配的资源
            quicConnection = nullptr;
            return;  // 直接返回，避免继续执行后续逻辑
        }
        std::cout << "Client " << clientId << ": 已连接 SFU" << std::endl;
    }

    // 同步信号
    void sync_sfu(uint64_t stream_id = 2, bool open = true) {

        std::cout << "Client " << clientId << ": 等待 SFU 发送 'READY' 信号..." << std::endl;
        uint8_t buf[10];
        ssize_t *length = new ssize_t(-1);

        if (open)
            quicConnection->open_stream(stream_id);
        //打印当前计算机时间,ms为单位
        std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
        std::cout << "current time: " << ms.count() << std::endl;

        std::cout<< "client isclosed before sync: " << quicConnection->isClosed <<std::endl;

        // quicConnection->threadTimeout();

        while (true) {
            quicConnection->quic_recv(buf, length);
            

            if (*length > 0 ) {
                
                std::cout << "Client: 收到 SFU 的 信号的 length: " << *length << std::endl;
                
                std::string receivedData(reinterpret_cast<char*>(buf), *length);
                std::cout<< "receivedData: " << receivedData << std::endl;
                if (receivedData =="READY") {
                    std::cout << "Client: 收到 SFU 的 'READY' 信号，开始上传模型数据" << std::endl;
                    break;
                }
                // break;
            }
            // std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        //  // 关闭流（终止读写）
        // quiche_conn_stream_shutdown(quicConnection->conn, stream_id, QUICHE_SHUTDOWN_WRITE, 0); // 关闭写操作
        // quiche_conn_stream_shutdown(quicConnection->conn, stream_id, QUICHE_SHUTDOWN_READ, 0);  // 关闭读操作
        delete length;
    }

    // 模型上传阶段：将本地模型文件上传到 SFU
    void uploadModel(uint64_t stream_id = 4) {

        connectToSFU();

        std::cout << "Client " << clientId << ": 开始上传模型文件到 SFU" << std::endl;

        quiche_stats stats;
        // quiche_conn_stats(quicConnection, stats);


        uint8_t *recvbuf = new uint8_t[MAX_BUF];
        ssize_t *recvret = new ssize_t(-1);

        quicConnection->threadRecv(recvbuf, recvret);

        //testing video sending
        uint8_t *vbuffer = new uint8_t[MAX_BUF];
        // uint8_t *vbuffer = new uint8_t[4096];
        if (vbuffer == nullptr) {
            perror("malloc error");
            return ;
        }
        
        const char* modelFilePath = "/home/ljl/workspace/Multi_3D_Conference/resource/grafana.zip";  // 假设模型文件名
        int model_fd = open(modelFilePath, O_RDONLY);
        if (model_fd < 0) {
            perror("无法打开模型文件");
            return;
        }

        quicConnection->open_stream(stream_id);

        ssize_t *ret = new ssize_t(-1);
        int err;

        cout<<"start sending model.."<<endl;
        int stop_cnt = 0;


        //输出doneFlagLength
        // std::cout << "doneFlagLength: " << doneFlagLength << std::endl;
    
        
        int len_flush = 2048;
        while(true){

            int len = read(model_fd, vbuffer, MAX_BUF);
            if (len > 0){
                stop_cnt = 0;
                quicConnection->quic_send(stream_id, vbuffer, len, false, ret);
                // std::cout << "send model data: " << len << std::endl;
                // usleep(500000);
            }
            else if (len == 0){
                stop_cnt++;
                usleep(100);
            }
            if (stop_cnt > 10000) {
                break;
            }
        }
        
    
        // // // 发送完模型后，发送标志消息 "UPLOAD_DONE"
        const char* doneFlag = "1";  // 可以是任意标志符，例如 "UPLOAD_DONE" 或 "1"
        size_t doneFlagLength = strlen(doneFlag);
    
        // 发送数据完成后的标志消息
        size_t bufferSize = doneFlagLength;
        uint8_t* buffer = new uint8_t[bufferSize];

        // 将标志消息 "UPLOAD_DONE" 写入缓冲区
        std::memcpy(buffer, doneFlag, doneFlagLength);

        // 发送缓冲区中的数据
        quicConnection->quic_send(stream_id, buffer, doneFlagLength, false, ret);
        std::cout << "send doneFlag: " << doneFlag << std::endl;

        // 释放缓冲区
        delete[] buffer;
    
        std::cout << "Client " << clientId << ": 模型文件上传完毕" << std::endl;

        quicConnection->stop_recv();

        //关闭流
        // quiche_conn_stream_shutdown(quicConnection->conn, stream_id, QUICHE_SHUTDOWN_WRITE, 0); // 关闭写操作
        // quiche_conn_stream_shutdown(quicConnection->conn, stream_id, QUICHE_SHUTDOWN_READ, 0);  // 关闭读操作
        delete ret;
        delete[] recvbuf;
        delete recvret;
        delete vbuffer;
        close(model_fd);


    }

    // 模型上传阶段：将本地模型文件上传到 SFU
    void uploadModel_twice(uint64_t stream_id = 4) {
        std::cout << "Client " << clientId << ": 开始上传模型文件到 SFU" << std::endl;

        const char* modelFilePath = "/home/ljl/workspace/Multi_3D_Conference/resource/grafana.zip";  // 假设模型文件名
        const char* doneFlag = "1";  // 标志消息
        size_t doneFlagLength = strlen(doneFlag);

        for (int i = 0; i < 2; ++i) {  // 循环两次传输
            std::cout << "Client " << clientId << ": 开始第 " << (i + 1) << " 次传输" << std::endl;

            // 申请资源
            uint8_t* recvbuf = new uint8_t[MAX_BUF];
            ssize_t* recvret = new ssize_t(-1);
            uint8_t* vbuffer = new uint8_t[MAX_BUF];
            ssize_t* ret = new ssize_t(-1);
            uint8_t* buffer = new uint8_t[doneFlagLength];

            if (vbuffer == nullptr || buffer == nullptr) {
                perror("malloc error");
                delete[] recvbuf;
                delete recvret;
                delete[] vbuffer;
                delete[] buffer;
                return;
            }

            // 打开模型文件
            int model_fd = open(modelFilePath, O_RDONLY);
            if (model_fd < 0) {
                perror("无法打开模型文件");
                delete[] recvbuf;
                delete recvret;
                delete[] vbuffer;
                delete[] buffer;
                return;
            }

            // 开启流
            quicConnection->open_stream(stream_id);

            // 开始接收线程
            quicConnection->threadRecv(recvbuf, recvret);

            // 发送模型文件数据
            int stop_cnt = 0;
            while (true) {
                int len = read(model_fd, vbuffer, MAX_BUF);
                if (len > 0) {
                    stop_cnt = 0;
                    quicConnection->quic_send(stream_id, vbuffer, len, false, ret);
                } else if (len == 0) {
                    stop_cnt++;
                    usleep(100);
                }
                if (stop_cnt > 10000) {
                    break;
                }
            }

            // 发送完成标志
            std::memcpy(buffer, doneFlag, doneFlagLength);
            quicConnection->quic_send(stream_id, buffer, doneFlagLength, false, ret);
            std::cout << "send doneFlag: " << doneFlag << std::endl;

            // 释放资源
            delete[] recvbuf;
            delete recvret;
            delete[] vbuffer;
            delete[] buffer;
            delete ret;
            close(model_fd);

            std::cout << "Client " << clientId << ": 第 " << (i + 1) << " 次传输完成" << std::endl;
        }
        quiche_conn_stream_shutdown(quicConnection->conn, stream_id, QUICHE_SHUTDOWN_WRITE, 0); // 关闭写操作
        std::cout << "Client " << clientId << ": 模型文件上传完毕" << std::endl;
    }
    
    // 模型上传阶段：将本地模型文件上传到 SFU
    void uploadModel_twice_receive(uint64_t stream_id = 4) {
        std::cout << "Client " << clientId << ": 开始上传模型文件到 SFU" << std::endl;
    
        const char* modelFilePath = "/home/ljl/workspace/Multi_3D_Conference/resource/grafana.zip";  // 假设模型文件名
        const char* doneFlag = "1";  // 标志消息
        size_t doneFlagLength = strlen(doneFlag);
    
        // 上传模型两次
        for (int i = 0; i < 2; ++i) {
            std::cout << "Client " << clientId << ": 开始第 " << (i + 1) << " 次传输" << std::endl;
    
            // 申请资源
            uint8_t* vbuffer = new uint8_t[MAX_BUF];
            ssize_t* ret = new ssize_t(-1);
            uint8_t* buffer = new uint8_t[doneFlagLength];
    
            if (vbuffer == nullptr || buffer == nullptr) {
                perror("malloc error");
                delete[] vbuffer;
                delete[] buffer;
                return;
            }
    
            // 打开模型文件
            int model_fd = open(modelFilePath, O_RDONLY);
            if (model_fd < 0) {
                perror("无法打开模型文件");
                delete[] vbuffer;
                delete[] buffer;
                return;
            }
    
            // 开启流
            quicConnection->open_stream(stream_id);
    
            // 发送模型文件数据
            int stop_cnt = 0;
            while (true) {
                int len = read(model_fd, vbuffer, MAX_BUF);
                if (len > 0) {
                    stop_cnt = 0;
                    quicConnection->quic_send(stream_id, vbuffer, len, false, ret);
                } else if (len == 0) {
                    stop_cnt++;
                    usleep(100);
                }
                if (stop_cnt > 10000) {
                    break;
                }
            }
    
            // 发送完成标志
            std::memcpy(buffer, doneFlag, doneFlagLength);
            quicConnection->quic_send(stream_id, buffer, doneFlagLength, false, ret);
            std::cout << "send doneFlag: " << doneFlag << std::endl;
    
            // 释放资源
            delete[] vbuffer;
            delete[] buffer;
            delete ret;
            close(model_fd);
    
            std::cout << "Client " << clientId << ": 第 " << (i + 1) << " 次传输完成" << std::endl;
        }
    
        // 上传完成后接收 SFU 返回的模型数据
        std::cout << "Client " << clientId << ": 开始接收 SFU 返回的模型数据..." << std::endl;
        quicConnection->stop_recv();

        quicConnection->isClosed = false;
        // 申请接收缓冲区
        uint8_t* recvbuf = new uint8_t[MAX_BUF];
        ssize_t* recvret = new ssize_t(-1);
        std::vector<uint8_t> modelData;
    
        // 开始接收线程
        // quicConnection->threadRecv(recvbuf, recvret);
    
        ssize_t receivedBytes;
        while (true) {
            // 接收模型数据
            quicConnection->quic_recv(recvbuf, &receivedBytes);
    
            if (receivedBytes > 0) {
                // 检查是否接收到完成标志
                if (receivedBytes == 1 && recvbuf[0] == '1') {
                    std::cout << "Client " << clientId << ": 收到完成标志，结束接收" << std::endl;
                    break;
                }
    
                // 将接收到的数据追加到模型数据中
                modelData.insert(modelData.end(), recvbuf, recvbuf + receivedBytes);
                std::cout << "Client " << clientId << ": 接收到数据长度: " << receivedBytes << " 字节" << std::endl;
            } else if (receivedBytes == 0) {
                // 如果接收到 0 字节，可能是流关闭或无数据，继续等待
                std::cout << "Client " << clientId << ": 接收到 0 字节，等待更多数据..." << std::endl;
                continue;
            } else {
                // 处理接收错误
                std::cerr << "Client " << clientId << ": 接收数据时发生错误" << std::endl;
                break;
            }
        }
    
        // 保存接收到的模型数据到文件
        std::string filename = "received_model_" + clientId + ".zip";
        std::ofstream outfile(filename, std::ios::binary);
        outfile.write(reinterpret_cast<char*>(modelData.data()), modelData.size());
        outfile.close();
    
        std::cout << "Client " << clientId << ": 接收到的模型文件已保存为 " << filename << std::endl;
    
        // // 停止接收线程
        // quicConnection->stop_recv();
    
        // 释放接收缓冲区
        delete[] recvbuf;
        delete recvret;
    
        // 关闭流
        quiche_conn_stream_shutdown(quicConnection->conn, stream_id, QUICHE_SHUTDOWN_WRITE, 0); // 关闭写操作
        quiche_conn_stream_shutdown(quicConnection->conn, stream_id, QUICHE_SHUTDOWN_READ, 0);  // 关闭读操作
    
        std::cout << "Client " << clientId << ": 模型文件上传和接收完毕" << std::endl;
    }

    // 模型下载阶段：从 SFU 下载其他 peer 的模型文件
    void downloadModel(uint64_t stream_id = 2) {
        std::cout << "Client " << clientId << ": 正在下载模型文件..." << std::endl;

        // 打开指定流
        // quicConnection->open_stream(stream_id);

        // 准备接收缓冲区
        std::vector<uint8_t> modelData;
        uint8_t recvbuf[MAX_BUF];
        ssize_t receivedBytes;

        while (true) {
            // 接收模型数据
            quicConnection->quic_recv(recvbuf, &receivedBytes);

            if (receivedBytes > 0) {
                // 检查是否接收到完成标志
                if (receivedBytes == 1 && recvbuf[0] == '1') {
                    std::cout << "Client " << clientId << ": 收到完成标志，结束接收" << std::endl;
                    break;
                }

                // 将接收到的数据追加到模型数据中
                modelData.insert(modelData.end(), recvbuf, recvbuf + receivedBytes);
                std::cout << "Client " << clientId << ": 接收到数据长度: " << receivedBytes << " 字节" << std::endl;
            } else if (receivedBytes == 0) {
                // 如果接收到 0 字节，可能是流关闭或无数据，继续等待
                // std::cout << "Client " << clientId << ": 接收到 0 字节，等待更多数据..." << std::endl;
                continue;
            } else {
                // 处理接收错误
                std::cerr << "Client " << clientId << ": 接收数据时发生错误" << std::endl;
                break;
            }
        }

        // 保存模型数据到文件
        std::string filename = "downloaded_model_" + clientId + ".zip";
        std::ofstream outfile(filename, std::ios::binary);
        outfile.write(reinterpret_cast<char*>(modelData.data()), modelData.size());
        outfile.close();

        std::cout << "Client " << clientId << ": 模型文件已保存为 " << filename << std::endl;
    }

    // 会议阶段：发送参数码流（上行），模拟周期性发送数据
    void sendParameterStream() {
        int counter = 0;
        while (true) {
            std::vector<char> paramData(20, 'P');  // 生成 20 字节的参数数据
            
            // Send parameter data using QUIC connection
            ssize_t sentBytes;
            quicConnection->quic_send(0, reinterpret_cast<uint8_t*>(paramData.data()), paramData.size(), false, &sentBytes);
            
            std::cout << "Client " << clientId << ": 发送参数数据" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (++counter > 20) break;
        }
    }

    // 会议阶段：接收 SFU 下发的组合码流，并按照 id 解析存入 FIFO
    void receiveParameterStream() {
        int counter = 0;
        while (true) {
            std::vector<uint8_t> packet(MAX_BUF);
            ssize_t receivedBytes;
            
            // Receive parameter data using QUIC connection
            quicConnection->quic_recv(packet.data(), &receivedBytes);

            // 解析封装格式：第 1 字节为发送者 id（这里只取一个字符），第 2 字节为数据长度，后续为数据
            if (receivedBytes < 2) continue;
            char senderId = packet[0];
            unsigned char length = static_cast<unsigned char>(packet[1]);
            if (receivedBytes < 2 + length) continue;
            std::vector<char> paramData(packet.begin() + 2, packet.begin() + 2 + length);
            {
                std::lock_guard<std::mutex> lock(fifoMutex);
                fifo.push(paramData);
            }
            std::cout << "Client " << clientId << ": 收到来自 " << senderId << " 的参数数据" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (++counter > 20) break;
        }
    }

    // 运行会议阶段，开启发送和接收线程
    void runConferencePhase() {
        std::thread sender(&Client::sendParameterStream, this);
        std::thread receiver(&Client::receiveParameterStream, this);
        sender.join();
        receiver.join();
    }

    ~Client() {
        if (quicConnection) delete quicConnection;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config_path>" << std::endl;
        return 1;
    }

    const char* CONFIG_PATH = argv[1];  // 获取命令行参数中的配置路径

    Client client;
    client.loadConfig(CONFIG_PATH);  // 使用传入的配置路径

    client.uploadModel();
    client.connectToSFU();
    // client.waitForReadySignal();
    // 休眠一段时间等待程序完成

    

    // client.uploadModel_twice(4);

    //打印当前时间戳，精确到ms
    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
    std::cout << "current time: " << ms.count() << std::endl;
    // usleep(500000);

    // sleep(5);

    // client.uploadModel();

    // client.waitForDownloadSignal();
    sleep(1);
    client.downloadModel(4);
    // client.runConferencePhase();
    
    return 0;
}