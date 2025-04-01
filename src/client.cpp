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

#define curLEVEL 30
#define DEBUGLEVEL 20

// Client class
class Client {
    private:
        std::string clientId;
        std::string sfuIp;
        int sfuPort;
        QUIC* quicConnection;  // QUIC 连接对象
        std::queue<std::vector<char>> fifo;  // 用于存放解析后的参数码流
        std::mutex fifoMutex;
    
        // 建立 QUIC 连接
        void connectToSFU() {
            std::cout << "Client " << clientId << ": 正在连接 SFU..." << std::endl;
            static int portOffset = 0;  // 用于动态调整端口号
            quicConnection = new QUIC();

            //动态调整端口号
            int adjustedPort = sfuPort + portOffset;
            std::string adjustedPortStr = std::to_string(adjustedPort);
    
            // 初始化 QUIC 连接（客户端）
            quicConnection->client_init(const_cast<char*>(sfuIp.c_str()), const_cast<char*>(adjustedPortStr.c_str()));
    
            // 尝试连接 SFU
            int connect_status = quicConnection->client_connect(const_cast<char*>(sfuIp.c_str()));
            if (connect_status < 0) {
                std::cerr << "Client " << clientId << ": 连接 SFU 失败，错误码: " << connect_status << std::endl;
                delete quicConnection;  // 释放已分配的资源
                quicConnection = nullptr;

                // 增加端口偏移量，避免下次冲突
                portOffset += 10;
                throw std::runtime_error("连接 SFU 失败");
            }
            std::cout << "Client " << clientId << ": 已连接 SFU" << std::endl;

            // 成功连接后，增加端口偏移量，供下次连接使用
            portOffset += 10;
        }
    
        // 释放 QUIC 连接
        void disconnectFromSFU() {
            if (quicConnection) {
                delete quicConnection;
                quicConnection = nullptr;
                std::cout << "Client " << clientId << ": 已释放 QUIC 连接" << std::endl;
            }
        }
    
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
    
        // 上传模型阶段
        void uploadModel(uint64_t stream_id = 4) {
            connectToSFU();  // 重新建立 QUIC 连接
            usleep(500000);  // 等待连接稳定
    
            std::cout << "Client " << clientId << ": 开始上传模型文件到 SFU" << std::endl;
    
            const char* modelFilePath = "/home/ljl/workspace/Multi_3D_Conference/resource/grafana.zip";
            const char* doneFlag = "1";  // 标志消息
            size_t doneFlagLength = strlen(doneFlag);
    
            // 打开模型文件
            int model_fd = open(modelFilePath, O_RDONLY);
            if (model_fd < 0) {
                perror("无法打开模型文件");
                disconnectFromSFU();
                return;
            }
    
            // 开启流
            quicConnection->open_stream(stream_id);

            uint8_t *recvbuf = new uint8_t[MAX_BUF];
            ssize_t *recvret = new ssize_t(-1);
    
            quicConnection->threadRecv(recvbuf, recvret);
            
            // 发送模型文件数据
            uint8_t* vbuffer = new uint8_t[MAX_BUF];
            ssize_t* ret = new ssize_t(-1);
            int stop_cnt = 0;

            int send_size = 0;
    
            while (true) {
                int len = read(model_fd, vbuffer, MAX_BUF);
                if (len > 0) {
                    stop_cnt = 0;
                    quicConnection->quic_send(stream_id, vbuffer, len, false, ret);
                    send_size += len;
                } else if (len == 0) {
                    stop_cnt++;
                    usleep(100);
                    
                }
                if (stop_cnt > 10000) {
                    break;
                }

            }
    
            // 发送完成标志
            uint8_t* buffer = new uint8_t[doneFlagLength];
            std::memcpy(buffer, doneFlag, doneFlagLength);
            sleep(1);
            quicConnection->quic_send(stream_id, buffer, doneFlagLength, true, ret);
            std::cout << "Client " << clientId << ": 模型文件上传完毕," << "send size: "<<send_size << std::endl;
            sleep(1);
            quicConnection->stop_recv();
            // 释放资源
            delete[] vbuffer;
            delete[] buffer;
            delete[] recvbuf;
            delete recvret;
            delete ret;
            close(model_fd);
    
            disconnectFromSFU();  // 释放 QUIC 连接
        }
    
        // 下载模型阶段
        void downloadModel(uint64_t stream_id = 4) {
            
            connectToSFU();  // 重新建立 QUIC 连接
    
            std::cout << "Client " << clientId << ": 开始下载模型文件..." << std::endl;
    
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

                    if (curLEVEL< DEBUGLEVEL)
                        std::cout << "Client " << clientId << ": 接收到数据长度: " << receivedBytes << " 字节" << std::endl;
                } else if (receivedBytes == 0) {
                    // 如果接收到 0 字节，可能是流关闭或无数据，继续等待
                    continue;
                } else {
                    // 处理接收错误
                    std::cerr << "Client " << clientId << ": 接收数据时发生错误" << std::endl;
                    break;
                }
            }
    
            // 保存模型数据到文件
            std::string filename = "../resource/client_receive_model/" + clientId +"/" + clientId+".zip";
            std::ofstream outfile(filename, std::ios::binary);
            outfile.write(reinterpret_cast<char*>(modelData.data()), modelData.size());
            outfile.close();
    
            std::cout << "Client " << clientId << ": 模型文件已保存为 " << filename << std::endl;
    
            disconnectFromSFU();  // 释放 QUIC 连接
        }
    
        // 运行会议阶段
        void runConferencePhase() {
            connectToSFU();  // 重新建立 QUIC 连接
    
            std::cout << "Client " << clientId << ": 开始会议阶段..." << std::endl;
    
            std::thread sender(&Client::sendParameterStream, this);
            std::thread receiver(&Client::receiveParameterStream, this);
            sender.join();
            receiver.join();
    
            disconnectFromSFU();  // 释放 QUIC 连接
        }
    
        // 发送参数码流
        void sendParameterStream() {
            int counter = 0;
            while (true) {
                std::vector<char> paramData(20, 'P');  // 生成 20 字节的参数数据
                ssize_t sentBytes;
                quicConnection->quic_send(0, reinterpret_cast<uint8_t*>(paramData.data()), paramData.size(), false, &sentBytes);
                std::cout << "Client " << clientId << ": 发送参数数据" << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (++counter > 20) break;
            }
        }
    
        // 接收参数码流
        void receiveParameterStream() {
            int counter = 0;
            while (true) {
                std::vector<uint8_t> packet(MAX_BUF);
                ssize_t receivedBytes;
                quicConnection->quic_recv(packet.data(), &receivedBytes);
    
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
    
        ~Client() {
            disconnectFromSFU();  // 确保析构时释放 QUIC 连接
        }
    };
    
    int main(int argc, char* argv[]) {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <config_path>" << std::endl;
            return 1;
        }
    
        const char* CONFIG_PATH = argv[1];
    
        Client client;
        client.loadConfig(CONFIG_PATH);
    
        try {
            client.uploadModel();
            sleep(1);
            client.downloadModel(4);
            sleep(3);
            // client.runConferencePhase();
        } catch (const std::exception& e) {
            std::cerr << "程序运行时发生错误: " << e.what() << std::endl;
        }
        sleep(3);
        
        return 0;
    }