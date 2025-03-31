#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstring>
#include <sstream>
#include <sys/wait.h>


// #include "quic/quiche.h"  
#include "quic/newQUIC.h"  // newQUIC.h 内包含了你实现的 QUIC 类

using namespace std;

#define MAX_BUF 65535

#define curLEVEL 30
#define DEBUGLEVEL 20

// #define CONFIG_PATH "../config/sfu_config.txt" // 更新路径

// 配置文件中保存的客户端信息
struct ClientInfo {
    std::string id;
    std::string ip;
    int port;
};

class SFU {
    private:
        int meetingParticipants;               // 预设参会人数
        std::vector<ClientInfo> clients;       // 客户端配置信息
        std::map<std::string, QUIC*> clientConnections; // 保存各客户端的 QUIC 连接对象
        std::mutex connMutex;
    
        // 建立与所有客户端的 QUIC 连接
        void connectToClients_old() {
            std::cout << "SFU: 正在连接所有客户端..." << std::endl;
            for (auto& info : clients) {
                QUIC* quicConn = new QUIC();
                std::string portStr = std::to_string(info.port);
    
                if (quicConn->server_init((char*)info.ip.c_str(), (char*)portStr.c_str()) < 0) {
                    std::cerr << "SFU: 为客户端 " << info.id << " 初始化 QUIC 失败" << std::endl;
                    delete quicConn;
                    continue;
                }
                // 输出初始化的server的ip和port

                std::cout<< "SFU: 初始化的server的ip和port: " << info.ip << ":" << info.port <<" client "<< info.id<<std::endl;
    
                if (quicConn->server_connect() < 0) {
                    std::cerr << "SFU: 与客户端 " << info.id << " 的 QUIC 连接建立失败" << std::endl;
                    delete quicConn;
                    continue;
                }
    
                std::cout << "SFU: 客户端 " << info.id << " (" << info.ip << ":" << info.port << ") 已通过 QUIC 连接" << std::endl;
                {
                    std::lock_guard<std::mutex> lock(connMutex);
                    clientConnections[info.id] = quicConn;
                }
            }
        }

        void connectToClients() {
            std::cout << "SFU: 正在连接所有客户端..." << std::endl;
        
            static int portOffset = 0;  // 用于动态调整端口号
        
            for (auto& info : clients) {
                QUIC* quicConn = new QUIC();
                int adjustedPort = info.port + portOffset;  // 动态调整端口号
                std::string portStr = std::to_string(adjustedPort);
        
                if (quicConn->server_init((char*)info.ip.c_str(), (char*)portStr.c_str()) < 0) {
                    std::cerr << "SFU: 为客户端 " << info.id << " 初始化 QUIC 失败，端口: " << adjustedPort << std::endl;
                    delete quicConn;
                    portOffset += 10;  // 增加端口偏移量，避免下次冲突
                    continue;
                }
        
                if (quicConn->server_connect() < 0) {
                    std::cerr << "SFU: 与客户端 " << info.id << " 的 QUIC 连接建立失败，端口: " << adjustedPort << std::endl;
                    delete quicConn;
                    portOffset += 10;  // 增加端口偏移量，避免下次冲突
                    continue;
                }
        
                std::cout << "SFU: 客户端 " << info.id << " (" << info.ip << ":" << adjustedPort << ") 已通过 QUIC 连接" << std::endl;
                {
                    std::lock_guard<std::mutex> lock(connMutex);
                    clientConnections[info.id] = quicConn;
                }
        
            }
            portOffset += 10;  // 增加端口偏移量，避免下次冲突
        }
    
        // 释放所有客户端的 QUIC 连接
        void disconnectFromClients() {
            for (auto& kv : clientConnections) {
                delete kv.second;
            }
            clientConnections.clear();
            std::cout << "SFU: 已释放所有客户端的 QUIC 连接" << std::endl;
        }
    
    public:
        SFU() : meetingParticipants(0) {}
    
        // 从配置文件加载参会人数和各客户端信息
        void loadConfig(const std::string& configFile) {
            std::ifstream infile(configFile);
            if (!infile) {
                std::cerr << "SFU: 无法打开配置文件: " << configFile << std::endl;
                return;
            }
            infile >> meetingParticipants;
            for (int i = 0; i < meetingParticipants; i++) {
                ClientInfo info;
                infile >> info.id >> info.ip >> info.port;
                clients.push_back(info);
            }
            infile.close();
            std::cout << "SFU: 配置加载完毕，共 " << meetingParticipants << " 个客户端" << std::endl;
        }
    
        // 模型上传阶段：从每个客户端接收模型数据并保存到文件
        void modelUploadPhase(uint64_t stream_id = 7) {
            connectToClients();  // 重新建立 QUIC 连接
    
            std::cout << "SFU: 开始模型上传阶段" << std::endl;
    
            for (auto& kv : clientConnections) {
                std::string clientId = kv.first;
                QUIC* conn = kv.second;
    
                uint8_t recv_buf[MAX_BUF];
                ssize_t receivedBytes;
                std::vector<char> modelData;
    
                conn->open_stream(stream_id);

                pid_t pid = fork();  // 创建子进程
                if (pid==0){
                    int receive_size = 0;
    
                    while (true) {
                        conn->quic_recv(recv_buf, &receivedBytes);
        
                        if (receivedBytes > 0) {
                             // 输出日志
                            std::cout << "SFU: 接收到数据，长度: " << receivedBytes << "，总接收长度: " << receive_size << std::endl;
                            // 检查是否接收到完成标志
                            if (receivedBytes == 1 && recv_buf[0] == '1') {
                                std::cout << "SFU: 客户端 " << clientId << " 模型上传完成" << std::endl;
                                //输出recv_buf中的数据

                                std::cout<<"recv_buf:"<< recv_buf[0]<<recv_buf[1] <<std::endl;
                                break;
                            }
                            // 保存接收到的数据
                            modelData.insert(modelData.end(), recv_buf, recv_buf + receivedBytes);
                            receive_size += receivedBytes;
                        }
                    }
        
                    // 保存模型数据到文件
                    std::string filename = "../resource/sfu_receive_model/model_" + clientId + ".zip";
                    std::ofstream outfile(filename, std::ios::binary);
                    outfile.write(modelData.data(), modelData.size());
                    outfile.close();
        
                    std::cout << "SFU: 客户端 " << clientId << " 模型保存到文件 " << filename << "Total size:" <<receive_size << std::endl;
                    exit(0);  // 子进程处理完后退出
                }else if (pid < 0) {
                    std::cerr << "SFU: 创建子进程失败" << std::endl;
                    continue;
                }

            }
                
            while (waitpid(-1, nullptr, 0) > 0);

            // SFU端接收到所有模型
            std::cout<< "SFU: 端接收到所有模型"<< std::endl;

            disconnectFromClients();  // 释放 QUIC 连接
        }
    
        // 模型下载阶段：将每个客户端上传的模型转发给其他客户端
        void modelDownloadPhase(uint64_t stream_id = 7) {
            connectToClients();  // 重新建立 QUIC 连接
    
            std::cout << "SFU: 开始模型下载阶段" << std::endl;
    
            for (auto& kv : clientConnections) {
                std::string clientId = kv.first;
                QUIC* conn = kv.second;
    
                // 构造模型文件路径
                std::string filename = "../resource/sfu_receive_model/model_" + clientId + ".zip";
                std::ifstream infile(filename, std::ios::binary);
                if (!infile) {
                    std::cerr << "SFU: 无法打开客户端 " << clientId << " 的模型文件: " << filename << std::endl;
                    continue;
                }
    
                // 读取模型文件数据
                std::vector<char> modelData((std::istreambuf_iterator<char>(infile)),
                                            std::istreambuf_iterator<char>());
                infile.close();
    
                std::cout << "SFU: 已读取客户端 " << clientId << " 的模型文件，大小为 " << modelData.size() << " 字节" << std::endl;
    
                conn->open_stream(stream_id);

                uint8_t *recvbuf = new uint8_t[MAX_BUF];
                ssize_t *recvret = new ssize_t(-1);
        
                conn->threadRecv(recvbuf, recvret);
    
                // 发送模型数据
                ssize_t sentBytes = 0;
                size_t offset = 0;
                while (offset < modelData.size()) {
                    size_t chunkSize = std::min<size_t>(MAX_BUF, modelData.size() - offset);
                    if (conn->quic_send(stream_id, reinterpret_cast<uint8_t*>(modelData.data() + offset), chunkSize, false, &sentBytes) < 0) {
                        std::cerr << "SFU: 向客户端 " << clientId << " 发送模型数据失败" << std::endl;
                        break;
                    }
                    offset += chunkSize;
                    if (curLEVEL < DEBUGLEVEL)
                        std::cout << "SFU: 已向客户端 " << clientId << " 发送 " << sentBytes << " 字节数据" << std::endl;
                }
    
                // 发送完成标志
                const char* doneFlag = "1";
                size_t doneFlagLength = strlen(doneFlag);
                uint8_t buffer[doneFlagLength];
                std::memcpy(buffer, doneFlag, doneFlagLength);
    
                if (conn->quic_send(stream_id, buffer, doneFlagLength, false, &sentBytes) < 0) {
                    std::cerr << "SFU: 向客户端 " << clientId << " 发送完成标志失败" << std::endl;
                } else {
                    std::cout << "SFU: 已向客户端 " << clientId << " 发送完成标志" << std::endl;
                }
            }
    
            disconnectFromClients();  // 释放 QUIC 连接
        }
    
        // 会议阶段：周期性接收各客户端的参数码流，打包后转发给其他客户端
        void conferencePhase() {
            connectToClients();  // 重新建立 QUIC 连接
    
            std::cout << "SFU: 开始会议阶段" << std::endl;
    
            bool running = true;
            int counter = 0;
            while (running) {
                for (auto& kv : clientConnections) {
                    std::string clientId = kv.first;
                    QUIC* conn = kv.second;
    
                    uint8_t param_buf[MAX_BUF];
                    ssize_t receivedBytes;
    
                    conn->quic_recv(param_buf, &receivedBytes);
    
                    if (receivedBytes > 0) {
                        // 封装数据格式：[id(1字节) | 长度(1字节) | 参数数据]
                        std::vector<uint8_t> packet;
                        uint8_t id_char = clientId[0];
                        packet.push_back(id_char);
                        uint8_t length = static_cast<uint8_t>(receivedBytes);
                        packet.push_back(length);
                        packet.insert(packet.end(), param_buf, param_buf + receivedBytes);
    
                        // 转发给其他客户端
                        for (auto& kv2 : clientConnections) {
                            if (kv2.first == clientId) continue;
                            QUIC* target = kv2.second;
    
                            ssize_t sentBytes;
                            if (target->quic_send(1, packet.data(), packet.size(), false, &sentBytes) < 0) {
                                std::cerr << "SFU: 向客户端 " << kv2.first << " 转发数据失败" << std::endl;
                            } else {
                                std::cout << "SFU: 已将来自 " << clientId << " 的数据转发给 " << kv2.first << std::endl;
                            }
                        }
                    }
                }
    
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (++counter > 10) running = false;  // 模拟有限次会议循环
            }
    
            disconnectFromClients();  // 释放 QUIC 连接
        }
    
        ~SFU() {
            disconnectFromClients();  // 确保析构时释放所有 QUIC 连接
        }
    };
    
    int main(int argc, char* argv[]) {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <config_path>" << std::endl;
            return 1;
        }
    
        const char* CONFIG_PATH = argv[1];
    
        SFU sfu;
        sfu.loadConfig(CONFIG_PATH);
    
        try {
            sfu.modelUploadPhase();
            sleep(1);
            sfu.modelDownloadPhase();
            sleep(3);
            // sfu.conferencePhase();
        } catch (const std::exception& e) {
            std::cerr << "程序运行时发生错误: " << e.what() << std::endl;
        }
        sleep(3);
        return 0;
    }