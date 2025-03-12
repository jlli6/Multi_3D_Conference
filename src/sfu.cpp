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

#define MAX_BUF 32768

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
    int connectedClients = 0;
    std::vector<ClientInfo> clients;       // 客户端配置信息
    std::map<std::string, QUIC*> clientConnections; // 保存各客户端的 QUIC 连接对象
    std::mutex connMutex;
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

    // 等待所有客户端通过 QUIC 连接到 SFU
    void waitForConnections() {
        std::cout << "SFU: 等待 " << meetingParticipants << " 个客户端通过 QUIC 连接..." << std::endl;
        // 对于配置中的每个客户端，创建一个 QUIC 对象，调用 server_init/server_connect 等接口
        for (auto& info : clients) {
            QUIC* quicConn = new QUIC();
            // 使用客户端配置中记录的 ip 与 port 进行“初始化”
            // 注意：这里将 info.port 转为字符串传入
            std::string portStr = std::to_string(info.port);

            if (quicConn->server_init((char*)info.ip.c_str(), (char*)portStr.c_str()) < 0) {
                std::cerr << "SFU: 为客户端 " << info.id << " 初始化 QUIC 失败" << std::endl;
                delete quicConn;
                continue;
            }
            // 尝试连接（实际中可能需要循环等待或事件轮询）
            if (quicConn->server_connect() < 0) {
                std::cerr << "SFU: 与客户端 " << info.id << " 的 QUIC 连接建立失败" << std::endl;
                delete quicConn;
                continue;
            }
            std::cout << "SFU: 客户端 " << info.id << " (" << info.ip << ":" << info.port << ") 已通过 QUIC 连接" << std::endl;
            {
                std::lock_guard<std::mutex> lock(connMutex);
                clientConnections[info.id] = quicConn;
                connectedClients++;
            }
        }
        // usleep(1000000);  // 等待 1 秒，确保所有客户端连接完成

    }

    // 确认所有客户端连接，并广播 "READY"
    void sync_client(uint64_t stream_id = 2,int ready_times = 1) {
        std::cout << "SFU: 所有客户端已连接，正在广播 'READY' 信号" << std::endl;
        
        const char* readyMsg = "READY";
        size_t readyFlagLength = strlen(readyMsg);

        for (auto& [id, conn] : clientConnections) {
            pid_t pid = fork();  // 创建子进程

            std::cout<< "SFU isclosed after stop_recv: " << conn->isClosed <<std::endl;
            if (pid == 0) {  // 子进程
                // 接收ACK
                uint8_t *recvbuf = new uint8_t[MAX_BUF];
                ssize_t *recvret = new ssize_t(-1);
                conn->threadRecv(recvbuf, recvret);
                
                // std::cout << "recv ret before conn " << *recvret<<endl;
                if (ready_times == 1)
                    conn->open_stream(stream_id);
                    // std::cout << "recv ret after conn " << *recvret<<endl;
                    // *recvret  置为-1
                //     *recvret = -1;
                // std::cout << "recv ret after conn and set " << *recvret<<endl;

                uint8_t* buffer = new uint8_t[readyFlagLength];
                std::memcpy(buffer, readyMsg, readyFlagLength);

                ssize_t *ret = new ssize_t(-1);

                
                std::cout << "recv ret before ready " << *recvret<<endl;
                while (ready_times --) {
                    conn->quic_send(stream_id, buffer, readyFlagLength, false, ret);
                    std::cout<< "send ready ..."<< std::endl;
                    usleep(100000);  // 等待 1 秒
                    // 打印当前时间，计算机时间
                    //打印当前计算机时间
                    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
                    std::cout << "current time: " << ms.count() << std::endl;
                    
                }

                std::cout << "SFU: 已向客户端 " << id << " 发送 'READY' 信号" << std::endl;

                // std::cout<< "sfu isclosed before stop_recv: " << conn->isClosed <<std::endl;
                // conn->stop_recv();  // 终止接收ack


                 // 关闭流（终止读写）
                // uint64_t stream_id = 7;  // 假设7是你要关闭的流的ID
                // quiche_conn_stream_shutdown(conn->conn, stream_id, QUICHE_SHUTDOWN_WRITE, 0); // 关闭写操作
                // quiche_conn_stream_shutdown(conn->conn, stream_id, QUICHE_SHUTDOWN_READ, 0);  // 关闭读操作

                // 释放内存
                delete[] buffer;
                delete[] recvbuf;
                delete recvret;
                delete ret;

                _exit(0);  // 子进程退出
            } else if (pid < 0) {  // fork 失败
                std::cerr << "SFU: 创建子进程失败，无法向客户端 " << id << " 发送 'READY'" << std::endl;
            }
        }

        // 父进程等待所有子进程完成
        while (waitpid(-1, nullptr, 0) > 0);

        std::cout << "SFU: 已向所有客户端广播 'READY' 信号" << std::endl;
    }

    //接收客户端模型前的确认
    void confirmAllConnection(){
        sync_client(7,1);
    }

    // 给客户端发送模型前的确认
    void confirmUpload(){
        sync_client(7,100); //1011
    }

    // 模型上传阶段：从每个客户端接收模型数据并保存到文件
    void modelUploadPhase() {
        std::cout << "SFU: 开始模型上传阶段" << std::endl;
        
        for (auto& kv : clientConnections) {
            // 输出当前客户端id
            std::cout << "当前客户端id: " << kv.first << std::endl;
            std::string clientId = kv.first;
            QUIC* conn = kv.second;

            uint8_t recv_buf[65535];
            ssize_t *length = new ssize_t(-1);

            quiche_stats stats;
            uint64_t stream_id = 7;  // 流id
            conn->open_stream(stream_id);

            // // 在 fork() 之前，先尝试读一次数据，避免阻塞
            // uint8_t temp_buf[65535];
            // ssize_t temp_length = -1;
            // conn->quic_recv(temp_buf, &temp_length);
            
            pid_t pid = fork();  // 创建子进程
            if (pid == 0) {
                // 子进程负责接收模型数据
                
                std::vector<char> modelData; //每次接收的字节数
                size_t totalReceived = 0;  // 记录接收到的总字节数

                conn->threadTimeout();
        
                while (true) {
                    // 尝试接收数据
                    conn->quic_recv(recv_buf, length);

                    if (*length > 0){
                        // std::cout<< "SFU: 客户端 " << clientId << "接收数据长度：" << *length << std::endl;
                        // 添加接收到的数据到 modelData
                        modelData.insert(modelData.end(), recv_buf, recv_buf + *length);

                        totalReceived += *length;  // 累加接收到的字节数
                    }

                    if (*length == 1) {
                        std::cout << "SFU: 接收到一个字节，结束接收" << std::endl;
                        std::cout << "SFU: 客户端 " << clientId << " 已接收 " << totalReceived << " 字节的模型数据" << std::endl;
                        break;
                    }
                }

                //关闭流
                // quiche_conn_stream_shutdown(conn->conn, stream_id, QUICHE_SHUTDOWN_WRITE, 0); // 关闭写操作
                // quiche_conn_stream_shutdown(conn->conn, stream_id, QUICHE_SHUTDOWN_READ, 0);  // 关闭读操作
        
                // 保存模型数据到文件
                std::string filename = "../resource/receive_model/model_" + clientId + ".zip";
                std::ofstream outfile(filename, std::ios::binary);
                outfile.write(modelData.data(), modelData.size());
                outfile.close();
        
                std::cout << "SFU: 客户端 " << clientId << " 模型上传完毕，保存到文件 " << filename << std::endl;

                // std::cout<< "sfu isclosed after save model: " << conn->isClosed <<std::endl;
                exit(0);  // 子进程处理完后退出
            }
            else if (pid < 0) {
                std::cerr << "SFU: 创建子进程失败" << std::endl;
                continue;
            }
        }
        
        // 等待所有子进程完成
        while (waitpid(-1, nullptr, 0) > 0);

        // SFU端接收到所有模型
        std::cout<< "SFU: 端接收到所有模型"<< std::endl;


    }

    // 模型下载阶段：将每个客户端上传的模型转发给其他客户端
    void modelDownloadPhase() {
        std::cout << "SFU: 开始模型下载阶段" << std::endl;
        for (auto& kv : clientConnections) {
            std::string senderId = kv.first;
            std::string filename = "model_" + senderId + ".bin";
            std::ifstream infile(filename, std::ios::binary);
            if (!infile) {
                std::cerr << "SFU: 无法打开 " << senderId << " 的模型文件" << std::endl;
                continue;
            }
            std::vector<char> modelData((std::istreambuf_iterator<char>(infile)),
                                        std::istreambuf_iterator<char>());
            infile.close();
            // 将该模型数据转发给除发送者外的所有客户端
            for (auto& kv2 : clientConnections) {
                if (kv2.first == senderId) continue;
                QUIC* target = kv2.second;
                // 打开 stream，假设使用 stream id 0 来传输模型数据
                if (target->open_stream(0) < 0) {
                    std::cerr << "SFU: 为客户端 " << kv2.first << " 打开模型传输流失败" << std::endl;
                    continue;
                }
                ssize_t send_ret = 0;
                if (target->quic_send(0, (uint8_t*)modelData.data(), modelData.size(), true, &send_ret) < 0) {
                    std::cerr << "SFU: 向客户端 " << kv2.first << " 发送模型数据失败" << std::endl;
                } else {
                    std::cout << "SFU: 已将 " << senderId << " 的模型数据发送给 " << kv2.first << std::endl;
                }
            }
        }
    }

    // 会议阶段：周期性接收各客户端的参数码流，打包后转发给其他客户端
    void conferencePhase() {
        std::cout << "SFU: 开始会议阶段" << std::endl;
        bool running = true;
        int counter = 0;
        while (running) {
            // 遍历每个客户端，接收参数数据（假设使用 stream id 1 传输参数数据）
            for (auto& kv : clientConnections) {
                std::string clientId = kv.first;
                QUIC* conn = kv.second;
                uint8_t param_buf[MAX_BUF];
                ssize_t ret = 0;
                if (conn->quic_recv(param_buf, &ret) < 0) {
                    std::cerr << "SFU: 接收来自客户端 " << clientId << " 的参数数据失败" << std::endl;
                    continue;
                }
                // 封装数据格式：[id(1字节) | 长度(1字节) | 参数数据]
                std::vector<uint8_t> packet;
                uint8_t id_char = clientId[0];
                packet.push_back(id_char);
                uint8_t length = static_cast<uint8_t>(ret);
                packet.push_back(length);
                packet.insert(packet.end(), param_buf, param_buf + ret);
                // 转发给除发送者外的所有客户端
                for (auto& kv2 : clientConnections) {
                    if (kv2.first == clientId) continue;
                    QUIC* target = kv2.second;
                    if (target->open_stream(1) < 0) {
                        std::cerr << "SFU: 为客户端 " << kv2.first << " 打开会议传输流失败" << std::endl;
                        continue;
                    }
                    ssize_t send_ret = 0;
                    if (target->quic_send(1, packet.data(), packet.size(), false, &send_ret) < 0) {
                        std::cerr << "SFU: 向客户端 " << kv2.first << " 发送会议数据失败" << std::endl;
                    } else {
                        std::cout << "SFU: 已将来自 " << clientId << " 的会议数据转发给 " << kv2.first << std::endl;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (++counter > 10) running = false; // 模拟有限次会议循环
        }
    }

    ~SFU() {
        for (auto& kv : clientConnections) {
            delete kv.second;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config_path>" << std::endl;
        return 1;
    }

    const char* CONFIG_PATH = argv[1];  // 获取命令行参数中的配置路径
    // 假设默认参会人数为 3
    SFU sfu;
    sfu.loadConfig(CONFIG_PATH);
    sfu.waitForConnections();
    // sfu.confirmAllConnection();

    sfu.modelUploadPhase();
    std::cout << "SFU: 再上传一次" << std::endl;
    sfu.modelUploadPhase();

    // sfu.confirmUpload();

    usleep(5000000);  // 等待 1 秒，确保所有客户端连接完成

    // while (true) {
    //     usleep(100000);
    // }
    sfu.modelDownloadPhase();
    // sfu.conferencePhase();
    return 0;
}


