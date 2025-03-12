#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <thread>
#include <mutex>
#include <sys/time.h>
#include <errno.h>

#include "quiche.h"

using namespace std;

//#define PF_UNSPEC 0
//#define SOCK_DGRAM 2

#define SERVER true
#define CLIENT false

#define DEBUGLEVEL 10
#define curLEVEL 20

#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350

#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

#define MAX_BUF 32768
#define STREAM_NUM 16
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))


class QUIC {
public:
    quiche_conn *conn;
    int sock;
    addrinfo *sock_addr;
    sockaddr_storage *peer_addr;
    socklen_t peer_addr_len;
    quiche_config *config;
    bool TYPE;
    bool stream_stat[STREAM_NUM + 1];
    thread recvThread;
    thread timeoutThread;
    mutex conn_mutex;
    timeval recvtime;
    bool isClosed;
private:

    static void debug_log(const char *line, void *argp);

    uint8_t *gen_cid(uint8_t *cid, size_t cid_len);


    void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len);

    bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len);


    quiche_conn *create_conn(uint8_t *dcid, size_t dcid_len, uint8_t *odcid,
                                 size_t odcid_len, uint8_t *cid);


    void flush(int sock, sockaddr_storage *peer_addr, quiche_conn *conn, bool test);

public:
    QUIC();

    ~QUIC();

    /*Init a server config.*/
    /*put ip address into host and port here.*/
    ssize_t server_init(char *host, char *port);

    /*Init a client config.*/
    /*put ip address into host and port here.*/
    ssize_t client_init(char *host, char *port);

    /*Make a connection action. This need to run multiple times.*/
    ssize_t server_try_connect();

    /*Repeatedly try to connect to client until the connection is done.*/
    ssize_t server_connect();

    /*Connect the client to server.*/
    ssize_t client_connect(char *host);

    int get_socket_fd();




    /*Send a certain length of len in buf.*/
    /*s: stream ID,

      open_stream(s) MUST be run BEFORE this send function!

      fin: If this is the last message of this stream connection
      ret: The return of this function, needs to be newed outside the function.
           Pointer of the total length of sent bytes
      */
    ssize_t quic_send(uint64_t s, uint8_t * buf, int len, bool fin, ssize_t *ret);

    /*Open a stream s connection*/
    ssize_t open_stream(uint64_t s);

    /*receive the content and save it in the recvbuf*/
    /*
    recvbuf: The address of the received content.
    ret: The return of this function, needs to be newed outside the function.
         Pointer of the total length of received bytes
    */
    ssize_t quic_recv(uint8_t* recv_buf, ssize_t *ret);

    /*Keep receive in the back*/
    void keep_recv(uint8_t* recv_buf, ssize_t *ret);

    void stop_recv();

    /*Keep a thread to keep receiving*/
    void threadRecv(uint8_t* recv_buf, ssize_t *ret);

    /*Time out event. Not used currently.*/
    void timeout();

    void keepCheck();

    void threadTimeout();
};

