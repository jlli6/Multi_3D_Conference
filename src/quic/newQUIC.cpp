#include "quic/newQUIC.h"

using namespace std;

//#define PF_UNSPEC 0
//#define SOCK_DGRAM 2


int QUIC:: get_socket_fd() 
{
    return sock;  // 返回存储的套接字文件描述符
}

void QUIC::debug_log(const char *line, void *argp)
{
    //fprintf(stderr, "%s\n", line);
}

uint8_t *QUIC::gen_cid(uint8_t *cid, size_t cid_len)
{
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, cid, cid_len);
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    return cid;
}

void QUIC::mint_token(const uint8_t *dcid, size_t dcid_len, struct sockaddr_storage *addr,
                      socklen_t addr_len, uint8_t *token, size_t *token_len)
{
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

bool QUIC::validate_token(const uint8_t *token, size_t token_len, struct sockaddr_storage *addr,
                          socklen_t addr_len, uint8_t *odcid, size_t *odcid_len)
{
    if ((token_len < sizeof("quiche") - 1) || memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

quiche_conn *QUIC::create_conn(uint8_t *dcid, size_t dcid_len, uint8_t *odcid, size_t odcid_len,
                               uint8_t *cid)
{
    memcpy(cid, dcid, LOCAL_CONN_ID_LEN);

    quiche_conn *conn = quiche_accept(cid, LOCAL_CONN_ID_LEN, odcid, odcid_len, config);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return NULL;
    }

    fprintf(stdout, "new connection\n");
    return conn;
}

void QUIC::flush(int sock, sockaddr_storage *peer_addr, quiche_conn *conn, bool test)
{
    uint8_t out[MAX_DATAGRAM_SIZE];
    while (1) {
        ssize_t written = quiche_conn_send(conn, out, sizeof(out));
        if (written == QUICHE_ERR_DONE) {
            // fprintf(stdout, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = sendto(sock, out, written, 0, (struct sockaddr *)peer_addr, peer_addr_len);

        if (sent != written) {
            perror("failed to send");
            return;
        }
        // if (test)
            // fprintf(stdout, "senddd: sent %zd bytes\n", sent);
        // else
            // fprintf(stdout, "recvvv: sent %zd bytes\n", sent);
        if (curLEVEL < DEBUGLEVEL) {
            timeval flushtime;
            gettimeofday(&flushtime, NULL);
            fprintf(
                stdout, "Sending Time: %d\n", 1000 * flushtime.tv_sec + flushtime.tv_usec / 1000);
        }
    }
}

QUIC::QUIC()
{
    conn = nullptr;
    const char *versionn;
    versionn = quiche_version();
    // fprintf(stdout, "Current version: %s\n", versionn);
    const char *correstVersion = "0.8.1";

    if (strcmp(versionn, correstVersion) != 0) {
        fprintf(stderr, "QUICHE version is not %s\n", correstVersion);
        exit(0);
    }
}

QUIC::~QUIC()
{
    if (conn != nullptr) {
        freeaddrinfo(sock_addr);
        quiche_conn_free(conn);
        quiche_config_free(config);
        if (TYPE == SERVER) {
            delete peer_addr;
        }
    }
}

/*Init a server config.*/
/*put ip address into host and port here.*/
ssize_t QUIC::server_init(char *host, char *port)
{
    TYPE          = SERVER;
    peer_addr_len = sizeof(sockaddr_storage);
    peer_addr     = new sockaddr_storage;
    isClosed      = false;
    memset(peer_addr, 0, peer_addr_len);
    gettimeofday(&recvtime, NULL);

    for (int i = 0; i < STREAM_NUM + 1; i++) { stream_stat[i] = false; }

    addrinfo hints = {
        .ai_family = PF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP};

    quiche_enable_debug_logging(debug_log, NULL);

    if (getaddrinfo(host, port, &hints, &sock_addr) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    sock = socket(sock_addr->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (bind(sock, sock_addr->ai_addr, sock_addr->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_load_cert_chain_from_pem_file(config, "../cert.crt");
    quiche_config_load_priv_key_from_pem_file(config, "../cert.key");

    quiche_config_set_application_protos(
        config, (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);

    quiche_config_set_max_idle_timeout(config, 50000);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);

    return 0;
}

/*Init a client config.*/
/*put ip address into host and port here.*/
ssize_t QUIC::client_init(char *host, char *port)
{
    TYPE          = CLIENT;
    isClosed      = false;
    peer_addr     = NULL;
    peer_addr_len = 0;

    for (int i = 0; i < STREAM_NUM + 1; i++) { stream_stat[i] = false; }

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP};

    if (getaddrinfo(host, port, &hints, &sock_addr) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    sock = socket(sock_addr->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (connect(sock, sock_addr->ai_addr, sock_addr->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    config = quiche_config_new(0xbabababa);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_set_application_protos(
        config, (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);

    quiche_config_set_max_idle_timeout(config, 50000);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_set_disable_active_migration(config, true);

    if (getenv("SSLKEYLOGFILE")) {
        quiche_config_log_keys(config);
    }

    return 0;
}

/*Make a connection action. This need to run multiple times.*/
ssize_t QUIC::server_try_connect()
{
    fd_set rd;
    int    err;
    FD_ZERO(&rd);
    FD_SET(sock, &rd);
    if (curLEVEL < DEBUGLEVEL)
        printf("Check Sock:\n");
    timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = 0;
    err             = select(sock + 1, &rd, NULL, NULL, NULL);
    if (err == 0) { //timeout
        if (curLEVEL < DEBUGLEVEL)
            printf("select time out!\n");
    } else if (err == -1) { //failed
        if (curLEVEL < DEBUGLEVEL)
            printf("fail to select!\n");
    } else { //success
        if (curLEVEL < DEBUGLEVEL)
            printf("data is available!\n");
        uint8_t buf[65535];
        uint8_t out[MAX_DATAGRAM_SIZE];
        while (1) {
            if (curLEVEL < DEBUGLEVEL)
                fprintf(stderr, "in while 1\n");
            ssize_t read = recvfrom(
                sock, buf, sizeof(buf), 0, (struct sockaddr *)peer_addr, &peer_addr_len);

            if (read < 0) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    fprintf(stderr, "recv would block\n");
                    break;
                }

                perror("failed to read");
                return -1;
            }

            if (read > 0) {
                uint8_t  type;
                uint32_t version;

                uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
                size_t  scid_len = sizeof(scid);

                uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
                size_t  dcid_len = sizeof(dcid);

                uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
                size_t  odcid_len = sizeof(odcid);
                fprintf(stderr, "init odcid\n");

                uint8_t token[MAX_TOKEN_LEN];
                size_t  token_len = sizeof(token);

                int rc = quiche_header_info(buf,
                                            read,
                                            LOCAL_CONN_ID_LEN,
                                            &version,
                                            &type,
                                            scid,
                                            &scid_len,
                                            dcid,
                                            &dcid_len,
                                            token,
                                            &token_len);
                if (rc < 0) {
                    fprintf(stderr, "failed to parse header: %d\n", rc);
                    return -1;
                }
                if (conn == NULL) {
                    if (!quiche_version_is_supported(version)) {
                        if (curLEVEL < DEBUGLEVEL)
                            fprintf(stderr, "version negotiation\n");

                        ssize_t written = quiche_negotiate_version(
                            scid, scid_len, dcid, dcid_len, out, sizeof(out));

                        if (written < 0) {
                            fprintf(stderr, "failed to create vneg packet: %zd\n", written);
                            return -1;
                        }

                        ssize_t sent = sendto(
                            sock, out, written, 0, (struct sockaddr *)peer_addr, peer_addr_len);
                        if (sent != written) {
                            perror("failed to send");
                            return -1;
                        }

                        fprintf(stderr, "sent %zd bytes\n", sent);
                        return 0;
                    }

                    if (token_len == 0) {
                        if (curLEVEL < DEBUGLEVEL)
                            fprintf(stderr, "stateless retry\n");

                        mint_token(dcid, dcid_len, peer_addr, peer_addr_len, token, &token_len);

                        uint8_t new_cid[LOCAL_CONN_ID_LEN];

                        if (gen_cid(new_cid, LOCAL_CONN_ID_LEN) == NULL) {
                            continue;
                        }

                        ssize_t written = quiche_retry(scid,
                                                       scid_len,
                                                       dcid,
                                                       dcid_len,
                                                       new_cid,
                                                       LOCAL_CONN_ID_LEN,
                                                       token,
                                                       token_len,
                                                       version,
                                                       out,
                                                       sizeof(out));

                        if (written < 0) {
                            fprintf(stderr, "failed to create retry packet: %zd\n", written);
                            return -1;
                        }

                        ssize_t sent = sendto(
                            sock, out, written, 0, (struct sockaddr *)peer_addr, peer_addr_len);
                        if (sent != written) {
                            perror("failed to send");
                            return -1;
                        }

                        fprintf(stderr, "sent %zd bytes\n", sent);
                        return 0;
                    }

                    if (!validate_token(
                            token, token_len, peer_addr, peer_addr_len, odcid, &odcid_len)) {
                        fprintf(stderr, "invalid address validation token\n");
                        return -1;
                    }
                    fprintf(stderr, "validate_token\n");

                    uint8_t cid[LOCAL_CONN_ID_LEN];
                    conn = create_conn(dcid, dcid_len, odcid, odcid_len, cid);

                    if (conn == NULL) {
                        fprintf(stderr, "create_conn failed.\n");
                        return -1;
                    }
                }
                ssize_t done = quiche_conn_recv(conn, buf, read);

                if (done == QUICHE_ERR_DONE) {
                    fprintf(stderr, "done reading\n");
                    break;
                }

                if (done < 0) {
                    fprintf(stderr, "failed to process packet: %zd\n", done);
                    return -1;
                }

                fprintf(stderr, "recv %zd bytes\n", done);

                if (quiche_conn_is_established(conn)) {
                    if (curLEVEL < DEBUGLEVEL)
                        fprintf(stderr, "QUICHE_CONN is established\n");
                    uint64_t s = 0;

                    quiche_stream_iter *readable = quiche_conn_readable(conn);

                    while (quiche_stream_iter_next(readable, &s)) {
                        fprintf(stdout, "stream %" PRIu64 " is readable\n", s);

                        bool    fin      = false;
                        ssize_t recv_len = quiche_conn_stream_recv(conn, s, buf, sizeof(buf), &fin);
                        if (recv_len < 0) {
                            break;
                        }

                        if (s == 4 && !stream_stat[s]) {
                            fprintf(stdout, "opening stream: %" PRIu64 ".\n", s);
                            stream_stat[s] = true;
                        }
                    }
                    quiche_stream_iter_free(readable);
                }
            }
        }
        flush(sock, peer_addr, conn, false);
    }
    return 0;
}

/*Repeatedly try to connect to client until the connection is done.*/
ssize_t QUIC::server_connect()
{
    if (TYPE == CLIENT) {
        fprintf(stderr, "Wrong quic type!\n");
        return -2;
    }

    while (conn == NULL || !quiche_conn_is_established(conn)) {
        if (server_try_connect() == 0) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

/*Connect the client to server.*/
ssize_t QUIC::client_connect(char *host)
{
    if (TYPE == SERVER) {
        fprintf(stderr, "Wrong quic type!\n");
        return -2;
    }

    uint8_t scid[LOCAL_CONN_ID_LEN];
    int     rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return -1;
    }

    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return -1;
    }

    conn = quiche_connect(host, (const uint8_t *)scid, sizeof(scid), config);
    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return -1;
    }

    flush(sock, peer_addr, conn, false);

    uint8_t buf[65535];
    fd_set  read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = 0;
    while (!quiche_conn_is_established(conn)) {
        select(sock + 1, &read_fds, NULL, NULL, NULL);
        while (1) {
            ssize_t read = recv(sock, buf, sizeof(buf), 0);

            if (read < 0) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    // fprintf(stderr, "recv would block\n");
                    break;
                }

                perror("failed to read");
                return -1;
            }

            ssize_t done = quiche_conn_recv(conn, buf, read);

            if (done == QUICHE_ERR_DONE) {
                fprintf(stderr, "done reading\n");
                break;
            }

            if (done < 0) {
                fprintf(stderr, "failed to process packet\n");
                return done;
            }

            // fprintf(stderr, "recv %zd bytes\n", done);
        }

        flush(sock, peer_addr, conn, false);
    }

    return 0;
}

/*Send a certain length of len in buf.*/
/*s: stream ID,

    open_stream(s) MUST be run BEFORE this send function!

    fin: If this is the last message of this stream connection
    ret: The return of this function, needs to be newed outside the function.
        Pointer of the total length of sent bytes
    */
ssize_t QUIC::quic_send(uint64_t s, uint8_t *buf, int len, bool fin, ssize_t *ret)
{
    timeval start, end;
    bool    BolckFlag     = false;
    bool    NonBlockFlage = false;
    if (conn != NULL && quiche_conn_is_established(conn)) {
        if (curLEVEL < DEBUGLEVEL)
            fprintf(stdout, "SENDINGGGGG: ALL GOOD\n");
        int send_size = 1;
        int byte_send = 1;
        int total_len = 0;
        if (len < 0) {
            fprintf(stdout, "error: %d\n", len);
            *ret = -1;
            return -1;
        }

        if (s % 4 == 2 && TYPE == SERVER) {
            fprintf(stderr, "Wrong quic type!\n");
            *ret = -2;
            return -2;
        }
        if (s % 4 == 3 && TYPE == CLIENT) {
            fprintf(stderr, "Wrong quic type!\n");
            *ret = -2;
            return -2;
        }

        BolckFlag     = false;
        NonBlockFlage = false;
        while (len > 0) {
            timeval flushtime;
            if (curLEVEL < DEBUGLEVEL) {
                gettimeofday(&flushtime, NULL);
                fprintf(stdout,
                        "Sending: wait for lock : %d\n",
                        (1000 * flushtime.tv_sec + flushtime.tv_usec / 1000));
            }

            conn_mutex.lock();

            if (curLEVEL < DEBUGLEVEL) {
                gettimeofday(&flushtime, NULL);
                fprintf(stdout,
                        "Sending: LOCKED! %d\n",
                        (1000 * flushtime.tv_sec + flushtime.tv_usec / 1000));
            }
            int capacity = quiche_conn_stream_capacity(conn, s);

            // for (int num =0 ; num<17;num++){
            //     std::cout<<quiche_conn_stream_capacity(conn, num)<< std::endl;
            // }
            // if (capacity >0)
            //     std::cout<< "capacity:"<< capacity<<std::endl;
            byte_send   = MIN(capacity, len);
            if (byte_send <= 0) {
                if (!BolckFlag) {
                    if (curLEVEL < DEBUGLEVEL) {
                        gettimeofday(&start, NULL);
                        fprintf(stdout,
                                "Starting time:  %d\n",
                                (1000 * start.tv_sec + start.tv_usec / 1000));
                    }
                    BolckFlag     = true;
                    NonBlockFlage = true;

                    if (curLEVEL < DEBUGLEVEL)
                        fprintf(stdout, "%d ; %d\n", capacity, len);

                    fprintf(stdout, "No capacity in stream\n");
                }
                conn_mutex.unlock();
                usleep(500);
                continue;
            }

            if (BolckFlag && NonBlockFlage) {
                if (curLEVEL < DEBUGLEVEL) {
                    gettimeofday(&end, NULL);
                    fprintf(stdout, "Ending time:  %d\n", (1000 * end.tv_sec + end.tv_usec / 1000));
                    fprintf(stdout,
                            "time gap: %d\n",
                            (1000 * (end.tv_sec - start.tv_sec) +
                             (end.tv_usec - start.tv_usec) / 1000));
                }
                NonBlockFlage = false;
            }

            // fprintf(stdout,
            //         "remain %d bytes, capacity %d bytes, send %d bytes\n",
            //         len,
            //         capacity,
            //         byte_send);

            send_size = quiche_conn_stream_send(conn, s, buf, len, fin);
            if (send_size <= 0) {
                fprintf(stderr, "vpipe send error%d\n", send_size);
                conn_mutex.unlock();
                usleep(500);
                continue;
            }
            len -= send_size;
            buf += send_size;
            total_len += send_size;

            if (curLEVEL < DEBUGLEVEL)
                fprintf(stdout, "flushing: SEND\n");
            flush(sock, peer_addr, conn, true);
            if (curLEVEL < DEBUGLEVEL)
                fprintf(stdout, "flushing: END SEND\n");
            conn_mutex.unlock();

            usleep(500);
        }

        *ret = total_len;
        return total_len;
    } else {
        fprintf(stderr, "Unable to send: no connection!\n");
        *ret = -1;
        return -1;
    }
}

/*Open a stream s connection*/
ssize_t QUIC::open_stream(uint64_t s)
{   
    isClosed = false;
    if (s % 2 == 0 && TYPE == SERVER) {
        fprintf(stderr, "Server type should not initiate stream %d\n", s);
        return -2;
    } else if (s % 2 != 0 && TYPE == CLIENT) {
        fprintf(stderr, "Client type should not initiate stream %d\n", s);
        return -2;
    }
    if (quiche_conn_is_established(conn)) {
        const uint8_t *app_proto;
        size_t         app_proto_len;

        quiche_conn_application_proto(conn, &app_proto, &app_proto_len);

        // fprintf(stderr, "connection established: %.*s\n", (int)app_proto_len, app_proto);

        const uint8_t r[] = "GET /index.html\r\n";
        if (quiche_conn_stream_send(conn, s, r, sizeof(r), false) < 0) {
            fprintf(stderr, "failed to send HTTP request\n");
            return -1;
        }

        // fprintf(stderr, "sent HTTP request\n");

        stream_stat[s] = true;
        flush(sock, peer_addr, conn, false);
        return 0;
    } else {
        fprintf(stderr, "Unable to open stream: quiche_conn not established!\n");
        return -1;
    }
}

/*receive the content and save it in the recvbuf*/
/*
recvbuf: The address of the received content.
ret: The return of this function, needs to be newed outside the function.
        Pointer of the total length of received bytes
*/
ssize_t QUIC::quic_recv(uint8_t *recv_buf, ssize_t *ret)
{
    ssize_t total_len = 0;
    fd_set  rd;
    int     err;
    FD_ZERO(&rd);
    FD_SET(sock, &rd);

    timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = 0;

    timeval flushtime;
    flushtime.tv_sec  = 0;
    flushtime.tv_usec = 500;

    timeval thistime;
    err = select(sock + 1, &rd, NULL, NULL, &timeout);
    if (err == 0) { //timeout
        if (curLEVEL < DEBUGLEVEL)
            printf("select time out!\n");
        *ret = 0;
        return 0;
    } else if (err == -1) { //failed
        if (curLEVEL < DEBUGLEVEL)
            printf("fail to select!\n");
        *ret = -1;
        return -1;
    } else { //success
        thistime = recvtime;
        if (curLEVEL < DEBUGLEVEL) {
            gettimeofday(&recvtime, NULL);
            fprintf(stdout,
                    "RECEIVING, wait for lock: %d\n",
                    1000 * (recvtime.tv_sec) + (recvtime.tv_usec) / 1000);
        }

        if (curLEVEL < DEBUGLEVEL)
            fprintf(stdout, "Something to recv!\n");

        uint8_t buf[MAX_BUF];

        conn_mutex.lock();
        if (curLEVEL < DEBUGLEVEL) {
            gettimeofday(&recvtime, NULL);
            fprintf(stdout,
                    "RECEIVING, locked! %d\n",
                    1000 * (recvtime.tv_sec) + (recvtime.tv_usec) / 1000);
        }
        while (1) {
            timeval flushtime;
            if (curLEVEL < DEBUGLEVEL) {
                gettimeofday(&flushtime, NULL);
                fprintf(
                    stdout, "whileRECV: %d\n", 1000 * flushtime.tv_sec + flushtime.tv_usec / 1000);
            }
            ssize_t read = recvfrom(
                sock, buf, sizeof(buf), 0, (struct sockaddr *)peer_addr, &peer_addr_len);
            if (read < 0) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    // fprintf(stdout, "recv would block\n");
                    break;
                }

                perror("failed to read");
                *ret = -1;
                conn_mutex.unlock();
                return -1;
            }

            if (read > 0) {
                ssize_t done = quiche_conn_recv(conn, buf, read);

                if (done == QUICHE_ERR_DONE) {
                    fprintf(stdout, "done reading\n");
                    break;
                }

                if (done < 0) {
                    fprintf(stderr, "quic_recv failed to process packet: %zd\n", done);
                    *ret = -1;
                    conn_mutex.unlock();
                    return -1;
                }

                // fprintf(stdout, "recv %zd bytes\n", done);
            }
        }

        if (quiche_conn_is_closed(conn)) {
            // fprintf(stderr, "connection closed\n");
            *ret = -1;
            conn_mutex.unlock();
            return -1;
        }

        if (quiche_conn_is_established(conn)) {
            if (curLEVEL < DEBUGLEVEL)
                fprintf(stdout, "QUICHE_CONN is established\n");
            uint64_t s = 0;

            quiche_stream_iter *readable = quiche_conn_readable(conn);

            while (quiche_stream_iter_next(readable, &s)) {
                // fprintf(stdout, "stream %" PRIu64 " is readable\n", s);

                bool    fin      = false;
                ssize_t recv_len = quiche_conn_stream_recv(conn, s, buf, sizeof(buf), &fin);
                if (recv_len < 0) {
                    break;
                }

                if (!stream_stat[s]) {
                    // fprintf(stdout, "opening stream: %" PRIu64 ".\n", s);
                    stream_stat[s] = true;
                } else {
                    memcpy(recv_buf + total_len, buf, recv_len);
                    total_len += recv_len;

                    if (curLEVEL < DEBUGLEVEL)
                        fprintf(stdout, "total_len: %d\n", total_len);
                }
            }

            quiche_stream_iter_free(readable);
        }

        flush(sock, peer_addr, conn, false);

        conn_mutex.unlock();
        *ret = total_len;
        if (curLEVEL < DEBUGLEVEL)
            // fprintf(stdout, "returning..\n");
        return total_len;
    }
}

/*Keep receive in the back*/
void QUIC::keep_recv(uint8_t *recv_buf, ssize_t *ret)
{
    while (!isClosed) { quic_recv(recv_buf, ret); }
    // fprintf(stdout, "Stoped recv!\n");
    return;
}

void QUIC::stop_recv()
{
    isClosed = true;
    // fprintf(stdout, "Trying to stop recving..\n");
}

/*Keep a thread to keep receiving*/
void QUIC::threadRecv(uint8_t *recv_buf, ssize_t *ret)
{
    recvThread = thread(&QUIC::keep_recv, this, recv_buf, ret);
    recvThread.detach();
    return;
}

/*Time out event. Not used currently.*/
void QUIC::timeout()
{
    conn_mutex.lock();
    quiche_conn_on_timeout(conn);

    if (quiche_conn_is_closed(conn)) {
        flush(sock, peer_addr, conn, false);
        quiche_stats stats;
        quiche_conn_stats(conn, &stats);
        // fprintf(stderr,
        //         "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns\n",
        //         stats.recv,
        //         stats.sent,
        //         stats.lost,
        //         stats.rtt);
        isClosed = true;
        conn_mutex.unlock();
        return;
    }
    conn_mutex.unlock();
}

void QUIC::keepCheck()
{
    while (!isClosed) { timeout(); }
}

void QUIC::threadTimeout()
{
    timeoutThread = thread(&QUIC::keepCheck, this);
    timeoutThread.detach();
    return;
}
