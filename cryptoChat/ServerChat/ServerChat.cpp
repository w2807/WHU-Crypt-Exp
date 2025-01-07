#include "ServerChat.h"

#pragma comment(lib, "ws2_32.lib")

void server_epoll() {
    std::vector<SOCKET> clnt_sockets;

    WSADATA wsaData;
    SOCKET serv_sock, clnt_sock;
    struct sockaddr_in serv_addr, clnt_addr;
    int clnt_sz = sizeof(clnt_addr);

    // 初始化 Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup() failed" << std::endl;
        return;
    }

    serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (serv_sock == INVALID_SOCKET) {
        std::cerr << "socket() error" << std::endl;
        WSACleanup();
        return;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(8080);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(serv_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
    std::cout << "Server running at " << ip_str << ":" << ntohs(serv_addr.sin_port) << std::endl;

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        std::cerr << "bind() error" << std::endl;
        closesocket(serv_sock);
        WSACleanup();
        return;
    }

    if (listen(serv_sock, 5) == SOCKET_ERROR) {
        std::cerr << "listen() error" << std::endl;
        closesocket(serv_sock);
        WSACleanup();
        return;
    }

    fd_set reads, copy_reads;
    FD_ZERO(&reads);
    FD_SET(serv_sock, &reads);

    char buffer[BUFSIZ];
    while (true) {
        copy_reads = reads;
        int event_count = select(0, &copy_reads, 0, 0, NULL);
        if (event_count == SOCKET_ERROR) {
            std::cerr << "select() error" << std::endl;
            break;
        }

        for (int i = 0; i < reads.fd_count; i++) {
            SOCKET sock = copy_reads.fd_array[i];
            if (sock == serv_sock) {
                clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_sz);
                if (clnt_sock == INVALID_SOCKET) {
                    std::cerr << "accept() error" << std::endl;
                    continue;
                }

                FD_SET(clnt_sock, &reads);
                clnt_sockets.push_back(clnt_sock);
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clnt_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                int client_port = ntohs(clnt_addr.sin_port);
                std::cout << "Connected client: " << client_ip << ":" << client_port << std::endl;
                std::cout << "Connected client: " << clnt_sock << std::endl;
            }
            else {
                int str_len = recv(sock, buffer, BUFSIZ, 0);
                if (str_len <= 0) {
                    FD_CLR(sock, &reads);
                    closesocket(sock);
                    clnt_sockets.erase(std::remove(clnt_sockets.begin(), clnt_sockets.end(), sock), clnt_sockets.end());
                    std::cout << "Closed client: " << sock << std::endl;
                }
                else {
                    for (SOCKET fd : clnt_sockets) {
                        send(fd, buffer, str_len, 0);
                    }
                }
            }
        }
    }

    for (SOCKET sock : clnt_sockets) {
        if (sock != serv_sock) { // 避免发送给服务端自身
            int send_result = send(sock, buffer, BUFSIZ, 0);
            if (send_result == SOCKET_ERROR) {
                std::cerr << "send() error on socket " << sock << std::endl;
                FD_CLR(sock, &reads);
                closesocket(sock);
                clnt_sockets.erase(std::remove(clnt_sockets.begin(), clnt_sockets.end(), sock), clnt_sockets.end());
            }
        }
    }

    closesocket(serv_sock);
    WSACleanup();
    std::cout << "Server closed" << std::endl;
}
