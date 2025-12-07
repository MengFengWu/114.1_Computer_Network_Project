#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>
#include <errno.h>
#include <unistd.h>

#include "crypto.h"

#include <map>
#include <deque>

#define MAX_HISTORY 30

std::string myName;
int listenPort;
int listenSocket = -1;

int peerSocket = -1; 
std::string peerName = "";

int groupSocket = -1; 

std::map<int, Crypto*> clientCryptos;

std::map<std::string, std::deque<std::string>> chatHistory;

struct groupData {
    std::deque<std::string> groupHistory;
    GroupCrypto groupCrypto;
};

std::map<std::string, groupData> groups;

enum state{
    IDLE,
    PENDING,
    CHATTING,
    GROUPING,
    WAITFILE
};

state clientState = IDLE;

std::string getPrimaryLocalIP() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);  // DNS port
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);

    connect(sock, (sockaddr*)&dst, sizeof(dst));

    sockaddr_in name{};
    socklen_t namelen = sizeof(name);
    getsockname(sock, (sockaddr*)&name, &namelen);

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &name.sin_addr, buf, sizeof(buf));

    close(sock);
    return buf;
}

bool isSelfConnection(const std::string& targetIP, int targetPort, int listenPort) {
    // Loopback is always self
    if (targetIP == "127.0.0.1" || targetIP == "::1")
        return targetPort == listenPort;

    // Real local IP
    static std::string localIP = getPrimaryLocalIP();

    if (targetIP == localIP && targetPort == listenPort)
        return true;

    return false;
}

void send_all_raw(int sockfd, const std::string &msg) {
    send(sockfd, msg.c_str(), msg.size(), 0);
}

void send_all(int sockfd, const std::string &msg) {
    if(clientCryptos.count(sockfd)) {
        std::string encryptedMsg = clientCryptos[sockfd]->encrypt(msg);
        send(sockfd, encryptedMsg.c_str(), encryptedMsg.size(), 0);
    }
}

int receive_all(int sockfd, std::string &res) {
    if(!clientCryptos.count(sockfd)) {
        return -1;
    }
    char buf[4096];
    ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';
    res = buf;
    res = clientCryptos[sockfd]->decrypt(res);
    while(!res.empty() && (res.back() == '\n' || res.back() == '\r')) {
        res.pop_back();
    }
    return 0;
}

Crypto* crypto_init(int sockfd) {
    Crypto *crypto = new Crypto();
    std::string myPublicKey = crypto->get_my_public_key();
    send_all_raw(sockfd, myPublicKey);
    char buf[4096];
    ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
    if(n <= 0) return nullptr;
    buf[n] = '\0';
    std::string peerKey(buf);
    crypto->set_peer_public_key(peerKey);
    clientCryptos[sockfd] = crypto;
    return crypto;
}

void safe_close(int sockfd) {
    if(clientCryptos.count(sockfd)) {
        delete clientCryptos[sockfd];
        clientCryptos.erase(sockfd);
    }
    close(sockfd);
}

int parse(std::string line, char token[4][4096]) {
    for(int i = 0; i < 4; i++) token[i][0] = '\0';
    int n = 0, ind = 0;
    int i = 0;
    while(i < line.length()) {
        if(line[i] == ' ') {
            token[n][ind] = '\0';
            n += 1;
            ind = 0;
            if(n >= 4) break;
            while(i < line.length() && line[i] == ' ') i++;
        }
        else {
            token[n][ind] = line[i];
            ind += 1;
            i++;
        }
    }
    if(n < 4) token[n][ind] = '\0';
    return n + 1;
}

void print_chat_history(std::deque<std::string> &history) {
    for(std::deque<std::string>::iterator it = history.begin(); it != history.end(); it++) {
        std::cout << *it << "\n";
    }
}

void save_chat_history(std::deque<std::string> &history, const std::string &line) {
    history.push_back(line);
    while(history.size() > MAX_HISTORY) {
        history.pop_front();
    }
}

// send request
// C: chatting
// G: group chat
bool send_request(int socket, const std::string &message, const std::string type) {
    char token[4][4096];
    int argc = parse(message, token);
    
    Crypto *crypto = crypto_init(socket);

    send_all(socket, type + " " + message);
    std::string res;
    if(receive_all(socket, res) < 0) return false;
    if(type == "C" || type == "F") {
        if(res == "y") return true;
        else return false;
    }
    else if(type == "G") {
        std::string groupName = token[1];
        groups[groupName].groupCrypto.set_group_key(res);
        return true;
    }
    else return false;
}

int send_file(int sockfd, const std::string &filename) {
    std::fstream file;
    file.open(filename, std::ios::in);
    if(!file) {
        return -1;
    }
    char buf[2048];
    while(file.read(buf, sizeof(buf) - 1) || file.gcount() > 0) {
        std::streamsize bytes_read = file.gcount();
        std::string chunk(buf, bytes_read);
        std::string encryptedMsg = clientCryptos[sockfd]->encrypt(chunk);
        send(sockfd, encryptedMsg.c_str(), encryptedMsg.size(), 0);
        recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (!file) break;

    }
    return 0;
}

int receive_file(int sockfd, const std::string &filename) {
    std::fstream file;
    file.open(filename, std::ios::out);
    if(!file) {
        return -1;
    }
    char buf[16384];
    ssize_t bytes_received;
    while (true) {
        bytes_received = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (bytes_received <= 0) return -1;
        buf[bytes_received] = '\0';
        std::string res = buf;
        res = clientCryptos[sockfd]->decrypt(res);
        send(sockfd, "ACK", std::string("ACK").size(), 0);

        if (bytes_received > 0) {
            file.write(res.c_str(), res.size());
        } 
        else if (bytes_received == 0) {
            break;
        } 
        else {
            return -1;
        }
    }
    file.close();
    return 0;
}

void chat_mode() {
    std::cout << "---Entered Chat Room (Type \"_exit\" to quit)---\n";
    clientState = CHATTING;

    print_chat_history(chatHistory[peerName]);

    fd_set read_fds;
    char buf[4096];

    while(true) {
        std::cout << "> " << std::flush;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(peerSocket, &read_fds);

        int activity = select(peerSocket + 1, &read_fds, NULL, NULL, NULL);

        if((activity < 0) && (errno != EINTR)) {
            perror("Error");
            break;
        }

        if(FD_ISSET(peerSocket, &read_fds)) {
            std::string res;
            if(receive_all(peerSocket, res) < 0) {
                std::cout << "\33[2K\r(" << peerName << " has left the chat)\n";
                break;
            }
            std::cout << "\33[2K\r" << peerName << ": " << res << "\n";
            save_chat_history(chatHistory[peerName], peerName + ": " + res);
        }
        if(FD_ISSET(STDIN_FILENO, &read_fds)) {
            std::string input;
            if(!getline(std::cin, input) || input == "_exit") break;
            std::cout << "\033[A\33[2K\r" << myName << ": " << input << "\n";
            send_all(peerSocket, input);
            save_chat_history(chatHistory[peerName], myName + ": " + input);
        }
    }

    safe_close(peerSocket);
    peerSocket = -1;
    peerName = "";

    std::cout << "---Left Chat Room---\n";
    clientState = IDLE;
}

void group_mode(int serverSocket, const std::string &groupName) {
    std::cout << "---Entered Group Room (Type \"_exit\" to quit)---\n";
    clientState = GROUPING;

    print_chat_history(groups[groupName].groupHistory);

    std::cout << "\33[2K\r(" << myName << " has entered the room)\n";
    save_chat_history(groups[groupName].groupHistory, "(" + myName + " has entered the room)");

    fd_set read_fds;
    char buf[4096];

    while(true) {
        std::cout << "> " << std::flush;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(serverSocket, &read_fds);

        int activity = select(serverSocket + 1, &read_fds, NULL, NULL, NULL);

        if((activity < 0) && (errno != EINTR)) {
            perror("Error");
            break;
        }

        if(FD_ISSET(serverSocket, &read_fds)) {
            std::string res;
            if(receive_all(serverSocket, res) < 0) { // server is down
                break;
            }

            char token[4][4096];
            int argc = parse(res, token);
            std::string msg = groups[groupName].groupCrypto.decrypt(res);
            std::string cmd = token[0];
            if(cmd == "_exit" || cmd == "_join") {
                if(cmd == "_exit") {
                    std::cout << "\33[2K\r(" << token[1] << " has left the room)\n";
                    save_chat_history(groups[groupName].groupHistory, "(" + std::string(token[1]) + " has left the room)");
                }
                else {
                    std::cout << "\33[2K\r(" << token[1] << " has entered the room)\n";
                    save_chat_history(groups[groupName].groupHistory, "(" + std::string(token[1]) + " has entered the room)");
                }

                std::string targetIP = token[2];
                int targetPort = atoi(token[3]);

                if(!isSelfConnection(targetIP, targetPort, listenPort)) {
                    // std::cout << "[CLIENT] Connecting to " << targetIP << ":" << targetPort << "...\n";
                    groupSocket = socket(AF_INET, SOCK_STREAM, 0);
                    if(groupSocket < 0) {
                        perror("Error");
                        std::cout << "[CLIENT] Connection failed, please retry later\n";
                        peerSocket = -1;
                        continue;
                    }
                    sockaddr_in groupAddr;
                    groupAddr.sin_family = AF_INET;
                    groupAddr.sin_port = htons(targetPort);
                    inet_pton(AF_INET, targetIP.c_str(), &groupAddr.sin_addr);
                    if(connect(groupSocket, (struct sockaddr*)&groupAddr, sizeof(groupAddr)) < 0) {
                        perror("Error");
                        std::cout << "[CLIENT] Connection failed, please retry later\n";
                        safe_close(groupSocket);
                        groupSocket = -1;
                    }
                    else {
                        if(send_request(groupSocket, myName + " " + groupName, "G")) {
                            safe_close(groupSocket);
                            groupSocket = -1;
                        }
                        else {
                            std::cout << "[CLIENT] Connection refused\n";
                            safe_close(groupSocket);
                            groupSocket = -1;
                        }
                    }
                }
            }
            else {
                std::cout << "\33[2K\r" << msg << "\n";
                save_chat_history(groups[groupName].groupHistory, msg);
            }
        }
        if(FD_ISSET(STDIN_FILENO, &read_fds)) {
            std::string input;
            if(!getline(std::cin, input) || input == "_exit") {
                std::cout << "\033[A\33[2K\r(" << myName << " has left the room)\n";
                save_chat_history(groups[groupName].groupHistory, "(" + myName + " has left the room)");
                send_all(serverSocket, "_exit\n");
                break;
            }
            std::cout << "\033[A\33[2K\r";
            std::string msg = groups[groupName].groupCrypto.encrypt(myName + ": " + input);
            send_all(serverSocket, msg);
            // save_chat_history(groups[groupName].groupHistory, myName + ": " + input);
        }
    }
    groupSocket = -1;

    std::cout << "---Left Group Room---\n";
    clientState = IDLE;
}

void* listener(void* arg) {
    int port = *(int*)arg;
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(listenSocket, (sockaddr*)&addr, sizeof(addr));
    listen(listenSocket, 5);

    while(true) {
        sockaddr_in caddr;
        socklen_t len = sizeof(caddr);
        int csock = accept(listenSocket, (sockaddr*)&caddr, &len);
        Crypto *crypto = crypto_init(csock);
        // if(clientState != IDLE) {
        //     safe_close(csock);
        //     continue;
        // }

        std::string res;
        if(receive_all(csock, res) < 0) {
            safe_close(csock);
            continue;
        }

        char token[4][4096];
        int argc = parse(res, token);
        
        if (argc >= 2) {
            std::string cmd = token[0];
            if(cmd == "C" && clientState == IDLE) {
                peerSocket = csock;
                peerName = token[1];
                std::cout << "\n[REQUEST] " << peerName << " wants to chat with you, accept? (y/n)\n> " << std::flush;

                clientState = PENDING;
            }
            else if(cmd == "G") {
                std::string groupName = token[2];
                send_all(csock, groups[groupName].groupCrypto.get_group_key());
                safe_close(csock);
                continue;
            }
            else if(cmd == "S" && clientState != PENDING && clientState != WAITFILE) {
                // std::cout << "S detected\n";
                std::string groupName = token[1];
                groups[groupName].groupCrypto.set_random_group_key();
                send_all(csock, "_ACK\n");
                safe_close(csock);
                continue;
            }
            else if(cmd == "F") {
                peerSocket = csock;
                peerName = token[1];
                std::cout << "\n[REQUEST] " << peerName << " wants to send a file to you, accept? (y/n)\n> " << std::flush;

                clientState = WAITFILE;
            }
            else {
                safe_close(csock);
                continue;
            }
        }
        else {
            safe_close(csock);
            continue;
        }
    }
    return nullptr;
}

int main(int argc, char** argv) {
    if(argc < 3) { 
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port>\n";
        return 1;
    }
    std::string serverIP = argv[1];
    int serverPort = atoi(argv[2]);
    // int listenPort = atoi(argv[3]);

    int mySocket = socket(AF_INET, SOCK_STREAM, 0);
    if(mySocket < 0) {
        perror("Error");
        return 1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddress.sin_addr) <= 0) {
        perror("Error");
        return 1;
    }
    if (connect(mySocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Error");
        safe_close(mySocket);
        return 1;
    }

    Crypto *crypto = crypto_init(mySocket);
    if(crypto == nullptr) {
        safe_close(mySocket);
        return 1;
    }

    std::cout << "Connected to server\n";
    std::cout << "Commands: register <username> <password> | login <username> <password> <client_listen_port> | logout | list | quit\n"
              << "        | chat <username> | group | create <groupname> | join <groupname> | send <username> <filename>\n";

    std::string line;
    while (true) {
        std::cout << "> ";
        if (!getline(std::cin, line)) break;
        if (line == "quit") {
            send_all(mySocket, "quit\n");
            break;
        }

        std::string pa = line;
        while(!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        // cout << "received: " << line << "\n";
        if(!line.empty()) {
            char token[4][4096];
            int argc = parse(line, token);
            std::string cmd = token[0];

            if(clientState == IDLE) {
                if(cmd == "login") {
                    if(argc == 4 && atoi(token[3]) >= 0) {
                        send_all(mySocket, line + "\n");
                        std::string res;
                        if(receive_all(mySocket, res) < 0) break;

                        if(res.find("Login failed") != std::string::npos || res.find("Invalid command") != std::string::npos) {
                            std::cout << "[SERVER] " << res << std::endl;
                            continue;
                        }

                        listenPort = atoi(token[3]);
                        myName = token[1];
                        pthread_t tid;
                        pthread_create(&tid, nullptr, listener, &listenPort);
                        pthread_detach(tid);

                        std::cout << "[SERVER] " << res << std::endl;
                        continue;
                    }
                }
                else if(cmd == "chat") {
                    if(argc == 2) {
                        send_all(mySocket, line + "\n");
                        std::string res;
                        if(receive_all(mySocket, res) < 0) break;

                        if(res.find("Chat failed") != std::string::npos || res.find("Invalid command") != std::string::npos) {
                            std::cout << "[SERVER] " << res << std::endl;
                            continue;
                        }

                        char resToken[4][4096];
                        int resArgc = parse(res, resToken);

                        std::string targetIP = resToken[0];
                        int targetPort = atoi(resToken[1]);
                        peerName = token[1];

                        std::cout << "[CLIENT] Connecting to " << targetIP << ":" << targetPort << "...\n";

                        peerSocket = socket(AF_INET, SOCK_STREAM, 0);
                        if(peerSocket < 0) {
                            perror("Error");
                            std::cout << "[CLIENT] Connection failed, please retry later\n";
                            peerSocket = -1;
                            peerName = "";
                            continue;
                        }
                        sockaddr_in peerAddr;
                        peerAddr.sin_family = AF_INET;
                        peerAddr.sin_port = htons(targetPort);
                        inet_pton(AF_INET, targetIP.c_str(), &peerAddr.sin_addr);
                        if(connect(peerSocket, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) < 0) {
                            perror("Error");
                            std::cout << "[CLIENT] Connection failed, please retry later\n";
                            safe_close(peerSocket);
                            peerSocket = -1;
                            peerName = "";
                            continue;
                        }
                        else {
                            if(send_request(peerSocket, myName, "C")) {
                                chat_mode();
                                continue;
                            }
                            else {
                                std::cout << "[CLIENT] Connection refused\n";
                                safe_close(peerSocket);
                                peerSocket = -1;
                                peerName = "";
                                continue;
                            }
                        }
                    }
                }
                else if(cmd == "join") {
                    if(argc == 2) {
                        send_all(mySocket, line + "\n");
                        std::string res;
                        if(receive_all(mySocket, res) < 0) break;

                        std::string groupName = token[2];
                        if(!groups.count(groupName)) {
                            groups[groupName].groupCrypto.set_random_group_key();
                        }

                        if(res.find("Join failed") != std::string::npos || res.find("Invalid command") != std::string::npos) {
                            std::cout << "[SERVER] " << res << std::endl;
                            continue;
                        }

                        char resToken[4][4096];
                        int resArgc = parse(res, resToken);

                        std::string targetIP = resToken[2];
                        int targetPort = atoi(resToken[3]);

                        if(isSelfConnection(targetIP, targetPort, listenPort)) {
                            group_mode(mySocket, groupName);
                            continue;
                        }
                        else {
                            std::cout << "[CLIENT] Connecting to " << targetIP << ":" << targetPort << "...\n";

                            groupSocket = socket(AF_INET, SOCK_STREAM, 0);
                            if(groupSocket < 0) {
                                perror("Error");
                                std::cout << "[CLIENT] Connection failed, please retry later\n";
                                peerSocket = -1;
                                continue;
                            }
                            sockaddr_in groupAddr;
                            groupAddr.sin_family = AF_INET;
                            groupAddr.sin_port = htons(targetPort);
                            inet_pton(AF_INET, targetIP.c_str(), &groupAddr.sin_addr);
                            if(connect(groupSocket, (struct sockaddr*)&groupAddr, sizeof(groupAddr)) < 0) {
                                perror("Error");
                                std::cout << "[CLIENT] Connection failed, please retry later\n";
                                safe_close(groupSocket);
                                groupSocket = -1;
                                continue;
                            }
                            else {
                                if(send_request(groupSocket, myName + " " + groupName, "G")) {
                                    safe_close(groupSocket);
                                    groupSocket = -1;
                                    group_mode(mySocket, groupName);
                                    continue;
                                }
                                else {
                                    std::cout << "[CLIENT] Connection refused\n";
                                    safe_close(groupSocket);
                                    groupSocket = -1;
                                    continue;
                                }
                            }
                        }
                    }
                }
                else if(cmd == "send") {
                    if(argc == 3) {
                        send_all(mySocket, line + "\n");
                        std::string res;
                        if(receive_all(mySocket, res) < 0) break;

                        if(res.find("Send failed") != std::string::npos || res.find("Invalid command") != std::string::npos) {
                            std::cout << "[SERVER] " << res << std::endl;
                            continue;
                        }

                        char resToken[4][4096];
                        int resArgc = parse(res, resToken);

                        std::string targetIP = resToken[0];
                        int targetPort = atoi(resToken[1]);
                        peerName = token[1];
                        std::string fileName = token[2];

                        std::cout << "[CLIENT] Connecting to " << targetIP << ":" << targetPort << "...\n";

                        peerSocket = socket(AF_INET, SOCK_STREAM, 0);
                        if(peerSocket < 0) {
                            perror("Error");
                            std::cout << "[CLIENT] Connection failed, please retry later\n";
                            peerSocket = -1;
                            peerName = "";
                            continue;
                        }
                        sockaddr_in peerAddr;
                        peerAddr.sin_family = AF_INET;
                        peerAddr.sin_port = htons(targetPort);
                        inet_pton(AF_INET, targetIP.c_str(), &peerAddr.sin_addr);
                        if(connect(peerSocket, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) < 0) {
                            perror("Error");
                            std::cout << "[CLIENT] Connection failed, please retry later\n";
                            safe_close(peerSocket);
                            peerSocket = -1;
                            peerName = "";
                            continue;
                        }
                        else {
                            if(send_request(peerSocket, myName, "F")) {
                                if(send_file(peerSocket, fileName) < 0) {
                                    std::cout << "[CLIENT] File transission failed, please retry later\n";
                                }
                                safe_close(peerSocket);
                                peerSocket = -1;
                                peerName = "";
                                continue;
                            }
                            else {
                                std::cout << "[CLIENT] Connection refused\n";
                                safe_close(peerSocket);
                                peerSocket = -1;
                                peerName = "";
                                continue;
                            }
                        }
                    }
                }
                send_all(mySocket, line + "\n");
                std::string res;
                if(receive_all(mySocket, res) < 0) break;

                std::cout << "[SERVER] " << res << std::endl;
            }
            else if(clientState == PENDING) {
                if(line == "y") {
                    send_all(peerSocket, "y\n");
                    chat_mode();
                }
                else if(line == "n") {
                    send_all(peerSocket, "n\n");
                    safe_close(peerSocket);
                    peerSocket = -1;
                    peerName = "";
                    clientState = IDLE;
                }
            }
            else if(clientState == WAITFILE) {
                if(line == "y") {
                    std::cout << "[REQUEST] Please enter the file name\n> " << std::flush;
                    std::string fileName;
                    std::cin >> fileName;
                    send_all(peerSocket, "y\n");
                    if(fileName.empty()) {
                        receive_file(peerSocket, "download");
                    }
                    else {
                        receive_file(peerSocket, fileName);
                    }
                    safe_close(peerSocket);
                    peerSocket = -1;
                    peerName = "";
                    clientState = IDLE;
                }
                else if(line == "n") {
                    send_all(peerSocket, "n\n");
                    safe_close(peerSocket);
                    peerSocket = -1;
                    peerName = "";
                    clientState = IDLE;
                }
            }
        }
    }

    safe_close(mySocket);

    std::cout << "Process finished\n";
    return 0;
}
