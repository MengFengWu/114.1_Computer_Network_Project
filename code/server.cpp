#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>
#include <errno.h>
#include <unistd.h>

#include "crypto.h"

#include <map>
#include <deque>
#define MAX_PORT_NUM 65535

int myPort;
std::string myIP;

enum userState{
    IDLE,
    GROUPING,
};

struct UserData {
    std::string password;
    bool online = false;
    std::string IP = "";
    int port = 0;
    int sockfd = -1;
    std::string currentGroup;
    std::map<std::string, std::string> groups;
};

struct GroupData {
    UserData* admin;
    std::deque<UserData*> members;
};

std::map<std::string, UserData> users;
std::map<std::string, GroupData> groups;
pthread_mutex_t userMutex = PTHREAD_MUTEX_INITIALIZER;

std::map<int, Crypto*> clientCryptos;

bool findRepeatIPPort(std::string IP, int port) {
    if (IP == myIP && port == myPort) {
        return true;
    }
    for (std::map<std::string, UserData>::iterator it = users.begin(); it != users.end(); ++it) {
        if(it->second.IP == IP && it->second.port == port) {
            return true;
        }
    }
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

int doRegister(int clientSocket, char token[4][4096], std::string& myUsername) {
    std::string username = token[1];
    std::string password = token[2];
    int res = 0;

    pthread_mutex_lock(&userMutex);
    if(myUsername != "\0") {
        send_all(clientSocket, "Register failed: you should logout first before registration\n");
        res = -1;
    }
    else if(users.count(username)) {
        send_all(clientSocket, "Register failed: username exists\n");
        res = -1;
    }
    else {
        users[username].password = password;
        send_all(clientSocket, "Register successed\n");
    }
    pthread_mutex_unlock(&userMutex);
    return res;
}

int doLogin(int clientSocket, char token[4][4096], std::string& myUsername, std::string myIP) {
    std::string username = token[1];
    std::string password = token[2];
    std::string clientListenPort = token[3];
    int res = 0;
    if(myUsername != "\0") {
        send_all(clientSocket, "Login failed: already logined as " + myUsername + ". Please logout first\n");
        res = -1;
    }
    else {
        pthread_mutex_lock(&userMutex);
        if(!users.count(username) || users[username].password != password) {
            send_all(clientSocket, "Login failed: username or password is invalid\n");
            res = -1;
        }
        else if(users[username].online == true) {
            send_all(clientSocket, "Login failed: already logined on the other divice\n");
            res = -1;
        }
        else if(atoi(clientListenPort.c_str()) <= 0 || atoi(clientListenPort.c_str()) > MAX_PORT_NUM) {
            send_all(clientSocket, "Login failed: client port is invalid\n");
            res = -1;
        }
        else if(findRepeatIPPort(myIP, atoi(clientListenPort.c_str())) == true) {
            send_all(clientSocket, "Login failed: port is already used\n");
            res = -1;
        }
        else {
            users[username].online = true;
            users[username].IP = myIP;
            users[username].port = atoi(clientListenPort.c_str());
            users[username].sockfd = clientSocket;
            myUsername = username;
            send_all(clientSocket, "Login successed\n");
        }
        pthread_mutex_unlock(&userMutex);
    }
    return res;
}

int doLogout(int clientSocket, char token[4][4096], std::string& myUsername) {
    int res = 0;
    if(myUsername == "\0") {
        send_all(clientSocket, "Logout failed: you are not logined yet\n");
        res = -1;
    }
    else {
        pthread_mutex_lock(&userMutex);
        if(users[myUsername].online != true) {
            send_all(clientSocket, "Logout failed: user is not online\n");
            res = -1;
        }
        else {
            users[myUsername].online = false;
            users[myUsername].IP = "";
            users[myUsername].port = 0;
            users[myUsername].sockfd = -1;
            myUsername = "\0";
            send_all(clientSocket, "Logout successed\n");
        }
        pthread_mutex_unlock(&userMutex);
    }
    return res;
}

int doList(int clientSocket, char token[4][4096], std::string& myUsername) {
    int res = 0;
    if(myUsername == "\0") {
        send_all(clientSocket, "List failed: you are not logined yet\n");
        res = -1;
    }
    else {
        pthread_mutex_lock(&userMutex);
        std::string info = "\n---Current Online Users---\n";
        for (std::map<std::string, UserData>::iterator it = users.begin(); it != users.end(); ++it) {
            if(it->second.online == true) {
                info += it->first + "\n";
            }
        }
        info += "---End of List---\n";
        send_all(clientSocket, info);
        pthread_mutex_unlock(&userMutex);
    }
    return res;
}

int doChat(int clientSocket, char token[4][4096], std::string& myUsername) {
    std::string username = token[1];
    int res = 0;
    pthread_mutex_lock(&userMutex);
    if(myUsername == "\0") {
        send_all(clientSocket, "Chat failed: you are not logined yet\n");
        res = -1;
    }
    else if(!users.count(username) || users[username].online == false || username == myUsername) {
        send_all(clientSocket, "Chat failed: username is invalid or it's not online\n");
        res = -1;
    }
    else {
        std::string IP = users[username].IP;
        int port = users[username].port;
        send_all(clientSocket, users[username].IP + " " + std::to_string(port) + "\n");
    }
    pthread_mutex_unlock(&userMutex);
    return res;
}

int doGroup(int clientSocket, char token[4][4096], std::string& myUsername) {
    int res = 0;
    if(myUsername == "\0") {
        send_all(clientSocket, "Group failed: you are not logined yet\n");
        res = -1;
    }
    else {
        pthread_mutex_lock(&userMutex);
        std::string info = "\n---Current Available Groups---\n";
        for (std::map<std::string, GroupData>::iterator it = groups.begin(); it != groups.end(); ++it) {
            info += it->first + "\n";
        }
        info += "---End of List---\n";
        send_all(clientSocket, info);
        pthread_mutex_unlock(&userMutex);
    }
    return res;
}

int doCreate(int clientSocket, char token[4][4096], std::string& myUsername) {
    std::string groupname = token[1];
    int res = 0;

    pthread_mutex_lock(&userMutex);
    if(myUsername == "\0") {
        send_all(clientSocket, "Create failed: you are not logined yet\n");
        res = -1;
    }
    else if(groups.count(groupname)) {
        send_all(clientSocket, "Create failed: groupname exists\n");
        res = -1;
    }
    else {
        // groups[groupname].members.push_back(&users[myUsername]);
        groups[groupname].admin = nullptr;
        send_all(clientSocket, "Create successed\n");
    }
    pthread_mutex_unlock(&userMutex);
    return res;
}

int doJoin(int clientSocket, char token[4][4096], std::string& myUsername) {
    std::string groupname = token[1];
    int res = 0;
    pthread_mutex_lock(&userMutex);
    if(myUsername == "\0") {
        send_all(clientSocket, "Join failed: you are not logined yet\n");
        res = -1;
    }
    else if(!groups.count(groupname)) {
        send_all(clientSocket, "Join failed: groupname is invalid\n");
        res = -1;
    }
    else if(!users[myUsername].groups.count(groupname)){
        if(groups[groupname].admin == nullptr) { // no one's active -> set the joiner as the admin
            groups[groupname].admin = &users[myUsername];
        }
        std::string IP = groups[groupname].admin->IP;
        int port = groups[groupname].admin->port;
        send_all(clientSocket, IP + " " + std::to_string(port) + "\n");
        groups[groupname].members.push_back(&users[myUsername]);
        users[myUsername].groups[groupname] = myUsername;
        users[myUsername].currentGroup = groupname;
        for(std::deque<UserData*>::iterator it = groups[groupname].members.begin(); it != groups[groupname].members.end(); it++) {
            if((*it)->currentGroup == groupname) {
                send_all((*it)->sockfd, "(" + myUsername + " entered the room)\n");
            }
        }
    }
    else {
        if(groups[groupname].admin == nullptr) { // no one's active -> set the joiner as the admin
            groups[groupname].admin = &users[myUsername];
        }
        std::string IP = groups[groupname].admin->IP;
        int port = groups[groupname].admin->port;
        send_all(clientSocket, IP + " " + std::to_string(port) + "\n");
        users[myUsername].currentGroup = groupname;
        for(std::deque<UserData*>::iterator it = groups[groupname].members.begin(); it != groups[groupname].members.end(); it++) {
            if((*it)->currentGroup == groupname) {
                send_all((*it)->sockfd, "(" + myUsername + " entered the room)\n");
            }
        }
    }
    pthread_mutex_unlock(&userMutex);
    return res;
}

int doQuit(int clientSocket, char token[4][4096], std::string& myUsername) {
    int res = 0;
    if(myUsername != "\0") {
        pthread_mutex_lock(&userMutex);
        users[myUsername].online = false;
        users[myUsername].IP = "";
        users[myUsername].port = 0;
        myUsername = "\0";
        pthread_mutex_unlock(&userMutex);
    }
    return res;
}

int doSend(int clientSocket, std::string& message, std::string& myUsername) {
    std::string groupname = users[myUsername].currentGroup;
    int res = 0;
    pthread_mutex_lock(&userMutex);
    if(message == "_exit") {
        res = -1;
        users[myUsername].currentGroup = "";
        groups[groupname].admin = nullptr;
        for(std::deque<UserData*>::iterator it = groups[groupname].members.begin(); it != groups[groupname].members.end(); it++) {
            if((*it)->currentGroup == groupname) {
                if(groups[groupname].admin == nullptr) {
                    groups[groupname].admin = (*it);
                }
                send_all((*it)->sockfd, "_exit " + myUsername + " " + groups[groupname].admin->IP + " " + std::to_string(groups[groupname].admin->port) + "\n");
            }
        }
    }
    else {
        for(std::deque<UserData*>::iterator it = groups[groupname].members.begin(); it != groups[groupname].members.end(); it++) {
            if((*it)->currentGroup == groupname) {
                send_all((*it)->sockfd, message + "\n");
            }
        }
    }
    pthread_mutex_unlock(&userMutex);
    return res;
}

void* clientHandler(void* arg) {
    int clientSocket = *(int*)arg;
    delete (int*)arg;
    char buf[4096];

    sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getpeername(clientSocket, (struct sockaddr*)&addr, &len);
    std::string clientIP = inet_ntoa(addr.sin_addr);

    std::string username = "\0";
    userState myState = IDLE;

    Crypto *crypto = crypto_init(clientSocket);
    if(crypto == nullptr) {
        safe_close(clientSocket);
        pthread_exit(nullptr);
    }

    while(true) {
        std::string line;
        if(receive_all(clientSocket, line) < 0) {
            break;
        }

        // std::cout << "received: " << line << "\n";
        if(line.empty()) {
            send_all(clientSocket, "Invalid command\n");
            continue;
        }
        char token[4][4096];
        int argc = parse(line, token);

        std::string cmd = token[0];

        if(myState == IDLE) {
            if (cmd == "register") {
                if(argc != 3) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                doRegister(clientSocket, token, username);
            }
            else if(cmd == "login") {
                if(argc != 4) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                doLogin(clientSocket, token, username, clientIP);
            }
            else if(cmd == "logout") {
                if(argc != 1) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                doLogout(clientSocket, token, username);
            }
            else if(cmd == "list") {
                if(argc != 1) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                doList(clientSocket, token, username);
            }
            else if(cmd == "chat") {
                if(argc != 2) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                doChat(clientSocket, token, username);
            }
            else if(cmd == "group") {
                if(argc != 1) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                doGroup(clientSocket, token, username);
            }
            else if(cmd == "create") {
                if(argc != 2) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                doCreate(clientSocket, token, username);
            }
            else if(cmd == "join") {
                if(argc != 2) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                if(doJoin(clientSocket, token, username) >= 0) {
                    myState = GROUPING;
                }
            }
            else if(cmd == "quit") {
                if(argc != 1) {
                    send_all(clientSocket, "Invalid command\n");
                    continue;
                }
                doQuit(clientSocket, token, username);
                break;
            }
            else {
                send_all(clientSocket, "Invalid command\n");
            }
        }
        else if(myState == GROUPING) {
            if(doSend(clientSocket, line, username) < 0) {
                myState = IDLE;
            }
        }
    }

    if(username != "\0") {
        pthread_mutex_lock(&userMutex);
        users[username].online = false;
        users[username].IP = "";
        users[username].port = 0;
        username = "\0";
        pthread_mutex_unlock(&userMutex);
    }
    safe_close(clientSocket);
    pthread_exit(nullptr);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }
    myPort = atoi(argv[1]);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSocket < 0) {
        perror("Error");
        return 1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(myPort);
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);
    myIP = "127.0.0.1";
    // serverAddress.sin_addr.s_addr = INADDR_ANY;

    if(bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Error");
        return 1;
    }
    if(listen(serverSocket, 10) < 0) {
        perror("Error");
        return 1;
    }
    std::cout << "Server listening on 127.0.0.1:" << myPort << "\n";

    while(true) {
        sockaddr_in clientAddress;
        socklen_t len = sizeof(clientAddress);
        int *clientSocket = new int(accept(serverSocket, (sockaddr*)&clientAddress, &len));
        pthread_t tid;
        pthread_create(&tid, nullptr, clientHandler, clientSocket);
        pthread_detach(tid);
    }

    safe_close(serverSocket);

    std::cout << "Process finished\n";
    return 0;
}