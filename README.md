# CN 2025 Project Phase 2

## Compilation instructions

To compile `server.cpp` and `client.cpp`, run

```
cd code # go to code/
make
```

This will create a `\bin` folder containing two binaries.

Then, to run the server program, use

```
cd .. # go back to main folder
./bin/server [port]
```

To run the client program, use

```
./bin/client [server_ip] [server_port]
```

For example,

```
./bin/server 8888
./bin/client 127.0.0.1 8888
```

Finally, to remove all files in `\bin`, use

```
make clean
```

## Usage (commands)

### `register <username> <password>`

Register a new account on the server. Use this only when the client is not logged in.
- **Format**: `register alice s3cr3t`
- **Success**: Server confirms "Register successed".
- **Failure**: Username already exists or user is already logged in.

### `login <username> <password> <client_listen_port>`

Authenticate and mark the user as online. The `<client_listen_port>` is the local port this client will open to accept direct Peer-to-Peer (P2P) connections.
- **Format**: `login alice s3cr3t 9001`
- **Success**: Server confirms login, starts a listener thread on the specified port, and marks the user as online.
- **Failure**: Wrong username/password, port conflict (port already used by another user or valid range error), or user already logged in.

### `logout`

Log out the currently logged-in user and mark them as offline on the server.
- **Format**: `logout`
- **Success**: Server confirms "Logout successed".
- **Failure**: If no user is currently logged in.

### `list`

Request the server to return the list of currently online users.
- **Format**: `list`
- **Success**: Server displays a list of online usernames.
- **Failure**: If the client is not logged in.

### `chat <username>`

Initiate a private P2P chat session with another online user. The client queries the server for the target's IP/Port, then connects directly.
- **Format**: `chat bob`
- **Success**: Target accepts the request (`y`), and both users enter **Chat Mode**.
- **Failure**: Target rejects the request (`n`), target is offline, or connection errors.
- **Note**: Inside Chat Mode, type `_exit` to quit the chat and return to the main menu.

### `group`

Request the list of all available chat groups currently active on the server.
- **Format**: `group`
- **Success**: Server lists all existing group names.
- **Failure**: If the client is not logged in.

### `create <groupname>`

Create a new chat group on the server.
- **Format**: `create study_group`
- **Success**: Server confirms "Create successed".
- **Failure**: Group name already exists or user is not logged in.

### `join <groupname>`

Join an existing group chat. This initiates **Group Mode**, allowing messages to be broadcast to all group members.
- **Format**: `join study_group`
- **Success**: Client enters the group room and loads chat history.
- **Failure**: Group does not exist or connection errors.
- **Note**: Inside Group Mode, type `_exit` to leave the room and return to the main menu.

### `send <username> <filename>`

Send a file to another online user via a direct P2P connection.
- **Format**: `send bob homework.txt`
- **Success**: Target accepts the transfer (`y`,`save_path`) and the file is transmitted successfully.
- **Failure**: Target rejects (`n`), file does not exist locally, or connection errors.

### `quit`

Terminate the client process. If a user is logged in, the client sends a quit signal to the server before exiting.
- **Format**: `quit`
- **Behavior**: Cleanly disconnects from the server and closes the application.