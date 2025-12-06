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

Register to the server (must used when client is not logged in yet).
If `<username>` already exists, `register` will fail.

### `login <username> <password> <client_listen_port>`

Login to the server, `<username>` and `<password>` must match the data in the server.
Client should also provide `<client_listen_port>` (though not used in phase 1), the port number should not be repeated if two clients have same IP address.
`login` must be use when client is not logged in yet.

### `logout`

Logout from the server, must be used when the user is logged in.

### `list`

List all online users (i.e., users that are currently logged in), must be used when the user is logged in.

### `quit`

Terminate the client process, if a user has logged it, `quit` will automatically log out that user.