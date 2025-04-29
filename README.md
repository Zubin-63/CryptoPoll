# CryptoPoll
A C/C++ based secure client-server polling system that ensures user authentication, message integrity, and confidentiality using cryptographic mechanisms over Linux sockets.

## Features
- User authentication using username/passwords.
    - Username and passwords in a text file which is acting as a database for this project.
    - Passwords are stored in hashed form (SHA-512).
    - **File**: `db.txt`
    - **Note**: Username's given in `db.txt` are sample usernames and passwords.

- Encrypted communication between client and server.
    - Confidentiality and Integrity services are maintained using encryption and signature mechanisms.
    - RSA (Public key cryptography) is used.
    - **Client File**: `client.cpp`
    - **Server File**: `server.c`

- Survey or Poll is stored at server side and then published to client's which are logged in succesfully
    - **Survey File**: `survey.txt`

- Each client locally reads survey and answers the poll.
    - Integrity of answers is maintained using signature mechanism
    - **File**: `local.txt`

- Server stores answer and publish results.
    - Results can be seen by anyone connected to server.
    - **Answer's file**: `answers.txt`

- Supports Multiple Client's
    - Multiple Clients are handled by Multithreading. 
    - Thread synchronization is implemented to prevent race conditions during concurrent client handling, ensuring consistent and       secure access to shared data.

- Built using low-level socket programming in C/C++.

---

## Technologies Used
- C / C++
- Linux (GCC/G++)
- POSIX Sockets(TCP)
- Open SSL
- GMP Library
- Pthread Library

---

## Installing Required Libraries

Before compiling and running the project, ensure the following libraries are installed on your Linux system:

### GMP (GNU Multiple Precision Arithmetic Library)
```bash
sudo apt-get update
sudo apt-get install libgmp-dev
```

### OpenSSL (for encryption and hashing)
```bash
sudo apt-get install libssl-dev
```
---

## Compiling and Running

### Server Code
```bash
gcc server.c -lgmp -lssl -lcrypto -pthread -o server
```

### Client Code
```bash
g++ client.cpp -lgmp -lssl -lcrypto -o client
```

### Running the compiled codes
```bash
./sever
./client
```



