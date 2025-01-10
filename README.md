# Basic C Server

This project implements a basic C server that can accept connections from clients and receive data. It demonstrates the use of socket programming in C.

## Files

- `src/server.c`: Contains the implementation of the server.
- `Makefile`: Used to compile the server program.

## Compilation

To compile the server, navigate to the project directory and run:

```
make
```

This will generate an executable file named `server`.

## Running the Server

After compiling, you can run the server using the following command:

```
./server
```

The server will start listening for incoming connections.

## Dependencies

- A C compiler (e.g., gcc)
- Basic knowledge of socket programming in C

## Usage

Once the server is running, you can connect to it using a client program that sends data to the server. The server will accept connections and read data sent by the client.

## License

This project is licensed under the MIT License.