#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
#include <time.h>

// Constants
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define WS_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocket frame definitions
#define WS_FIN 0x80
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA
#define WS_MASK 0x80

// Data structures - single definition here
struct MovementData {
    float x;
    float y;
    float z;
    float rotation;
    int player_id;
};

struct Client {
    int socket;
    int player_id;
    int active;
    int is_websocket;
    time_t last_active;
};

// Global declarations
extern struct Client clients[MAX_CLIENTS];

// Function declarations 
void log_client_connection(struct Client *client);
void log_received_data(const char* buffer, size_t length, const char* type, int client_slot);

// Add new function declarations
void print_active_connections(void);
void log_connection_message(const char* buffer, size_t length, int client_slot);
void handle_websocket_frame(int socket, char* buffer, size_t length);

#endif