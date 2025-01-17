#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

#include "server.h"

#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define WS_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define DEBUG_PREFIX "[DEBUG]"
#define INFO_PREFIX "[INFO]"
#define ERROR_PREFIX "[ERROR]"

// Add WebSocket frame definitions
#define WS_FIN 0x80
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA
#define WS_MASK 0x80

// Add after existing WebSocket definitions
void create_websocket_frame(char* frame, const void* data, size_t data_len, int binary) {
    frame[0] = 0x80 | (binary ? WS_OPCODE_BINARY : WS_OPCODE_TEXT);

    if (data_len <= 125) {
        frame[1] = data_len;
        memcpy(frame + 2, data, data_len);
    } else if (data_len <= 65535) {
        frame[1] = 126;
        frame[2] = (data_len >> 8) & 0xFF;
        frame[3] = data_len & 0xFF;
        memcpy(frame + 4, data, data_len);
    } else {
        frame[1] = 127;
        for (int i = 0; i < 8; i++) {
            frame[2 + i] = (data_len >> ((7 - i) * 8)) & 0xFF;
        }
        memcpy(frame + 10, data, data_len);
    }
}

// Data structures

volatile int running = 1;

void handle_signal(int sig) {
    running = 0;
}

void log_client_connection(struct Client *client) {
    printf("\n%s ---- New Client Connected ----\n", DEBUG_PREFIX);
    printf("Player ID: %d\n", client->player_id);
    printf("--------------------------------\n\n");
}

// Debug output function
void print_movement_debug(struct MovementData *movement, struct sockaddr_in *client_addr) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    printf("\n%s ---- Binary Message %zu bytes ----\n", DEBUG_PREFIX, sizeof(struct MovementData));
    printf("Time: %s\n", timestamp);
    
    if (client_addr) {
        printf("From: %s:%d\n", 
               inet_ntoa(client_addr->sin_addr), 
               ntohs(client_addr->sin_port));
    }
    
    printf("Player ID: %d\n", movement->player_id);
    printf("Position: (%.2f, %.2f, %.2f)\n", 
           movement->x, movement->y, movement->z);
    printf("Rotation: %.2f\n", movement->rotation);

    // Hex dump of raw data
    printf("Raw data: ");
    unsigned char *data = (unsigned char *)movement;
    for(size_t i = 0; i < sizeof(struct MovementData); i++) {
        printf("%02x ", data[i]);
    }
    printf("\n--------------------------------\n\n");
}

// Update handshake function
void handle_websocket_handshake(int socket, char* buffer) {
    printf("%s Processing WebSocket handshake\n", DEBUG_PREFIX);
    
    // Verify required headers
    if(!strstr(buffer, "Upgrade: websocket") || 
       !strstr(buffer, "Connection: Upgrade") ||
       !strstr(buffer, "Sec-WebSocket-Key:")) {
        printf("%s Invalid WebSocket handshake - missing headers\n", ERROR_PREFIX);
        close(socket);
        return;
    }

    char *key_start = strstr(buffer, "Sec-WebSocket-Key: ") + 19;
    char *key_end = strstr(key_start, "\r\n");
    int key_length = key_end - key_start;
    
    char key[256];
    strncpy(key, key_start, key_length);
    key[key_length] = '\0';
    
    char combined_key[512];
    sprintf(combined_key, "%s%s", key, WS_KEY);
    
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)combined_key, strlen(combined_key), sha1_hash);
    
    char *base64 = malloc(32);
    EVP_EncodeBlock((unsigned char*)base64, sha1_hash, SHA_DIGEST_LENGTH);
    
    char response[512];
    sprintf(response, 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        base64);
    
    send(socket, response, strlen(response), 0);
    free(base64);

    // Send READY as WebSocket frame
    char ready_frame[8] = {0};
    const char* ready_msg = "READY";
    create_websocket_frame(ready_frame, ready_msg, 5, 0);
    send(socket, ready_frame, 7, 0);

    printf("%s WebSocket handshake complete\n", DEBUG_PREFIX);
}

void unmask_payload(char* payload, size_t length, char* mask) {
    for(size_t i = 0; i < length; i++) {
        payload[i] ^= mask[i % 4];
    }
}

void handle_websocket_frame(int socket, char* buffer, size_t length) {
    unsigned char fin = (buffer[0] & WS_FIN) != 0;
    unsigned char opcode = buffer[0] & 0x0F;
    unsigned char masked = (buffer[1] & WS_MASK) != 0;
    unsigned long payload_length = buffer[1] & 0x7F;

    printf("%s Received WebSocket frame: FIN=%d, opcode=%d, masked=%d, length=%lu\n",
           DEBUG_PREFIX, fin, opcode, masked, payload_length);

    if(opcode == WS_OPCODE_CLOSE) {
        int client_slot = -1;
        for(int i = 0; i < MAX_CLIENTS; i++) {
            if(clients[i].active && clients[i].socket == socket) {
                client_slot = i;
                break;
            }
        }

        if(client_slot >= 0) {
            printf("%s Client %d closing connection normally\n", 
                   INFO_PREFIX, clients[client_slot].player_id);
            
            // Send close acknowledgment with status 1000 (normal closure)
            unsigned char close_frame[4] = {
                0x88, // FIN + Close opcode
                0x02, // Payload length 2 
                0x03, 0xE8 // Status code 1000 in network byte order
            };
            send(socket, close_frame, 4, 0);
            
            // Don't close immediately - let client close first
            clients[client_slot].active = 0;
            print_active_connections();
        }
        return;
    }

    // Debug raw frame
    printf("\n%s Raw WebSocket frame (%zu bytes):\n", DEBUG_PREFIX, length);
    for(size_t i = 0; i < length; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
        if((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
    
    printf("\n%s Frame Header:\n", DEBUG_PREFIX);
    printf("FIN: %d\n", fin);
    printf("Opcode: %d\n", opcode);
    printf("Masked: %d\n", masked);
    printf("Initial payload length: %lu\n", payload_length);
    
    char* payload;
    char* mask;
    size_t header_size;
    
    // Calculate actual payload length and header size
    if(payload_length <= 125) {
        header_size = masked ? 6 : 2;
        payload = buffer + header_size;
    } else if(payload_length == 126) {
        payload_length = (buffer[2] << 8) | buffer[3];
        header_size = masked ? 8 : 4;
        payload = buffer + header_size;
    } else {
        payload_length = 0;
        for(int i = 0; i < 8; i++) {
            payload_length = (payload_length << 8) | buffer[2 + i];
        }
        header_size = masked ? 14 : 10;
        payload = buffer + header_size;
    }

    if(masked) {
        mask = buffer + (header_size - 4);
        unmask_payload(payload, payload_length, mask);
    }
    
    printf("%s Actual payload length: %lu\n", DEBUG_PREFIX, payload_length);
    printf("%s Header size: %zu\n", DEBUG_PREFIX, header_size);
    
    if(opcode == WS_OPCODE_TEXT) {
        // Handle text frame
        char* message = malloc(payload_length + 1);
        memcpy(message, payload, payload_length);
        message[payload_length] = '\0';
        printf("%s Text message received: %s\n", DEBUG_PREFIX, message);
        free(message);
    }
    else if(opcode == WS_OPCODE_BINARY && payload_length == sizeof(struct MovementData)) {
        struct MovementData movement;
        memcpy(&movement, payload, sizeof(struct MovementData));
        print_movement_debug(&movement, NULL);
            
        // Send acknowledgment
        char frame[3] = {0};
        char ack = 1;
        create_websocket_frame(frame, &ack, 1, 1);
        send(socket, frame, 3, 0);
    }
    else if(opcode == WS_OPCODE_CLOSE) {
        printf("%s Client requested close\n", INFO_PREFIX);
        
        // Find client slot
        int client_slot = -1;
        for(int i = 0; i < MAX_CLIENTS; i++) {
            if(clients[i].active && clients[i].socket == socket) {
                client_slot = i;
                break;
            }
        }
        
        if(client_slot >= 0) {
            // Send close acknowledgment
            char close_frame[4] = {0x88, 0x02, 0x03, 0xE8}; // Close frame with status 1000
            send(socket, close_frame, 4, 0);
            
            // Close socket and mark inactive
            close(clients[client_slot].socket);
            clients[client_slot].active = 0;
            printf("%s Client %d disconnected\n", INFO_PREFIX, clients[client_slot].player_id);
            
            print_active_connections();
        }
    } else {
        printf("%s Unhandled frame - opcode: %d, length: %lu\n", 
               ERROR_PREFIX, opcode, payload_length);
    }
}

// Update broadcast function
void broadcast_movement(struct Client *clients, struct MovementData *movement, int sender_id) {
    char frame[sizeof(struct MovementData) + 10];
    create_websocket_frame(frame, movement, sizeof(struct MovementData), 1);

    size_t frame_len = sizeof(struct MovementData) + 
        (sizeof(struct MovementData) <= 125 ? 2 : 
         sizeof(struct MovementData) <= 65535 ? 4 : 10);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].is_websocket && 
            clients[i].player_id != sender_id) {
            send(clients[i].socket, frame, frame_len, 0);
        }
    }
}

// Global array definition
struct Client clients[MAX_CLIENTS] = {0};

void log_received_data(const char* buffer, size_t length, const char* type, int client_slot) {
    printf("\n%s ---- Received %s Data ----\n", DEBUG_PREFIX, type);
    printf("Time: %ld\n", time(NULL));
    printf("Length: %zu bytes\n", length);

    // Log headers if present
    if(strstr(buffer, "GET") && strstr(buffer, "HTTP/1.1")) {
        char* line = strtok((char*)buffer, "\r\n");
        while(line) {
            printf("%s\n", line);
            line = strtok(NULL, "\r\n");
        }
        printf("\n");
    }

    // Hex dump for binary data
    printf("Raw data (hex):\n");
    for(size_t i = 0; i < length; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
        if((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Parse WebSocket frame for binary data
    if(clients[client_slot].is_websocket && length > 6) {
        unsigned char fin = (buffer[0] & 0x80) != 0;
        unsigned char opcode = buffer[0] & 0x0F;
        unsigned char masked = (buffer[1] & 0x80) != 0;
        unsigned long payload_len = buffer[1] & 0x7F;
        
        printf("WebSocket Frame:\n");
        printf("FIN: %d\n", fin);
        printf("Opcode: %d\n", opcode);
        printf("Masked: %d\n", masked);
        printf("Payload Length: %lu\n", payload_len);
    }

    // ASCII representation for text data
    printf("ASCII:\n");
    for(size_t i = 0; i < length; i++) {
        unsigned char c = buffer[i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    printf("\n--------------------------------\n\n");
}

void parse_movement_data(const char* buffer, struct MovementData* movement) {
    // Parse little-endian binary data
    float* x_ptr = (float*)buffer;
    float* y_ptr = (float*)(buffer + 4);
    float* z_ptr = (float*)(buffer + 8); 
    float* rotation_ptr = (float*)(buffer + 12);
    int* player_id_ptr = (int*)(buffer + 16);

    movement->x = *x_ptr;
    movement->y = *y_ptr;
    movement->z = *z_ptr;
    movement->rotation = *rotation_ptr;
    movement->player_id = *player_id_ptr;
}

void log_movement_data(const char* buffer, size_t length, struct sockaddr_in* client_addr) {
    printf("\n[DEBUG] ---- Movement Data Received ----\n");
    printf("Time: %ld\n", time(NULL));
    printf("Client: %s:%d\n", 
           inet_ntoa(client_addr->sin_addr), 
           ntohs(client_addr->sin_port));
    printf("Data length: %zu bytes\n", length);

    if (length == 20) {  // Verify correct movement data size
        struct MovementData movement;
        parse_movement_data(buffer, &movement);
        
        printf("Player ID: %d\n", movement.player_id);
        printf("Position: (%.2f, %.2f, %.2f)\n", 
               movement.x, movement.y, movement.z);
        printf("Rotation: %.2f\n", movement.rotation);
    }

    // Binary dump
    printf("Raw bytes: ");
    for(size_t i = 0; i < length; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n--------------------------------\n\n");
}

// Update movement handling
void handle_movement_data(int socket, const char* buffer, size_t length) {
    if (length == sizeof(struct MovementData)) {
        struct MovementData movement;
        parse_movement_data(buffer, &movement);
        print_movement_debug(&movement, NULL);

        char frame[3] = {0};
        char ack = 1;
        create_websocket_frame(frame, &ack, 1, 1);
        send(socket, frame, 3, 0);
    }
}

// Add JSON parsing helper
int parse_handshake_player_id(const char* buffer) {
    char* id_start = strstr(buffer, "\"playerId\":");
    if (!id_start) return -1;
    return atoi(id_start + 10);
}

// Update client slot finding logic
int find_client_slot(struct Client* clients, int player_id) {
    // First try to find existing client
    for(int i = 0; i < MAX_CLIENTS; i++) {
        if(clients[i].active && clients[i].player_id == player_id) {
            return i;
        }
    }
    
    // If not found, find free slot
    for(int i = 0; i < MAX_CLIENTS; i++) {
        if(!clients[i].active) {
            return i;
        }
    }
    return -1;
}

void print_active_connections() {
    int active_count = 0;
    printf("\n%s ---- Active Connections ----\n", DEBUG_PREFIX);
    
    for(int i = 0; i < MAX_CLIENTS; i++) {
        if(clients[i].active) {
            active_count++;
            time_t idle_time = time(NULL) - clients[i].last_active;
            printf("Client %d: Socket %d, Player ID %d, Idle %lds\n", 
                   i, clients[i].socket, clients[i].player_id, idle_time);
        }
    }
    
    printf("Total active clients: %d\n", active_count);
    printf("--------------------------------\n\n");
}

// Update connection handling
void update_client_activity(int client_slot) {
    if(clients[client_slot].active) {
        clients[client_slot].last_active = time(NULL);
    }
}

void log_connection_message(const char* buffer, size_t length, int client_slot) {
    printf("\n%s ---- Message from Client %d ----\n", DEBUG_PREFIX, clients[client_slot].player_id);
    printf("Time: %ld\n", time(NULL));
    printf("Length: %zu bytes\n", length);
    
    // Print message content
    printf("Content: ");
    for(size_t i = 0; i < length; i++) {
        unsigned char c = buffer[i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    printf("\n");

    // Hex dump
    printf("Raw data: ");
    for(size_t i = 0; i < length; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n--------------------------------\n\n");
}

// Add packet logging function
void log_packet(const char* buffer, size_t length, const char* direction) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    printf("\n%s ---- Packet %s (%zu bytes) ----\n", DEBUG_PREFIX, direction, length);
    printf("Time: %s\n", timestamp);

    // Hex dump
    printf("Data: ");
    for(size_t i = 0; i < length; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
        if((i + 1) % 16 == 0) printf("\n      ");
    }
    printf("\n--------------------------------\n\n");
}

void log_client_message(int client_slot, const char* buffer, size_t length) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, 26, "%H:%M:%S", tm_info);

    printf("\n%s [%s] Client %d Message:\n", 
           DEBUG_PREFIX,
           timestamp,
           clients[client_slot].player_id);

    // For binary messages (movement data)
    if(length == sizeof(struct MovementData)) {
        struct MovementData* movement = (struct MovementData*)buffer;
        printf("Type: Movement Data\n");
        printf("Position: (%.2f, %.2f, %.2f)\n", 
               movement->x, movement->y, movement->z);
        printf("Rotation: %.2f\n", movement->rotation);
    } 
    // For text messages
    else {
        printf("Type: Text/Other\n");
        printf("Length: %zu bytes\n", length);
        printf("Data: ");
        for(size_t i = 0; i < length; i++) {
            printf("%02x ", (unsigned char)buffer[i]);
        }
        printf("\n");
    }
    printf("--------------------------------\n");
}

int main() {
    // Add signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int server_fd;
    struct sockaddr_in address;
    char buffer[BUFFER_SIZE] = {0};
    
    // After socket creation, add non-blocking and socket options
    if ((server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Add socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_KEEPALIVE, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms timeout
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("WebSocket server running on port %d\n", PORT);
    
    int addrlen = sizeof(address);
    // Update main loop to handle non-blocking
    fd_set readfds;
    int max_sd, sd, activity;
    struct timeval timeout = {5, 0}; // 5 seconds timeout

    // Main server loop
    while(running) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        for(int i = 0; i < MAX_CLIENTS; i++) {
            if(clients[i].active) {
                sd = clients[i].socket;
                if(sd > 0) {
                    FD_SET(sd, &readfds);
                }
                if(sd > max_sd) {
                    max_sd = sd;
                }
            }
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, &timeout);

        if(activity > 0) {
            if(FD_ISSET(server_fd, &readfds)) {
                // Handle new connections
                int new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
                if (new_socket < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // No pending connections, continue
                        continue;
                    }
                    if (errno == EINTR) continue;
                    perror("Accept failed");
                    continue;
                }

                // Set client socket to non-blocking too
                int flags = fcntl(new_socket, F_GETFL, 0);
                fcntl(new_socket, F_SETFL, flags | O_NONBLOCK);

                // Find free client slot
                int client_slot = -1;
                for(int i = 0; i < MAX_CLIENTS; i++) {
                    if(!clients[i].active) {
                        client_slot = i;
                        break;
                    }
                }

                if(client_slot >= 0) {
                    clients[client_slot].socket = new_socket;
                    clients[client_slot].active = 1;
                    clients[client_slot].player_id = client_slot + 1;
                    log_client_connection(&clients[client_slot]);

                    // Handle client data
                    int valread = read(new_socket, buffer, BUFFER_SIZE);
                    if(strstr(buffer, "Upgrade: websocket")) {
                        handle_websocket_handshake(new_socket, buffer);
                        clients[client_slot].is_websocket = 1;
                    } else if(strstr(buffer, "\"type\":\"handshake\"")) {
                        int player_id = parse_handshake_player_id(buffer);
                        if(player_id != -1) {
                            // Find slot by player_id
                            client_slot = find_client_slot(clients, player_id);
                            if(client_slot >= 0) {
                                if(clients[client_slot].active) {
                                    // Client reconnecting - update socket
                                    close(clients[client_slot].socket);
                                    printf("[DEBUG] Client %d reconnected\n", player_id);
                                } else {
                                    // New client
                                    printf("[DEBUG] New client %d connected\n", player_id);
                                }
                                clients[client_slot].socket = new_socket;
                                clients[client_slot].active = 1;
                                clients[client_slot].player_id = player_id;
                                clients[client_slot].is_websocket = 1;
                                
                                const char* ready_msg = "READY";
                                send(new_socket, ready_msg, strlen(ready_msg), 0);
                            }
                        }
                    } else {
                        int bytes_read = valread;
                        if (bytes_read == sizeof(struct MovementData)) {
                            struct MovementData *movement = (struct MovementData *)buffer;
                            print_movement_debug(movement, &address);
                            // ... existing broadcasting code ...
                        }
                    }
                } else {
                    printf("%s Server full, rejecting client\n", ERROR_PREFIX);
                    close(new_socket);
                }
            }

            // Check data from clients
            for(int i = 0; i < MAX_CLIENTS; i++) {
                if(clients[i].active && FD_ISSET(clients[i].socket, &readfds)) {
                    char buffer[BUFFER_SIZE] = {0};
                    int bytes_read = recv(clients[i].socket, buffer, BUFFER_SIZE, 0);
                    
                    if(bytes_read > 0) {
                        if(clients[i].is_websocket) {
                            handle_websocket_frame(clients[i].socket, buffer, bytes_read);
                        }
                        update_client_activity(i);
                    }
                }
            }
        }

        // Status update every 5 seconds
        static time_t last_status = 0;
        time_t now = time(NULL);
        if(now - last_status >= 5) {
            print_active_connections();
            last_status = now;
        }
    }

    // Cleanup
    for(int i = 0; i < MAX_CLIENTS; i++) {
        if(clients[i].active) {
            close(clients[i].socket);
        }
    }
    close(server_fd);
    return 0;
}