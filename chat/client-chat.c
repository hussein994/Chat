#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


#define CHECK(op)                                                              \
  do {                                                                         \
    if ((op) == -1) {                                                          \
      perror(#op);                                                             \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define MAX_BUFFER 1024

#ifdef BIN
#define HELO 0x01
#define QUIT 0x02
#endif

#ifdef USR
#define MAX_CLIENTS 10
#endif

#ifdef BIN
typedef struct {
  uint8_t command;
} CMDbinary;
#endif

#ifdef USR
typedef struct {
  struct sockaddr_storage addr;
  int id;
} Client;
#endif


void try_bind_socket(int sockfd, struct sockaddr_in6 *address, bool *server) {
  if (bind(sockfd, (struct sockaddr *)address, sizeof(*address)) == -1) {
    if (errno == EADDRINUSE) {
      *server = false;
      inet_pton(AF_INET6, "::1", &address->sin6_addr);
    } else {
      perror("bind error");
      close(sockfd);
      exit(EXIT_FAILURE);
    }
  } else {
    *server = true;
  }
}

void send_initial_message(int sockfd, struct sockaddr_in6 *address,
                          bool server) {
  if (!server) {
    char buffer[MAX_BUFFER];
    strncpy(buffer, "/HELO", MAX_BUFFER - 1);
    buffer[MAX_BUFFER - 1] = '\0'; // Ensure null termination

    sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)address,
           sizeof(*address));
  }
}

void print_sender_info(const struct sockaddr_storage *sender_addr) {
  char sender_ip[INET6_ADDRSTRLEN];
  int sender_port;

  if (sender_addr->ss_family == AF_INET) { // IPv4
    const struct sockaddr_in *s = (const struct sockaddr_in *)sender_addr;
    inet_ntop(AF_INET, &s->sin_addr, sender_ip, sizeof(sender_ip));
    sender_port = ntohs(s->sin_port);
  } else { // IPv6
    const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sender_addr;
    inet_ntop(AF_INET6, &s->sin6_addr, sender_ip, sizeof(sender_ip));
    sender_port = ntohs(s->sin6_port);
  }

  printf("%s %d\n", sender_ip, sender_port);
}

int process_buffer(char *buffer, bool server,
                   struct sockaddr_storage *sender_addr,
                   bool *is_first_message) {
  if (strncmp(buffer, "/HELO", 5) == 0 && server) {
    print_sender_info(sender_addr);
    *is_first_message = false;
  } else if (strncmp(buffer, "/QUIT",5) == 0 && server) {
    printf("Client exited using /QUIT \n");
    return 0;
  } else if (strncmp(buffer, "/QUIT",5) == 0 && !server) {
    printf("Server exited using /QUIT\n");
    return 0;
  } else {
    printf("Received message: %s", buffer);
  }
  return 1;
}

#ifdef FILEIO
const char *get_file_extension(const char *filename) {
  const char *dot = strrchr(filename, '.');
  if (!dot || dot == filename) {
    return ""; // No extension found
  }
  return dot; // Return the extension
}


void duplicate_file(const char *source_filename) {
  // Get the extension of the source file
  const char *extension = get_file_extension(source_filename);
  printf("Transferring file...\n");

  // Construct the destination filename
  char destination_filename[256];
  snprintf(destination_filename, sizeof(destination_filename),
           "transferred_file%s", extension);

  // Open the source file in binary read mode
  FILE *source_file = fopen(source_filename, "rb");
  if (source_file == NULL) {
    perror("Failed to open source file");
    return;
  }

  // Open the destination file in binary write mode
  FILE *destination_file = fopen(destination_filename, "wb");
  if (destination_file == NULL) {
    perror("Failed to open destination file");
    fclose(source_file);
    return;
  }

  char buffer[MAX_BUFFER];
  size_t bytes_read;

  while ((bytes_read = fread(buffer, 1, MAX_BUFFER, source_file)) > 0) {
    fwrite(buffer, 1, bytes_read, destination_file);
  }

  fclose(source_file);
  fclose(destination_file);
  printf("File successfully duplicated as '%s'.\n", destination_filename);
}
#endif

#ifdef USR

void broadcast_message(int sockfd, const char *buffer, const Client *clients,
                       int num_clients, int sender_id,
                       struct sockaddr_in6 address, bool server) {
  if (server) {
    for (int i = 0; i < num_clients; i++) {
      sendto(sockfd, buffer, strlen(buffer), 0,
             (struct sockaddr *)&clients[i].addr, sizeof(address));
    }
  } else {
    for (int i = 0; i < num_clients; i++) {
      if (clients[i].id != sender_id) {
        sendto(sockfd, buffer, strlen(buffer), 0,
               (struct sockaddr *)&clients[i].addr, sizeof(address));
      }
    }
  }
}

int find_sender_id(const Client *clients, int num_clients,
                   const struct sockaddr_storage *sender_addr) {
  for (int i = 0; i < num_clients; ++i) {
    if (memcmp(&clients[i].addr, sender_addr, sizeof(*sender_addr)) == 0) {
      return clients[i].id;
    }
  }
  return 0; // Return 0 if not found
}

#endif


int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s port_number\n", argv[0]);
    return 1;
  }

  int port = atoi(argv[1]);
  if (port < 10000 || port > 65000) {
    printf("Invalid port number. Please use a port number between 10000 and "
           "65000.\n");
    return 1;
  }

#ifdef USR
  Client clients[MAX_CLIENTS];
  int num_clients = 0;
#endif

  int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
  CHECK(sockfd);

  int value = 0; // 0 means dual-stack
  CHECK(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)));

  struct sockaddr_in6 address;
  memset(&address, 0, sizeof(address));
  address.sin6_family = AF_INET6;
  address.sin6_port = htons(port);
  address.sin6_addr = in6addr_any;

  bool server;
  char buffer[MAX_BUFFER];

  try_bind_socket(sockfd, &address, &server);

#ifdef BIN
  if (!server) {
    buffer[0] = HELO;
    sendto(sockfd, buffer, 1, 0, (struct sockaddr *)&address, sizeof(address));
  }
#else
  send_initial_message(sockfd, &address, server);
#endif

  struct pollfd fds[2];
  fds[0].fd = STDIN_FILENO;
  fds[0].events = POLLIN;
  fds[1].fd = sockfd;
  fds[1].events = POLLIN;

  bool is_first_message = true;
  struct sockaddr_storage sender_addr;
  socklen_t addr_len = sizeof(sender_addr);
  char sender_ip[INET6_ADDRSTRLEN];
  int sender_port;



  if (server) {
    printf("Server Up and Running ✅\n");
  }

  if (!server) {
    printf("Joined the server ✅\n");
  }

  while (true) {
    int poll_res = poll(fds, 2, -1);
    CHECK(poll_res);

    if (fds[0].revents & POLLIN) {
      memset(buffer, 0, MAX_BUFFER);
      int read_res = read(STDIN_FILENO, buffer, MAX_BUFFER - 1);
      CHECK(read_res);
      buffer[read_res] = '\0'; // Zero-terminate the string

#ifdef BIN

      int send_length = strlen(buffer);
      if (strncmp(buffer, "/QUIT", 5) == 0) {
        buffer[0] = QUIT;
        send_length = 1; // Only sending the QUIT command
      }

      if (server && !is_first_message) {
        sendto(sockfd, buffer, send_length, 0, (struct sockaddr *)&sender_addr,
               addr_len);
      } else if (!server) {
        sendto(sockfd, buffer, send_length, 0, (struct sockaddr *)&address,
               sizeof(address));
      }

      if (buffer[0] == QUIT) {
        break; // Exit the loop after sending QUIT
      }

#elif defined(USR)

      int sender_id = find_sender_id(clients, num_clients, &sender_addr);
      if (server) {
        broadcast_message(sockfd, buffer, clients, num_clients, sender_id,
                          address, server);
      } else {
        sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&address,
               sizeof(address));
      }

#elif FILEIO
      if (strncmp(buffer, "/SENDFILE", 9) == 0) {
        char *filepath;
        printf("Enter file path: ");
        scanf("%s", filepath);
        duplicate_file(filepath);
      } else if (server && !is_first_message) {
        sendto(sockfd, buffer, strlen(buffer), 0,
               (struct sockaddr *)&sender_addr, addr_len);
      } else if (!server) {
        sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&address,
               sizeof(address));
      }
#else
      if (server && !is_first_message) {
        sendto(sockfd, buffer, strlen(buffer), 0,
               (struct sockaddr *)&sender_addr, addr_len);
      } else if (!server) {
        sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&address,
               sizeof(address));
      }
      if (strncmp(buffer, "/QUIT", 5) == 0) {
        break;
      }

#endif
    }



    if (fds[1].revents & POLLIN) {
      memset(buffer, 0, MAX_BUFFER);
      int recv_res = recvfrom(sockfd, buffer, MAX_BUFFER - 1, 0,
                              (struct sockaddr *)&sender_addr, &addr_len);
      CHECK(recv_res);
      buffer[recv_res] = '\0'; // Zero-terminate the string

#ifdef BIN

      // BIN-specific message handling
      if (buffer[0] == QUIT && server) {
        printf("Client exited using /QUIT : %0x (0x02)\n", buffer[0]);
      } else if (buffer[0] == QUIT && !server) {
        printf("Server exited using /QUIT : %0x (0x02)\n", buffer[0]);
        break;
      } else if (buffer[0] == HELO && server) {
        printf("Received /HELO command: %0x (0x01)\n", buffer[0]);
        print_sender_info(&sender_addr);
        is_first_message = false;
      } else {
        printf("Received message: %s", buffer);
      }

#elif FILEIO
      if (strncmp(buffer, "/QUIT", 5) == 0 && !server) {
        break;
      } else if (strncmp(buffer, "/HELO", 5) == 0 && server) {
        print_sender_info(&sender_addr);
        is_first_message = false;
      } else {
        // Handle as a regular text message
        printf("%s", buffer);
      }
    
#elif defined(USR)

      if (strncmp(buffer, "/HELO", 5) == 0 && num_clients < MAX_CLIENTS) {
        if (num_clients < MAX_CLIENTS) {
          clients[num_clients].addr = sender_addr;
          clients[num_clients].id =
              num_clients + 1; // Assign an ID to the client
          printf("\nNew client (ID: %d) entered the chat\n",
                 clients[num_clients].id);
          num_clients++;

          if (server) {
            printf("Received /HELO command\n");
            print_sender_info(&sender_addr);
            is_first_message = false;
          }
          printf("Number of Clients in chat: %d\n", num_clients);
        } else {
          printf("Chat is full\n");
        }
      } else if (strcmp(buffer, "/QUIT") == 0) {
        printf("Received /QUIT command\n");
        break;
      } else {

        int sender_id = find_sender_id(clients, num_clients, &sender_addr);
        if (server) {
          printf("Client %d: %s", sender_id, buffer);
        } else {
          printf("Server: %s", buffer);
        }
        broadcast_message(sockfd, buffer, clients, num_clients, sender_id,
                          address, false);
      }

#else
      if (process_buffer(buffer, server, &sender_addr, &is_first_message) ==
          0) {
        break;
      }
#endif

    }
  }

  close(sockfd);
  return 0;
}
