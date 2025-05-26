#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// https://www.geeksforgeeks.org/tcp-ip-packet-format/

typedef struct {
  uint16_t source_port;
  uint16_t destination_port;
  uint32_t sequence_number;
  uint32_t acknowledgement_number;
  uint16_t offset_flags;
  uint16_t congestion_window;
  uint16_t checksum;
  uint16_t urgent_pointer;
} tcp_header;

typedef struct {
  tcp_header header;
  char data[0x400];
} tcp_packet;

enum control_flag {
  FIN = 0x00000001,
  SYN = 0x00000002,
  RST = 0x00000004,
  PSH = 0x00000008,
  ACK = 0x00000010,
  URG = 0x00000020,
};

uint16_t client_port;
uint16_t server_port;

int pipe_fd1[2];
int pipe_fd2[2];

int curr_SEQ;
int curr_ACK;

void init() {
  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);
  setvbuf(stderr, 0, _IONBF, 0);
}

uint16_t offset(int offs) { return offs << 12; }

uint16_t carry_around_add(uint16_t a, uint16_t b) {
  int c = a + b;
  return (c & 0xffff) + (c >> 16);
}

uint16_t calculate_checksum(tcp_packet *packet) {
  uint16_t old_checksum = packet->header.checksum;
  packet->header.checksum = 0;
  const char *as_char = (char *)packet;
  uint16_t res = 0;
  for (int i = 0; i < sizeof(tcp_packet); i += 2) {
    res = carry_around_add(res, *(uint16_t *)as_char);
  }
  packet->header.checksum = old_checksum;
  return ~res;
}

int client_send(char *data, int nbytes) {
  return write(pipe_fd1[1], &nbytes, 4) > 0 &&
         write(pipe_fd1[1], data, nbytes) > 0;
}

int client_recv(char *buf) {
  int nbytes = 0;
  int res =
      read(pipe_fd2[0], &nbytes, 4) > 0 && read(pipe_fd2[0], buf, nbytes) > 0;
  return ((tcp_packet *)buf)->header.checksum ==
             calculate_checksum((tcp_packet *)buf) &&
         res;
}

int server_send(char *data, int nbytes) {
  return write(pipe_fd2[1], &nbytes, 4) > 0 &&
         write(pipe_fd2[1], data, nbytes) > 0;
}

int server_recv(char *buf, int *size) {
  int nbytes = 0;
  int res = read(pipe_fd1[0], &nbytes, 4) > 0 &&
            read(pipe_fd1[0], buf, nbytes) > 0 && (*size = nbytes);
  return ((tcp_packet *)buf)->header.checksum ==
             calculate_checksum((tcp_packet *)buf) &&
         res;
}

void client() {
  char raw_data[0x800];
  char received_data[0x800];
  tcp_packet syn_packet = {
      client_port, server_port, 0, -1, offset(0x20) | SYN, 0x400, 0, 0,
  };
  syn_packet.header.checksum = calculate_checksum(&syn_packet);

  tcp_packet data_packet1 = {
      client_port, server_port, 1, 1, offset(0x20) | ACK, 0x400, 0,
  };

  tcp_packet fin_packet = {
      client_port, server_port, 1, 1, offset(0x20) | FIN, 0x400, 0,
  };

  tcp_packet data_packet2 = {
      client_port, server_port, 1, 1, offset(0x20) | ACK, 0x400, 0,
  };

  int nbytes = 0;

  puts("[+ CLIENT] Developing connection.");
  puts("[+ CLIENT] Requesting connection from server.");
  if (!client_send((char *)&syn_packet, sizeof(tcp_header))) {
    puts("[+ CLIENT] Developing connection failed.");
    exit(-1);
  }
  puts("[+ CLIENT] Waiting for SYNACK from server");
  if (client_recv(received_data) &&
      ((tcp_packet *)received_data)->header.offset_flags & (SYN | ACK)) {
    puts("[+ CLIENT] Received SYNACK from server. Connection successfully "
         "developed.");
  } else {
    puts("[+ CLIENT] Failed developing connection.");
    exit(-1);
  }
  printf("Enter data: ");
  nbytes = read(STDIN_FILENO, raw_data, 0x800);
  printf("[+ CLIENT] Sending data: %s\n", raw_data);

  if (nbytes <= 0x400) {
    memcpy(data_packet1.data, raw_data, nbytes);
    puts("[+ CLIENT] Calculating checksum.");
    data_packet1.header.checksum = calculate_checksum(&data_packet1);
    puts("[+ CLIENT] Sending data to server.");
    if (!client_send((char *)&data_packet1, nbytes + sizeof(tcp_header))) {
      puts("[+ CLIENT] Failed sending data to server.");
      exit(-1);
    }
    puts("[+ CLIENT] Sending data succeeds.");
  } else {
    puts("[+ CLIENT] Data length is larger than congestion window. Seperating "
         "into 2 packets.");
    memcpy(data_packet1.data, raw_data, 0x400);
    memcpy(data_packet2.data, raw_data + 0x400, nbytes - 0x400);
    puts("[+ CLIENT] Calculating checksum.");
    data_packet1.header.checksum = calculate_checksum(&data_packet1);
    data_packet2.header.checksum = calculate_checksum(&data_packet2);
    data_packet2.header.sequence_number = 0x400;
    char *tmp = malloc(sizeof(tcp_packet) * 2);
    memcpy(tmp, &data_packet1, sizeof(tcp_packet));
    memcpy(tmp + sizeof(tcp_packet), &data_packet2,
           sizeof(tcp_header) + nbytes - 0x400);
    puts("[+ CLIENT] Sending data to server.");
    if (!client_send(tmp, nbytes + sizeof(tcp_header) * 2)) {
      puts("[+ CLIENT] Failed sending data to server.");
      exit(-1);
    }
    puts("[+ CLIENT] Sending data succeeds.");
    free(tmp);
  }
  puts("[+ CLIENT] Waiting response from server");
  if (client_recv(received_data) &&
      ((tcp_packet *)received_data)->header.offset_flags & ACK)
    puts("[+ CLIENT] Received ACK from server. Data sent successfully.");
  else {
    puts("[+ CLIENT] Did not receive ACK from server. Internal server error.");
    exit(-1);
  }
}

void server() {
  char *tmp = malloc(0x1000);
  char received_data[0x800 + sizeof(tcp_header)];


  int nbytes;
  int received_len = 0;
  tcp_packet fin_packet = {
      client_port, server_port, 1, 1, offset(0x20) | FIN, 0x400, 0,
  };

  tcp_packet syn_ack_packet = {
      client_port, server_port, 1, 1, offset(0x20) | SYN | ACK, 0x400, 0,
  };
  syn_ack_packet.header.checksum = calculate_checksum(&syn_ack_packet);
  tcp_packet ack_packet = {
      client_port, server_port, 1, 1, offset(0x20) | ACK, 0x400, 0,
  };

  puts("[+ SERVER] Waiting for SYN packet from client.");
  if (!server_recv(received_data, &nbytes) ||
      (((tcp_packet *)received_data)->header.offset_flags & SYN) == 0) {
    puts("[+ SERVER] Did not receive SYN packet from client. Failed developing "
         "connection.");
    exit(-1);
  }
  puts("[+ SERVER] Received SYN packet from client. Sending back SYNACK "
       "packet.");
  if (!server_send((char *)&syn_ack_packet, sizeof(tcp_header))) {
    puts("[+ SERVER] Failed sending SYNACK to client");
    exit(-1);
  }
  puts("[+ SERVER] Sending SYNACK packet succeeds.");
  puts("[+ SERVER] Waiting for ACK packet from client.");
  if (!server_recv(received_data, &nbytes) ||
      (((tcp_packet *)received_data)->header.offset_flags & ACK) == 1) {
    puts("[+ SERVER] Did not receive ACK from client.");
    exit(-1);
  }
  puts("[+ SERVER] Received ACK from client");
  if (nbytes < sizeof(tcp_packet)) {
    memcpy(tmp, ((tcp_packet *)received_data)->data,
           nbytes - sizeof(tcp_header));
    ack_packet.header.acknowledgement_number = nbytes - sizeof(tcp_header);
  } else {
    memcpy(tmp, ((tcp_packet *)received_data)->data, 0x400);
    memcpy(tmp + sizeof(tcp_packet),
           ((tcp_packet *)(received_data + sizeof(tcp_packet)))->data,
           nbytes - 0x400 - sizeof(tcp_header) * 2);
    ack_packet.header.acknowledgement_number =
        nbytes - sizeof(tcp_header) * 2 - 0x400;
  }
  ack_packet.header.checksum = calculate_checksum(&ack_packet);
  printf("[+ SERVER] Data received: %s", tmp);
  puts("[+ SERVER] Sending back ACK to client");
  if (!server_send((char *)&ack_packet, sizeof(tcp_header))) {
    puts("[+ SERVER] Failed sending ACK to client");
    exit(-1);
  }
}

void start_routine() {
  if (pipe(pipe_fd1) == -1 || pipe(pipe_fd2) == -1) {
    perror("Error creating pipe. Exiting");
    exit(-1);
  }
  pid_t pid = fork();
  if (fork < 0) {
    perror("Error forking process. Exiting");
    exit(-1);
  }
  if (pid > 0) {
    while (1) {
      client();
      char c;
      printf("Continue? [y/n]\n");
      c = getchar();
      getchar();
      if (c == 'n') {
        kill(pid, 9);
        break;
      }
    }
  } else
    while (1)
      server();
}

int main(int argc, char *argv[]) {
  init();
  puts("This is a super simplified TCP transport protocol simulation.");
  printf("Enter client port: ");
  scanf("%hd", &client_port);
  printf("Enter server port: ");
  scanf("%hd", &server_port);
  getchar();
  start_routine();
  return EXIT_SUCCESS;
}
