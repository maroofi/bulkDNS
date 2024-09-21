#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <cmdparser.h>
#include <cqueue.h>


#ifndef _BULKDNS_SCANNER_H
#define _BULKDNS_SCANNER_H

#define BULKDNS_MAX_QUEUE_SIZE 1000000

#define BULKDNS_MAX_SOCKET_FOR_POLL 32


struct scanner_input {
    int udp_only;                   // should we send only udp queries?
    int set_do;                     // should we enable dnssec ok bit?
    int set_nsid;                   // should we send nsid with the packet?
    int no_edns;                    // should we have edns0?
    int rr_type;                    // which DNS RR type
    int rr_class;                   // which DNS class?
    char * resolver;                // which recursive resolver use to get the data from
    unsigned int port;              // which port use to send the queries
    char * output_file;             // where to write the results
    char * output_error;            // where to write the errors
    unsigned int timeout;           // timeout for socket operation
    int help;                       // show help string
    FILE * OUTPUT;                  // output file handle
    FILE * ERROR;                   // error file handle
    FILE * INPUT;                   // input file handle
    unsigned int concurrency;       // number of concurrent requests (This is the number of open sockets/ports)
    unsigned int server_mode;       // should we work in server mode instead of active scan
    char * lua_file;                // Lua file to use either in server mode or custom scan
    char * bind_ip;                 // this is the IP address we want to bind to in server-mode
    int no_tcp;                     // should we run TCP server (1 which is default) or not (0)
};

struct thread_param {
    char * quit_data;
    struct scanner_input * si;
    pthread_mutex_t lock;
    cqueue_ctx * qinput;
    cqueue_ctx * queue_tcp;
};

typedef struct{
    int * sock_list;
    int num_sock;
    struct thread_param * tp;
}scan_mode_receiver_param;


typedef struct {
    void * item;
    int udp_sock;
    struct sockaddr_in server;
}scan_mode_worker_item;


// server-mode structure definition

typedef struct {
    pthread_mutex_t * mutex_queue;
    pthread_cond_t * cond_queue;
    int sockfd;
    cqueue_ctx * queue_handle;
    char * lua_file;
} server_mode_thread_params;

typedef struct{
    char * ip;
    uint16_t port;
    char * lua_file;
    int run_tcp_server;         // 1 means we should run and 0 means no TCP server
} server_mode_server_param;

typedef struct{
    struct sockaddr_in client_addr;
    unsigned int client_addr_len;
    char * received;
    size_t received_len;
    char * to_send;
    size_t to_send_len;
    int ready_to_send;
    int is_udp;                 // 1 means it's UDP and zero means it's TCP
    int tcp_sock;
} server_mode_queue_data;




//server-mode function declaration
void handle_read_socket(int sockfd, char * mem_result, struct thread_param * tp);
int udp_socket_send(char * tosend_buffer, size_t tosend_len, int sockfd, struct sockaddr_in server);
void server_mode_to_log(const char * msg, FILE* fd);
void server_mode_run_all(server_mode_server_param *smsp);
void switch_server_mode(struct scanner_input *);


// scan mode function declaration
void * tcp_routine_handler(void * ptr);
void * scan_receiver_routine(void * ptr);
void * read_item_from_queue(struct thread_param * tp);

int init_udp_socket(struct scanner_input * si);
#ifdef COMPILE_WITH_LUA
void * scan_lua_worker_routine(void * ptr);
#endif
void dns_routine_scan(scan_mode_worker_item*, struct scanner_input * si, char * mem_result);
int perform_lookup_udp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer, size_t * toreceive_len, struct scanner_input * si, int sockfd);
int perform_lookup_tcp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer, size_t * toreceive_len, struct scanner_input * si);
void *scan_worker_routine(void * ptr);
int convert_type_to_int(char * type);
int convert_class_to_int(char * cls);
char * readline(FILE * fp);

#ifdef COMPILE_WITH_LUA
void lua_dns_routine_scan(void * item, struct scanner_input * si, lua_State * L);
#else
void lua_dns_routine_scan(void);
#endif

// command-line function declaration

PARG_CMDLINE create_command_line_arguments();
void get_command_line(PARG_PARSED_ARGS pargs, struct scanner_input * si);
int initial_check_command_line(struct scanner_input * si, PARG_CMDLINE cmd);
void free_cmd(PARG_CMDLINE);

#endif




