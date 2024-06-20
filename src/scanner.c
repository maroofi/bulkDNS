#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>         ///< sleep function
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cstrlib.h>
#include <cqueue.h>
#include <sdns.h>
#include <sdns_json.h>
#include <sdns_print.h>
#include <cmdparser.h>

#define BULKDNS_MAX_QUEUE_SIZE 1000000


struct scanner_input {
    int udp_only;
    int set_do;
    int no_edns;
    int rr_type;
    int rr_class;
    char * resolver;
    unsigned int port;
    char * output_file;
    char * output_error;
    unsigned int timeout;
    int help;
    FILE * OUTPUT;
    FILE * ERROR;
    FILE * INPUT;
    unsigned int threads;
};

struct thread_param {
    char * quit_data;
    struct scanner_input * si;
};

void dns_routine(void*, struct scanner_input * si);
int perform_lookup_udp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer, size_t * toreceive_len, struct scanner_input * si);
int perform_lookup_tcp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer, size_t * toreceive_len, struct scanner_input * si);


pthread_mutex_t lock;
cqueue_ctx * qinput;
cqueue_ctx * qoutput;
//unsigned long int cnt = 0;

void dns_routine(void * item, struct scanner_input * si){
    char * domain_name = strdup(item);
    sdns_context * dns = sdns_init_context();
    if (NULL == dns)
        return;
    int res = sdns_make_query(dns, si->rr_type, si->rr_class, domain_name, ~si->no_edns);
    if (res != 0){
        sdns_free_context(dns);
        return;
    }
    if (si->set_do && (!si->no_edns))
        dns->msg->additional->opt_ttl.DO = 1;
    res = sdns_to_wire(dns);
    if (res != 0){
        sdns_free_context(dns);
        return;
    }
    char * result = (char*) malloc(65535);
    if (NULL == result){
        sdns_free_context(dns);
        return;
    }
    size_t result_len = 65535;
    res = perform_lookup_udp(dns->raw, dns->raw_len, &result, &result_len, si);
    if (res != 0){
        free(result);
        sdns_free_context(dns);
        return;
    }
    //sdns_free_context(dns);
    sdns_context * dns_udp_response = sdns_init_context();
    dns_udp_response->raw = result;
    dns_udp_response->raw_len = result_len;
    res = sdns_from_wire(dns_udp_response);
    if (res != 0){
        sdns_free_context(dns);
        sdns_free_context(dns_udp_response);
        return;
    }
    if (si->udp_only){
        sdns_free_context(dns);
        char * dmp = sdns_json_dns_string(dns_udp_response);
        fprintf(si->OUTPUT, "%s\n", dmp);
        free(dmp);
        sdns_free_context(dns_udp_response);
        return;
    }
    if (dns_udp_response->msg->header.tc == 1){
        memset(result, 0, 65535);
        dns_udp_response->raw = NULL;
        dns_udp_response->raw_len = 0;
        sdns_free_context(dns_udp_response);
        result_len = 65535;
        res = perform_lookup_tcp(dns->raw, dns->raw_len, &result, &result_len, si);
        sdns_free_context(dns);
        if (res != 0){  // we got TCP error
            free(result);
            return;
        }
        sdns_context * dns_tcp_response = sdns_init_context();
        if (NULL == dns_tcp_response){
            free(result);
            return;
        }
        dns_tcp_response->raw = result;
        dns_tcp_response->raw_len = result_len;
        res = sdns_from_wire(dns_tcp_response);
        if (res != 0){
            sdns_free_context(dns_tcp_response);
            return;
        }
        char * dmp = sdns_json_dns_string(dns_tcp_response);
        fprintf(si->OUTPUT, "%s\n", dmp);
        free(dmp);
        sdns_free_context(dns_tcp_response);
        return;
    }else{
        sdns_free_context(dns);
        char * dmp = sdns_json_dns_string(dns_udp_response);
        fprintf(si->OUTPUT, "%s\n", dmp);
        free(dmp);
        sdns_free_context(dns_udp_response);
        return;
    }
}


void *worker_routine(void * ptr){
    // this will be called by several threads
    // ptr is a structure of type thread_param
    void * item;
    struct scanner_input * si = ((struct thread_param*)ptr)->si;
    while (1){
        // loop forever until item is "quit"
        // as our queue is not thread-safe, we have to lock it
        pthread_mutex_lock(&lock);
        item = cqueue_get(qinput);
        if (item == NULL){
            // sleep 1 sec and continue
            pthread_mutex_unlock(&lock);
            sleep(1);
            continue;
            //fprintf(si->ERROR, "ERROR: %s\n", qinput->errmsg);
        }
        //cnt += 1;
        pthread_mutex_unlock(&lock);
        if (item == NULL){
            // something is wrong
            fprintf(si->ERROR, "We should never have NULL item in the queue!!!!!\n");
            // just quit the thread
            return NULL;
        }
        if (strcmp((char*) item, ((struct thread_param*)ptr)->quit_data) == 0){
            //printf("We have received a quit message in thread#%ld\n", pthread_self());
            return NULL;
        }
        // do whatever you want with the item
        //fprintf(stdout, "Item: %s\n", (char*)item);
        dns_routine(item, si);
        free(item);
    }
    return NULL;
}



int perform_lookup_udp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer,
                       size_t * toreceive_len, struct scanner_input * si){
    //char buffer[256] = {0x00};
    //char * error = buffer;
    struct timeval tv = {.tv_sec = si->timeout, .tv_usec = 0};
    struct sockaddr_in server;
    unsigned int from_size;
    server.sin_port = htons(si->port);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(si->resolver);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1){
        close(sockfd);
        fprintf(si->ERROR, "Error in creating socket\n");
        return 1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
        fprintf(si->ERROR, "Error in setsocketopt\n");
        close(sockfd);
        return 2;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0){
        fprintf(si->ERROR, "Error in setsockeopt() function\n");
        return 3;
    }

    ssize_t sent = 0;
    sent = sendto(sockfd, tosend_buffer, tosend_len, 0, (struct sockaddr *)&server, sizeof(server));
    if (sent == -1){  //error
        fprintf(si->ERROR, "Error in sendto()\n");
        close(sockfd);
        return 4;
    }
    if (sent == 0){
        fprintf(si->ERROR, "Can not send the data to the server\n");
        close(sockfd);
        return 5;
    }
    // now let's receive the data
    ssize_t received = 0;
                                                    
    from_size = 0;
    received = recvfrom(sockfd, *toreceive_buffer, 65535, MSG_WAITALL, (struct sockaddr*)&server, &from_size);
    if (received == -1){
        close(sockfd);
        fprintf(si->ERROR, "Error in receive function\n");
        return 2;
    }
    if (received == 0){
        close(sockfd);
        return 2;
    }
    *toreceive_len = received;
    close(sockfd);
    return 0;
}

int perform_lookup_tcp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer,
                       size_t * toreceive_len, struct scanner_input * si){
    struct timeval tv = {.tv_sec = si->timeout, .tv_usec = 0};
    struct sockaddr_in server;
    server.sin_port = htons(si->port);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(si->resolver);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1){
        close(sockfd);
        fprintf(si->ERROR, "Error in creating socket\n");
        return 1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
        fprintf(si->ERROR, "Error in setsocketopt\n");
        close(sockfd);
        return 2;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0){
        fprintf(si->ERROR, "Error in setsockeopt() function\n");
        close(sockfd);
        return 2;
    }
    if (connect(sockfd, (struct sockaddr *) &server, sizeof(server)) < 0){
        fprintf(si->ERROR, "Can not connect to TCP socket\n");
        close(sockfd);
        return 2;
    }
    ssize_t sent = 0;
    uint16_t payload_size = tosend_len;
    char * payload = (char*) malloc(2 + payload_size);
    payload[0] = (uint8_t)((payload_size >> 8) & 0xFF);
    payload[1] = (uint8_t)(payload_size & 0xFF);
    memcpy(payload + 2, tosend_buffer, tosend_len);
    sent = send(sockfd, payload, tosend_len + 2, 0);
    if (sent < 0){
        free(payload);
        close(sockfd);
        fprintf(si->ERROR, "Cann not send data to TCP socket...\n");
        return 1;
    }
    free(payload);
    ssize_t received = 0;
    char recv_payload[2] = {0x00};
    received = recv(sockfd, (void*)recv_payload, 2, 0);
    uint16_t to_allocate = (uint8_t)recv_payload[0] << 8 |
                           (uint8_t)recv_payload[1];

    received = 0;
    char * receive_payload = (char*) malloc(to_allocate);
    received = recv(sockfd, receive_payload, to_allocate, MSG_WAITALL);
    if (received < 0){  // we have socket error
        fprintf(si->ERROR, "Error reading from socket...\n");
        close(sockfd);
        free(receive_payload);
        return 1;
    }
    *toreceive_len = to_allocate;
    *toreceive_buffer = receive_payload;
    return 0;   //success
}


char * readline(FILE * fp){
    const int MAX_LINE_SIZE = 255;
    char * line = (char*) calloc(MAX_LINE_SIZE + 1, sizeof(char));
    int ch = -1;
    char * new_memory = NULL;
    unsigned long int count = 0;
    while ((ch = fgetc(fp)) != EOF){
        line[count++] = ch;
        if (ch == '\n'){
            return line;
        }
        if (count % MAX_LINE_SIZE == 0){
            // we need to reallocate
            new_memory = (char*)realloc(line, strlen(line) + MAX_LINE_SIZE);
            if (new_memory == NULL){
                printf("ERROR: Can not reallocate memory for reading line...");
                free(line);
                return NULL;
            }
            line = new_memory;
        }
    }
    if (count == 0){
        // we are at the end of file
        free(line);
        return NULL;
    }
    line[count] = '\0';
    return line;
}


int convert_type_to_int(char * type){
    // no allocation no leak
    if (type == NULL)
        return -1;
    if (strcasecmp(type, "A") == 0)
        return sdns_rr_type_A;
    if (strcasecmp(type, "NS") == 0)
        return sdns_rr_type_NS;
    if (strcasecmp(type, "TXT") == 0)
        return sdns_rr_type_TXT;
    if (strcasecmp(type, "MX") == 0)
        return sdns_rr_type_MX;
    if (strcasecmp(type, "SOA") == 0)
        return sdns_rr_type_SOA;
    if (strcasecmp(type, "AAAA") == 0)
        return sdns_rr_type_AAAA;
    if (strcasecmp(type, "PTR") == 0)
        return sdns_rr_type_PTR;
    if (strcasecmp(type, "SRV") == 0)
        return sdns_rr_type_SRV;
    if (strcasecmp(type, "RRSIG") == 0)
        return sdns_rr_type_RRSIG;
    if (strcasecmp(type, "CNAME") == 0)
        return sdns_rr_type_CNAME;
    if (strcasecmp(type, "HINFO") == 0)
        return sdns_rr_type_HINFO;
    if (strcasecmp(type, "NID") == 0)
        return sdns_rr_type_NID;
    if (strcasecmp(type, "L32") == 0)
        return sdns_rr_type_L32;
    if (strcasecmp(type, "L64") == 0)
        return sdns_rr_type_L64;
    if (strcasecmp(type, "LP") == 0)
        return sdns_rr_type_LP;
    if (strcasecmp(type, "URI") == 0)
        return sdns_rr_type_URI;
    return -2;
}

int convert_class_to_int(char * cls){
    // no allocation no leak
    if (cls == NULL)
        return -1;
    if (strcasecmp(cls, "IN") == 0)
        return sdns_q_class_IN;
    if (strcasecmp(cls, "CH") == 0)
        return sdns_q_class_CH;
    return -2;
}


void get_command_line(PARG_PARSED_ARGS pargs, struct scanner_input * si){
    si->udp_only = arg_is_tag_set(pargs, "udp_only")?1:0;
    si->set_do  = arg_is_tag_set(pargs, "set_do")?1:0;
    si->no_edns = arg_is_tag_set(pargs, "noedns")?1:0;
    si->resolver = arg_is_tag_set(pargs, "resolver")?strdup(arg_get_tag_value(pargs, "resolver")):strdup("1.1.1.1");
    if (arg_is_tag_set(pargs, "port")){
        si->port = (unsigned int)atoi(arg_get_tag_value(pargs, "port"));
    }else{
        si->port = 53;
    }
    if (arg_is_tag_set(pargs, "timeout")){
        si->timeout = (unsigned int)atoi(arg_get_tag_value(pargs, "timeout"));
    }else{
        si->timeout = 3;
    }
    si->rr_type = convert_type_to_int((char*)(arg_is_tag_set(pargs, "rr_type")?arg_get_tag_value(pargs, "rr_type"):"A"));
    si->rr_class = convert_class_to_int((char*)(arg_is_tag_set(pargs, "rr_class")?arg_get_tag_value(pargs, "rr_class"):"IN"));
    si->help = arg_is_tag_set(pargs, "print_help")?1:0;
    si->output_file = (char*)(arg_is_tag_set(pargs, "output")?arg_get_tag_value(pargs, "output"):NULL);
    si->output_error = (char*)(arg_is_tag_set(pargs, "error")?arg_get_tag_value(pargs, "error"):NULL);
    if (arg_is_tag_set(pargs, "threads")){
        si->threads = (unsigned int)atoi(arg_get_tag_value(pargs, "threads"));
    }else{
        si->threads = 300;
    }
}

int main(int argc, char ** argv){
    struct scanner_input * si = (struct scanner_input*) malloc(sizeof(struct scanner_input));
    if (NULL == si){
        fprintf(stderr, "Can not allocate memory for input....\n");
        return 1;
    }
    
    ARG_CMDLINE cmd;
    cmd.accept_file = 1;
    cmd.extra = NULL;
    cmd.summary = "Bulk DNS scanner based on sdns low-level DNS library.";
    ARG_CMD_OPTION cmd_option[] = {
        {.short_option=0, .long_option = "udp-only", .has_param = NO_PARAM, .help="Only query using UDP connection (Default will follow TCP)", .tag="udp_only"},
        {.short_option=0, .long_option = "set-do", .has_param = NO_PARAM, .help="Set DNSSEC OK (DO) bit in queries (default is no DO)", .tag="set_do"},
        {.short_option=0, .long_option = "noedns", .has_param = NO_PARAM, .help="Do not support EDNS0 in queries (Default supports EDNS0)", .tag="noedns"},
        {.short_option='t', .long_option = "type", .has_param = HAS_PARAM, .help="Resource Record type (Default is 'A')", .tag="rr_type"},
        {.short_option='c', .long_option = "class", .has_param = HAS_PARAM, .help="RR Class (IN, CH). Default is 'IN'", .tag="rr_class"},
        {.short_option='r', .long_option = "resolver", .has_param = HAS_PARAM, .help="Resolver IP address to send the query to (default 1.1.1.1)", .tag="resolver"},
        {.short_option=0, .long_option = "threads", .has_param = HAS_PARAM, .help="How many threads should be used (it's pthreads, and default is 300)", .tag="threads"},
        {.short_option='p', .long_option = "port", .has_param = HAS_PARAM, .help="Resolver port number to send the query to (default 53)", .tag="port"},
        {.short_option='o', .long_option = "output", .has_param = HAS_PARAM, .help="Output file name (default is the terminal with stdout)", .tag="output"},
        {.short_option='e', .long_option = "error", .has_param = HAS_PARAM, .help="where to write the error (default is terminal with stderr)", .tag="error"},
        {.short_option='h', .long_option = "help", .has_param = NO_PARAM, .help="Print this help message", .tag="print_help"},
        {.short_option=0, .long_option = "", .has_param = NO_PARAM, .help="", .tag=NULL}
    };
    cmd.cmd_option = cmd_option;
    int err_arg = 0;
    PARG_PARSED_ARGS pargs = arg_parse_arguments(&cmd, argc, argv, &err_arg);
    if (pargs == NULL || err_arg != 0){
        arg_show_help(&cmd, argc, argv);
        return 1;
    }
    // this will fill our scanner_input structure by examing all the params
    get_command_line(pargs, si);
    if (si->help){
        arg_show_help(&cmd, argc, argv);
        return 0;
    }
    if (si->port < 0 || si->port > 65535){
        fprintf(stderr, "Wrong port number specified\n");
        return 1;
    }
    if (si->timeout <= 0){
        fprintf(stderr, "Timeout must be greater or equal to 1\n");
        return 1;
    }
    if (si->rr_type == -2){
        fprintf(stderr, "Wrong or not supported RR type specified\n");
        return 1;
    }
    if (si->rr_class == -2){
        fprintf(stderr, "Wrong or not supported RR class specified\n");
        return 1;
    }
    if (si->output_file != NULL){
        si->OUTPUT = fopen(si->output_file, "w");
    }else{
        si->OUTPUT = stdout;
    }
    if (si->output_error != NULL){
        si->ERROR = fopen(si->output_error, "w");
    }else{
        si->ERROR = stderr;
    }
    if (cmd.extra == NULL){
       si->INPUT = stdin;
    }else{
        si->INPUT = fopen(cmd.extra, "r");
        if (si->INPUT == NULL){
            perror("Error openning input file");
            return 1;
        }
    }
    struct thread_param * tp = (struct thread_param*) malloc(sizeof(struct thread_param));
    if (NULL == tp){
        fprintf(stderr, "Can not allocate memory for thread paremeters\n");
        return 1;
    }
    qinput = cqueue_init(BULKDNS_MAX_QUEUE_SIZE);   // init unlimited queue
    srand(time(NULL));
    char quit_msg[50];
    sprintf(quit_msg, "QUIT_%d%d", rand(), rand());
    char * quit_data = strdup(quit_msg);
    tp->quit_data = quit_data;
    tp->si = si;
    //read input file
    char * line;
    PSTR str;
    char * line_stripped;
    
    // launch threads first
    if (pthread_mutex_init(&lock, NULL) != 0){
        printf("Can not create the lock\n");
        cqueue_free(qinput);
        free(quit_data);
        return 1;
    }

    pthread_t * threads = (pthread_t*) malloc(si->threads * sizeof(pthread_t));
    for (int i=0; i< si->threads; ++i){
        // add one quit for each thread to queue
        if (pthread_create(&threads[i], NULL, worker_routine, (void*) tp) != 0){
            printf("ERROR: Can not create thread#%d\n", i);
            free(quit_data);
            cqueue_free(qinput);
            return 2;
        }
    }
    

    int res_q = 0;
    // add everything to the queue
    while ((line = readline(si->INPUT)) != NULL){
        str = str_init(line);
        free(line);
        line_stripped = str->str_strip(str, NULL);
        str_free(str);
        if (line_stripped == NULL)
            continue;
        if(strlen(line_stripped) == 0){
            free(line_stripped);
            continue;
        }
        do{
            pthread_mutex_lock(&lock);
            res_q = cqueue_put(qinput, (void*) line_stripped);
            pthread_mutex_unlock(&lock);
            if (res_q == 1){    // this means queue is full
                sleep(5);
                continue;
            }
            break;
        }while(1);
    }
    //fprintf(stdout, "we are done with the input\n");
    fclose(si->INPUT);
    do{
        pthread_mutex_lock(&lock);
        int qs = cqueue_size(qinput);
        //fprintf(stdout, "***************%d\n", BULKDNS_MAX_QUEUE_SIZE - qs);
        if (BULKDNS_MAX_QUEUE_SIZE - qs < si->threads){
            pthread_mutex_unlock(&lock);
            //fprintf(stdout, "let's sleep for 3 seconds until queue has enough space for quit signature\n");
            sleep(3);
            continue;
        }
        pthread_mutex_unlock(&lock);
        break;
    }while(1);

    // add one quit message for each thread
    for (int i=0; i<si->threads; ++i){
        pthread_mutex_lock(&lock);
        if (cqueue_put(qinput, (void*)quit_data) != 0){
            //fprintf(stderr, "Can not submit the quit message to queue\n");
        }
        pthread_mutex_unlock(&lock);
    }
       

    // now join the threads and fuck the lock
    for (int i=0; i<si->threads; ++i){
        pthread_join(threads[i], NULL);
    }
    pthread_mutex_destroy(&lock);

    free(threads);
    free(quit_data);
    cqueue_free(qinput);
    arg_free(pargs);
    free(si->resolver);
    if (si->ERROR != stderr){
        fclose(si->ERROR);
    }
    if (si->OUTPUT != stdout)
        fclose(si->OUTPUT);
    free(si);

    free(tp);
    // we are done when we are done! (Ben)
}
