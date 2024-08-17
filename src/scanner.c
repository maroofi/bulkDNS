#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>         ///< sleep function
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>


#ifdef COMPILE_WITH_LUA
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#endif

#include <cstrlib.h>
#include <cqueue.h>
#include <sdns.h>
#include <sdns_json.h>
#include <sdns_print.h>
#include <cmdparser.h>
#include <scanner.h>


// manual compile with:
//



/*****************static function definitions*******************/

static inline void * bulkdns_malloc_or_abort(size_t n){
    void * p = malloc(n);
    if (NULL == p)
        abort();
    return p;
}

static char * bulkdns_mem_copy(char * data, unsigned long int len){
    char * tmp = (char *) bulkdns_malloc_or_abort(len);
    memcpy(tmp, data, len);
    return tmp;
}

#ifdef COMPILE_WITH_LUA
static char * bulkdns_mem_tcp_copy(char * data, unsigned long int len){
    // this is the same as bulkdns_mem_copy() but adds two bytes at
    // the beginning of the memory to show the length of the data.
    // this is how TCP protocol works in DNS operation.
    char * tmp = (char *) bulkdns_malloc_or_abort(len + 2);
    tmp[0] = (uint8_t)((len & 0xFFFF) >> 8);
    tmp[1] = (uint8_t)((len & 0xFF));
    memcpy(tmp+2, data, len);
    return tmp;
}
#endif

/***************************************************************/



int main(int argc, char ** argv){
    struct scanner_input * si = (struct scanner_input*) malloc(sizeof(struct scanner_input));
    if (NULL == si){
        fprintf(stderr, "Can not allocate memory for input....\n");
        return 1;
    }
    // set zero to silent the valgrind 'uninitialized.....' warning
    memset(si, 0, sizeof(struct scanner_input));

    // create command-line (list of switches)
    PARG_CMDLINE cmd = create_command_line_arguments();
    if (cmd == NULL){
        fprintf(stderr, "Can not allocate memory...\n");
        return 1;
    }

    // parse command-line
    int err_arg = 0;
    PARG_PARSED_ARGS pargs = arg_parse_arguments(cmd, argc, argv, &err_arg);
    if (pargs == NULL || err_arg != 0){
        arg_show_help(cmd, argc, argv);
        return 1;
    }
    
    // this will fill our scanner_input structure by examing all the params of commandline
    get_command_line(pargs, si);

    // let's check if the input values from user make sense!
    if (initial_check_command_line(si, cmd) == -1){
        return 1;       // we can't continue, we have to exit
    }
    // if user want to see the help, let's show him
    if (si->help){
        arg_show_help(cmd, argc, argv);
        free_cmd(cmd);
        arg_free(pargs);
        free(si->resolver);
        free(si->bind_ip);
        free(si->lua_file);
        free(si);
        return 0;
    }

    // we dont need command-line stuff anymore, let's free() them
    free_cmd(cmd);
    arg_free(pargs);

    // now we need to check if we want to run bulkDNS in scan mode
    // or server mode.
    if (si->server_mode){  // we can just launch the server mode and we are done
        switch_server_mode(si);
        return 0;
    }

    // if we are here, it means we are in bulk DNS scan mode

    struct thread_param * tp = (struct thread_param*) malloc(sizeof(struct thread_param));
    if (NULL == tp){
        fprintf(stderr, "Can not allocate memory for thread paremeters\n");
        return 1;
    }
    
    // init the input queue
    tp->qinput = cqueue_init(BULKDNS_MAX_QUEUE_SIZE);   // init unlimited queue

    // randomize the DNS IDs
    srand(time(NULL));

    // when a thread fetches 'quit_msg' value from input queue, it knows that it's time to die!
    char quit_msg[50];
    sprintf(quit_msg, "QUIT_%d%d", rand(), rand());
    char * quit_data = strdup(quit_msg);
    tp->quit_data = quit_data;

    // we need to pass input switches to each thread
    tp->si = si;


    //read input file
    char * line;
    PSTR str;
    char * line_stripped;
    
    // launch the threads first
    if (pthread_mutex_init(&(tp->lock), NULL) != 0){
        fprintf(stderr, "ERROR: Can not initialize the mutex\n");
        cqueue_free(tp->qinput);
        free(quit_data);
        return 1;
    }

    pthread_t * threads = (pthread_t*) malloc(si->threads * sizeof(pthread_t));
    for (int i=0; i< si->threads; ++i){
        if (si->lua_file != NULL){
            // this is lua-based custom scan scenario
#ifdef COMPILE_WITH_LUA
            if (pthread_create(&threads[i], NULL, scan_lua_worker_routine, (void*) tp) != 0){
                fprintf(stderr, "ERROR: Can not create thread#%d\n", i);
                free(quit_data);
                cqueue_free(tp->qinput);
                return 2;
            }
#else
            fprintf(stderr, "ERROR: You must compile bulkDNS with Lua to use this feature\n");
            fprintf(stderr, "INFO: To compile with Lua, use 'make with-lua'\n");
            exit(1);
#endif
        }else{
            // this is a normal bulkDNS scan option
            if (pthread_create(&threads[i], NULL, scan_worker_routine, (void*) tp) != 0){
                fprintf(stderr, "ERROR: Can not create thread#%d\n", i);
                free(quit_data);
                cqueue_free(tp->qinput);
                return 2;
            }
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
            pthread_mutex_lock(&(tp->lock));
            res_q = cqueue_put(tp->qinput, (void*) line_stripped);
            pthread_mutex_unlock(&(tp->lock));
            if (res_q == 1){    // this means queue is full
                sleep(5);
                continue;
            }
            break;
        }while(1);
    }

    fclose(si->INPUT);
    do{
        pthread_mutex_lock(&(tp->lock));
        int qs = cqueue_size(tp->qinput);

        if (BULKDNS_MAX_QUEUE_SIZE - qs < si->threads){
            pthread_mutex_unlock(&(tp->lock));
            //fprintf(stdout, "let's sleep for 3 seconds until queue has enough space for quit signature\n");
            sleep(3);
            continue;
        }
        pthread_mutex_unlock(&(tp->lock));
        break;
    }while(1);

    // add one quit message for each thread
    for (int i=0; i<si->threads; ++i){
        pthread_mutex_lock(&(tp->lock));
        if (cqueue_put(tp->qinput, (void*)quit_data) != 0){
            // it's almost impossible to fail here but still need more considerations
            //fprintf(stderr, "Can not submit the quit message to queue\n");
        }
        pthread_mutex_unlock(&(tp->lock));
    }

    // join the threads and destroy the lock since we are done
    for (int i=0; i<si->threads; ++i){
        pthread_join(threads[i], NULL);
    }
    pthread_mutex_destroy(&(tp->lock));

    // free the remaining memory parts
    free(threads);
    free(quit_data);
    cqueue_free(tp->qinput);
    free(si->resolver);
    free(si->bind_ip);
    free(si->lua_file);

    // close it if it's not standard input/output/error
    if (si->ERROR != stderr){
        fclose(si->ERROR);
    }
    if (si->OUTPUT != stdout)
        fclose(si->OUTPUT);

    free(si);
    free(tp);

    // we are done when we are done! (Ben)
}


/***************************************************************************/
/***************** Functions related to buldDNS scan mode ******************/
/***************************************************************************/

void dns_routine_scan(void * item, struct scanner_input * si, char * mem_result){
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
    if (si->set_nsid && (!si->no_edns)){
        sdns_opt_rdata * nsid = sdns_create_edns0_nsid(NULL, 0);
        if (nsid != NULL){
            res = sdns_add_edns(dns, nsid);
            if (res != 0){
                sdns_free_context(dns);
                sdns_free_opt_rdata(nsid);
                return;
            }
        }
    }
    res = sdns_to_wire(dns);
    if (res != 0){
        sdns_free_context(dns);
        return;
    }
    size_t result_len = 65535;
    res = perform_lookup_udp(dns->raw, dns->raw_len, &mem_result, &result_len, si);
    if (res != 0){
        sdns_free_context(dns);
        return;
    }
    sdns_context * dns_udp_response = sdns_init_context();
    dns_udp_response->raw = mem_result;
    dns_udp_response->raw_len = result_len;
    res = sdns_from_wire(dns_udp_response);
    if (res != 0){
        sdns_free_context(dns);
        dns_udp_response->raw = NULL;
        sdns_free_context(dns_udp_response);
        return;
    }
    if (si->udp_only){
        sdns_free_context(dns);
        char * dmp = sdns_json_dns_string(dns_udp_response);
        fprintf(si->OUTPUT, "%s\n", dmp);
        free(dmp);
        dns_udp_response->raw = NULL;
        sdns_free_context(dns_udp_response);
        return;
    }
    if (dns_udp_response->msg->header.tc == 1){
        dns_udp_response->raw = NULL;
        dns_udp_response->raw_len = 0;
        sdns_free_context(dns_udp_response);
        result_len = 65535;
        res = perform_lookup_tcp(dns->raw, dns->raw_len, &mem_result, &result_len, si);
        sdns_free_context(dns);
        if (res != 0){  // we got TCP error
            return;
        }
        sdns_context * dns_tcp_response = sdns_init_context();
        if (NULL == dns_tcp_response){
            return;
        }
        dns_tcp_response->raw = mem_result;
        dns_tcp_response->raw_len = result_len;
        res = sdns_from_wire(dns_tcp_response);
        if (res != 0){
            dns_tcp_response->raw = NULL;
            sdns_free_context(dns_tcp_response);
            return;
        }
        char * dmp = sdns_json_dns_string(dns_tcp_response);
        fprintf(si->OUTPUT, "%s\n", dmp);
        free(dmp);
        dns_tcp_response->raw = NULL;
        sdns_free_context(dns_tcp_response);
        return;
    }else{
        sdns_free_context(dns);
        char * dmp = sdns_json_dns_string(dns_udp_response);
        fprintf(si->OUTPUT, "%s\n", dmp);
        free(dmp);
        dns_udp_response->raw = NULL;
        sdns_free_context(dns_udp_response);
        return;
    }
}


#ifdef COMPILE_WITH_LUA
void * scan_lua_worker_routine(void * ptr){
    // this worker routine is for custom scan scenario
    // this will be called by several threads in non-custom scan mode
    // ptr is a structure of type thread_param
    void * item;
    struct thread_param * tp = (struct thread_param*)ptr;
    struct scanner_input * si = tp->si;
    // initialize lua State and set up the stack
    // we develop it inside macro to just to make
    // sure vim does not complain about Lua library
    // but it's not necessary.
    lua_State * L = luaL_newstate();
    if (L == NULL){
        fprintf(stderr, "error creating lua state\n");
        return NULL;
    }
    luaL_openlibs(L);
    if (luaL_loadfile(L, si->lua_file) != LUA_OK){
        fprintf(stderr, "Can not load the lua file...it probably has an error\n");
        
        return NULL;
    }
    if (lua_pcall(L, 0, 0, 0) != 0){
        size_t len;
        const char * d = luaL_checklstring(L, -1, &len);
        fprintf(stderr, "Error: %s\n", d);
        return NULL;
    }
    //fprintf(stdout, "starting thread...\n");
    while (1){
        // loop forever until item is "quit"
        // as our queue is not thread-safe, we have to lock it
        pthread_mutex_lock(&(tp->lock));
        item = cqueue_get(tp->qinput);
        if (item == NULL){
            // sleep 1 sec and continue
            pthread_mutex_unlock(&(tp->lock));
            sleep(1);
            continue;
            //fprintf(si->ERROR, "ERROR: %s\n", qinput->errmsg);
        }
        //cnt += 1;
        pthread_mutex_unlock(&(tp->lock));
        if (item == NULL){
            // something is wrong. we should never be here.
            fprintf(stderr, "We should never have NULL item in the queue!!!!!\n");
            // just quit the thread
            return NULL;
        }
        if (strcmp((char*) item, tp->quit_data) == 0){
            //fprintf(stderr, "We have received a quit message in thread#%ld\n", pthread_self());
            lua_close(L);
            return NULL;
        }
        
        lua_settop (L, 0);
        // do whatever you want with the item
        lua_dns_routine_scan(item, si, L);
        // item is just a char* pointer (one stripped line of the input file)
        free(item);
    }
    return NULL;
}
#endif

#ifdef COMPILE_WITH_LUA
void lua_dns_routine_scan(void * item, struct scanner_input * si, lua_State * L){
    if (lua_getglobal(L, "main") != LUA_TFUNCTION){
        fprintf(stdout, "No 'main' function detected in Lua script\n");
        return;
    }
    lua_pushstring(L, (char*)item);
    size_t str_len;
    int res = lua_pcall(L, 1, 1, 0);
    if (res != 0){
        const char * result = luaL_checkstring(L, -1);
        fprintf(stdout, "ERROR: %s\n", result);
        return;
    }
    // what is in the stack is what we should log in the output file
    // if Lua script returns null, we don't need to log anything
    if (lua_isnil(L, -1) == 1){
        lua_pop(L, 1);
        return;
    }
    const char * response = luaL_checklstring(L, -1, &str_len);
    fprintf(si->OUTPUT, "%s\n", response);
    lua_pop(L, 1);
    return;
}   
#else
void lua_dns_routine_scan(void){
    return;
}
#endif


void *scan_worker_routine(void * ptr){
    // this will be called by several threads in non-custom scan mode
    // ptr is a structure of type thread_param
    void * item;
    struct thread_param * tp = (struct thread_param*)ptr;
    struct scanner_input * si = tp->si;
    char * mem_result = (char*) bulkdns_malloc_or_abort(65535);
    while (1){
        // loop forever until item is "quit"
        // as our queue is not thread-safe, we have to lock it
        pthread_mutex_lock(&(tp->lock));
        item = cqueue_get(tp->qinput);
        if (item == NULL){
            // sleep 1 sec and continue
            pthread_mutex_unlock(&(tp->lock));
            sleep(1);
            continue;
            //fprintf(si->ERROR, "ERROR: %s\n", qinput->errmsg);
        }
        //cnt += 1;
        pthread_mutex_unlock(&(tp->lock));
        if (item == NULL){
            // something is wrong. we should never be here.
            fprintf(si->ERROR, "We should never have NULL item in the queue!!!!!\n");
            // just quit the thread
            free(mem_result);
            return NULL;
        }
        if (strcmp((char*) item, tp->quit_data) == 0){
            //printf("We have received a quit message in thread#%ld\n", pthread_self());
            free(mem_result);
            return NULL;
        }
        // do whatever you want with the item
        dns_routine_scan(item, si, mem_result);

        // item is just a char* pointer (one stripped line of the input file)
        free(item);
    }
    free(mem_result);
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
        close(sockfd);
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
        //fprintf(si->ERROR, "Error in receive function\n");
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
    char * receive_payload = *toreceive_buffer;
    received = recv(sockfd, receive_payload, to_allocate, MSG_WAITALL);
    if (received < 0){  // we have socket error
        fprintf(si->ERROR, "Error reading from socket...\n");
        close(sockfd);
        return 1;
    }
    *toreceive_len = to_allocate;
    *toreceive_buffer = receive_payload;
    close(sockfd);
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
    if (strcasecmp(type, "CAA") == 0)
        return sdns_rr_type_CAA;
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




/************************************************************************************/
/**************** Functions from here are related to server mode *******************/
/************************************************************************************/

server_mode_queue_data * init_server_mode_queue_data(){
    server_mode_queue_data * qd = (server_mode_queue_data*)bulkdns_malloc_or_abort(sizeof(server_mode_queue_data));
    qd->client_addr_len = sizeof(qd->client_addr);
    qd->received_len = 0;
    qd->received = NULL;
    qd->to_send = NULL;
    qd->to_send_len = 0;
    qd->ready_to_send = 0;
    qd->is_udp = 1;
    qd->tcp_sock = -1;
    return qd;
}

void free_server_mode_queue_data(server_mode_queue_data * qd){
    free(qd->received);
    free(qd->to_send);
    free(qd);
}


#ifdef COMPILE_WITH_LUA
void server_mode_process_input_tcp(server_mode_queue_data * cqd, lua_State * L){
    // what happens here is like this:
    // we call a lua function and pass the raw data to the lua function.
    // we named the function 'main'. So we need to push it to stack for each
    // call.
    // we analyze the result and return back to C code.
        
    if (lua_getglobal(L, "main") != LUA_TFUNCTION){
        fprintf(stdout, "No 'main' function detected in Lua script\n");
        return;
    }
    lua_pushlstring(L, cqd->received, cqd->received_len);
    // push a lua table {ip, port, proto}
    lua_createtable(L, 0, 3);
    lua_pushstring(L, "port");
    lua_pushinteger(L, ntohs(cqd->client_addr.sin_port));
    lua_settable(L, -3);
    char ip_result[40] = {0x00};
    inet_ntop(cqd->client_addr.sin_family, &(cqd->client_addr.sin_addr), ip_result, 40);
    lua_pushstring(L, "ip");
    lua_pushstring(L, ip_result);
    lua_settable(L, -3);
    lua_pushstring(L, "proto");
    lua_pushstring(L, "TCP");
    lua_settable(L, -3);
        
    int res = lua_pcall(L, 2, 2, 0);
    if (res != 0){
        const char * result = luaL_checkstring(L, -1);
        fprintf(stdout, "ERROR: %s\n", result);
        return;
    }

    // the value on top of the stack is either nil or string (to is what to send to client)
    if (lua_isnil(L, -1) == 1){
        // means we can just drop the TCP packet. No need to send response to client
        // do nothing
    }else if (lua_isstring(L, -1) == 1){
        size_t len;
        const char * response = luaL_checklstring(L, -1, &len);
        cqd->to_send = bulkdns_mem_tcp_copy((char*)response, len);
        cqd->to_send_len = len + 2;
    }else{
        // should never happen
        fprintf(stdout, "ERROR: return value from Lua code is neither string nor nil\n");
        return;
    }
    // the second value in the stack is what we want to log in the output (nil or string)
    if (lua_isnil(L, -2) == 1){
        // means there is nothing to log
        return;
    }else if (lua_isstring(L, -2) == 1){
        size_t len;
        const char * response = luaL_checklstring(L, -2, &len);
        server_mode_to_log(response, stdout);
        return;
    }else{
        // should never happen
        fprintf(stdout, "ERROR: return value from Lua code is neither string nor nil\n");
        return;
    }
}
#endif

#ifdef COMPILE_WITH_LUA
void server_mode_process_input_udp(server_mode_queue_data * cqd, lua_State * L){
    
    // what happens here is like this:
    // we call a lua function and pass the raw data to the lua function.
    // we named the function 'main'. So we need to push it to stack for each
    // call.
    // we analyze the result and return back to C code.
    
    if (lua_getglobal(L, "main") != LUA_TFUNCTION){
        fprintf(stdout, "No 'main' function detected in Lua script\n");
        return;
    }
    lua_pushlstring(L, cqd->received, cqd->received_len);

    // push a lua table {ip, port, proto}
    lua_createtable(L, 0, 3);
    lua_pushstring(L, "port");
    lua_pushinteger(L, ntohs(cqd->client_addr.sin_port));
    lua_settable(L, -3);
    char ip_result[40] = {0x00};
    inet_ntop(cqd->client_addr.sin_family, &(cqd->client_addr.sin_addr), ip_result, 40);
    lua_pushstring(L, "ip");
    lua_pushstring(L, ip_result);
    lua_settable(L, -3);
    lua_pushstring(L, "proto");
    lua_pushstring(L, "UDP");
    lua_settable(L, -3);

    int res = lua_pcall(L, 2, 2, 0);
    if (res != 0){
        const char * result = luaL_checkstring(L, -1);
        fprintf(stdout, "ERROR: %s\n", result);
        return;
    }

        
    // the value on top of the stack is either nil or string (to is what to send to client)
    if (lua_isnil(L, -1) == 1){
        // means we can just drop the UDP packet. No need to send response to client
    }else if (lua_isstring(L, -1) == 1){
        size_t len;
        const char * response = luaL_checklstring(L, -1, &len);
        cqd->to_send = bulkdns_mem_copy((char*)response, len);
        cqd->to_send_len = len;
    }else{
        // should never happen
        fprintf(stdout, "ERROR: return value from Lua code is neither string nor nil\n");
        return;
    }
    // the second value in the stack is what we want to log in the output (nil or string)
    if (lua_isnil(L, -2) == 1){
        // means there is nothing to log
        return;
    }else if (lua_isstring(L, -2) == 1){
        size_t len;
        const char * response = luaL_checklstring(L, -2, &len);
        server_mode_to_log(response, stdout);
        return;
    }else{
        // should never happen
        fprintf(stdout, "ERROR: return value from Lua code is neither string nor nil\n");
        return;
    }
}
#endif

#ifdef COMPILE_WITH_LUA
void * smode_func_sender_tcp(void * data){
    server_mode_thread_params * tp = (server_mode_thread_params*) data;
    void * to_consume = NULL;

    lua_State * L = luaL_newstate();
    if (L == NULL){
        fprintf(stdout, "error creating lua state\n");
        return NULL;
    }
    luaL_openlibs(L);
    if (luaL_loadfile(L, tp->lua_file) != LUA_OK){
        fprintf(stdout, "Can not load the lua file...there might be an error in the file\n");
        close(tp->sockfd);
        exit(1);
        return NULL;
    }
    if (lua_pcall(L, 0, 0, 0) != 0){
        size_t len;
        const char * d = luaL_checklstring(L, -1, &len);
        fprintf(stdout, "Error: %s\n", d);
        close(tp->sockfd);
        exit(2);
        return NULL;
    }
    
    while(1){
        pthread_mutex_lock(tp->mutex_queue);
        to_consume = cqueue_get(tp->queue_handle);
        if (NULL == to_consume){  // queue is empty
            pthread_mutex_unlock(tp->mutex_queue);
            //usleep(100000);     // 1 millisec
            continue;
        }
        // the data is ready to be sent
        pthread_mutex_unlock(tp->mutex_queue);

        // send it to be process
        server_mode_process_input_tcp((server_mode_queue_data *)to_consume, L);
        
        // this is TCP sending so we need to send the size as two bytes
        // but this will be handled in process_work routine for TCP
        if (((server_mode_queue_data*)to_consume)->to_send != NULL){
            send(((server_mode_queue_data*)to_consume)->tcp_sock,
                 ((server_mode_queue_data*)to_consume)->to_send,
                 ((server_mode_queue_data*)to_consume)->to_send_len, 0);

        }
        close(((server_mode_queue_data*)to_consume)->tcp_sock);
        free_server_mode_queue_data((server_mode_queue_data*)to_consume);
    }
    return NULL;
}
#else

void * smode_func_sender_tcp(void * data){
    return NULL;
}
#endif


void * smode_func_receiver_tcp(void * data){
    server_mode_thread_params * tp = (server_mode_thread_params*) data;
    fprintf(stderr, "Waiting for a client to send a message (TCP).....\n");
    ssize_t received_len;
    char * buff = (char*)bulkdns_malloc_or_abort(550);            // more than maximum DNS packet size
    server_mode_queue_data * qd = init_server_mode_queue_data();
    qd->is_udp = 0;
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};       // wait for 2 seconds for sending
    int new_confd;
    while (1){
        new_confd = accept(tp->sockfd, (struct sockaddr*)&qd->client_addr, &(qd->client_addr_len));
        if (new_confd == -1){
            perror("Errorrrr");
            usleep(10000);
            continue;
        }
        if (setsockopt(new_confd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0){
            close(new_confd);
            continue;
        }
        if (setsockopt(new_confd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
            close(new_confd);
            continue;
        }
        received_len = recv(new_confd, buff, 550, 0);
        // why 514 and 18 instead of 512 and 16?
        // TCP connections have 2 bytes header for the size of the received payload
        if (received_len < 0 || received_len > 514 || received_len < 18){
            perror("Error");
            close(new_confd);
            continue;
        }
        // the question section must be exactly one otherwise it's invalid DNS msg
        if ((uint8_t)buff[4 + 2] != 0 || (uint8_t)buff[5 + 2] != 1){
            close(new_confd);
            continue;
        }
        // DNS qr must be zero so we drop this one as well
        if ((((uint8_t)buff[2 + 2]) & 0x80) == 128){
            close(new_confd);
            continue;
        }
        qd->tcp_sock = new_confd;
        qd->received_len = received_len;
        // remove the TCP size first
        qd->received = bulkdns_mem_copy(buff+2, received_len - 2);
        pthread_mutex_lock(tp->mutex_queue);
        cqueue_put(tp->queue_handle, (void*)qd);
        pthread_mutex_unlock(tp->mutex_queue);
        // init another queue data
        qd = init_server_mode_queue_data();
    }
    return NULL;
}

#ifdef COMPILE_WITH_LUA
// this is the function for the thread which wait for client to connect
void * smode_func_receiver_udp(void * data){
    server_mode_thread_params * tp = (server_mode_thread_params*) data;
    fprintf(stderr, "Waiting for a client to send a message (UDP).....\n");
    ssize_t received_len;
    char * buff = (char*)bulkdns_malloc_or_abort(550);            // more than maximum DNS packet size
    server_mode_queue_data * qd = init_server_mode_queue_data();


    lua_State * L = luaL_newstate();
    if (L == NULL){
        fprintf(stdout, "error creating lua state\n");
        return NULL;
    }
    luaL_openlibs(L);
    if (luaL_loadfile(L, tp->lua_file) != LUA_OK){
        fprintf(stdout, "Can not load the lua file\n");
        return NULL;
    }

    if (lua_pcall(L, 0, 0, 0) != 0){
        size_t len;
        const char * d = luaL_checklstring(L, -1, &len);
        fprintf(stdout, "Error: %s\n", d);
        return NULL;
    }

    while (1){
        received_len = recvfrom(tp->sockfd, buff, 550, 0, 
                                (struct sockaddr *)&(qd->client_addr),
                                 &(qd->client_addr_len));
        if (received_len < 0){
            perror("Error in receiving data....");
            abort();
        }
        // the size of the packet must be at least 16 bytes (12 header + 4 bytes question)
        // a DNS request is always <= 512 bytes
        if (received_len > 512 || received_len < 16)
            continue;
        // the question section must be exactly one otherwise it's invalid DNS msg
        if ((uint8_t)buff[4] != 0 || (uint8_t)buff[5] != 1)
            continue;
        // DNS qr must be zero so we drop this one as well
        if (((uint8_t)buff[2] & 0x80) == 128)
            continue;
        // print_connection_info(&(qd->client_addr), 1);
        // finish basic tests, we send it to queue
        qd->is_udp = 1;
        qd->received_len = received_len;
        qd->received = bulkdns_mem_copy(buff, received_len);
        received_len = -1;
        
        server_mode_process_input_udp(qd, L);

        if (qd->to_send != NULL){
            sendto(tp->sockfd, qd->to_send, qd->to_send_len, 0,
                   (struct sockaddr *)(&(qd->client_addr)),
                   qd->client_addr_len);
        }
        free_server_mode_queue_data(qd);

        // init another queue data
        qd = init_server_mode_queue_data();
    }
    return NULL;
};
#else

void * smode_func_receiver_udp(void * data){
    return NULL;
}
#endif


// running the code if we receive ctrl+c from keyboard
void sig_int_handler(int val){
    fprintf(stdout, "Receiving....CTRL+C....\n");
    exit(1);
}

void* server_mode_run_udp(void * param){
    server_mode_server_param * smsp = (server_mode_server_param*) param;

    int sockfd;
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(smsp->port);
    if (inet_pton(AF_INET, (const char *)smsp->ip, &(server.sin_addr.s_addr)) != 1){
        fprintf(stderr, "Can not bind to the provided IP address\n");
        exit(1);
    }
    //server.sin_addr.s_addr = htonl(server_ip);   //htonl(INADDR_ANY);
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0){
        perror("Error in creating socket");
        exit(1);
    }

    int enable_reuseaddr = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable_reuseaddr, sizeof(int)) < 0){
        perror("Error making socket reusable");
        close(sockfd);
        exit(1);
    }

    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) != 0){
        close(sockfd);
        perror("Error in binding socket");
        exit(1);
    }
    

    // creating a queue. The receiver will put data in our queue and 
    // the sender will read the data, process it and send the result to the client.
    // The queue will be passed as an argument to both threads.
    cqueue_ctx * queue_handle = cqueue_init(50);       // we receive up to 50 records
                                                        // and then start to drop the packets
    
    // can not continue if we can not create the queues
    if (NULL == queue_handle)
        abort();
     

    // this what we pass as the parameter to both threads
    server_mode_thread_params tp = {.sockfd=sockfd, .lua_file=smsp->lua_file};

    // now we create two threads: one for listening and receiving data, putting it
    // in the queue. The other one reading the queue constantly, fetching the data,
    // processing it and send the result back to the client.

    smode_func_receiver_udp((void*)&tp);

    // killing with sigkill will result in never reaching this
    // part of the code!

    fprintf(stdout, "Stopping the server.......\n");
    // do the clean-up here
    // TODO: clean up

    // close the socket
    close(sockfd);

    return NULL;
}


void * server_mode_run_tcp(void * param){
    server_mode_server_param * smsp = (server_mode_server_param*)param;
    // TODO: implement this
    int sockfd;
    struct sockaddr_in servaddr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        perror("Can not create TCP socket");
        exit(1);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(smsp->port);
    /*
    */
    if (inet_pton(AF_INET, (const char *)smsp->ip, &(servaddr.sin_addr.s_addr)) != 1){
        fprintf(stderr, "Can not bind to the provided IP address\n");
        close(sockfd);
        exit(1);
    }

    int enable_reuseaddr = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable_reuseaddr, sizeof(int)) < 0){
        perror("Error making socket reusable");
        close(sockfd);
        exit(1);
    }

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0){
        perror("Can not bind TCP socket");
        close(sockfd);
        exit(1);
    }

    if (listen(sockfd, 10) != 0){
        perror("Can not listen to TCP port");
        close(sockfd);
        exit(1);
    }

    // creating sender thread
    pthread_t * pthrd_sender = (pthread_t*) bulkdns_malloc_or_abort(sizeof(pthread_t));
    

    // creating a queue. The receiver will put data in our queue and 
    // the sender will read the data, process it and send the result to the client.
    // The queue will be passed as an argument to both sender and receiver.
    cqueue_ctx * queue_handle = cqueue_init(50);       // we receive up to 50 records
                                                        // and then start dropping the packets
    
    // can not continue if we can not create the queues
    if (NULL == queue_handle)
        abort();
    
    // create a lock for the queue (two threads going to have access to our queue)
    pthread_mutex_t * mutex_queue = bulkdns_malloc_or_abort(sizeof(pthread_mutex_t));
    
    // abort if we can not create a mutex
    if (pthread_mutex_init(mutex_queue, NULL) != 0)
        abort();
     
    // this what we pass as the parameter to both threads
    server_mode_thread_params tp = {.queue_handle  = queue_handle, .mutex_queue = mutex_queue, .sockfd=sockfd, .lua_file=smsp->lua_file};


    // now we create one thread: for reading the queue constantly, fetching the data,
    // processing it and send the result back to the client.
    if (pthread_create(pthrd_sender, NULL, smode_func_sender_tcp, (void*)(&tp)) != 0)
        abort();

    smode_func_receiver_tcp((void*)(&tp));

    // we never reach here to do the clean up
    //TODO: do the clean up

    return NULL;
}

void server_mode_run_all(server_mode_server_param *smsp){
    pid_t newpid = fork();
    if (newpid == 0){   // this is the child where we run TCP mode
        server_mode_run_tcp((void*)smsp);
    }else if (newpid > 0){  // this is parent where we run UDP mode
        server_mode_run_udp((void*)smsp);
    }else{      // this is error where we should never reach
        exit(0);
    }
}

void switch_server_mode(struct scanner_input * si){
#ifdef COMPILE_WITH_LUA
    // first connect the signal handler
    signal(SIGINT, sig_int_handler);
    server_mode_server_param p = {.ip = si->bind_ip, .port=si->port, .lua_file=si->lua_file};
    server_mode_run_all(&p);
#else
    fprintf(stderr, "ERROR: You need to compile the code with Lua to use the server mode\n");
    fprintf(stderr, "To do this, you can use: `make with-lua`\n");
    exit(1);
#endif
}

void server_mode_to_log(const char * msg, FILE * fd){
    // writes 'msg' to file 'f'
    fprintf(fd, "%s\n", msg);
}


/************************************************************************************/
/*************** functions from here are related to command-line options**************/
/************************************************************************************/


int initial_check_command_line(struct scanner_input * si, PARG_CMDLINE cmd){
    // the function returns -1 in case of error and 0 in case of success

    // check if the port number is valid
    if (si->port < 0 || si->port > 65535){
        fprintf(stderr, "Wrong port number specified\n");
        return -1;      // error
    }
    // check if timeout option is valid
    if (si->timeout <= 0){
        fprintf(stderr, "Timeout must be greater or equal to 1\n");
        return -1;      // error
    }
    // check if we support this RR type
    if (si->rr_type == -2){
        fprintf(stderr, "Wrong or not supported RR type specified\n");
        return -1;      // error
    }
    // check if we support this DNS class
    if (si->rr_class == -2){
        fprintf(stderr, "Wrong or not supported RR class specified\n");
        return -1;      // error
    }
    // set the output file handle based on user-input
    if (si->output_file != NULL){
        si->OUTPUT = fopen(si->output_file, "w");
    }else{
        si->OUTPUT = stdout;
    }
    // set the output error handle based on user-input
    if (si->output_error != NULL){
        si->ERROR = fopen(si->output_error, "w");
    }else{
        si->ERROR = stderr;
    }
    // set the input file handle based on user-input
    if (cmd->extra == NULL){
       si->INPUT = stdin;
    }else{
        si->INPUT = fopen(cmd->extra, "r");
        if (si->INPUT == NULL){
            perror("Error openning input file");
            return -1;      // error
        }
    }
    if (si->server_mode == 1){
        if (si->lua_file == NULL){
            fprintf(stderr, "Server mode needs a lua script to work\n");
            fprintf(stderr, "You must make sure that you compile bulkDNS with Lua\n");
            fprintf(stderr, "and pass your custom lua script to be used in server mode\n");
            return -1;      // error
        }
    }
    if (si->server_mode == 1){
        if (si->port < 1024){
            fprintf(stderr, "Not safe to run server-mode on privileged ports. Choose a port number > 1024\n");
            return -1;
        }
    }
    return 0;       // success
}


PARG_CMDLINE create_command_line_arguments(){
    PARG_CMDLINE cmd = (PARG_CMDLINE) malloc(sizeof(ARG_CMDLINE));
    if (cmd == NULL)
        return NULL;
    cmd->accept_file = 1;
    cmd->extra = NULL;
    cmd->summary = strdup("Bulk DNS scanner based on sdns low-level DNS library.");
    ARG_CMD_OPTION cmd_option[] = {
        {.short_option=0, .long_option = "udp-only", .has_param = NO_PARAM, .help="Only query using UDP connection (Default will follow TCP)", .tag="udp_only"},
        {.short_option=0, .long_option = "set-do", .has_param = NO_PARAM, .help="Set DNSSEC OK (DO) bit in queries (default is no DO)", .tag="set_do"},
        {.short_option=0, .long_option = "set-nsid", .has_param = NO_PARAM, .help="The packet has NSID in edns0", .tag="set_nsid"},
        {.short_option=0, .long_option = "noedns", .has_param = NO_PARAM, .help="Do not support EDNS0 in queries (Default supports EDNS0)", .tag="noedns"},
        {.short_option='t', .long_option = "type", .has_param = HAS_PARAM, .help="Resource Record type (Default is 'A')", .tag="rr_type"},
        {.short_option='c', .long_option = "class", .has_param = HAS_PARAM, .help="RR Class (IN, CH). Default is 'IN'", .tag="rr_class"},
        {.short_option='r', .long_option = "resolver", .has_param = HAS_PARAM, .help="Resolver IP address to send the query to (default 1.1.1.1)", .tag="resolver"},
        {.short_option=0, .long_option = "threads", .has_param = HAS_PARAM, .help="How many threads should be used (it's pthreads, and default is 300)", .tag="threads"},
        {.short_option='p', .long_option = "port", .has_param = HAS_PARAM, .help="Resolver port number to send the query to (default 53)", .tag="port"},
        {.short_option='o', .long_option = "output", .has_param = HAS_PARAM, .help="Output file name (default is the terminal with stdout)", .tag="output"},
        {.short_option='e', .long_option = "error", .has_param = HAS_PARAM, .help="where to write the error (default is terminal with stderr)", .tag="error"},
        {.short_option='h', .long_option = "help", .has_param = NO_PARAM, .help="Print this help message", .tag="print_help"},
        {.short_option=0, .long_option = "server-mode", .has_param = NO_PARAM, .help="Run bulkDNS in server mode", .tag="server_mode"},
        {.short_option=0, .long_option= "lua-script", .has_param = HAS_PARAM, .help="Lua script to be used either for scan or server mode", .tag="lua_file"},
        {.short_option=0, .long_option="bind-ip", .has_param = HAS_PARAM, .help="IP address to bind to in server mode (default 127.0.0.1)", .tag="bind_ip"},
        {.short_option=0, .long_option="timeout", .has_param = HAS_PARAM, .help="Timeout of the socket (default is 3 seconds)", .tag="timeout"},
        {.short_option=0, .long_option = "", .has_param = NO_PARAM, .help="", .tag=NULL}
    };
    // let's copy it
    int cmd_opt_len = 0;
    PARG_CMD_OPTION cmdopt = cmd_option;
    while (cmdopt->tag != NULL){
        cmd_opt_len++;
        cmdopt++;
    }
    cmd_opt_len++;   // this is for the NULL one (the last record)
    cmdopt = (PARG_CMD_OPTION)bulkdns_malloc_or_abort(cmd_opt_len * sizeof(ARG_CMD_OPTION));
    PARG_CMD_OPTION tmp = cmd_option;
    cmd_opt_len = 0;
    while(tmp[cmd_opt_len].tag != NULL){
        (cmdopt[cmd_opt_len]).short_option = cmd_option[cmd_opt_len].short_option;
        (cmdopt[cmd_opt_len]).long_option = strdup(cmd_option[cmd_opt_len].long_option);
        (cmdopt[cmd_opt_len]).has_param = cmd_option[cmd_opt_len].has_param;
        (cmdopt[cmd_opt_len]).help = strdup(cmd_option[cmd_opt_len].help);
        (cmdopt[cmd_opt_len]).tag = strdup(cmd_option[cmd_opt_len].tag);
        cmd_opt_len++;
    }
    cmdopt[cmd_opt_len].tag = NULL;
    cmdopt[cmd_opt_len].short_option = 0;
    cmdopt[cmd_opt_len].long_option = NULL;
    cmdopt[cmd_opt_len].help = NULL;
    cmd->cmd_option = cmdopt;
    return cmd;
}

void get_command_line(PARG_PARSED_ARGS pargs, struct scanner_input * si){
    si->udp_only = arg_is_tag_set(pargs, "udp_only")?1:0;
    si->set_do  = arg_is_tag_set(pargs, "set_do")?1:0;
    si->set_nsid  = arg_is_tag_set(pargs, "set_nsid")?1:0;
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
    si->server_mode = arg_is_tag_set(pargs, "server_mode")?1:0;
    if (arg_is_tag_set(pargs, "lua_file")){
        si->lua_file = arg_get_tag_value(pargs, "lua_file") != NULL?strdup(arg_get_tag_value(pargs, "lua_file")):NULL;
    }
    if (arg_is_tag_set(pargs, "bind_ip")){
        si->bind_ip = strdup(arg_get_tag_value(pargs, "bind_ip"));
    }else{
        si->bind_ip = strdup("127.0.0.1");
    }
}


void free_cmd(PARG_CMDLINE cmd){
    PARG_CMD_OPTION tmp_option = cmd->cmd_option;
    while (tmp_option->tag != NULL){
        free((void*)tmp_option->help);
        free((void*)tmp_option->long_option);
        free((void*)tmp_option->tag);
        tmp_option++;
    }
    free(cmd->cmd_option);
    free((void*)cmd->summary);
    free(cmd);
}

