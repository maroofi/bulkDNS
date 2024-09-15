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



/*****************static function definitions*******************/

static inline void * bulkdns_malloc_or_abort(size_t n){
    /**A simple wrapper on malloc to abort in case of allocation fails*/
    void * p = malloc(n);
    if (NULL == p)
        abort();
    return p;
}

static char * bulkdns_mem_copy(char * data, unsigned long int len){
    /**Copies a memory block of abort. Only for critical use cases.*/
    char * tmp = (char *) bulkdns_malloc_or_abort(len);
    memcpy(tmp, data, len);
    return tmp;
}

/*We use COMPILE_WITH_LUA macro because what we have inside the macro
is only useful when we compile the code with Lua support.*/
#ifdef COMPILE_WITH_LUA
static char * bulkdns_mem_tcp_copy(char * data, unsigned long int len){
    /* 
       This is the same as bulkdns_mem_copy() but adds two bytes at
       the beginning of the memory to show the length of the data.
       This is how TCP protocol works in DNS operation.
    */
    char * tmp = (char *) bulkdns_malloc_or_abort(len + 2);
    tmp[0] = (uint8_t)((len & 0xFFFF) >> 8);
    tmp[1] = (uint8_t)((len & 0xFF));
    memcpy(tmp+2, data, len);
    return tmp;
}
#endif

/*********************End of static definitions*******************/



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
    tp->qinput = cqueue_init(BULKDNS_MAX_QUEUE_SIZE);

    // init the TCP queue
    tp->queue_tcp = cqueue_init(BULKDNS_MAX_QUEUE_SIZE);

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

    // init the mutex   
    if (pthread_mutex_init(&(tp->lock), NULL) != 0){
        fprintf(stderr, "ERROR: Can not initialize the mutex\n");
        cqueue_free(tp->qinput);
        free(quit_data);
        return 1;
    }

    // how many TCP threads we want to run?
    int num_tcp_threads = 0;

    // stores the array of TCP pthreads
    pthread_t * tcp_threads = NULL;

    int actual_num_threads = 0;
    pthread_t * actual_threads_array = NULL;
    int * sock_array = NULL;

    // here is the case we want to use Lua. We launch normal threads
    if (si->lua_file != NULL){

#ifdef COMPILE_WITH_LUA
        actual_num_threads = si->concurrency;
        pthread_t * threads = (pthread_t*) malloc(si->concurrency * sizeof(pthread_t));      //TODO: fix this number
        actual_threads_array = threads;
#endif

        for (int i=0; i< si->concurrency; ++i){
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
        }

    }else{
        // we don't have Lua option. We need to launch our concurrent model with select

        // let's say the number of concurrent open ports is '--concurrency'
        // each thread can handle 50 ports (max_select variable).
        // Therefore, we need 'floor(concurrency / max_select) + (1 if concurrency % max_select > 0 else 0)'
        
        int concurrency = si->concurrency;
        int max_select = BULKDNS_MAX_SOCKET_FOR_POLL;
        
        int int_part = concurrency / max_select;
        int remainder = concurrency % max_select;
        int num_threads = int_part + (remainder > 0?1:0);

        // --concurrency param is the same as number of open ports.
        // so we need to open 'concurrency' sockes.
        sock_array = (int *) bulkdns_malloc_or_abort(concurrency * sizeof(int));
        for (int i=0; i< concurrency; ++i){
            sock_array[i] = init_udp_socket(si);
            if (sock_array[i] < 0){
                fprintf(stderr, "Can not initialize sockets....\n");
                for (int j=0; j<i; ++j){
                    close(sock_array[j]);
                    //TODO: do other free() here
                    exit(1);
                }
            }
        }
        // we have all the sockets initialized. Let's init our threads.
        actual_num_threads = num_threads;
        pthread_t * threads = (pthread_t*) malloc((num_threads) * sizeof(pthread_t));
        actual_threads_array = threads;
        
        for (int i=0; i< num_threads; ++i){
            scan_mode_receiver_param * tmp_tp = bulkdns_malloc_or_abort(sizeof(scan_mode_receiver_param));
            tmp_tp->tp = tp;
            if (remainder > 0)
                tmp_tp->num_sock = i == num_threads -1?remainder:max_select;
            else
                tmp_tp->num_sock = max_select;
            tmp_tp->sock_list = sock_array + (i * max_select);
            // this is a normal bulkDNS scan option
            if (pthread_create(&threads[i], NULL, scan_receiver_routine, (void*) tmp_tp) != 0){
                fprintf(stderr, "ERROR: Can not create thread#%d\n", i);
                free(quit_data);
                cqueue_free(tp->qinput);
                cqueue_free(tp->queue_tcp);
                return 2;
            }
        }
        // we should also run some threads to handle TCP connections
        // I guess two is enough but we can increase it dynamically based
        // on the number of TCP hits....
        num_tcp_threads = (10 * actual_num_threads / 100) > 1?(10 * actual_num_threads / 100):1 ;
        tcp_threads = (pthread_t*) malloc((num_tcp_threads) * sizeof(pthread_t));
        for (int i=0; i< num_tcp_threads; ++i){
            if (pthread_create(&(tcp_threads[i]), NULL, tcp_routine_handler, (void*) tp) != 0){
                fprintf(stderr, "ERROR: Can not create TCP thread#%d\n", i);
                free(quit_data);
                cqueue_free(tp->qinput);
                cqueue_free(tp->queue_tcp);
                return 2;
            }
        }
    }
    
    
    int res_q = 0;
    // we start adding input lines to the queue. If we reach
    // the max size of the queue, we sleep for 5 seconds and continue.
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

    // we want to add the quit_message to queue. One for each thread.
    // However, we need to make sure our queue has enough space. So we
    // loop and sleep until we have enough space. This is a very poor code
    // and must be changed.
    do{
        pthread_mutex_lock(&(tp->lock));
        int qs = cqueue_size(tp->qinput);
        if (BULKDNS_MAX_QUEUE_SIZE - qs < actual_num_threads){
            pthread_mutex_unlock(&(tp->lock));
            sleep(3);
            continue;
        }
        pthread_mutex_unlock(&(tp->lock));
        break;
    }while(1);

    // add one quit message for each thread
    for (int i=0; i<actual_num_threads; ++i){   // in fact, we need to only send it to sender threads
                                                // but now we are sending it to all threads.
        pthread_mutex_lock(&(tp->lock));
        if (cqueue_put(tp->qinput, (void*)quit_data) != 0){
            // it's almost impossible to fail here but still need more considerations
            // What we should do? :-D
        }
        pthread_mutex_unlock(&(tp->lock));
    }

    // join the threads and destroy the lock since we are done
    for (int i=0; i<actual_num_threads; ++i){
        pthread_join(actual_threads_array[i], NULL);
    }
    
    // let's join TCP threads
    // fprintf(stderr, "Let's join TCP threads....\n");
    for (int i=0; i<num_tcp_threads; ++i){
        pthread_join(tcp_threads[i], NULL);
    }

    pthread_mutex_destroy(&(tp->lock));

    // free the remaining memory parts
    free(actual_threads_array);
    free(tcp_threads);
    

    // we allocated heap memory for 'quit_data'
    free(quit_data);

    void * dummy;

    // we need to empty the queue before freeing its memory
    while((dummy = cqueue_get(tp->qinput)) != NULL);
    cqueue_free(tp->qinput);

    while((dummy = cqueue_get(tp->queue_tcp)) != NULL);
    cqueue_free(tp->queue_tcp);

    // we used strdup() for 'resolver', 'bind_ip' and 'lua_file'
    free(si->resolver);
    free(si->bind_ip);
    free(si->lua_file);

    // close it if it's not standard input/output/error
    if (si->ERROR != stderr)
        fclose(si->ERROR);
    if (si->OUTPUT != stdout)
        fclose(si->OUTPUT);

    // These were also allocated by heap.
    free(sock_array);
    free(si);
    free(tp);

    /*We are done when we are done! (Ben)*/
}


/***************************************************************************/
/***************** Functions related to buldDNS scan mode ******************/
/***************************************************************************/

void * tcp_routine_handler(void * ptr){
    // handle TCP connections
    struct thread_param * tp = (struct thread_param *)ptr;
    char * mem = bulkdns_malloc_or_abort(65535);
    void * item = NULL;

    while (1){
        pthread_mutex_lock(&(tp->lock));
        item = cqueue_get(tp->queue_tcp);
        pthread_mutex_unlock(&(tp->lock));
        if (item == NULL){
            // sleep 1 sec and continue    
            sleep(1);
            continue;
            //fprintf(si->ERROR, "ERROR: %s\n", qinput->errmsg);
        }
        
        if (item == NULL){
            // something is wrong. we should never be here.
            fprintf(tp->si->ERROR, "We should never have NULL item in the queue!!!!!\n");
            // just quit the thread
            return NULL;
        }
        if (strcmp((char*) item, tp->quit_data) == 0){
            //fprintf(stderr, "We have received a quit message in thread#%ld\n", pthread_self());
            // or break and close them after while-loop
            break;
        }
        // do the TCP lookup and print out the output
        // item is a domain name
        char * domain_name = (char*)item;
        sdns_context * dns = sdns_init_context();
        if (NULL == dns)
            continue;
        int res = sdns_make_query(dns, tp->si->rr_type, tp->si->rr_class, domain_name, ~(tp->si->no_edns));
        if (res != 0){
            fprintf(stderr, "Can not make a query packet for TCP....\n");
            sdns_free_context(dns);
            continue;
        }
        if (tp->si->set_do && (!(tp->si->no_edns)))
            dns->msg->additional->opt_ttl.DO = 1;
        if (tp->si->set_nsid && (!(tp->si->no_edns))){
            sdns_opt_rdata * nsid = sdns_create_edns0_nsid(NULL, 0);
            if (nsid != NULL){
                res = sdns_add_edns(dns, nsid);
                if (res != 0){
                    sdns_free_context(dns);
                    sdns_free_opt_rdata(nsid);
                    continue;
                }
            }
        }
        res = sdns_to_wire(dns);
        if (res != 0){
            fprintf(stderr, "Can not make a to_wire packet for TCP....\n");
            sdns_free_context(dns);
            continue;
        }
        size_t to_receive = 0;
        res = perform_lookup_tcp(dns->raw, dns->raw_len, &mem, &to_receive, tp->si);
        sdns_free_context(dns);
        if (res != 0){
            // TODO:we have timeout or any other types of error. we need to send it to output
            continue;
        }
        sdns_context * dns_tcp_response = sdns_init_context();
        if (NULL == dns_tcp_response){
            continue;
        }
        dns_tcp_response->raw = mem;
        dns_tcp_response->raw_len = to_receive;
        res = sdns_from_wire(dns_tcp_response);
        if (res != 0){
            dns_tcp_response->raw = NULL;
            sdns_free_context(dns_tcp_response);
            continue;
        }
        char * dmp = sdns_json_dns_string(dns_tcp_response);
        fprintf(tp->si->OUTPUT, "%s\n", dmp);
        free(dmp);
        dns_tcp_response->raw = NULL;
        sdns_free_context(dns_tcp_response);
        continue;
    }
    free(mem);
    return NULL;
}


void * read_item_from_queue(struct thread_param * tp){
    // Safe routine to read from input-queue and return the item.
    // if the queue is empty, wait until there is an entry.
    // if we receive quit_message in queue, we return NULL
    void * item = NULL;
    while (1){
        pthread_mutex_lock(&(tp->lock));
        item = cqueue_get(tp->qinput);
        pthread_mutex_unlock(&(tp->lock));
        if (item == NULL){
            // sleep 1 sec and continue
            sleep(1);
            continue;
            //fprintf(si->ERROR, "ERROR: %s\n", qinput->errmsg);
        }
        
        if (item == NULL){
            // something is wrong. we should never be here.
            fprintf(tp->si->ERROR, "We should never have NULL item in the queue!!!!!\n");
            // just quit the thread
            return NULL;
        }
        if (strcmp((char*) item, tp->quit_data) == 0){
            //fprintf(stderr, "We have received a quit message in thread#%ld\n", pthread_self());
            // or break and close them after while-loop
            return NULL;
        }
        return item;
    }
}

void * scan_receiver_routine(void * ptr){
    scan_mode_receiver_param * smrp = (scan_mode_receiver_param*) ptr;
    struct thread_param * tp = (struct thread_param*) smrp->tp;
    
    // fprintf(stderr, "receiver_thread\n");
    // each thread handle around 50 sockets for receiving data from
    // the resolver and sending data to resolver.
    // if the request needs TCP connection (truncated), we submit it to another
    // queue for TCP request. Otherwise, print out the result and continue
    
    int nfds = smrp->num_sock;
    struct pollfd * pfds;
    pfds = calloc(nfds, sizeof(struct pollfd));
    if (NULL == pfds){
        fprintf(stderr, "Can not allocate memory for polling\n");
        exit(1);
    }
    // fill the structures with socket
    for (int i=0; i< nfds; ++i){
        pfds[i].fd = smrp->sock_list[i];
        pfds[i].events = POLLIN;
        //pfds[i].events |= POLLOUT;
    }
    char * mem_send = bulkdns_malloc_or_abort(65535);
    char * mem_recv = bulkdns_malloc_or_abort(65535);


    struct sockaddr_in server;
    server.sin_port = htons(tp->si->port);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(tp->si->resolver);
    scan_mode_worker_item smwi = {.item=NULL, .udp_sock=-1, .server=server};
    void * item = NULL;
    int ready;      // result of poll() goes here

    cqueue_ctx * ready_to_send = cqueue_init(nfds);
    for (int i=0; i<nfds; ++i){
        cqueue_put(ready_to_send, (void*)(&(smrp->sock_list[i])));
    }
    int quit = 0;
    while (1){
        if (item == NULL && quit == 0){
            item = read_item_from_queue(tp);
            if (item == NULL)
                quit = 1;
        }

        if (item != NULL){
            void * sock_to_send = (cqueue_get(ready_to_send));
            if (sock_to_send != NULL){
                // we have a socket to send data to
                int sock = *((int *)sock_to_send);
                smwi.item = item;
                smwi.udp_sock = sock;
                dns_routine_scan(&smwi, tp->si, mem_send);
                //fprintf(stderr, "Sending %s to %d\n", (char*)item, sock);
                free(item);
                item = NULL;
                continue;
            }
        }
        ready = poll(pfds, nfds, tp->si->timeout * 1000);
        if (ready == -1){
            // this is an error
            perror("ERROR in poll()");
            exit(1);
        }

        if (ready == 0 ){
            // fprintf(stderr, "POLL() function timedout.....\n");
            if (quit == 1){
                break;
            }else{
                //TODO: WE NEED TO ADD ALL THE SOCKETS TO READY_TO_SEND?
                // add all the sockets to ready_to_send state
                void * dummy;
                while ((dummy = cqueue_get(ready_to_send)) != NULL);
                for (int i=0; i< nfds; ++i){
                    cqueue_put(ready_to_send, (void*)(&(smrp->sock_list[i])));
                }
                continue;
            }
        }
        //fprintf(stderr, "*********We have socket to read.....%d\n", ready);
        // this one is just for reading
        for (int j=0; j < nfds; ++j){
            if (pfds[j].revents == 0)
                continue;
            if (pfds[j].revents & POLLIN){
                // we are ready to read
                handle_read_socket(pfds[j].fd, mem_recv, tp);
                cqueue_put(ready_to_send, (void*)(&(pfds[j].fd)));
                continue;
            }else if(pfds[j].revents & POLLNVAL){
                // fprintf(stderr, "Apparently socket is closed (%d)\n", pfds[j].fd);
                continue;
            }else{
                // fprintf(stderr, "we have another event: %d\n", pfds[j].revents);
            }
            // we don't care about other cases
        }
    }
    // fprintf(stderr, "Done with the thread routine.... %d\n", num_item_received);
    free(item);
    free(mem_send);
    free(mem_recv);
    while ((item = cqueue_get(ready_to_send)) != NULL);
    cqueue_free(ready_to_send);
    // close all the sockets that are open
    for (int i=0; i<nfds; ++i){
        close(smrp->sock_list[i]);
    }   
    free(pfds);
    free(ptr);
    while (1){
        pthread_mutex_lock(&(tp->lock));
        quit = cqueue_put(tp->queue_tcp, (void*)tp->quit_data);
        pthread_mutex_unlock(&(tp->lock));
        if (quit == 0){
            break;
        }
    }
    return NULL;
}

void handle_read_socket(int sockfd, char * mem_result, struct thread_param * tp){ 
    struct sockaddr_in server;
    unsigned int from_size = 0;
    ssize_t received = recvfrom(sockfd, (void*)mem_result, 65535, 0, (struct sockaddr*)&server, &from_size);
    if (received == -1){
        perror("Error receive=-1");
        //fprintf(si->ERROR, "Error in receive function\n");
        return;
    }
    if (received == 0){
        perror("Error receive=0");
        return;
    }
    
    sdns_context * dns_udp_response = sdns_init_context();
    dns_udp_response->raw = mem_result;
    dns_udp_response->raw_len = received;
    
    int res = sdns_from_wire(dns_udp_response);
    if (res != 0){
        dns_udp_response->raw = NULL;
        sdns_free_context(dns_udp_response);
        return;
    }
    
    if (tp->si->udp_only){
        char * dmp = sdns_json_dns_string(dns_udp_response);
        fprintf(tp->si->OUTPUT, "%s\n", dmp);
        free(dmp);
        dns_udp_response->raw = NULL;
        sdns_free_context(dns_udp_response);
        return;
    }
    // we are here, it means we need to check the truncation 
    // for a possible TCP request
    if (dns_udp_response->msg->header.tc == 1){
        
        
        int res;
        char * domain = dns_udp_response->msg->question.qname == NULL?NULL:strdup(dns_udp_response->msg->question.qname);
        if (domain == NULL)
            return;
        dns_udp_response->raw = NULL;
        sdns_free_context(dns_udp_response);
        while (1){
            pthread_mutex_lock(&(tp->lock));
            res = cqueue_put(tp->queue_tcp, (void*)(domain));
            pthread_mutex_unlock(&(tp->lock));
            if (res != 0){
                sleep(1);
                continue;
            }else{
                break;
            }
        }
        return;
    }else{
        char * dmp = sdns_json_dns_string(dns_udp_response);
        fprintf(tp->si->OUTPUT, "%s\n", dmp);
        free(dmp);
        dns_udp_response->raw = NULL;
        sdns_free_context(dns_udp_response); 
        return;
    }
}

int udp_socket_send(char * tosend_buffer, size_t tosend_len, int sockfd, struct sockaddr_in server){

    ssize_t sent = 0;
    sent = sendto(sockfd, tosend_buffer, tosend_len, 0, (struct sockaddr *)&server, sizeof(server));
    if (sent == -1){  //error
        perror("error");
        fprintf(stderr, "Error in sendto()\n");
        return 4;
    }
    if (sent == 0){
        fprintf(stderr, "Can not send the data to the server\n");
        return 5;
    }
    return 0;   // success
}

void dns_routine_scan(scan_mode_worker_item * smwi, struct scanner_input * si, char * mem_result){

    char * domain_name = strdup((char*)smwi->item);
    sdns_context * dns = sdns_init_context();
    if (NULL == dns)
        return;
    int res = sdns_make_query(dns, si->rr_type, si->rr_class, domain_name, ~(si->no_edns));
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
    
    res = udp_socket_send(dns->raw, dns->raw_len, smwi->udp_sock, smwi->server);
    sdns_free_context(dns);
    return;
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
        pthread_mutex_unlock(&(tp->lock));
        if (item == NULL){
            // sleep 1 sec and continue
            sleep(1);
            continue;
            //fprintf(si->ERROR, "ERROR: %s\n", qinput->errmsg);
        }
        //cnt += 1;
        if (item == NULL){
            // something is wrong. we should never be here.
            fprintf(stderr, "We should never have NULL item in the queue!!!!!\n");
            // just quit the thread
            return NULL;
        }
        if (strcmp((char*) item, tp->quit_data) == 0){
            //fprintf(stderr, "We have received a quit message in thread#%ld\n", pthread_self());
            // let's call the lua script for the last time but pass nil instead
            // this is very usefull for the lua file to know the last call
            lua_settop (L, 0);
            lua_dns_routine_scan(NULL, si, L);
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
    if (NULL == item){
        lua_pushnil(L);
    }else{
        lua_pushstring(L, (char*)item);
    }
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

int init_udp_socket(struct scanner_input * si){

    struct timeval tv = {.tv_sec = 0, .tv_usec = 100};
    // bind the socket to a port randomly but keep it until the 
    // end of the scan. This is bad practice but I guess increase the
    // scan speed.
    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_port = 0;     // this makes the OS choose the port for us
    if (inet_pton(AF_INET, (const char *)si->bind_ip, &(local.sin_addr.s_addr)) != 1){
        fprintf(si->ERROR, "Can not convert the provided IP address\n");
        return -1;
    }
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1){
        fprintf(si->ERROR, "Error in creating socket\n");
        return -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
        fprintf(si->ERROR, "Error in setsocketopt\n");
        close(sockfd);
        return -2;
    }
    
    int enable_reuseaddr = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable_reuseaddr, sizeof(int)) < 0){
        perror("Error making socket reusable");
        close(sockfd);
        exit(1);
    }
    if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) != 0){
        close(sockfd);
        perror("Error in binding socket");
        return -3;
    }
    return sockfd;
}


int perform_lookup_udp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer,
                       size_t * toreceive_len, struct scanner_input * si, int sockfd){
    //char buffer[256] = {0x00};
    //char * error = buffer;
    struct sockaddr_in server;
    unsigned int from_size;
    server.sin_port = htons(si->port);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(si->resolver);
    
    ssize_t sent = 0;
    
    sent = sendto(sockfd, tosend_buffer, tosend_len, 0, (struct sockaddr *)&server, sizeof(server));
    if (sent == -1){  //error
        perror("error");
        fprintf(si->ERROR, "Error in sendto()\n");
        return 4;
    }
    if (sent == 0){
        fprintf(si->ERROR, "Can not send the data to the server\n");
        return 5;
    }
    
    // now let's receive the data
    ssize_t received = 0;
                                                    
    from_size = 0;
    received = recvfrom(sockfd, *toreceive_buffer, 65535, 0, (struct sockaddr*)&server, &from_size);
    if (received == -1){
        //perror("Error receive=-1");
        //fprintf(si->ERROR, "Error in receive function\n");
        return 2;
    }
    if (received == 0){
        //perror("Error receive=0");
        return 2;
    }
    
    *toreceive_len = received;
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
    
    // make sure the stack is empty before each call as we only init L one time
    lua_settop(L, 0);
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
    if (si->concurrency < 0 || si->concurrency == 0){
        fprintf(stderr, "Concurrency param must be greater than zero!\n");
        return -1;      // error
    }
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
        {.short_option=0, .long_option = "concurrency", .has_param = HAS_PARAM, .help="How many concurrent requests should we send (default is 1000)", .tag="concurrency"},
        {.short_option='p', .long_option = "port", .has_param = HAS_PARAM, .help="Resolver port number to send the query to (default 53)", .tag="port"},
        {.short_option='o', .long_option = "output", .has_param = HAS_PARAM, .help="Output file name (default is the terminal with stdout)", .tag="output"},
        {.short_option='e', .long_option = "error", .has_param = HAS_PARAM, .help="where to write the error (default is terminal with stderr)", .tag="error"},
        {.short_option='h', .long_option = "help", .has_param = NO_PARAM, .help="Print this help message", .tag="print_help"},
        {.short_option=0, .long_option = "server-mode", .has_param = NO_PARAM, .help="Run bulkDNS in server mode", .tag="server_mode"},
        {.short_option=0, .long_option= "lua-script", .has_param = HAS_PARAM, .help="Lua script to be used either for scan or server mode", .tag="lua_file"},
        {.short_option=0, .long_option="bind-ip", .has_param = HAS_PARAM, .help="IP address to bind to in server mode (default 127.0.0.1)", .tag="bind_ip"},
        {.short_option=0, .long_option="timeout", .has_param = HAS_PARAM, .help="Timeout of the socket (default is 5 seconds)", .tag="timeout"},
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
        si->timeout = 5;
    }
    si->rr_type = convert_type_to_int((char*)(arg_is_tag_set(pargs, "rr_type")?arg_get_tag_value(pargs, "rr_type"):"A"));
    si->rr_class = convert_class_to_int((char*)(arg_is_tag_set(pargs, "rr_class")?arg_get_tag_value(pargs, "rr_class"):"IN"));
    si->help = arg_is_tag_set(pargs, "print_help")?1:0;
    si->output_file = (char*)(arg_is_tag_set(pargs, "output")?arg_get_tag_value(pargs, "output"):NULL);
    si->output_error = (char*)(arg_is_tag_set(pargs, "error")?arg_get_tag_value(pargs, "error"):NULL);
    if (arg_is_tag_set(pargs, "concurrency")){
        si->concurrency = (unsigned int)atoi(arg_get_tag_value(pargs, "concurrency"));
    }else{
        si->concurrency = 1000;
    }
    si->server_mode = arg_is_tag_set(pargs, "server_mode")?1:0;
    if (arg_is_tag_set(pargs, "lua_file")){
        si->lua_file = arg_get_tag_value(pargs, "lua_file") != NULL?strdup(arg_get_tag_value(pargs, "lua_file")):NULL;
    }
    if (arg_is_tag_set(pargs, "bind_ip")){
        si->bind_ip = strdup(arg_get_tag_value(pargs, "bind_ip"));
    }else{
        if (si->server_mode == 1){
            si->bind_ip = strdup("127.0.0.1");
        }else{
            si->bind_ip = strdup("0.0.0.0");
        }
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

