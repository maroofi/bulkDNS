#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmdparser.h>



static PARG_PARSED_ARGS realloc_memory(PARG_PARSED_ARGS parsed, const char * tag, const char * val);


// return value: 0: not set, 1: set
int arg_is_tag_set(PARG_PARSED_ARGS pa, const char * tag){
    PARG_PARSED_ARGS tmp = pa;
    while(tmp->tag != NULL){
        if (strcmp(tag, tmp->tag) == 0){
            return 1;
        }
        tmp++;
    }
    return 0;
}

const char * arg_get_tag_value(PARG_PARSED_ARGS pa, const char * tag){
    if (pa == NULL){
        return NULL;
    }
    while (pa->tag != NULL){        // last member of ARG_PARSED_ARGS is always null
        if (0 == strcmp(pa->tag, tag)){
            return pa->val;
        }
        pa++;
    }
    return NULL;
}



static int is_valid_long_without_param(PARG_CMDLINE pcmd, char * arg){
    PARG_CMD_OPTION opt = pcmd->cmd_option;
    int j = 0;
    while(opt[j].tag){
        if (strcmp(&(arg[2]), opt[j].long_option) == 0)
            if (opt[j].has_param == 0)
                return 1;
        j++;
    }
    return 0;
}

static int is_valid_long_with_param(PARG_CMDLINE pcmd, char * arg){
    PARG_CMD_OPTION opt = pcmd->cmd_option;
    int j=0;
    while(opt[j].tag){
        if (strcmp(&(arg[2]), opt[j].long_option) == 0)
                if (opt[j].has_param == 1)
                    return 1;
        j++;
    }
    return 0;
}


static int does_short_opt_exists(PARG_CMDLINE pcmd, char shrt){
    PARG_CMD_OPTION opt = pcmd->cmd_option;
    int j=0;
    while(opt[j].tag){
        if (shrt == opt[j].short_option)
            return 1;
        j++;
    }
    return 0;
}

static const char * get_tag_from_short(PARG_CMDLINE pcmd, char short_opt){
    PARG_CMD_OPTION opt = pcmd->cmd_option;
    int j = 0;
    while (opt[j].tag){
        if (opt[j].short_option == short_opt)
            return opt[j].tag;
        j++;
    }
    return NULL;
}

static const char * get_tag_from_long_option(PARG_CMDLINE pcmd, char * lng){
    PARG_CMD_OPTION opt = pcmd->cmd_option;
    int j = 0;
    while (opt[j].tag){
        if (strcmp(opt[j].long_option, lng) == 0)
            return opt[j].tag;
        j++;
    }
    return NULL;
}

static int does_short_has_param(PARG_CMDLINE pcmd, char short_opt){
    PARG_CMD_OPTION opt = pcmd->cmd_option;
    int j = 0;
    while (opt[j].tag){
        if (opt[j].short_option == short_opt)
            if (opt[j].has_param == 1)
                return 1;
        j++;
    }
    return 0;
}



/* long options always start with --
* short options always start with -
* long options have the syntax --long=value or --long
* short options have the syntax -s or -s 23
* mandatory options must always present (either in short or long format)
* mandatory options with param (has_param = 1) must always have value 
* finally, if we have --help or -h, just show the help and exit
* */
PARG_PARSED_ARGS arg_parse_arguments(PARG_CMDLINE pcmd, int argc, char ** argv, int * parse_error){
    pcmd->extra = NULL;
    PARG_PARSED_ARGS parsed = NULL;
    if (argc == 1){
        // we have nothing to parse but there is no error
        parsed = malloc(sizeof(ARG_PARSED_ARGS));
        parsed->tag = NULL;
        parsed->val = NULL;
        return parsed;
    }
    int  value_expected = 0;
    // do we have atleast one mandatory option?
    int j = 0;
    char * prev_tag = NULL;
    char tmp_mem[200] = {0};
    j = 1;   // start iterating over args
    while (j < argc){
        char * arg = argv[j];
        if (arg[0] == '-'){
            if (value_expected){
                value_expected = 0;
                // expect value here
                // consider this param as a value of previous found option
                // then continue
                parsed = realloc_memory(parsed, prev_tag, arg);
                prev_tag = NULL;
                j++;
                continue;
            }else{
                // expect options
                // this is an option (short or long?)
                if (strlen(arg) <= 1){
                    *parse_error = ARG_MISSING_VALUE;
                    return NULL;
                }
                if (arg[1] == '-'){
                    // long option
                    char * sign_pos = strchr(arg, '=');
                    if (NULL == sign_pos){
                        // there is no sign then either an error
                        // or this is long option without param
                        if (!is_valid_long_without_param(pcmd, arg)){
                            // either missing value or wrong param
                            *parse_error = ARG_MISSING_VALUE;
                            return NULL;
                        }else{
                            value_expected = 0;   // we don't expect value
                            // we have one long option, make the node
                            parsed = realloc_memory(parsed, get_tag_from_long_option(pcmd, &(arg[2])), NULL);
                            j++;
                            continue;
                        }
                    }else{
                        // there is a sign: it must be long with param
                        strncpy(tmp_mem, arg, sign_pos - arg);
                        tmp_mem[sign_pos - arg] = '\0';
                        if (is_valid_long_with_param(pcmd, tmp_mem)){
                            if (strlen(sign_pos+1) == 0){
                                // empty value!
                                *parse_error = ARG_MISSING_VALUE;
                                return NULL;
                            }
                            strncpy(tmp_mem, arg + 2, sign_pos - arg - 2);
                            tmp_mem[sign_pos - arg - 2] = '\0';
                            prev_tag = (char*)get_tag_from_long_option(pcmd, tmp_mem);
                            parsed = realloc_memory(parsed, prev_tag, sign_pos+1);
                            memset(tmp_mem, 0, 200);
                            value_expected = 0;
                            prev_tag = NULL;
                            j++;
                            continue;
                        }else{
                            *parse_error = ARG_MISSING_VALUE;
                            return NULL;
                        }
                    }
                }else{
                    // short option
                    char short_opt = arg[1];
                    if (!does_short_opt_exists(pcmd, short_opt)){
                        // short option does not exists
                        *parse_error = ARG_UNKNOWN_OPTION;
                        return NULL;
                    }
                    if (does_short_has_param(pcmd, short_opt)){
                        value_expected = 1;
                        prev_tag = (char*)get_tag_from_short(pcmd, short_opt);
                        j++;
                        continue;
                    }
                    // short option has no param, create memory for it
                    prev_tag = (char*)get_tag_from_short(pcmd, short_opt);
                    parsed = realloc_memory(parsed, prev_tag, NULL);
                    prev_tag = NULL;
                    value_expected = 0;
                    j++;
                    continue;
                }
            }
        }else{
            // either extra option or value
            if (value_expected){
                value_expected = 0;
                // value expected
                parsed = realloc_memory(parsed, prev_tag, arg);
                prev_tag = NULL;
                j++;
                continue;
            }else{  // extra option
                if (pcmd->extra){       // we can only have one extra as a file input
                    *parse_error = ARG_UNKNOWN_OPTION;
                    return NULL;
                }else{
                    pcmd->extra = arg;
                    j++;
                    continue;
                }
            }
        }
    }
    if (parsed == NULL && pcmd->extra != NULL){
        // this must not be treated as parsed = NULL as
        // something passed to the cmd line and it's in extra
        // now!
        parsed = malloc(sizeof(ARG_PARSED_ARGS));
        parsed->tag = NULL;
        parsed->val = NULL;
        return parsed;
    }
    return parsed;
}

static PARG_PARSED_ARGS realloc_memory(PARG_PARSED_ARGS parsed, const char * tag, const char * val){
    // prone to segfault as I don't check the return value of malloc and realloc!!
    PARG_PARSED_ARGS tmp = parsed;
    if (parsed == NULL){
        //allocate a new memory and return it
        //one for new data and one for NULL
        parsed = (PARG_PARSED_ARGS)malloc(sizeof(ARG_PARSED_ARGS) * 2);
        parsed[0].tag = strdup(tag);
        parsed[0].val = val == NULL?NULL:strdup(val);
        parsed[1].tag = NULL;
        parsed[1].val = NULL;
        return parsed;
    }else{
        int row_count = 1;
        tmp = parsed;
        while(tmp->tag != NULL){
            row_count++;
            tmp++;
        }
        // we need to allocate one more

        row_count += 1; // one for null
        parsed = (PARG_PARSED_ARGS)realloc(parsed, row_count * sizeof(ARG_PARSED_ARGS));
        (parsed+row_count-1)->tag = NULL;
        (parsed+row_count-1)->val = NULL;
        (parsed+row_count-2)->tag = strdup(tag);
        (parsed+row_count-2)->val = val == NULL?NULL:strdup(val);
        return parsed;
    }
    return parsed;
}

void arg_free(ARG_PARSED_ARGS * parsed){
    if (parsed == NULL)
        return;
    PARG_PARSED_ARGS tmp = parsed;
    int j=0;
    while (tmp[j].tag != NULL){
        free(tmp[j].tag);
        free(tmp[j].val);
        j++;
    }
    free(parsed);
}

void arg_show_help(PARG_CMDLINE cmd, int argc, char ** argv){
    fprintf(stdout, "[Help]\n\n");   
    fprintf(stdout, "Summary:\n");
    fprintf(stdout, "%s", cmd->summary);
    fprintf(stdout, "\n\n");
    fprintf(stdout, "%s [OPTIONS] ", argv[0]);
    fprintf(stdout, "%s\t", cmd->accept_file?"<INPUT|FILE>":"");
    fprintf(stdout, "\n\n");

    fprintf(stdout, "\t-t <param>, --type=<param>\t\t");
    fprintf(stdout, "Resource Record type (Default is 'A')\n");

    fprintf(stdout, "\t-c <param>, --class=<param>\t\t");
    fprintf(stdout, "RR Class (IN, CH). Default is 'IN'\n");

    fprintf(stdout, "\t-r <param>, --resolver=<param>\t\t");
    fprintf(stdout, "Resolver IP address to send the query to (default 1.1.1.1)\n");

    fprintf(stdout, "\t-p <param>, --port=<param>\t\t");
    fprintf(stdout, "Resolver port number to send the query to (default 53)\n");

    fprintf(stdout, "\t-e <param>, --error=<param>\t\t");
    fprintf(stdout, "where to write the error (default is terminal with stderr)\n");

    fprintf(stdout, "\t-o <param>, --output=<param>\t\t");
    fprintf(stdout, "Output file name (default is the terminal with stdout)\n");

    fprintf(stdout, "\t--lua-script=<param>\t\t\t");
    fprintf(stdout, "Lua script to be used either for scan or server mode\n");

    fprintf(stdout, "\t--bind-ip=<param>\t\t\t");
    fprintf(stdout, "IP address to bind (default 127.0.0.1 for scan mode, 0.0.0.0 for server-mode)\n");

    fprintf(stdout, "\t--timeout=<param>\t\t\t");
    fprintf(stdout, "Timeout of the socket (default is 5 seconds)\n");

    fprintf(stdout, "\t--concurrency=<param>\t\t\t");
    fprintf(stdout, "How many concurrent requests should we send (default is 1000)\n");

    fprintf(stdout, "\t--udp-only\t\t\t\t");
    fprintf(stdout, "Only query using UDP connection (Default will follow TCP)\n");

    fprintf(stdout, "\t--set-do\t\t\t\t");
    fprintf(stdout, "Set DNSSEC OK (DO) bit in queries (default is no DO)\n");

    fprintf(stdout, "\t--set-nsid\t\t\t\t");
    fprintf(stdout, "The packet has NSID in edns0\n");

    fprintf(stdout, "\t--noedns\t\t\t\t");
    fprintf(stdout, "Do not support EDNS0 in queries (Default supports EDNS0)\n");

    fprintf(stdout, "\t--server-mode\t\t\t\t");
    fprintf(stdout, "Run bulkDNS in server mode\n");

    fprintf(stdout, "\t--no-tcp\t\t\t\t");
    fprintf(stdout, "Run the server-mode only for UDP (No TCP listening)\n");

    fprintf(stdout, "\t-h, --help\t\t\t\t");
    fprintf(stdout, "Print this help message\n");

    fprintf(stdout, "\nbulkDNS currently supports the following RRs:\n");
    fprintf(stdout, "\tA, AAAA, NS, RRSIG, SOA, MX, SRV, URI, PTR,\n");
    fprintf(stdout, "\tHINFO, TXT, CNAME, NID, L32, L64, LP, CAA\n");
    fprintf(stdout, "Supported DNS classes: IN, CH\n\n\n");
    fprintf(stdout, "Please report bugs to:\n");
    fprintf(stdout, "\thttps://github.com/maroofi/bulkDNS\n\n");
}

