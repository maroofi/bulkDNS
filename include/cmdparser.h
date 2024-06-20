#ifndef CMDPARSER_H
#define CMDPARSER_H

#define HAS_PARAM 1
#define NO_PARAM 0
#define ARG_OPTIONAL 0

#define ARG_FILE 2

// define the list of possible errors
#define ARG_ERROR_UNKNOWN 5             // when there is an unknown switch
#define ARG_MISSING_VALUE 7             // when a switch has param but is missing
#define ARG_UNKNOWN_OPTION 8            // if we have an unknown option
#define ARG_SUCCESS 0
#define ARG_FAILED 3
#define ARG_HELPME 4

// specify the end of array when the tag is null
typedef struct _ARG_CMD_OPTION{
    char short_option;          // short option like -e, -f 
    const char * long_option;   // long option in a form of --bytes=100 or --data
    short int has_param;        // has_param is 0 or 1. if the option has parameter or not
    const char * help;          // description of this option
    const char * tag;           // identifier of this option
} ARG_CMD_OPTION, *PARG_CMD_OPTION;


typedef struct _ARG_CMDLINE{
    PARG_CMD_OPTION cmd_option;
    const char * summary;
    char * extra;               ///< this can be used as a file option
    int accept_file;
} ARG_CMDLINE, *PARG_CMDLINE;


typedef struct _ARG_PARSED_ARGS{
    char * tag;
    char * val;
} ARG_PARSED_ARGS, *PARG_PARSED_ARGS;

// check if this option entered by the user or not
int arg_is_tag_set(PARG_PARSED_ARGS, const char * tag);


// free the parsed argument
void arg_free(ARG_PARSED_ARGS * parsed);


// get the value from an specific tag
const char * arg_get_tag_value(PARG_PARSED_ARGS, const char *);


/*This function is responsible for parsing the arguments
 * arguments are: pointer to the structure, argc, argv, pointer to int to receive the parsing errors*/
PARG_PARSED_ARGS arg_parse_arguments(PARG_CMDLINE, int, char **, int * error_code);

// show the help message
void arg_show_help(PARG_CMDLINE pcmd, int argc, char ** argv);

int _option_is_long_or_short(char *);
void error_to_msg(int);


#endif
