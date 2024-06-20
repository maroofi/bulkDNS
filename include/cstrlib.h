/** @file */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>


#ifndef STRLIB_H
#define STRLIB_H


#define ERROR_OK 0                          ///< No error
#define ERROR_SUBSTRING_IS_NULL 1           ///< Empty substring passed to the function
#define ERROR_CAN_NOT_ALLOCATE_MEMORY 2     ///< Malloc/realloc can not allocate memory
#define ERROR_EMPTY_DELIMITER 3             ///< Empty delimiter passed to the function


typedef struct _SPLITLIST SPLITLIST, *PSPLITLIST;

/**
 * @details This structure is used for the #str_split() function.
 * 
 * When we split a string with #str_split(), the return value is a pointer
 * to this structure. 
 */
struct _SPLITLIST{
    char ** list;               ///< an array of pointers each points to one part of the split
    unsigned int len;           ///< length of the list array
};



/**
* @details Type definition of the struct _STR
* 
* STR: structure of type _STR
* 
* PSTR: Pointer to the structure of type _STR
* 
*/
typedef struct _STR STR, *PSTR;

/**
 * @details This structure simulates Python str class.
 * 
 * Different function defined in this structure to emulate the functionality 
 * of the Python str class. We don't directly use this structure but instead, 
 * we use str_init() and str_free() to initialize and destroy the #STR structure.
 */
struct _STR{
    char * st_memory;                   ///< keeps the start of the allocated memory (for internal use)
    char * str;                         ///< pointer to char *, pointed to the string
    size_t len;                         ///< length of the string pointed by str
    int err;                            ///< possible error code set after string operations
    char * errmsg;                      ///< custom error message set after string operations
    size_t (*str_len)(PSTR);            ///< pointer to the cstrlib.str_len() function
    int (*str_count)(PSTR, const char *);                   ///< pointer to the str_count() function
    int (*str_find)(PSTR, const char *);                    ///< pointer to the str_find() function
    int (*str_startswith)(PSTR, const char *);              ///< pointer to the str_startswith() function
    int (*str_endswith)(PSTR, const char *);                ///< pointer to the str_endswith() function
    char * (*str_lstrip)(PSTR, const char *);               ///< pointer to the str_lstrip() function
    char * (*str_rstrip)(PSTR, const char *);               ///< pointer to the str_rstrip() function 
    char * (*str_strip)(PSTR, const char *);                ///< pointer to the str_strip() function
    char * (*str_reverse)(PSTR);                            ///< pointer to the str_reverse() function
    char * (*str_upper)(PSTR);                              ///< pointer to the str_upper() function
    char * (*str_lower)(PSTR);                              ///< pointer to the str_lower() function
    const char * (*str_getval)(PSTR);                       ///< pointer to the str_getval() function
    int (*str_setval)(PSTR, const char *);                  ///< pointer to the str_setval() function
    char * (*str_swapcase)(PSTR);                           ///< pointer to the str_swapcase() function
    int (*str_isdigit)(PSTR);                               ///< pointer to the str_isdigit() function
    int (*str_append_char)(PSTR, int);                      ///< Pointer to the str_append_char() function
    int (*str_append_string)(PSTR, char *);                 ///< Pointer to the str_append_string() function
    int (*str_prepend_char)(PSTR, int);                      ///< Pointer to the str_prepend_char() function
    int (*str_prepend_string)(PSTR, char *);                 ///< Pointer to the str_prepend_string() function
    char * (*str_copy)(PSTR);                               ///< pointer to the str_copy() function
    char * (*str_replace)(PSTR, const char *, const char *, int);    ///< pointer to the str_replace() function
    int (*str_join)(PSTR, PSPLITLIST, char*);                        ///< Pointer to the str_join() function
    PSPLITLIST (*str_split)(PSTR, char *, int);                      ///< Pointer to the str_split() function
    int (*str_any_of_in)(PSTR, const char *);                             ///< Pointer to the str_any_of_in() function
    
};


size_t str_len(PSTR);       ///< see the definition of str_len()
PSTR str_init(const char *);
int str_any_of_in(PSTR, const char *);
int str_count(PSTR, const char *);
int str_find(PSTR, const char *);
int str_startswith(PSTR, const char *);
int str_endswith(PSTR, const char *);
char * str_lstrip(PSTR, const char *);
char * str_rstrip(PSTR, const char *);
char * str_strip(PSTR, const char *);
char * str_reverse(PSTR);
char * str_upper(PSTR);
char * str_lower(PSTR);
const char * str_getval(PSTR);
int str_setval(PSTR, const char *);
char * str_swapcase(PSTR pstr);
int str_isdigit(PSTR);
void str_free(PSTR);
char * str_replace(PSTR, const char *, const char *, int);
char * str_copy(PSTR);
int str_append_string(PSTR, char *);
int str_append_char(PSTR, int);

int str_prepend_string(PSTR, char *);
int str_prepend_char(PSTR, int);

PSPLITLIST str_split(PSTR, char *, int);
void str_free_splitlist(PSPLITLIST);
int str_join(PSTR pstr, PSPLITLIST splt, char * join_str);
#endif
