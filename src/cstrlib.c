#include <cstrlib.h>

/// @file cstrlib.c

/**
 * @brief Returns the length of the string
 * @param pstr Pointer to the STR structure
 * @return size_t length of the string pointed by pstr
 */
size_t str_len(PSTR pstr){
    return pstr->len;
}

/**
 * @brief Initialize the STR structure with the given string
 * 
 * This must be the first method to be called in order to use other functions.
 * @param val initial string of type char * or NULL
 * @return A pointer to STR structure on success or NULL if fails
 */
PSTR str_init(const char * val){
    PSTR pstr = (PSTR) malloc(sizeof(STR));
    if (NULL == pstr){
        return NULL;
    }
    pstr->err = 0;      // no error
    pstr->errmsg = (char*)malloc(sizeof(char) * 0xFF);
    if (NULL == pstr->errmsg){
        memset(pstr->errmsg, '\0', 0xFF);
    }
    size_t len;
    if (NULL == val){
        pstr->str = NULL;
        pstr->len = 0;
        pstr->st_memory = NULL;
    }else{
        len = strlen(val);
        pstr->len = len;
        pstr->str = (char *) malloc((len * sizeof(char)) + 1);
        if (NULL == pstr->str){
            return NULL;
        }else{
            pstr->st_memory = pstr->str;
            memcpy(pstr->str, val, len);
            pstr->str[len] = '\0';
        }
    }
    pstr->str_count = str_count;
    pstr->str_len = str_len;
    pstr->str_getval = str_getval;
    pstr->str_setval = str_setval;
    pstr->str_find = str_find;
    pstr->str_startswith = str_startswith;
    pstr->str_endswith = str_endswith;
    pstr->str_reverse = str_reverse;
    pstr->str_lstrip = str_lstrip;
    pstr->str_rstrip = str_rstrip;
    pstr->str_strip = str_strip;
    pstr->str_isdigit = str_isdigit;
    pstr->str_upper = str_upper;
    pstr->str_lower = str_lower;
    pstr->str_swapcase = str_swapcase;
    pstr->str_replace = str_replace;
    pstr->str_copy = str_copy;
    pstr->str_split = str_split;
    pstr->str_append_char = str_append_char;
    pstr->str_append_string = str_append_string;
    pstr->str_prepend_char = str_prepend_char;
    pstr->str_prepend_string = str_prepend_string;
    pstr->str_join = str_join;
    pstr->str_any_of_in = str_any_of_in;
    //TODO: DO IT FOR THE REST
    return pstr;
}

/**
 * @brief Frees the allocated memory for STR structure.
 * 
 * This must be the last function to call to free the allocated memory
 * for the STR structure. It's important to call this function if you don't 
 * use the variable anymore since all the memories allocated by malloc function,
 * they won't be free just by leaving the function.
 * 
 * @param pstr Pointer to the STR structure created by str_init()
 * @return There is no meaningful return value for this function
 */
void str_free(PSTR pstr){
    if (NULL == pstr)
        return;
    if (NULL != pstr->errmsg){
        free(pstr->errmsg);
    }
    if (NULL != pstr->str)
        free(pstr->st_memory);
    free(pstr);
    return;
}

/**
 * @brief checks if any of characters is in the string
 * @param pstr Pointer to the STR structure returned by str_init()
 * @param characters A null-terminated string consisting of the characters to check
 * @return 1 if any of characters is in string else 0
 */
int str_any_of_in(PSTR pstr, const char * characters){
    if (characters == NULL)
        return 0;
    unsigned long int charlen = strlen(characters);
    if (charlen == 0 || !pstr || pstr->len == 0)
        return 0;
    for (unsigned long int i=0; i<charlen; ++i){
        for (unsigned long int j=0; j< pstr->len; ++j){
            if (characters[i] == pstr->str[j])
                return 1;
        }
    }
    return 0;
}



/**
 * @brief Replaces the oldval by newval and return a new string
 * @param pstr Pointer to the STR structure returned by str_init()
 * @param oldval The old substring to work on
 * @param newval The new substring to replce
 * @param count The number of replacement (-1 means all occurrence must be replaced)
 * @return char * on success or NULL if fails.
 *
 * **User is responsible to free the 
 *  memory allocated for the return value (allocated by malloc)**.
 *
 * The behaviour of this function is the same as _python3_ replace() function.
 */
char * str_replace(PSTR pstr, const char * oldval, const char * newval, int count){
    if (pstr == NULL)
        return NULL;
    if (NULL == oldval){
        pstr->err = ERROR_SUBSTRING_IS_NULL;
        strcpy(pstr->errmsg, "oldval of str_replace can not be NULL");
        return NULL;
    }
    if (NULL == newval){
        pstr->err = ERROR_SUBSTRING_IS_NULL;
        strcpy(pstr->errmsg, "newval of str_replace can not be NULL");
        return NULL;
    }
#ifdef DEBUG
    printf("We passed the initial checks...\n");
#endif
    size_t new_val_len = strlen(newval);
    size_t old_val_len = strlen(oldval);
    if (pstr->len == 0 && old_val_len == 0){
        // return newval
        char * new_str = (char *) malloc(sizeof(char) * new_val_len + 1);
        if (NULL == new_str){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            return NULL;
        }
        memcpy(new_str, newval, new_val_len);
        new_str[new_val_len] = '\0';
        return new_str;
    }
    if (old_val_len == 0 && new_val_len == 0){
        //return the original string
        return str_copy(pstr);
    }
    if (old_val_len == 0){
        // copy newval before and after of each char in original string
        size_t new_size = (pstr->len) + 1;
        if (count == -1){
            new_size += (pstr->len -1 + 2) * new_val_len;
        }else{
            if (count <= pstr->len -1 + 2){
                new_size += count * new_val_len;
            }else{
                new_size += (pstr->len -1 + 2) * new_val_len;
            }
        }
        char * new_str = (char *) malloc(sizeof(char) * new_size);
        if (NULL == new_str){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            return NULL;
        }
        memset(new_str, 0, new_size);
        int cnt = 0;
        if (count != 0){
            memcpy(new_str, newval, new_val_len);
            cnt++;
        }else{
            memcpy(new_str, pstr->str, pstr->len);
        }
        if (count == 0){
            return new_str;
        }
        unsigned int j = new_val_len;
        char * tmp = (char *)newval;
        for (unsigned int i=0;i<pstr->len; ++i){
            tmp = (char*)newval;
            new_str[j++] = pstr->str[i];
            if (cnt++ != count && count != 0){
                while(*tmp != '\0'){
                    new_str[j++] = *tmp;
                    ++tmp;
                }
            }else{
                cnt--;
            }
        }
        return new_str;
    }
    if (count == 0){
        // return the original string no matter what
        char * new_str = (char *) malloc(pstr->len * sizeof(char) + 1);
        if (NULL == new_str){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            return NULL;
        }
        return pstr->str_copy(pstr);
    }

    int start = 0;
    int replace_count = 0;
    size_t oldval_len = old_val_len;
    size_t newval_len = new_val_len;
    char * new_pos = NULL;
    while (1){
        new_pos = strstr(pstr->str + start, oldval);
        if (new_pos != NULL){
            // we have a match
            replace_count++;
            start = (int)(new_pos - pstr->str) + oldval_len;
        }else{
            break;
        }
    } // end-loop

    if (replace_count == 0){
        return pstr->str_copy(pstr);
    }
    size_t new_len;
    if (count == -1){
        new_len = (sizeof(char) * ((pstr->len) - (replace_count * oldval_len) + (replace_count*newval_len))) + 1;
    }else{
        new_len = (sizeof(char) * ((pstr->len) - ((replace_count > count?count:replace_count) * oldval_len) + ((replace_count>count?count:replace_count)*newval_len))) + 1;
    }
    char * tmp = (char *)malloc(new_len);
    if (NULL == tmp){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    memset(tmp, 0xFF, new_len);
    tmp[new_len-1] = '\0';
    start = 0;
    memcpy(tmp, pstr->str, pstr->len);
    PSTR newpstr = str_init(pstr->str);
    unsigned int cnt = 0;
    new_pos = NULL;
    while(cnt++ != count){
        new_pos = strstr(newpstr->str + start, oldval);
        if (new_pos !=  NULL){
            start = new_pos - newpstr->str;
            memcpy(tmp+start, newval, newval_len);
            memcpy(tmp+start+newval_len, pstr->str + start + oldval_len, pstr->len - (start + oldval_len));
            newpstr->str_setval(newpstr, tmp);
        }else{
            break;
        }
    }
    char * return_me = (char *)malloc(sizeof(char) * newpstr->len + 1);
    if (NULL == return_me){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    memcpy(return_me, newpstr->str, newpstr->len);
    return_me[newpstr->len] = '\0';
    str_free(newpstr);
    free(tmp);
    return return_me;
}

/**
 * @brief Clones the string inside the STR structure
 * @param pstr Pointer to the STR structure returned by str_init()
 *
 * Users are responsible to free the memory after using.
 *
 * This method is the same as str_getval(), but the difference is that str_getval() won't copy 
 * the string but just returns the pointer to the string while this method return
 * a pointer to the newly allocated memory for the string.
 *
 * The method is equivalent of strdup() function.
 *
 * @return a copy of the string inside the STR structure (by malloc).
 */
char * str_copy(PSTR pstr){
    if (NULL == pstr)
        return NULL;
    char * tmp = (char *) malloc(sizeof(char) * pstr->len + 1);
    if (tmp == NULL){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    memcpy(tmp, pstr->str, pstr->len);
    tmp[pstr->len] = '\0';
    return tmp;
}


/**
 * @brief Return the number of non-overlapping occurrences of substring sub
 * @param pstr Pointer to the STR structure
 * @param sub substring to count
 * @return returns an integer greater or equal to zero
 */
int str_count(PSTR pstr, const char * sub){
    if (NULL == sub){
        strcpy(pstr->errmsg, "ERR:sub can not be null");
        pstr->err = ERROR_SUBSTRING_IS_NULL;
        return 0;
    }
    if (strcmp(sub, "") == 0){
        return strlen(pstr->str) + 1;
    }
    pstr->err = ERROR_OK;
    unsigned int count = 0;
    char * pos = NULL;
    char * tmp = pstr->str;
    while ((pos = strstr((const char *)tmp, (const char*)sub)) != NULL){
        ++count;
        tmp = pos + strlen(sub);
    }
    return count;
}

/**
 * @brief Return the lowest index in the string where substring sub is found
 * @param pstr Pointer to the STR structure
 * @param sub substring to search for
 * @return index of the substring (>= 0) or -1 if sub is not found.
 */
int str_find(PSTR pstr, const char * sub){
    if (NULL == sub){
        pstr->err = ERROR_SUBSTRING_IS_NULL;
        strcpy(pstr->errmsg, "ERR:sub can not be NULL!");
        return 0;
    }
    if (0 == strcmp(sub, "")){
        return 0;
    }
    pstr->err = ERROR_OK;
    char * s = strstr((pstr->str), sub);
    if (NULL == s)
        return -1;
    else
        return s - pstr->str;
}

/**
 * @brief Free the memory allocated for #SPLITLIST structure returned by str_split()
 * @param plst
 */
void str_free_splitlist(PSPLITLIST plst){
    if (plst == NULL)
        return;
    if (plst->len == 0){
        free(plst);
        return;
    }
    for (unsigned int i=0;i< plst->len; i++){
        if (plst->list[i] != NULL){
            free(*((plst->list) + i));
        }
    }
    
    free(plst->list);
    free(plst);
    return;
}

/**
 * @brief Return a list of the words in the string, using sep as the delimiter string.
 * @param pstr pointer to the STR structure returned by str_init()
 * @param delimiter The delimiter according which to split the string.
 * @param maxsplit Maximum number of splits to do (-1 means no limit)
 * @return either NULL in failure or a pointer to #SPLITLIST structure. User
 * is responsible to free the returned structure.
 */
PSPLITLIST str_split(PSTR pstr, char * delimiter, int maxsplit){
    PSPLITLIST plst = (PSPLITLIST)malloc(sizeof(SPLITLIST));
    plst->list = NULL;
    if (NULL == plst){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    if (pstr->len == 0){
        char * tmp = (char*) malloc(sizeof(char));
        *tmp = '\0';
        plst->len = 1;
        plst->list = (char **) malloc(1 * sizeof(char*));
        if (plst->list == NULL){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            str_free_splitlist(plst);
            free(tmp);
            return NULL;
        }
        plst->list[0] = tmp;
        return plst;
    }
    // if delimiter is null, return the string itself
    if (delimiter == NULL){
        char * tmp = pstr->str_copy(pstr);
        plst->len = 1;
        plst->list = (char **) malloc(1 * sizeof(char*));
        if (plst->list == NULL){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            free(tmp);
            str_free_splitlist(plst);
            return NULL;
        }
        plst->list[0] = tmp;
        return plst;
    }
    unsigned int delim_len = strlen(delimiter);
    //if len(delimiter) == 0 -> error empty delimiter
#ifdef DEBUG
    printf("Len of delimiter is: %d\n", delim_len);
#endif
    if (delim_len == 0){
        pstr->err = ERROR_EMPTY_DELIMITER;
        strcpy(pstr->errmsg, "ERR: empyty delimiter is not allowed!");
        str_free_splitlist(plst);
        return NULL;
    }
    int cnt = 0;
    int start = 0;
    char * tmp = NULL;
    if (maxsplit == 0){
        // we just return the string itself
        char * tmp = pstr->str_copy(pstr);
        plst->len = 1;
        plst->list = (char **) malloc(1 * sizeof(char*));
        if (plst->list == NULL){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            free(tmp);
            str_free_splitlist(plst);
            return NULL;
        }
        plst->list[0] = tmp;
        return plst;
    }
    while((tmp = strstr(pstr->str + start, delimiter)) != NULL){
        start = tmp - pstr->str;
        start += delim_len;
        cnt++;
        if (cnt == maxsplit)
            break;
    }
    if (cnt == 0){
        //return the whole string again
        plst->len = 1;
        char * tmp = pstr->str_copy(pstr);
        plst->list = (char **) malloc(1 * sizeof(char*));
        if (plst->list == NULL){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            free(tmp);
            str_free_splitlist(plst);
            return NULL;
        }
        plst->list[0] = tmp;
        return plst;
    }
    // array len is cnt+1
    plst->len = cnt + 1;
    plst->list = (char **)malloc((cnt+1) * sizeof(char *));
    if (plst->list == NULL){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        str_free_splitlist(plst);
        return NULL;
    }
    start = 0;
    cnt = 0;
    int i = 0;
    char * tmp_pos = NULL;
    tmp = NULL;
    while((tmp_pos = strstr(pstr->str + start, delimiter)) != NULL){
        start = tmp_pos - pstr->str;
        tmp = (char *)malloc((start - cnt +1) *sizeof(char));
        plst->list[i] = tmp;
        strncpy(tmp, (pstr->str + (cnt)), start - cnt);
        tmp[start - cnt] = '\0';
        start += delim_len;
        cnt = start;
        i++;
        if (i == maxsplit)
            break;
    }
    tmp = (char *)malloc((pstr->len - cnt + 2) *sizeof(char));
    tmp[pstr->len -cnt + 1] = '\0';
    strncpy(tmp, (pstr->str + (cnt)), pstr->len - cnt + 1);
    plst->list[i] = tmp;
    return plst;
}



/**
 * @brief Returns 0 (#ERROR_OK) if pstr starts with prefix otherwise 1
 * @param pstr Pointer to the STR structure
 * @param prefix substring to search for
 * @return 1 on success and 0 if fails
 */
int str_startswith(PSTR pstr, const char * prefix){
    // return 1 (true) if starts with 'seq' or 0 (false) otherwise
    if (NULL == prefix){
        pstr->err = ERROR_SUBSTRING_IS_NULL;
        strcpy(pstr->errmsg, "ERR:sub can not be NULL!");
        return 0;
    }
    if (strcmp(prefix, "") == 0){
        return 1;
    }
    if (strncmp(prefix, pstr->str, strlen(prefix)) == 0)
        return 1;
    return 0;
}

/**
 * @brief Returns 0 (#ERROR_OK) if pstr ends with suffix else 1
 * @param pstr pointer to the STR structure
 * @param seq substring to search for 
 * @return 1 on success and 0 if fails
 */
int str_endswith(PSTR pstr, const char * suffix){
    // return 1 (true) if ends with 'suffix' or 0 (false) otherwise
    if (NULL == suffix){
        pstr->err = ERROR_SUBSTRING_IS_NULL;
        strcpy(pstr->errmsg, "ERR:sub can not be NULL!");
        return 1;
    }
    if (strcmp(suffix, "") == 0){
        return 1;
    }
    size_t len = strlen(suffix);
    if (strncmp(suffix, (pstr->str) + pstr->len - len , len) == 0)
        return 1;
    return 0;
}


/**
 * @brief Return a copy of the string with leading and trailing characters removed (Read Python doc for more info).
 * @param pstr pointer to the STR structure returned by str_init()
 * @param seq const char * (list of characters to remove)
 *
 * The default whitespace characters are space (0x20), tab (\\t), new line (\\n),
 * carriage return (\\r), 0x0b and 0x0c
 * @return a pointer to a new char array (Users are responsible to free it)
 */
char * str_strip(PSTR pstr, const char * seq){
    //  if seq == NULL, remove all the whitespace chars: ' \t\n\r\x0b\x0c'
    PSTR new_str = str_init(pstr->str);
    char * lstrip = str_lstrip(new_str, seq);
#ifdef DEBUG
    printf("Value we get from lstrip: '%s'\n", lstrip);
#endif
    str_setval(new_str, lstrip);
    free(lstrip);
#ifdef DEBUG
    printf("The new string set is: '%s'\n", new_str->str);
#endif
    char * final_string = str_rstrip(new_str, seq);
#ifdef DEBUG
    printf("Value we get from rstrip: '%s'\n", final_string);
#endif
    str_free(new_str);
    return final_string;
}


/**
 * @brief Return a copy of the string with leading characters removed (Read Python doc for more info).
 * @param pstr pointer to the STR structure
 * @param seq const char * (list of characters to remove)
 *
 * default whitespace characters are the same as str_strip() function.
 *
 * @return a pointer to a new char array (Users are responsible to free it)
 */
char * str_lstrip(PSTR pstr, const char * seq){
    if (pstr->len == 0){
        char * new_str = (char *) malloc(sizeof(char));
        new_str[0] = '\0';
        return new_str;
    }
    // if seq == NULL, remove all the whitespace chars: ' \t\n\r\x0b\x0c'
    char * tmp_seq = (char *) seq;
    if (NULL == tmp_seq){
        tmp_seq = (char *)malloc(sizeof(char) * 7); // 7 is the num of white chars
        if (NULL == tmp_seq){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            return NULL;
        }
        strcpy(tmp_seq, " \t\n\r\x0b\x0c");
        tmp_seq[6] = '\0';
    }
    
    unsigned int i = 0;
    const char * tmp = pstr->str;
    char ch;
    unsigned int found = 0;
    while (*tmp != '\0'){
        while((ch = tmp_seq[i++]) != '\0'){
            if (ch == *tmp){
                tmp += 1;
                i = 0;
                found = 1;
                break;
            }
            found = 0;
        }
        if (!found)
            break;
    }
    //now tmp is the pointer to the new string
    char * new_str = (char *)malloc(sizeof(char) * strlen(tmp) + 1);
    if (NULL == new_str){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    strcpy(new_str, tmp);
    // free tmp_seq before leaving
    if (NULL == seq){
        free(tmp_seq);
    }
    return new_str;
}

/**
 * @brief Returns a copy of the string with trailing characters removed (Read Python doc for more info)
 * 
 * @param pstr pointer to the STR structure
 * @param seq const char * (list of characters to remove)
 *
 * Default whitespace characters are the same as str_strip() function
 *
 * @return A pointer to a new char array (Users are responsible to free the pointer)
 */
char * str_rstrip(PSTR pstr, const char * seq){
    if (pstr->len == 0){
        char * new_str = (char *) malloc(sizeof(char));
        new_str[0] = '\0';
        return new_str;
    }
    // if seq == NULL, remove all the whitespace chars: ' \t\n\r\x0b\x0c'
    char * tmp_seq = (char *) seq;
    if (NULL == tmp_seq){
        tmp_seq = (char *) malloc(sizeof(char) * 7); // 7 is the num of white chars
        if (NULL == tmp_seq){
#ifdef DEBUG
            printf("Can not allocate memory for tmp_seq\n");
#endif
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            return NULL;
        }
        strcpy(tmp_seq, " \t\n\r\x0b\x0c");
    }
    char * temp_str = NULL;
    PSTR tmp_str = str_init(pstr->str);
    temp_str = tmp_str->str_reverse(tmp_str);
    tmp_str->str_setval(tmp_str, temp_str);
    free(temp_str);
    temp_str = tmp_str->str_lstrip(tmp_str, tmp_seq);
    tmp_str->str_setval(tmp_str, temp_str);
    free(temp_str);
    char * tmp = tmp_str->str_reverse(tmp_str);
    str_free(tmp_str);
    if (seq == NULL)
        free(tmp_seq);
    return tmp;
}

/**
 * @brief Returns the reverse version of the string
 * @param pstr pointer to the STR structure
 *
 * string or NULL in case of failure.
 *
 * Users are responsible to free the returned string after use (allocated by malloc).
 *
 * @return Returns char * type which is the reverse value of the original or NULL on failure
 */
char * str_reverse(PSTR pstr){
    /*returns the reverse version of the string 
     * and the user is responsible to free it*/
    if (NULL == pstr){
        return NULL;
    }
    if (pstr->str == NULL)
        return NULL;
    char * new_str = NULL;
    new_str = malloc(pstr->len * sizeof(char) + 1);
    if (new_str == NULL){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    for (unsigned int i=pstr->len; i > 0; i--)
        new_str[pstr->len - i] = pstr->str[i-1];
    new_str[pstr->len] = '\0';
    return new_str;
}

/**
 * @brief Return the upper-case version of the string
 * @param pstr pointer to the STR structure
 * string or NULL in case of failure.
 * User are responsible to free the returned string after use (allocated by malloc).
 *
 * @return Returns char * type which is the uppercase of the original or NULL on failure
 */
char * str_upper(PSTR pstr){
    /*user is responsible to free the allocated memory for the string*/
    if (NULL == pstr)
        return NULL;
    if (pstr->len == 0){
        char * new_str = (char *) malloc(sizeof(char));
        if (NULL == new_str){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            return NULL;
        }
        new_str[0] = '\0';
        return new_str;
    }
    char * tmp = (char *) malloc(pstr->len + 1);
    if (tmp == NULL){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    memcpy(tmp, pstr->str, pstr->len);
    tmp[pstr->len] = '\0';
    for (unsigned int i=0; i<pstr->len; i++){
        if (tmp[i] >= 'a' && tmp[i] <= 'z')
            tmp[i] -= 32;
    }
    return tmp;
}

/**
 * @brief Return the lower-case version of the string
 * @param pstr pointer to the STR structure
 * @return Returns char * type which is the lowercase of the original
 * string or NULL in case of failure. Users are responsible to free the returned
 * string after use (allocated by malloc).
 */
char * str_lower(PSTR pstr){
    /*user is responsible to free the allocated memory for the returned string*/
    if (NULL == pstr)
        return NULL;
    if (pstr->len == 0){
        char * new_str = (char *) malloc(sizeof(char));
        if (NULL == new_str){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            return NULL;
        }
        new_str[0] = '\0';
        return new_str;
    }
        
    char * tmp = (char *) malloc(pstr->len + 1);
    if (tmp == NULL){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    memcpy(tmp, pstr->str, pstr->len);
    tmp[pstr->len] = '\0';
    for (unsigned int i=0; i<pstr->len; i++){
        if (tmp[i] >= 'A' && tmp[i] <= 'Z')
            tmp[i] += 32;
    }
    return tmp;
}


/**
 * @brief Returns the pointer pointed to the string
 * @param pstr pointer to the STR structure
 *
 * **DO NOT FREE this pointer since it's part of the STR structure. You should use free_str() method to free the whole STR structure**.
 *
 * @return Pointer to the string. 
 */
const char * str_getval(PSTR pstr){
    return (const char *) pstr->str;
}

/**
 * @brief Sets a new value for the STR structure
 * @param pstr pointer to the STR structure
 * @param newval new string of type char *
 *  
 * This method will copy the newval into the internal structure so 
 * it's safe to free() the passed string.
 *
 * @return 0 on success or whatever else for failure
 */
int str_setval(PSTR pstr, const char * newval){
    if (pstr->st_memory != NULL){
        free(pstr->st_memory);
        pstr->str = NULL;
    }
    size_t len = 0;
    if (NULL == newval)
        return 1;
    len = strlen(newval);
    pstr->str = (char *) malloc((len+1) * sizeof(char));
    if (NULL == pstr->str){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return ERROR_CAN_NOT_ALLOCATE_MEMORY;
    }
    pstr->st_memory = pstr->str;
    memcpy(pstr->str, newval, len);
    pstr->str[len] = '\0';
    pstr->len = len;
    return ERROR_OK;
}

/**
 * @brief Swaps the case of the letters in the string
 * @param pstr pointer to the STR structure
 *
 * @return Returns a copy of the string which should be free by users (allocated by malloc)
 */
char * str_swapcase(PSTR pstr){
    /*user is responsible to free the allocated memory for the returned string*/
    if (NULL == pstr)
        return NULL;
    if (pstr->len == 0){
        char * new_str = (char *) malloc(sizeof(char));
        if (NULL == new_str){
            pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
            strcpy(pstr->errmsg, "Can not allocate memory!");
            return NULL;
        }
        new_str[0] = '\0';
        return new_str;
    }
    char * tmp = (char *) malloc(pstr->len + 1);
    if (tmp == NULL){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return NULL;
    }
    memcpy(tmp, pstr->str, pstr->len);
    tmp[pstr->len] = '\0';
    for (unsigned int i=0; i<pstr->len; i++){
        if (tmp[i] >= 'A' && tmp[i] <= 'Z'){
            tmp[i] += 32;
            continue;
        }
        if (tmp[i] >= 'a' && tmp[i] <= 'z'){
            tmp[i] -= 32;
            continue;
        }
    }
    return tmp;
}

/**
 * @brief Return True if all characters in the string are digits and there is at least one character, False otherwise.
 * @param pstr pointer to the STR structure
 *
 * Note that 234234.234234 is not all digit but 2342342 is all digit
 *
 * @return 1 on success 0 on failure. 
 */
int str_isdigit(PSTR pstr){
    /* returns 1 if all the string is digit 0 otherwise.
     * Note that 2342.2342 is not all digit but 234234 is all digit
     **/
    if (pstr == NULL)
        return 0;
    if (pstr->len == 0)
        return 0;
    for (unsigned int i=0; i<pstr->len; i++){
        if (! isdigit((int)(pstr->str[i])))
            return 0;
    }
    return 1;
}

/**
 * @brief Appends a null-terminated string.
 * @param pstr A pointer to the structure returned by str_init()
 * @param string A null-terminated string which will be appended
 *
 * @return 0 on success, 1 on failure
 */
int str_append_string(PSTR pstr, char * string){
    if (pstr == NULL)
        return 1;
    size_t new_str_len = strlen(string);
    char * tmp = (char *) realloc(pstr->str, pstr->len + new_str_len + 1);
    if (!tmp){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return 1;
    }
#ifdef DEBUG
    fprintf(stdout, "Successfully allocated new memory for appending string\n");
#endif
    pstr->st_memory = tmp;
    pstr->str = tmp;
    memcpy(pstr->str + pstr->len, string, new_str_len);
    pstr->str[pstr->len + new_str_len] = '\0';
    pstr->len = pstr->len + new_str_len;
    return 0;
}


/**
 * @brief Prepends a null-terminated string.
 * @param pstr A pointer to the structure returned by str_init()
 * @param string A null-terminated string which will be prepended
 *
 * @return 0 on success, 1 on failure
 */
int str_prepend_string(PSTR pstr, char * string){
    if (pstr == NULL)
        return 1;
    size_t new_str_len = strlen(string);
    char * tmp = (char *) malloc(pstr->len + new_str_len + 1);
    if (!tmp){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return 1;
    }
    memcpy(tmp, string, new_str_len);
    memcpy(tmp + new_str_len, pstr->str, pstr->len);
    tmp[pstr->len + new_str_len] = '\0';
    pstr->str_setval(pstr, tmp);
    free(tmp);
    return 0;
}


/**
 * @brief Prepends one character.
 * @param pstr A pointer to the structure returned by str_init()
 * @param ch character which will be prepended
 *
 * @return 0 on success, 1 on failure
 */
int str_prepend_char(PSTR pstr, int ch){
    if (pstr == NULL)
        return 1;
    char * tmp = (char *) malloc(pstr->len + 2);
    if (!tmp){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return 1;
    }
    tmp[0] = ch;
    strncpy(tmp + 1, pstr->str, pstr->len);
    tmp[pstr->len + 1] = '\0';
    pstr->str_setval(pstr, tmp);
    free(tmp);
    return 0;
}


/**
 * @brief Appends one character.
 * @param pstr A pointer to the structure returned by str_init()
 * @param ch character which will be appended
 *
 * @return 0 on success, 1 on failure
 */
int str_append_char(PSTR pstr, int ch){
    if (pstr == NULL)
        return 1;
    char * tmp = (char *) realloc(pstr->str, pstr->len + 2);
    if (!tmp){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return 1;
    }
    pstr->st_memory = tmp;
    pstr->str = tmp;
    pstr->len = pstr->len + 1;
    pstr->str[pstr->len -1] = ch;
    pstr->str[pstr->len] = '\0';
    return 0;
}

/**
 * @brief Concatenate strings using a join str
 * @param pstr A pointer to the structure returned by str_init()
 * @param splt A pointer to the list of strings
 * @param join_str A pointer to the seperator used for concatenating strings
 *
 * @return 0 on success, 1 on failure
 */
int str_join(PSTR pstr, PSPLITLIST splt, char * join_str){
    if (!pstr)
        return 1;
    if (!splt)
        return 1;
    // calculate the length of final string
    size_t final_len = 0;
    for (int i=0; i< splt->len; ++i){
        final_len += strlen(splt->list[i]);
    }
    size_t join_len = strlen(join_str);
    final_len += (splt->len -1) * join_len;

    char * new_str = (char*) malloc(final_len + 1);
    if (!new_str){
        pstr->err = ERROR_CAN_NOT_ALLOCATE_MEMORY;
        strcpy(pstr->errmsg, "Can not allocate memory!");
        return 1;
    }
    char * tmp = new_str;
    for (int i=0; i< splt->len; ++i){
        strcpy(tmp, splt->list[i]);
        if (i < splt->len -1)
            strcpy(tmp + strlen(splt->list[i]), join_str);
        tmp += strlen(splt->list[i]) + join_len;
    }
    new_str[final_len] = '\0';
    pstr->str_setval(pstr, new_str);
    free(new_str);
    return 0;
}
