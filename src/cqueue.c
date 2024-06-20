#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cqueue.h>

cqueue_ctx * cqueue_init(unsigned long int maxsize){
    // if maxsize is zero, we have an unlimited queue
    cqueue_ctx * ctx = (cqueue_ctx*) malloc(sizeof(cqueue_ctx));
    if (!ctx){
        fprintf(stderr, "Can not initialize the queue\n");
        return NULL;
    }
    ctx->errmsg = (char *) malloc(256);
    if (ctx->errmsg == NULL){
        fprintf(stderr, "Can not allocate memory for queue\n");
        free(ctx);
        return NULL;
    }
    memset(ctx->errmsg, 0, 256);
    ctx->maxsize = maxsize;
    ctx->number_of_items = 0;
    ctx->first_item = NULL;
    ctx->last_item = NULL;
    //ctx->items = NULL;
    return ctx;
}

// put an item to the queue 
// return 0 on success and errors are: 
//  1 -> queue is full,
//  2 -> malloc failed
// sets the errmsg to an appropriate value
int cqueue_put(cqueue_ctx * ctx, void * item){
    if (ctx->maxsize != 0){
        if (ctx->number_of_items == ctx->maxsize){
            ctx->errcode = CQUEUE_ERROR_QUEUE_IS_FULL;
            strcpy(ctx->errmsg, "cqueue_put(): queue is full");
            return 1;       // if queue is full
        }
    }
    struct _cqueue_item * new_item = (struct _cqueue_item*) malloc(sizeof(struct _cqueue_item));
    if (!new_item){
        ctx->errcode = CQUEUE_ERROR_MEMORY_ALLOCATION;
        strcpy(ctx->errmsg, "Can not allocate memory for the new item");
        return 2;       // malloc failed
    }
    new_item->data = item;
    new_item->prev = NULL;
    new_item->next = NULL;
    if (ctx->number_of_items == 0){
        // this is the first item
        ctx->first_item = new_item;
        ctx->last_item = new_item;
        ctx->number_of_items = 1;
        ctx->errcode = CQUEUE_ERROR_SUCCESS;
        ctx->errmsg[0] = '\0';
        return 0;
    }
    // we already have some items
    new_item->prev = ctx->last_item;
    ctx->last_item->next = new_item;
    ctx->last_item = new_item;
    ctx->number_of_items += 1;
    ctx->errcode = CQUEUE_ERROR_SUCCESS;
    ctx->errmsg[0] = '\0';
    return 0;
}

// get an item from the queue
// return a pointer on success NULL on error and set the error code
// sets the err me
// in a multi-thread situation, you can not use the global error code
// as it's not thread safe.
// The only possible reason of failure for this function is the case
// that the queue is empty. This means that in a multithread program
// you can lock->read->unlock->sleep->repeat until you get the answer.
void * cqueue_get(cqueue_ctx * ctx){
    if (ctx->number_of_items == 0){
        ctx->errcode = CQUEUE_ERROR_QUEUE_EMPTY;
        strcpy(ctx->errmsg, "cqueue_get(): queue is empty");
        return NULL;    // queue is empty
    }
    struct _cqueue_item * tmp = ctx->first_item;
    ctx->first_item = tmp->next;
    if (ctx->number_of_items == 2)
        ctx->last_item = tmp->next;
    if (ctx->number_of_items == 1){
        ctx->last_item = NULL;
        ctx->first_item = NULL;
    }
    ctx->number_of_items -= 1;
    void * data = tmp->data;
    free(tmp);
    ctx->errcode = CQUEUE_ERROR_SUCCESS;
    ctx->errmsg[0] = '\0';
    return data;
}

// get the current size of the queue
unsigned long int cqueue_size(cqueue_ctx * ctx){
    return ctx->number_of_items;
}

// empty the queue and return 0 on success
int cqueue_empty(cqueue_ctx * ctx){
    struct _cqueue_item * tmp = ctx->first_item;
    while (tmp != NULL){
        free(tmp->data);
        ctx->first_item = tmp->next;
        free(tmp);
        tmp = ctx->first_item;
    }
    ctx->errcode = CQUEUE_ERROR_SUCCESS;
    ctx->errmsg[0] = '\0';
    return 0;
}

void cqueue_free(cqueue_ctx * ctx){
    if (ctx == NULL)
        return;
    struct _cqueue_item * tmp = ctx->first_item;
    while (tmp != NULL){
        free(tmp->data);
        ctx->first_item = tmp->next;
        free(tmp);
        tmp = ctx->first_item;
    }
    free(ctx->errmsg);
    free(ctx);
}

