#ifndef CQUEUE_H
#define CQUEUE_H

#define CQUEUE_DEFAULT_SIZE 1
#define CQUEUE_ERROR_SUCCESS 0
#define CQUEUE_ERROR_QUEUE_IS_FULL 1
#define CQUEUE_ERROR_MEMORY_ALLOCATION 2
#define CQUEUE_ERROR_QUEUE_EMPTY 3

struct _cqueue_item{
    struct _cqueue_item * prev;
    struct _cqueue_item * next;
    void * data;
};

struct _cqueue_ctx{
    unsigned long int maxsize;
    //struct _cqueue_item ** items;
    struct _cqueue_item * first_item;
    struct _cqueue_item * last_item;
    unsigned long int number_of_items;
    unsigned int errcode;
    char *errmsg;
};

typedef struct _cqueue_ctx cqueue_ctx;

/*function declaration*/
cqueue_ctx * cqueue_init(unsigned long int);
void * cqueue_get(cqueue_ctx*);
int cqueue_put(cqueue_ctx*, void *);
int cqueue_empty(cqueue_ctx * ctx);
unsigned long int cqueue_size(cqueue_ctx * ctx);
void cqueue_free(cqueue_ctx * ctx);



#endif
