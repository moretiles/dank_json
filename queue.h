/*
 * queue.h -- header file that provides queue data structure to represent file
 *
 * dank_json - Another tool for working with JSON in C
 * https://github.com/moretiles/dank_json
 * Project licensed under Apache-2.0 license
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

// Make sure that MAX_BLOCK_SIZE is a multiple of 3 and 4
#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE (3 * 1024 * 1024)
#endif

#define ERR_QUEUE_OUT_OF_MEMORY (-1 * (1 << 0))
#define ERR_QUEUE_INVALID_SIZE (-1 * (1 << 1))
#define ERR_QUEUE_EMPTY (-1 * (1 << 2))
#define ERR_QUEUE_FILE_OPEN (-1 * (1 << 8))
#define ERR_QUEUE_FILE_IO (-1 * (1 << 9))

#ifndef QUEUE_STRUCT
#define QUEUE_STRUCT 1
typedef struct queue {
    FILE *file;
    char *chars;
    int pos;
    int base;
    int cap;
} Queue;
#endif

/*
 * Dequeue size bytes from store->chars to data
 * Uses base to know what the bottom should be
 */
int dequeue(Queue *store, char *data, int size);

// Enqueue size bytes to store->chars
int enqueue(Queue *store, char *data, int size);

/*
 * Move size bytes from readQueue to writeQueue
 */
int exchange(Queue *readQueue, Queue *writeQueue, int size);

// Dequeue a single byte from store->chars
int dequeuec(Queue *store, char *cptr);

// Enqueue a single byte to store->chars
int enqueuec(Queue *store, char c);

// Enqueue a single byte to store->chars
int enqueuecn(Queue *store, char c, long n);

// Copy from store->chars over [base, pos) to start of store->chars
int foldDown(Queue *store);

// Enqueue MAX_BLOCK_SIZE bytes from attached file into store->chars
int fenqueue(Queue *store, int size);

// Dequeue MAX_BLOCK_SIZE bytes in store->chars to a file
int fdequeue(Queue *store, int size);

int queueRewind(Queue *store, int back);

int queueRedact(Queue *store, int back);

bool queueCanHold(Queue *queue, int size);

int queueEnsureSpace(Queue *store, int max);
