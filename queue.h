/*
 * queue.h -- header file that provides queue data structure to represent file
 *
 * dank_json - Another tool for working with JSON in C
 * https://github.com/moretiles/dank_json
 * Project licensed under Apache-2.0 license
 */

#include <stdio.h>
#include <string.h>

#ifndef false
#define false 0
#endif

#ifndef true
#define true 1
#endif

// Make sure that MAX_BLOCK_SIZE is a multiple of 3 and 4
#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE (3 * 1024 * 1024)
#endif

#define ERR_QUEUE_OUT_OF_MEMORY (-1 * (1 << 0))
#define ERR_QUEUE_INVALID_SIZE (-1 * (1 << 1))
#define ERR_QUEUE_EMPTY (-1 * (1 << 2))
#define ERR_QUEUE_FILE_OPEN (-1 * (1 << 8))
#define ERR_QUEUE_FILE_IO (-1 * (1 << 9))

struct queue {
    FILE *file;
    char *chars;
    int pos;
    int base;
    int cap;
};

/* 
 * Dequeue size bytes from store->chars to data 
 * Uses base to know what the bottom should be
 * */
int dequeue(struct queue *store, char *data, int size){
    if (size <= 0){
        return ERR_QUEUE_INVALID_SIZE;
    }
    if(size > store->pos - store->base){
        size = store->pos - store->base;
    }

    memcpy(data, store->chars + store->base, size);
    store->base = store->base + size;
    return size;
}

// Enqueue size bytes to store->chars
int enqueue(struct queue *store, char *data, int size){
    if (size <= 0){
        return ERR_QUEUE_INVALID_SIZE;
    }
    if (store->pos + size > store->cap){
        return ERR_QUEUE_OUT_OF_MEMORY;
    }

    memcpy(store->chars + store->pos, data, size);
    store->pos = store->pos + size;
    return size;
}

/*
 * Move size bytes from readQueue to writeQueue
 */
int exchange(struct queue *readQueue, struct queue *writeQueue, int size){
    if (size <= 0){
        return ERR_QUEUE_INVALID_SIZE;
    }
    if(size > readQueue->pos - readQueue->base){
        size = readQueue->pos - readQueue->base;
    }
    if (writeQueue->pos + size > writeQueue->cap){
        return ERR_QUEUE_OUT_OF_MEMORY;
    }
    memcpy(writeQueue->chars + writeQueue->pos, readQueue->chars + readQueue->base, size);
    readQueue->base = readQueue->base + size;
    writeQueue->pos = writeQueue->pos + size;
    return size;
}

// Dequeue a single byte from store->chars
int dequeuec(struct queue *store, char *cptr){
    if (store->base == store->pos){
        return ERR_QUEUE_OUT_OF_MEMORY;;
    }

    *cptr = store->chars[store->base];
    store->base = store->base + 1;
    return 0;
}

// Enqueue a single byte to store->chars
int enqueuec(struct queue *store, char c){
    if (store->pos + 1 > store->cap){
        return ERR_QUEUE_OUT_OF_MEMORY;;
    }

    *(store->chars + store->pos) = c;
    store->pos = store->pos + 1;
    return 0;
}

// Copy from store->chars over [base, pos) to start of store->chars
int foldDown(struct queue *store){
    int diff = store->pos - store->base;
    if(diff > store->base){
        return ERR_QUEUE_OUT_OF_MEMORY;
    }

    memcpy(store->chars, store->chars + store->base, diff);
    store->pos = diff;
    store->base = 0;
    return diff;
}

// Enqueue MAX_BLOCK_SIZE bytes from attached file into store->chars
int fenqueue(struct queue *store, int size){
    int read = 0;
    if (store->pos + size > store->cap){
        return ERR_QUEUE_OUT_OF_MEMORY;;
    }
    if(ferror(store->file)){
        return ERR_QUEUE_FILE_IO;
    }

    read = fread(store->chars + store->pos, 1, size, store->file);
    store->pos = store->pos + read;
    return read;
}

// Dequeue MAX_BLOCK_SIZE bytes in store->chars to a file
int fdequeue(struct queue *store, int size){
    int difference = 0;
    int write = 0;
    if (store->pos == 0){
        return ERR_QUEUE_EMPTY;
    }
    if(ferror(store->file)){
        return ERR_QUEUE_FILE_IO;
    }

    difference = store->pos - store->base;
    size = (size > difference) ? difference : size;
    write = fwrite(store->chars, 1, size, store->file);
    store->pos = store->pos - difference;
    if(store->pos < 0){
        store->pos = 0;
    }
    return write;
}

int queueRewind(struct queue *store, int back){
	if (store->base - back < 0){
		return ERR_QUEUE_INVALID_SIZE;
	}

	store->base -= back;
	return back;
}
