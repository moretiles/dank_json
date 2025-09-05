#include "queue.h"

int dequeue(Queue *store, char *data, int size) {
    if (size <= 0) {
        return ERR_QUEUE_INVALID_SIZE;
    }
    if (size > store->pos - store->base) {
        size = store->pos - store->base;
    }

    memcpy(data, store->chars + store->base, size);
    store->base = store->base + size;
    return size;
}

int enqueue(Queue *store, char *data, int size) {
    if (size <= 0) {
        return ERR_QUEUE_INVALID_SIZE;
    }
    if (store->pos + size > store->cap) {
        return ERR_QUEUE_OUT_OF_MEMORY;
    }

    memcpy(store->chars + store->pos, data, size);
    store->pos = store->pos + size;
    return size;
}

/*
 * Move size bytes from readQueue to writeQueue
 */
int exchange(Queue *readQueue, Queue *writeQueue, int size) {
    if (size <= 0) {
        return ERR_QUEUE_INVALID_SIZE;
    }
    if (size > readQueue->pos - readQueue->base) {
        size = readQueue->pos - readQueue->base;
    }
    if (writeQueue->pos + size > writeQueue->cap) {
        return ERR_QUEUE_OUT_OF_MEMORY;
    }
    memcpy(writeQueue->chars + writeQueue->pos,
           readQueue->chars + readQueue->base, size);
    readQueue->base = readQueue->base + size;
    writeQueue->pos = writeQueue->pos + size;
    return size;
}

// Dequeue a single byte from store->chars
int dequeuec(Queue *store, char *cptr) {
    if (store->base == store->pos) {
        return ERR_QUEUE_OUT_OF_MEMORY;
    }

    *cptr = store->chars[store->base];
    store->base = store->base + 1;
    return 0;
}

// Enqueue a single byte to store->chars
int enqueuec(Queue *store, char c) {
    if (store->pos + 1 > store->cap) {
        return ERR_QUEUE_OUT_OF_MEMORY;
    }

    *(store->chars + store->pos) = c;
    store->pos = store->pos + 1;
    return 0;
}

// Enqueue a single byte to store->chars
int enqueuecn(Queue *store, char c, long n) {
    if (store->pos + n > store->cap) {
        return ERR_QUEUE_OUT_OF_MEMORY;
    }

    if (memset((store->chars + store->pos), c, n) == NULL) {
        return ERR_QUEUE_OUT_OF_MEMORY;
    }
    store->pos = store->pos + n;
    return 0;
}

// Copy from store->chars over [base, pos) to start of store->chars
int foldDown(Queue *store) {
    int diff = store->pos - store->base;
    if (diff > store->base) {
        return ERR_QUEUE_OUT_OF_MEMORY;
    }

    memcpy(store->chars, store->chars + store->base, diff);
    store->pos = diff;
    store->base = 0;
    return diff;
}

// Enqueue MAX_BLOCK_SIZE bytes from attached file into store->chars
int fenqueue(Queue *store, int size) {
    int read = 0;
    if (store->pos + size > store->cap) {
        return ERR_QUEUE_OUT_OF_MEMORY;
    }
    if (ferror(store->file)) {
        return ERR_QUEUE_FILE_IO;
    }

    read = fread(store->chars + store->pos, 1, size, store->file);
    store->pos = store->pos + read;
    return read;
}

// Dequeue MAX_BLOCK_SIZE bytes in store->chars to a file
int fdequeue(Queue *store, int size) {
    int difference = 0;
    int write = 0;
    if (store->pos == 0) {
        return ERR_QUEUE_EMPTY;
    }
    if (ferror(store->file)) {
        return ERR_QUEUE_FILE_IO;
    }

    difference = store->pos - store->base;
    size = (size > difference) ? difference : size;
    write = fwrite(store->chars, 1, size, store->file);
    store->pos = store->pos - difference;
    if (store->pos < 0) {
        store->pos = 0;
    }
    return write;
}

int queueRewind(Queue *store, int back) {
    if (store->base - back < 0) {
        return ERR_QUEUE_INVALID_SIZE;
    }

    store->base -= back;
    return back;
}

int queueRedact(Queue *store, int back) {
    if (store->pos - back < 0) {
        return ERR_QUEUE_INVALID_SIZE;
    }

    store->pos -= back;
    return back;
}

bool queueCanHold(Queue *queue, int size) {
    if(queue == NULL) {
        return false;
    }

    return queue->pos + size < queue->cap;
}

int queueEnsureSpace(Queue *queue, int max) {
    if(queue == NULL) {
        return 1;
    }

    if(!queueCanHold(queue, max)) {
        fdequeue(queue, queue->pos - queue->base);
        queue->pos = 0;
        queue->base = 0;
    }

    return 0;
}
