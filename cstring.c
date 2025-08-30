#include "cstring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _CUSTOM_CSTRING_FUNCTIONS
#define _CUSTOM_CSTRING_FUNCTIONS 1
char *cstrncpy(char *dest, const char *src, size_t m) {
    size_t n = 0;

    if (m == 0 || dest == NULL || src == NULL) {
        return NULL;
    }

    // + 1 for trailing '\x00'
    n = strlen(src) + 1;

    if (n < m) {
        m = n;
    }
    memcpy(dest, src, m);
    dest[m - 1] = '\x00';
    return dest;
}

void *cmemcpy(void *dest, const void *src, size_t count) {
    if(dest == NULL || src == NULL || count == 0) {
        return NULL;
    }

    return memcpy(dest, src, count);
}
#endif
