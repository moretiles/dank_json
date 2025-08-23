#include "jsonpath.h"

struct json_path_partial *copy_json_path_partial(struct json_path_partial *src) {
    if(src == NULL) {
        return NULL;
    }

    struct json_path_partial *dest = calloc(sizeof(struct json_path_partial), 1);

    if(dest == NULL) {
        return NULL;
    }

    switch(src->type) {
    case(JSON_ARRAY):
        dest->path.index = src->path.index;
        dest->type = JSON_ARRAY;
        break;

    case(JSON_OBJECT):
        if(src->path.key == NULL) {
            free(dest);
            return NULL;
        }

        size_t len = 1 + strlen(src->path.key);
        char *ptr = calloc(sizeof(char), len);
        if(ptr == NULL) {
            free(dest);
            return NULL;
        }
        cstrncpy(ptr, src->path.key, len);
        dest->path.key = ptr;
        dest->type = JSON_OBJECT;
        break;

    default:
        free(dest);
        return NULL;
        break;
    }

    return dest;
}

int delete_json_path_partial(struct json_path_partial *path_partial) {
    if(path_partial == NULL) {
        return 1;
    }

    switch(path_partial->type) {
    case(JSON_ARRAY):
        break;
    case(JSON_OBJECT):
        //calling free when a pointer is NULL produces no issues
        free(path_partial->path.key);
        break;
    default:
        return 2;
        break;
    }

    free(path_partial);

    return 0;
}

JsonPath *_jsonPathPush(JsonPath *path, ...) {
    va_list args;
    va_start(args);

    if(path == NULL) {
        path = calloc(sizeof(JsonPath), 1);
        if(path == NULL) {
            return NULL;
        }
    }

    struct json_path_partial *partial, *prev;

    prev = path->tail;
    partial = va_arg(args, struct json_path_partial*);
    while(partial != NULL) {
        partial = copy_json_path_partial(partial);
        if(partial == NULL) {
            jsonPathDelete(path);
            return NULL;
        }
        if(path->head == NULL) {
            path->head = partial;
        }

        partial->prev = prev;
        path->tail = partial;
        path->members += 1;

        prev = partial;
        partial = va_arg(args, struct json_path_partial*);
    }

    va_end(args);
    return path;
}

int jsonPathPop(JsonPath *path) {
    if(path == NULL) {
        return 1;
    }

    if(path->tail != NULL) {
        struct json_path_partial *prev_tail = path->tail;
        delete_json_path_partial(prev_tail);

        if(path->tail != path->head) {
            path->tail = prev_tail->prev;
        } else {
            path->head = prev_tail->prev;
            path->tail = prev_tail->prev;
        }
        path->members -= 1;
    } else {
        path->tail = NULL;
        path->members = 0;
    }

    return 0;
}

int jsonPathDelete(JsonPath *path) {
    if(path == NULL) {
        return 1;
    }

    while(path->members != 0 && jsonPathPop(path) == 0);
    free(path);

    return 0;
}
