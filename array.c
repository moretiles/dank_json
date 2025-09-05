#include "array.h"

JsonNode *array_head(JsonNode *array) {
    if(array == NULL || !(array->type & JSON_ARRAY)) {
        return NULL;
    }

    if(array->contents.a != NULL && (array->contents.a->flags & JSON_ELEM_IS_TAIL) != 0) {
        if(array->contents.a->flags & JSON_ELEM_IS_HEAD) {
            return array->contents.a;
        } else if(array->contents.a->next != NULL && (array->contents.a->next->flags & JSON_ELEM_IS_HEAD) != 0) {
            return array->contents.a->next;
        }
    }

    return NULL;
}

JsonNode *array_tail(JsonNode *array) {
    if(array == NULL || !(array->type & JSON_ARRAY)) {
        return NULL;
    }

    if(array->contents.a != NULL && (array->contents.a->flags & JSON_ELEM_IS_TAIL) != 0) {
        return array->contents.a;
    }

    return NULL;
}

int array_update_head(JsonNode *array) {
    if(array == NULL || !(array->type & JSON_ARRAY) || array->contents.a == NULL) {
        return 1;
    }

    if(array->contents.a->next != NULL) {
        array->contents.a->next->prev = array;
        return 0;
    } else if(array->contents.a->flags & JSON_ELEM_IS_HEAD) {
        array->contents.a->prev = array;
        return 0;
    }

    return 2;
}

int array_add_node(JsonNode *array, JsonNode *elem) {
    JsonNode *head = array_head(array), *tail = array_tail(array);
    if (!elem || !array || array->type != JSON_ARRAY) {
        return 1;
    }

    if (!head) {
        elem->flags |= (JSON_ELEM_IS_HEAD | JSON_ELEM_IS_TAIL);
        elem->prev = array;
        elem->next = NULL;

        array->contents.a = elem;
    } else if (tail->next == NULL) {
        head->flags &= (0xff ^ JSON_ELEM_IS_TAIL);
        elem->flags |= JSON_ELEM_IS_TAIL;

        head->next = elem;
        elem->prev = head;
        elem->next = head;

        array->contents.a = elem;
    } else {
        tail->flags &= (0xff ^ JSON_ELEM_IS_TAIL);
        elem->flags |= JSON_ELEM_IS_TAIL;

        elem->prev = tail;
        elem->next = head;
        tail->next = elem;

        array->contents.a = elem;
    }

    return 0;
}

int array_insert_node(JsonNode *array, JsonNode *elem, size_t pos) {
    JsonNode *prev = NULL, *current = NULL, *next = NULL, *head = array_head(array), *tail = array_tail(array);
    size_t init = pos;

    if (!elem || !array || array->type != JSON_ARRAY) {
        return 1;
    }

    if (array->contents.a == NULL) {
        if (pos == 0) {
            array_add_node(array, elem);
            return 0;
        } else {
            return -1;
        }
    }

    current = head;
    prev = current->prev;
    next = current->next;

    while (pos != 0) {
        if (current == NULL) {
            return init - pos;
        }

        prev = current;
        current = next;
        next = current->next;
        pos--;
    }

    if(current->flags & JSON_ELEM_IS_HEAD) {
        tail->next = elem;

        elem->flags |= JSON_ELEM_IS_HEAD;
        elem->prev = array;
        elem->next = current;

        current->prev = elem;
        current->flags &= (0xff ^ JSON_ELEM_IS_HEAD);
    } else {
        elem->prev = prev;
        elem->next = current;

        prev->next = elem;
        current->prev = elem;
    }

    return 0;
}

int array_destroy_node(struct json_pool *pool, JsonNode *array, JsonNode *elem) {
    JsonNode *prev = NULL, *next = NULL, *head = array_head(array), *tail = array_tail(array);

    /*
     * It should always be the case that if prev exists then next exists and vice
     * versa
     */
    if (!pool || !array || !elem || array->type != JSON_ARRAY || !head || !tail) {
        return 1;
    }

    if(elem->flags & JSON_ELEM_IS_HEAD) {
        if(array != elem->prev) {
            // something has gone terribly wrong
            return 2;
        }

        if(head->next == NULL) {
            array->contents.a = NULL;
        } else {
            next = head->next;

            if(tail == next) {
                tail->next = NULL;
            } else {
                tail->next = next;
            }

            next->prev = array;
            next->flags |= JSON_ELEM_IS_HEAD;
        }
    } else if (elem->flags & JSON_ELEM_IS_TAIL) {
        if(tail->prev == NULL) {
            array->contents.a = NULL;
        } else {
            prev = tail->prev;

            prev->next = head;
            prev->flags |= JSON_ELEM_IS_TAIL;
            array->contents.a = prev;
        }
    } else {
        prev = elem->prev;
        next = elem->next;

        prev->next = next;
        next->prev = prev;
    }

    elem->prev = NULL;
    elem->next = NULL;

    destroy_node(pool, elem);
    return 0;
}

int array_destroy(struct json_pool *pool, JsonNode *array) {
    if(pool == NULL || array == NULL || !(array->type & JSON_ARRAY)) {
        return 1;
    }

    while(array->contents.a != NULL) {
        array_destroy_node(pool, array, array_get_nth(array, 0));
    }

    return 0;
}

JsonNode *array_get_nth(JsonNode *array, size_t n) {
    JsonNode *elem = NULL;
    if (array == NULL) {
        return NULL;
    }

    elem = array_head(array);
    while (n != 0 && elem != NULL && !(elem->flags & JSON_ELEM_IS_TAIL)) {
        n--;
        elem = elem->next;
    }
    if (n == 0) {
        return elem;
    } else {
        return NULL;
    }
}

JsonNode *get_json_array(struct json_pool *pool, struct queue *file, struct queue *scratch, JsonNode *elem) {
    JsonNode *from_pool = NULL;
    JsonNode current = { 0 };
    char sep = ',', error = 0;

    // printf("inside array\n");

    if (file == NULL || scratch == NULL) {
        return NULL;
    }
    elem->contents.a = 0;
    elem->type = JSON_ARRAY;

    // Process elements
    while (!error && sep != ']') {
        if (sep != ',') {
            return NULL;
        }
        process(file, &current);
        if(!(current.type & JSON_CLOSE)) {
            //from_pool = new_node(elems);
            from_pool = new_node(pool);
            memcpy(from_pool, &current, sizeof(JsonNode));
            if(from_pool->type & JSON_ARRAY && from_pool->contents.a != NULL && from_pool->contents.a->next != NULL) {
                from_pool->contents.a->next->prev = from_pool;
            }
            array_add_node(elem, from_pool);
            sep = get_sep(file);
        } else {
            sep = ']';
        }
        // printf("%c\n", sep);
    }

    if (!error) {
        // printf("end\n");
        return elem;
    } else {
        // array_destroy(read, new_array);
        return NULL;
    }
}
