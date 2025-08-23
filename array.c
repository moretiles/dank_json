#include "array.h"

int array_add_node(JsonNode *array, JsonNode *elem) {
    JsonNode *head = NULL, *tail = NULL;
    if (!elem || !array || array->type != JSON_ARRAY) {
        return 1;
    }
    head = array->contents.a;
    if (head && head->prev) {
        tail = head->prev;
    };

    if (!head) {
        array->contents.a = elem;
        elem->flags |= (JSON_ELEM_IS_HEAD | JSON_ELEM_IS_TAIL);
        elem->prev = NULL;
        elem->next = NULL;
    } else if (head->prev == NULL || head->next == NULL) {
        head->prev = elem;
        head->next = elem;
        head->flags &= (0xff - JSON_ELEM_IS_TAIL);
        elem->prev = head;
        elem->next = head;
        elem->flags |= JSON_ELEM_IS_TAIL;
    } else {
        elem->prev = tail;
        tail->flags &= (0xff - JSON_ELEM_IS_TAIL);
        elem->flags |= JSON_ELEM_IS_TAIL;
        elem->next = head;

        tail->next = elem;
        head->prev = elem;
    }

    return 0;
}

int array_insert_node(JsonNode *array, JsonNode *elem, size_t pos) {
    JsonNode *prev = NULL, *current = NULL, *next = NULL;
    size_t init = pos;

    if (!elem || !array || array->type != JSON_ARRAY ||
            (pos > 0 && array->contents.a == NULL)) {
        return 1;
    }

    if (pos == 0) {
        if (array->contents.a == NULL) {
            array_add_node(array, elem);
            return 0;
        }
    }

    current = array->contents.a;
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

    elem->prev = prev;
    elem->next = current;

    prev->next = elem;
    current->prev = elem;

    if (init - pos == 0) {
        array->contents.a = elem;
        current->flags &= 0xff - JSON_ELEM_IS_HEAD;
        elem->flags |= JSON_ELEM_IS_HEAD;
    }

    return 0;
}

int array_destroy_node(struct json_pool *pool, JsonNode *array, JsonNode *elem) {
    JsonNode *prev = NULL, *next = NULL;

    /*
     * It should always be the case that if prev exists then next exists and vice
     * versa
     */
    if (!pool || !array || !elem || array->type != JSON_ARRAY) {
        return 1;
    }

    if (elem->prev && elem->next) {
        prev = elem->prev;
        next = elem->next;

        if (elem->flags & JSON_ELEM_IS_HEAD) {
            next->flags |= JSON_ELEM_IS_HEAD;
            array->contents.a = next;
        }
        prev->next = next;
        if (elem->flags & JSON_ELEM_IS_TAIL) {
            prev->flags |= JSON_ELEM_IS_HEAD;
        }
        next->prev = prev;
    } else {
        array->contents.a = NULL;
    }

    // special condition for when the length before deletion was 2
    if(elem->prev != NULL && elem->next != NULL && elem->prev == elem->next) {
        if(elem->prev != NULL) {
            elem->prev->prev = NULL;
        }

        if(elem->next != NULL) {
            elem->next->next = NULL;
        }
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

    elem = array->contents.a;
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
    JsonNode current;
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
        if(current.type != JSON_CLOSE) {
            //from_pool = new_node(elems);
            from_pool = new_node(pool);
            memcpy(from_pool, &current, sizeof(JsonNode));
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
