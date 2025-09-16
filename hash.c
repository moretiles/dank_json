#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"

struct ht *ht_init(size_t numElems) {
    struct ht *ret = calloc(1, sizeof(struct ht));
    JsonNode **vals = calloc(numElems, sizeof(JsonNode *));

    if (ret == NULL || vals == NULL) {
        free(ret);
        free(vals);
        return NULL;
    }
    ret->vals = vals;
    ret->count = 0;
    ret->cap = numElems;
    ret->head_val = NULL;
    ret->tail_val = NULL;

    return ret;
}

uint64_t fnv(const char *data, size_t len) {
    __uint128_t hash = FNV_OFFSET_BASIS;
    size_t i = 0;
    if (data == NULL) {
        return hash;
    }

    while (len > 8) {
        hash *= FNV_PRIME;
        hash ^= (uint64_t)data[i];
        len -= 8;
        i += 8;
    }

    if (len > 0) {
        hash *= FNV_PRIME;
        while (len > 0) {
            hash ^= (__uint128_t)data[i] << (8 * (i % 8));
            len--;
            i++;
        }
    }

    return (uint64_t)hash;
}

uint64_t fnv_str(const char *data) {
    return (uint64_t)fnv(data, strlen(data));
}

int fnv_hash(const char *data, uint32_t *offset, uint32_t *iterate) {
    uint64_t hash = fnv_str(data);
    *offset = (uint32_t)hash;
    *iterate = (uint32_t)(hash >> 32);
    // even iterate can prevent visiting open spaces, need to make odd
    *iterate |= 0x1;
    return 0;
}

JsonNode *ht_insert_copy(struct ht *table, const char *key, JsonNode *val) {
    JsonNode *node;

    if(key == NULL){
        return NULL;
    }

    char *newKey = cstrndup(key, strlen(key) + 1);
    if(newKey == NULL){
	    return NULL;
    }

    node = ht_insert_direct(table, newKey, val);
    if(node == NULL){
	    free(newKey);
    }

    return node;
}

JsonNode *ht_insert_direct(struct ht *table, char *key, JsonNode *val) {
    if (table == NULL || key == NULL || val == NULL) {
        return NULL;
    }

    struct ht *new = NULL;
    uint32_t offset, iterate;

    // find index
    {
        fnv_hash(key, &offset, &iterate);

        size_t max_possible = table->cap;
        while (table->vals[offset % table->cap] != NULL && max_possible > 0) {
            offset += iterate;
            max_possible -= 1;
        }
        if (max_possible == 0) {
            return NULL;
        }
    }

    // insert
    {
        table->count += 1;

	val->key = key;
        table->vals[offset % table->cap] = val;
    }

    // adjust head and prev/next
    {
        if(table->head_val == NULL) {
            val->prev = NULL;

            table->head_val = val;
            table->tail_val = val;
        } else if(table->tail_val != NULL) {
            val->prev = table->tail_val;
            table->tail_val->next = val;
            table->tail_val = val;
        }
    }

    // grow if too small
    {
        if (table->count + 1 > table->cap / 2) {
            new = ht_grow(table, (size_t)(table->cap * 2));
            if (new != NULL) {
                table = new;
            }
        }
    }
    return ht_find_val(table, key);
}

/*
JsonNode *ht_find_key(struct ht *table, const char *key) {
    if (table == NULL || key == NULL) {
        return NULL;
    }

    uint32_t offset, iterate;

    fnv_hash(key, &offset, &iterate);

    size_t max_possible = table->cap;
    while (max_possible > 0) {
        if (table->keys[offset % table->cap] != NULL &&
                table->vals[offset % table->cap] != NULL &&
                table->keys[offset % table->cap]->contents.s != NULL &&
                !strcmp(table->keys[offset % table->cap]->contents.s, key)) {
            return table->keys[offset % table->cap];
        }
        offset += iterate;
        max_possible -= 1;
    }
    return NULL;
}
*/

JsonNode *ht_find_val(struct ht *table, const char *key) {
    if (table == NULL || key == NULL) {
        return NULL;
    }

    uint32_t offset, iterate;

    fnv_hash(key, &offset, &iterate);

    size_t max_possible = table->cap;
    while (max_possible > 0) {
        if (table->vals[offset % table->cap] != NULL &&
                table->vals[offset % table->cap]->key != NULL &&
                !strcmp(table->vals[offset % table->cap]->key, key)) {
            return table->vals[offset % table->cap];
        }
        offset += iterate;
        max_possible -= 1;
    }
    return NULL;
}

JsonNode *ht_set(struct ht *table, const char *key, JsonNode *elem) {
    if (table == NULL || key == NULL || elem == NULL) {
        return NULL;
    }

    JsonNode *target_val = ht_find_val(table, key);
    if (target_val != NULL) {
        copy_json_node_preserve_references(target_val, elem);
    }
    return target_val;
}

JsonNode *ht_del(struct json_pool *pool, struct ht *table, size_t index) {
    JsonNode *deleted;

    if(pool == NULL || table == NULL) {
        return NULL;
    }

    if(table->head_val != NULL && table->tail_val != NULL) {
        if(table->vals[index] == table->head_val) {
            if(table->vals[index]->next == NULL) {
                table->head_val = NULL;
                table->tail_val = NULL;
            } else {
                table->vals[index]->next->prev = NULL;
                table->head_val = table->vals[index]->next;
            }
        } else if(table->vals[index] == table->tail_val) {
            table->vals[index]->prev->next = NULL;

            table->tail_val = table->vals[index]->prev;
        } else {
            if(table->vals[index]->prev == NULL) {
                int truck = 1;
                truck ^= truck;
            }
            table->vals[index]->prev->next = table->vals[index]->next;
            table->vals[index]->next->prev = table->vals[index]->prev;
        }
    }

    deleted = destroy_node(pool, table->vals[index]);
    table->vals[index] = NULL;

    table->count -= 1;
    return deleted;
}

JsonNode *ht_del_by_key(struct json_pool *pool, struct ht *table, const char *key) {
    if (table == NULL || key == NULL) {
        return NULL;
    }

    uint32_t offset, iterate;

    fnv_hash(key, &offset, &iterate);

    size_t max_possible = table->cap;
    while (max_possible > 0) {
        if (table->vals[offset % table->cap] != NULL &&
                table->vals[offset % table->cap]->key != NULL &&
                !strcmp(table->vals[offset % table->cap]->key, key)) {
            return ht_del(pool, table, offset % table->cap);
        } else if (table->vals[offset % table->cap] == NULL) {
            return NULL;
        }
        offset += iterate;
        max_possible -= 1;
    }

    return NULL;
}

JsonNode *ht_del_by_val(struct json_pool *pool, struct ht *table, const JsonNode *val) {
    for(JsonNode *current = table->head_val;
            current != NULL;
            current = current->next) {
        if(current == val) {
            return ht_del_by_key(pool, table, current->key);
        }
    }

    return NULL;
}

struct ht *ht_grow(struct ht *old, size_t cap) {
    if (old == NULL) {
        return NULL;
    }

    struct ht *new = ht_init(cap);
    if(new == NULL){
	    return NULL;
    }

    for(JsonNode *current = old->head_val;
            current != NULL;
            current = current->next) {

        ht_insert_direct(new, current->key, current);
    }

    free(old->vals);
    old->vals = NULL;
    memcpy(old, new, sizeof(struct ht));
    free(new);
    new = NULL;
    return old;
}

void ht_destroy(struct json_pool *pool, struct ht *table) {
    if (table == NULL) {
        return;
    }

    for(JsonNode *current = table->head_val;
            current != NULL;
            current = current->next) {

        destroy_node(pool, current);
    }

    free(table->vals);
    table->vals = NULL;
    free(table);
    table = NULL;
    return;
}
