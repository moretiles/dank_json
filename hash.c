#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"

struct ht *ht_init(size_t numElems) {
    struct ht *ret = calloc(1, sizeof(struct ht));
    JsonNode **keys = calloc(numElems, sizeof(JsonNode *));
    JsonNode **vals = calloc(numElems, sizeof(JsonNode *));

    if (ret == NULL || keys == NULL || vals == NULL) {
        free(ret);
        free(keys);
        free(vals);
        return NULL;
    }
    ret->keys = keys;
    ret->vals = vals;
    ret->count = 0;
    ret->cap = numElems;
    ret->head_key = NULL;
    ret->tail_key = NULL;
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
    return ht_insert_direct(table, jsonCreate(key, JSON_STR), val);
}

JsonNode *ht_insert_direct(struct ht *table, JsonNode *key, JsonNode *val) {
    if (table == NULL || key == NULL || val == NULL) {
        return NULL;
    }

    struct ht *new = NULL;
    uint32_t offset, iterate;

    // find index
    {
        fnv_hash(key->contents.s, &offset, &iterate);

        size_t max_possible = table->cap;
        while (table->keys[offset % table->cap] != NULL &&
                table->vals[offset % table->cap] != NULL && max_possible > 0) {
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
        table->keys[offset % table->cap] = key;
        table->vals[offset % table->cap] = val;
    }

    // adjust head and prev/next
    {
        if(table->head_key == NULL || table->head_val == NULL) {
            key->prev = NULL;
            val->prev = NULL;

            table->head_key = key;
            table->tail_key = key;
            table->head_val = val;
            table->tail_val = val;
        } else if(table->head_key != NULL && table->tail_val != NULL) {
            key->prev = table->tail_key;
            table->tail_key->next = key;
            table->tail_key = key;

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
    return ht_find_val(table, key->contents.s);
}

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

JsonNode *ht_find_val(struct ht *table, const char *key) {
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

    if(table->head_key != NULL && table->head_val != NULL && table->tail_key != NULL && table->tail_val != NULL) {
        if(table->keys[index] == table->head_key && table->vals[index] == table->head_val) {
            if(table->keys[index]->next == NULL || table->vals[index]->next == NULL) {
                table->head_val = NULL;
                table->tail_val = NULL;
                table->head_key = NULL;
                table->tail_key = NULL;
            } else {
                table->keys[index]->next->prev = NULL;
                table->vals[index]->next->prev = NULL;

                table->head_key = table->keys[index]->next;
                table->head_val = table->vals[index]->next;
            }
        } else if(table->keys[index] == table->tail_key && table->vals[index] == table->tail_val) {
            table->keys[index]->prev->next = NULL;
            table->vals[index]->prev->next = NULL;

            table->tail_key = table->keys[index]->prev;
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

    destroy_node(pool, table->keys[index]);
    table->keys[index] = NULL;
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
        if (table->keys[offset % table->cap] != NULL &&
                table->vals[offset % table->cap] != NULL &&
                table->keys[offset % table->cap]->contents.s != NULL &&
                !strcmp(table->keys[offset % table->cap]->contents.s, key)) {
            return ht_del(pool, table, offset % table->cap);
        } else if (table->keys[offset % table->cap] == NULL &&
                   table->vals[offset % table->cap] == NULL) {
            return NULL;
        }
        offset += iterate;
        max_possible -= 1;
    }

    return NULL;
}

JsonNode *ht_del_by_val(struct json_pool *pool, struct ht *table, const JsonNode *val) {
    for(JsonNode *currentKey = table->head_key, *currentVal = table->head_val;
            currentKey != NULL && currentVal != NULL;
            currentKey = currentKey->next, currentVal = currentVal->next) {
        if(currentVal == val) {
            return ht_del_by_key(pool, table, currentKey->contents.s);
        }
    }

    return NULL;
}

struct ht *ht_grow(struct ht *old, size_t cap) {
    if (old == NULL) {
        return NULL;
    }

    struct ht *new = calloc(1, sizeof(struct ht));
    JsonNode **new_keys = calloc(cap, sizeof(JsonNode *));
    JsonNode **new_vals = calloc(cap, sizeof(JsonNode *));
    if (new == NULL || new_keys == NULL || new_vals == NULL) {
        free(new);
        free(new_keys);
        free(new_vals);
        return NULL;
    }
    new->keys = new_keys;
    new->vals = new_vals;
    new->cap = cap;
    for(JsonNode *currentKey = old->head_key, *currentVal = old->head_val;
            currentKey != NULL && currentVal != NULL;
            currentKey = currentKey->next, currentVal = currentVal->next) {

        ht_insert_direct(new, currentKey, currentVal);
    }

    free(old->keys);
    old->keys = NULL;
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

    for(JsonNode *currentKey = table->head_key, *currentVal = table->head_val;
            currentKey != NULL && currentVal != NULL;
            currentKey = currentKey->next, currentVal = currentVal->next) {

        destroy_node(pool, currentKey);
        destroy_node(pool, currentVal);
    }

    free(table->keys);
    table->keys = NULL;
    free(table->vals);
    table->vals = NULL;
    free(table);
    table = NULL;
    return;
}
