#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"

struct ht *ht_init(size_t numElems) {
    struct ht *ret = calloc(1, sizeof(struct ht));
    char **keys = calloc(numElems, sizeof(char *));
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

    return ret;
}

uint64_t fnv(const char *data, size_t len) {
    /* There is no bug here.
     * It is okay for __uint128_t to hold a value that would be to big
     * for some signed numbers.
     */
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

JsonNode *ht_insert(struct ht *table, const char *key, JsonNode *val) {
    if (table == NULL || key == NULL || val == NULL) {
        return NULL;
    }

    char *new_key = NULL;
    struct ht *new = NULL;
    uint32_t offset, iterate;

    fnv_hash(key, &offset, &iterate);

    size_t max_possible = table->cap;
    while (table->keys[offset % table->cap] != NULL &&
            table->vals[offset % table->cap] != NULL && max_possible > 0) {
        offset += iterate;
        max_possible -= 1;
    }
    if (max_possible == 0) {
        return NULL;
    }
    table->count += 1;
    new_key = calloc(1 + strlen(key), sizeof(char));
    if (new_key == NULL) {
        return NULL;
    }
    memcpy(new_key, key, strlen(key) + 1);
    new_key[strlen(key)] = '\x00';
    table->keys[offset % table->cap] = new_key;
    table->vals[offset % table->cap] = val;
    if (table->count + 1 >= table->cap / 2) {
        new = ht_grow(table, (size_t)(table->cap * 2));
        if (new != NULL) {
            table = new;
        }
    }
    return ht_find(table, key);
}

JsonNode *ht_insert_direct(struct ht *table, char *key, JsonNode *val) {
    if (table == NULL || key == NULL || val == NULL) {
        return NULL;
    }

    struct ht *new = NULL;
    uint32_t offset, iterate;

    fnv_hash(key, &offset, &iterate);

    size_t max_possible = table->cap;
    while (table->keys[offset % table->cap] != NULL &&
            table->vals[offset % table->cap] != NULL && max_possible > 0) {
        offset += iterate;
        max_possible -= 1;
    }
    if (max_possible == 0) {
        return NULL;
    }
    table->count += 1;
    table->keys[offset % table->cap] = key;
    table->vals[offset % table->cap] = val;
    if (table->count + 1 > table->cap / 2) {
        new = ht_grow(table, (size_t)(table->cap * 2));
        if (new != NULL) {
            table = new;
        }
    }
    return ht_find(table, key);
}

JsonNode *ht_find(struct ht *table, const char *key) {
    if (table == NULL || key == NULL) {
        return NULL;
    }

    uint32_t offset, iterate;

    fnv_hash(key, &offset, &iterate);

    size_t max_possible = table->cap;
    while (max_possible > 0) {
        if (table->keys[offset % table->cap] != NULL &&
                table->vals[offset % table->cap] != NULL &&
                !strcmp(table->keys[offset % table->cap], key)) {
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

    JsonNode *target_val = ht_find(table, key);
    if (target_val != NULL) {
        copy_json_node(target_val, elem);
    }
    return target_val;
}

JsonNode *ht_del(struct json_pool *pool, struct ht *table, const char *key) {
    if (table == NULL || key == NULL) {
        return NULL;
    }

    JsonNode *cleared = NULL;
    uint32_t offset, iterate;

    fnv_hash(key, &offset, &iterate);

    size_t max_possible = table->cap;
    while (max_possible > 0) {
        if (table->keys[offset % table->cap] != NULL &&
                table->vals[offset % table->cap] != NULL &&
                !strcmp(table->keys[offset % table->cap], key)) {
            cleared = table->vals[offset % table->cap];
            free(table->keys[offset % table->cap]);
            table->keys[offset % table->cap] = NULL;
            destroy_node(pool, table->vals[offset % table->cap]);
            table->vals[offset % table->cap] = NULL;
            table->count -= 1;
            return cleared;
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
    size_t i = 0, seen = 0;
    JsonNode *deleted = NULL;

    for(i = 0; i < table->cap && seen < table->count; i++) {
        if(table->vals[i] != NULL) {
            seen++;
            if(table->vals[i] == val) {
                free(table->keys[i]);
                table->keys[i] = NULL;
                deleted = destroy_node(pool, table->vals[i]);
                table->vals[i] = NULL;

                table->count -= 1;
                return deleted;
            }
        }
    }

    return NULL;
}

struct ht *ht_grow(struct ht *old, size_t cap) {
    if (old == NULL) {
        return NULL;
    }

    struct ht *new = calloc(1, sizeof(struct ht));
    char **new_keys = calloc(cap, sizeof(char *));
    JsonNode **new_vals = calloc(cap, sizeof(JsonNode *));
    size_t i = 0;
    if (new == NULL || new_keys == NULL || new_vals == NULL) {
        free(new);
        free(new_keys);
        free(new_vals);
        return NULL;
    }
    new->keys = new_keys;
    new->vals = new_vals;
    new->cap = cap;
    for (i = 0; i < old->cap; i++) {
        if (old->keys[i] == NULL || old->vals[i] == NULL) {
            continue;
        }

        ht_insert_direct(new, old->keys[i], old->vals[i]);
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
    size_t i = 0;

    if (table == NULL) {
        return;
    }

    for (i = 0; i < table->cap; i++) {
        if (table->keys[i] != NULL) {
            free(table->keys[i]);
            table->keys[i] = NULL;
        }

        if (table->vals[i] != NULL) {
            destroy_node(pool, table->vals[i]);
            table->vals[i] = NULL;
        }
    }

    free(table->keys);
    table->keys = NULL;
    free(table->vals);
    table->vals = NULL;
    free(table);
    table = NULL;
    return;
}
