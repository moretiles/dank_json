#include "ds.h"
#include "queue.h"

extern JsonNode *copy_json_node(JsonNode *dest, JsonNode *src);
extern JsonNode *destroy_node(struct json_pool *pool, JsonNode *elem);

// #define FNV_PRIME (pow(2, 40) + pow(2, 8) + 0x3b)
#define FNV_PRIME (1099511628091)
#define FNV_OFFSET_BASIS (14695981039346656037)

// hash table funcs
uint64_t fnv(const char *data, size_t len);
static inline uint64_t fnv_str(const char *data);
JsonNode *ht_insert(struct ht *table, char *key, JsonNode *val);
JsonNode *ht_insert_direct(struct ht *table, char *key, JsonNode *val);
JsonNode *ht_find(struct ht *table, char *key);
JsonNode *ht_set(struct ht *table, char *key, JsonNode *elem);
JsonNode *ht_del(struct json_pool *pool, struct ht *table, const char *key);
struct ht *ht_grow(struct ht *old, size_t cap);
void ht_destroy(struct json_pool *pool, struct ht *table);
JsonNode *get_json_object(struct queue *file, struct queue *scratch,
                           JsonNode *elem);
