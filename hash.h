#include "ds.h"
#include "queue.h"

extern JsonNode *jsonCreate(const void *src, char type);
extern JsonNode *copy_json_node(JsonNode *dest, JsonNode *src);
extern JsonNode *copy_json_node_preserve_references(JsonNode *dest, JsonNode *src);
extern JsonNode *destroy_node(struct json_pool *pool, JsonNode *elem);

// #define FNV_PRIME (pow(2, 40) + pow(2, 8) + 0x3b)
#define FNV_PRIME (1099511628091u)
#define FNV_OFFSET_BASIS (14695981039346656037u)

// hash table funcs
struct ht *ht_init(size_t numElems);
uint64_t fnv(const char *data, size_t len);
static inline uint64_t fnv_str(const char *data);
JsonNode *ht_insert_copy(struct ht *table, const char *key, JsonNode *val);
JsonNode *ht_insert_direct(struct ht *table, JsonNode *key, JsonNode *val);
JsonNode *ht_find_key(struct ht *table, const char *key);
JsonNode *ht_find_val(struct ht *table, const char *key);
JsonNode *ht_set(struct ht *table, const char *key, JsonNode *elem);
JsonNode *ht_del(struct json_pool *pool, struct ht *table, size_t index);
JsonNode *ht_del_by_key(struct json_pool *pool, struct ht *table, const char *key);
JsonNode *ht_del_by_val(struct json_pool *pool, struct ht *table, const JsonNode *val);
struct ht *ht_grow(struct ht *old, size_t cap);
void ht_destroy(struct json_pool *pool, struct ht *table);
JsonNode *get_json_object(struct queue *file, struct queue *scratch, JsonNode *elem);
