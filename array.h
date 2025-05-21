#include "ds.h"
#include "queue.h"

#include <stddef.h>
#include <stdint.h>

extern JsonNode *destroy_node(struct json_pool *pool, JsonNode *elem);
extern JsonNode *process(struct queue *file, JsonNode *elem);
extern JsonNode *new_node(struct json_pool *pool);
extern char get_sep(struct queue *store);

// array
int array_add_node(JsonNode *array, JsonNode *elem);
int array_insert_node(JsonNode *array, JsonNode *elem, size_t pos);
int array_destroy_node(struct json_pool *pool, JsonNode *array,
                       JsonNode *elem);
JsonNode *array_get_nth(JsonNode *array, size_t n);
JsonNode *get_json_array(struct json_pool *pool, struct queue *file, struct queue *scratch, JsonNode *elem);
