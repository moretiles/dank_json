#include "pool.h"

#include <stdlib.h>

extern JsonNode *destroy_node(struct json_pool *pool, JsonNode *elem);

/*
 * Init pool
 */
int init_pool(struct json_pool *pool, size_t size) {
  if (pool == NULL) {
    return 1;
  }

  pool->items = calloc(size, sizeof(JsonNode));
  if (pool->items == NULL) {
    return 2;
  }
  pool->stored = 0;
  pool->cap = size;
  pool->next_free = NULL;
  return 0;
}

/*
 * Destroy pool
 */
int destroy_pool(struct json_pool *pool) {
  if (pool == NULL) {
    return 1;
  }

  if (pool->prev != NULL) {
    destroy_pool(pool->prev);
  }

  size_t i = 0;
  for (i = 0; i < pool->cap; i++) {
    destroy_node(pool, &((pool->items)[i]));
  }
  if (pool->items != NULL) {
    free(pool->items);
    pool->items = NULL;
  }

  free(pool);
  pool = NULL;

  return 0;
}

struct json_pool *double_pool(struct json_pool **pool) {
  struct json_pool *ptr = calloc(1, sizeof(struct json_pool));

  if (!ptr) {
    return NULL;
  }

  init_pool(ptr, (*pool)->cap * 2);
  ptr->prev = *pool;
  *pool = ptr;
  return *pool;
}

