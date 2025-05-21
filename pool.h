#include "ds.h"

#include <stddef.h>
#include <stdint.h>

// pool
int init_pool(struct json_pool *pool, size_t size);
int destroy_pool(struct json_pool *pool);
struct json_pool *double_pool(struct json_pool **pool);
