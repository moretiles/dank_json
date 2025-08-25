#include "ds.h"
#include "cstring.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

// Expresses a char* as a key to be used when accessing an object's fields.
#define jsonPathKey(k) &((struct json_path_partial) {.path.key = k, .type = JSON_OBJECT})

// Expresses an offset as an index to be used when accessing an array's fields.
#define jsonPathIndex(i) &((struct json_path_partial) {.path.index = i, .type = JSON_ARRAY})

struct json_path_partial *copy_json_path_partial(struct json_path_partial *src);
int delete_json_path_partial(struct json_path_partial *path_partial);

JsonPath *_jsonPathPush(JsonPath *path, ...);
#define jsonPathPush(path, args...) _jsonPathPush(path, ##args, NULL);
int jsonPathPop(JsonPath *path);
int jsonPathDelete(JsonPath *path);
