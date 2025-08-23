#include "ds.h"
#include "cstring.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

struct json_path_partial *copy_json_path_partial(struct json_path_partial *src);
int delete_json_path_partial(struct json_path_partial *path_partial);

// Uses the jsonPath naming scheme even though doesn't return that
struct json_path_partial jsonPathIndex(size_t index);
struct json_path_partial jsonPathKey(char *src);

JsonPath *_jsonPathPush(JsonPath *path, ...);
#define jsonPathPush(path, args...) _jsonPathPush(path, ##args, NULL);
int jsonPathPop(JsonPath *path);
int jsonPathDelete(JsonPath *path);
