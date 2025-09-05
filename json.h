#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if TEST_BUILD == 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "ds.h"
#include "cstring.h"
#include "jsonpath.h"
#include "queue.h"
#include "hash.h"
#include "array.h"
#include "pool.h"

#ifdef UNITY_BUILD
#include "cstring.c"
#include "jsonpath.c"
#include "queue.c"
#include "hash.c"
#include "array.c"
#include "pool.c"
#endif

/*
 *  * Possible values for literal
 *   */
#define _JSON_TRUE (0)
jsonLiteral JSON_TRUE = _JSON_TRUE;
#define _JSON_FALSE (1)
jsonLiteral JSON_FALSE = _JSON_FALSE;
#define _JSON_NULL (2)
jsonLiteral JSON_NULL = _JSON_NULL;

int jsonLibInit();
JsonNode *jsonOpen(const char *fileName);
void jsonClose(const char *fileName);
int jsonLibEnd();

/*
 * Provides you with a new node.
 *
 * You will never call free on a returned node. Ever.
 * The memory used for this node will be freed upon under any of the below
 * conditions:
 * 1. Calling jsonDelete on this node.
 * 2. Calling jsonClose on the file associated with this node.
 * 3. Calling jsonEnd.
 */
JsonNode *_jsonCreate();
JsonNode *jsonCreate(const void *src, char type);
#define jsonCreatel(src, type, root, args...) jsonUpdate(src, type, jsonCopyl(_jsonCreate(), root, ##args, NULL))
JsonNode *jsonCreates(const void *src, char type, JsonNode *root, JsonPath *path);

// read
JsonNode *_jsonReadl(JsonNode *root, ...);
#define jsonReadl(root, args...) _jsonReadl((root), ##args, NULL)
JsonNode *jsonReads(JsonNode *root, JsonPath *path);
JsonNode *jsonReads_recurse(JsonNode *root, struct json_path_partial *path);

// update
JsonNode *jsonUpdate(const void *src, char type, JsonNode *root);
#define jsonUpdatel(src, type, root, args...) jsonUpdate(src, type, jsonReadl(root, ##args, NULL))
JsonNode *jsonUpdates(const void *src, char type, JsonNode *root, JsonPath *path);

// copy
JsonNode *jsonCopy(JsonNode *root);
JsonNode *_jsonCopyl(JsonNode *node, JsonNode *root, ...);
#define jsonCopyl(node, root, args...) _jsonCopyl((node), (root), ##args, NULL)
JsonNode *jsonCopys(JsonNode *src, JsonNode *root, JsonPath *path);
JsonNode *jsonCopys_recurse(JsonNode *root, struct json_path_partial *path);

// delete
JsonNode *jsonDelete(JsonNode *elem);
#define jsonDeletel(root, args...) jsonDelete(jsonReadl(root, ##args, NULL))
JsonNode *jsonDeletes(JsonNode *root, JsonPath *path);

// check type
jsonType *jsonCheckType(JsonNode *root);
#define jsonCheckTypel(root, args...) jsonCheckType(jsonReadl(root, ##args NULL))
jsonType *jsonCheckTypes(JsonNode *root, JsonPath *keys);

// check type
bool jsonIsType(jsonType type, JsonNode *root);
#define jsonIsTypel(type, root, args...) jsonIsType(type, jsonReadl(root, ##args NULL))
bool jsonIsTypes(jsonType type, JsonNode *root, JsonPath *keys);

// read{type}
jsonLiteral *jsonReadLiteral(JsonNode *root);
#define jsonReadLiterall(root, args...) jsonReadLiteral(jsonReadl(root, ##args, NULL))
jsonLiteral *jsonReadLiterals(JsonNode *root, JsonPath *path);
double *jsonReadDouble(JsonNode *root);
#define jsonReadDoublel(root, args...) jsonReadDouble(jsonReadl(root, ##args, NULL))
double *jsonReadDoubles(JsonNode *root, JsonPath *path);
char *jsonReadStr(JsonNode *root);
#define jsonReadStrl(root, args...) jsonReadStr(jsonReadl(root, ##args, NULL))
char *jsonReadStrs(JsonNode *root, JsonPath *path);
JsonNode *jsonReadArray(JsonNode *root);
#define jsonReadArrayl(root, args...) jsonReadArray(jsonReadl(root, ##args, NULL))
JsonNode *jsonReadArrays(JsonNode *root, JsonPath *path);
JsonNode *jsonReadObject(JsonNode *root);
#define jsonReadObjectl(root, args...) jsonReadObject(jsonReadl(root, ##args, NULL))
JsonNode *jsonReadObjects(JsonNode *root, JsonPath *path);

// output json structure and children as string
int jsonOut(FILE *dest, char minify, JsonNode *elem);
#define jsonOutl(dest, minify, root, args...)                               \
  jsonOut(dest, minify, jsonReadl(root, ##args, NULL))
int jsonOuts(FILE *dest, char minify, JsonNode *root, JsonPath *path);

/*
 *
 *  ___ _   _ _____ _____ ____  _   _    _    _
 * |_ _| \ | |_   _| ____|  _ \| \ | |  / \  | |
 *  | ||  \| | | | |  _| | |_) |  \| | / _ \ | |
 *  | || |\  | | | | |___|  _ <| |\  |/ ___ \| |___
 * |___|_| \_| |_| |_____|_| \_\_| \_/_/   \_\_____|
 *
 *
 * Everything below here refers to internal methods.
 * Please use the above camelCased methods to interact with JSON data.
 */

// internal JsonNode functions
static inline int is_whitespace(char c);
void get_next(char *outer, struct queue *store);
char get_sep(struct queue *store);
static inline int is_json_literal(char *str);
static inline int is_json_str(char *str);
static inline int is_part_of_num(char c);
int is_json_num(char *str);
static inline int is_json_array(char *str);
static inline int is_json_object(char *str);
int identify(char *str, JsonNode *elem);
static inline char get_json_literal(const char *ptr);
char *get_json_str(struct queue *read, struct queue *scratch);
static inline double get_json_num(char *str);
JsonNode *new_node(struct json_pool *pool);
JsonNode *copy_json_node(JsonNode *dest, JsonNode *src);
JsonNode *copy_json_node_preserve_references(JsonNode *dest, JsonNode *src);
JsonNode *destroy_node(struct json_pool *pool, JsonNode *elem);
JsonNode *destroy_node_contents(JsonNode *elem);
JsonNode *process(struct queue *file, JsonNode *elem);

// internal output function
int json_out_recurse(struct queue *dest, char minify, int offset, JsonNode *elem);

// test
void read_tests();
void array_tests();
void object_tests();
void copy_tests();
void output_tests();

void jsonRead_tests();
void jsonDelete_tests();
void jsonUpdate_tests();
void jsonCopy_tests();
void jsonCreate_tests();

int main();
