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
 * Expresses a string as a key to be used when accessing a object's fields.
 */

#define _KEY(k)                                                                \
  &((struct json_path_partial) {.path.key = k, .type = JSON_OBJECT, .prev = NULL})

/*
 * Expresses an offset as an index to be used when accessing an array's fields.
 */
#define _INDEX(i)                                                              \
  &((struct json_path_partial) {.path.index = i, .type = JSON_ARRAY, .prev = NULL})

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
//JsonNode *jsonCreate();
JsonNode *_jsonCreate();
//JsonNode *jsonCreatetd(void *src, char type);
JsonNode *jsonCreate(void *src, char type);
//#define jsonCreatetdl(src, type, root, args...) jsonCreatensl(jsonCopy(src, type), root, ##args NULL)
#define jsonCreatel(src, type, root, args...) jsonUpdate(src, type, jsonCopyl(_jsonCreate(), root, ##args, NULL))
//JsonNode *jsonCreatetdv(void *src, char type, JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonCreatev(void *src, char type, JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonCreates(void *src, char type, JsonNode *root, JsonPath *path);
//JsonNode *jsonCreatets(void *src, char type);
//#define jsonCreatetsl(src, type, root, args...) jsonCreatensl(jsonCreatets(src, type), root, ##args, NULL)
//#define jsonCreatensl(root, args...) cmemcpy(jsonCreatndl(&((JsonNode) {.contents.a = NULL, .type = JSON_ARRAY, .flags = 0, .prev = NULL, .next = NULL}), node, root, ##args, NULL), sizeof(JsonNode))
//JsonNode *jsonCreatetsv(void *src, char type, JsonNode *root, struct json_path_partial **keys);
//JsonNode *jsonCreatensv(JsonNode *node, JsonNode *root, struct json_path_partial **keys);

// read
//JsonNode *jsonReadnsl(JsonNode *root, ...);
JsonNode *_jsonReadl(JsonNode *root, ...);
#define jsonReadl(root, args...) _jsonReadl((root), ##args, NULL)
//JsonNode *jsonReadnsv(JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonReadv(JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonReads(JsonNode *root, JsonPath *path);
JsonNode *jsonReads_recurse(JsonNode *root, struct json_path_partial *path);
// ts* family expect a char**
//JsonNode *jsonReadts(void *dest, char type, JsonNode *root);
//#define jsonReadtsl(dest, type, root, args...) jsonReadts(dest, type, jsonReadnsl(root, ##args, NULL))
//JsonNode *jsonReadtsv(void *dest, char type, JsonNode *root, struct json_path_partial **keys);
//JsonNode *jsonReadtd(void *dest, char type, JsonNode *root);
//#define jsonReadtdl(dest, type, root, args...) jsonReadtd(dest, type, jsonReadnsl(root, ##args, NULL))
//JsonNode *jsonReadtdv(void *dest, char type, JsonNode *root, struct json_path_partial **keys);
//JsonNode *jsonReadnd(JsonNode *elem);
//#define jsonReadndl(root, args...) jsonReadnd(jsonReadnsl(root, ##args, NULL))
//JsonNode *jsonReadndv(JsonNode *root, struct json_path_partial **keys);

// update
//JsonNode *jsonUpdatetd(void *src, char type, JsonNode *root);
JsonNode *jsonUpdate(void *src, char type, JsonNode *root);
//#define jsonUpdatetdl(src, type, root, args...) jsonUpdatetd(src, type, jsonReadnsl(root, ##args))
#define jsonUpdatel(src, type, root, args...) jsonUpdate(src, type, jsonReadl(root, ##args, NULL))
//JsonNode *jsonUpdatetdv(void *src, char type, JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonUpdatev(void *src, char type, JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonUpdates(void *src, char type, JsonNode *root, JsonPath *path);
//JsonNode *jsonUpdatens(JsonNode *src, JsonNode *root);
//JsonNode *jsonUpdatend(JsonNode *src, JsonNode *root);
//#define jsonUpdatendl(src, root, args...) jsonUpdatend(src, jsonReadnsl(root, ##args))
//JsonNode *jsonUpdatendv(JsonNode *src, JsonNode *root, struct json_path_partial **keys);
//JsonNode *jsonUpdatets(void *src, char type, JsonNode *root);
//#define jsonUpdatensl(src, root, args...) jsonUpdatens(src, jsonReadnsl(root, ##args))
//JsonNode *jsonUpdatensv(JsonNode *src, JsonNode *root, struct json_path_partial **keys);
//#define jsonUpdatetsl(src, type, root, args...) jsonUpdatets(src, type, jsonReadnsl(root, ##args))
//JsonNode *jsonUpdatetsv(void *src, char type, JsonNode *root, struct json_path_partial **keys);

// copy
JsonNode *jsonCopy(JsonNode *root);
//JsonNode *jsonCreatendl(JsonNode *node, JsonNode *root, ...);
//JsonNode *jsonCopyl(JsonNode *node, JsonNode *root, ...);
JsonNode *_jsonCopyl(JsonNode *node, JsonNode *root, ...);
#define jsonCopyl(node, root, args...) _jsonCopyl((node), (root), ##args, NULL)
//JsonNode *jsonCreatendv(JsonNode *node, JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonCopyv(JsonNode *src, JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonCopys(JsonNode *src, JsonNode *root, JsonPath *path);
JsonNode *jsonCopys_recurse(JsonNode *root, struct json_path_partial *path);

// delete
JsonNode *jsonDelete(JsonNode *elem);
#define jsonDeletel(root, args...) jsonDelete(jsonReadl(root, ##args, NULL))
JsonNode *jsonDeletev(JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonDeletes(JsonNode *root, JsonPath *path);

// check type
jsonType *jsonCheckType(JsonNode *root);
#define jsonCheckTypel(root, args...) jsonCheckType(jsonReadl(root, ##args NULL))
jsonType *jsonCheckTypev(JsonNode *root, struct json_path_partial **keys);
jsonType *jsonCheckTypes(JsonNode *root, JsonPath *keys);

// read{type}
jsonLiteral *jsonReadLiteral(JsonNode *root);
#define jsonReadLiterall(root, args...) jsonReadLiteral(jsonReadl(root, ##args, NULL))
jsonLiteral *jsonReadLiteralv(JsonNode *root, struct json_path_partial **keys);
jsonLiteral *jsonReadLiterals(JsonNode *root, JsonPath *path);
double *jsonReadDouble(JsonNode *root);
#define jsonReadDoublel(root, args...) jsonReadDouble(jsonReadl(root, ##args, NULL))
double *jsonReadDoublev(JsonNode *root, struct json_path_partial **keys);
double *jsonReadDoubles(JsonNode *root, JsonPath *path);
char *jsonReadStr(JsonNode *root);
#define jsonReadStrl(root, args...) jsonReadStr(jsonReadl(root, ##args, NULL))
char *jsonReadStrv(JsonNode *root, struct json_path_partial **keys);
char *jsonReadStrs(JsonNode *root, JsonPath *path);
JsonNode *jsonReadArray(JsonNode *root);
#define jsonReadArrayl(root, args...) jsonReadArray(jsonReadl(root, ##args, NULL))
JsonNode *jsonReadArrayv(JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonReadArrays(JsonNode *root, JsonPath *path);
JsonNode *jsonReadObject(JsonNode *root);
#define jsonReadObjectl(root, args...) jsonReadObject(jsonReadl(root, ##args, NULL))
JsonNode *jsonReadObjectv(JsonNode *root, struct json_path_partial **keys);
JsonNode *jsonReadObjects(JsonNode *root, JsonPath *path);

// output json structure and children as string
int jsonOut(FILE *dest, char minify, JsonNode *elem);
#define jsonOutl(dest, minify, root, args...)                               \
  jsonOut(dest, minify, jsonReadl(root, ##args, NULL))
int jsonOutv(FILE *dest, char minify, JsonNode *root, struct json_path_partial **keys);

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
JsonNode *process(struct queue *file, JsonNode *elem);

// internal output function
int json_out_recurse(struct queue *dest, char minify, int offset, JsonNode *elem);

// test
void read_tests();
void array_tests();
void object_tests();
void copy_tests();
void jsonRead_tests();

void jsonCreate_tests();
void jsonRead_tests();
void jsonUpdate_tests();

int main();
