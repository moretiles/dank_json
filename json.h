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
#include "queue.h"
#include "hash.h"
#include "array.h"
#include "pool.h"

#ifdef UNITY_BUILD
#include "queue.c"
#include "hash.c"
#include "array.c"
#include "pool.c"
#endif

int jsonLibInit();
JsonNode *jsonOpen(const char *fileName);
void jsonClose(const char *fileName);
int jsonLibEnd();

/*
 * Expresses a string as a key to be used when accessing a object's fields.
 */

#define _KEY(k)                                                                \
  &((struct path) {.path.key = k, .type = JSON_OBJECT, .next = NULL})

/*
 * Expresses an offset as an index to be used when accessing an array's fields.
 */
#define _INDEX(i)                                                              \
  &((struct path) {.path.index = i, .type = JSON_ARRAY, .next = NULL})

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
JsonNode *jsonCreate();
JsonNode *jsonCreatets(void *src, char type);
JsonNode *jsonCreatetd(void *src, char type);
#define jsonCreatensl(root, args...) cmemcpy(node, jsonCreatndl(&((JsonNode) {.contents.a = NULL, .type = JSON_ARRAY, .flags = 0, .prev = NULL, .next = NULL}), root, ##args), sizeof(JsonNode))
JsonNode *jsonCreatensv(JsonNode *node, JsonNode *root, struct path **keys);
JsonNode *jsonCreatendl(JsonNode *node, JsonNode *root, ...);
JsonNode *jsonCreatendv(JsonNode *node, JsonNode *root, struct path **keys);
// both Createt* functions can leak memory
#define jsonCreatetsl(src, type, root, args...) jsonCreatensl(jsonCreatets(src, type), root, ...)
#define jsonCreatetdl(src, type, root, args...) jsonCreatensl(jsonCopy(src, type), root, ...)
JsonNode *jsonCreatetsv(void *src, char type, JsonNode *root, struct path **keys);
JsonNode *jsonCreatetdv(void *src, char type, JsonNode *root, struct path **keys);

// read
JsonNode *jsonReadnd(JsonNode *elem);
JsonNode *jsonReadnsl(JsonNode *root, ...);
JsonNode *jsonReadnsv(JsonNode *root, struct path **keys);
JsonNode *jsonReadnd(JsonNode *elem);
#define jsonReadndl(root, args...) jsonReadnd(jsonReadnsl(root, ##args))
JsonNode *jsonReadndv(JsonNode *root, struct path **keys);
// ts* family expect a char**
int jsonReadts(void *dest, char type, JsonNode *root);
#define jsonReadtsl(dest, type, root, args...)                                   \
  jsonReadts(dest, type, jsonReadnsl(root, ##args))
int jsonReadtsv(void *dest, char type, JsonNode *root, struct path **keys);
int jsonReadtd(void *dest, char type, JsonNode *root);
#define jsonReadtdl(dest, type, root, args...)                                   \
  jsonReadtd(dest, type, jsonReadnsl(root, ##args))
int jsonReadtdv(void *dest, char type, JsonNode *root, struct path **keys);

// bad interface for update method methods ts/tsv return JsonNode* while td/tdv return int
// update
int jsonUpdatetd(void *src, char type, JsonNode *root);
JsonNode *jsonUpdatend(JsonNode *src, JsonNode *root);
#define jsonUpdatendl(src, root, args...) jsonUpdatend(src, jsonReadnsl(root, ##args))
JsonNode *jsonUpdatendv(JsonNode *src, JsonNode *root, struct path **keys);
#define jsonUpdatetdl(src, type, root, args...)                                     \
  jsonUpdatetd(src, type, jsonReadnsl(root, ##args))
int jsonUpdatetdv(void *src, char type, JsonNode *root, struct path **keys);
JsonNode *jsonUpdatets(void *src, char type, JsonNode *root);
#define jsonUpdatensl(src, root, args...) jsonUpdatens(src, jsonReadnsl(root, ##args))
JsonNode *jsonUpdatensv(JsonNode *src, JsonNode *root, struct path **keys);
#define jsonUpdatetsl(src, type, root, args...)                                     \
  jsonUpdatets(src, type, jsonReadnsl(root, ##args))
JsonNode *jsonUpdatetsv(void *src, char type, JsonNode *root, struct path **keys);

// delete
JsonNode *jsonDelete(JsonNode *elem);
#define jsonDeletel(root, args...) jsonDelete(jsonReadnsl(root, ##args))
JsonNode *jsonDeletev(JsonNode *root, struct path **keys);

// output json structure and children as string
int jsonOut(FILE *dest, char minify, JsonNode *elem);
int jsonOutRecurse(struct queue *dest, char minify, int offset,
                      JsonNode *elem);
#define jsonOutl(dest, minify, root, args...)                               \
  jsonOut(dest, minify, jsonReadnsl(root, ##args))
int jsonOutv(FILE *dest, char minify, JsonNode *root, struct path **keys);

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
JsonNode *destroy_node(struct json_pool *pool, JsonNode *elem);
JsonNode *process(struct queue *file, JsonNode *elem);

// test
void read_tests();
void array_tests();
void object_tests();
void copy_tests();
void interface_tests();

void jsonCreate_tests();
void jsonRead_tests();
void jsonUpdate_tests();

int main();
