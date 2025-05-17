#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if TEST_BUILD == 1
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "cstring.h"
#include "queue.h"

/*
 * json node flags
 * The four leading bits are used to store flags relevent across all json_node
 * types The four trailing bits are used to store flags relevent just to a
 * specific type
 */
#define JSON_ELEM_IS_HEAD (1 << 7)
#define JSON_ELEM_IS_TAIL (1 << 6)

#define JSON_NUM_IS_NUM (1 << 0)
#define JSON_NUM_IS_SCIENTIFIC (1 << 1)
#define JSON_NUM_IS_INT (1 << 2)

// #define FNV_PRIME (pow(2, 40) + pow(2, 8) + 0x3b)
#define FNV_PRIME (1099511628091)
#define FNV_OFFSET_BASIS (14695981039346656037)

/*
 * Possible type values
 * 0 and 1 are internal
 * 2 to 6 are actual types
 */
#define META_INVALID (0)
#define META_FREE (1)
#define JSON_ELEMENT (1 << 1)
#define JSON_LITERAL (1 << 2)
#define JSON_STR (1 << 3)
#define JSON_NUM (1 << 4)
#define JSON_ARRAY (1 << 5)
#define JSON_OBJECT (1 << 6)

/*
 * Possible values for literal
 */
#define JSON_TRUE (0)
#define JSON_FALSE (1)
#define JSON_NULL (2)

/*
 * union so we can store all possible types of json values
 * l, d, s, a, and o are for holding actual json types
 * n is for holding the pointer to the next free node
 */
union json_union {
  char l;
  double d;
  char *s;
  struct json_node *a;
  struct ht *o;
  struct json_node *n;
};

/*
 * Actual node
 * The field `contents` stores the data of this node.
 * The field `type` stores the type of this node.
 * The field `flags` stores metadata abouth the type/data.
 *
 * We make the assumption that almost every node is going to be stored in an
 * array or object. As both are implemented as linked lists we include a `prev`
 * and `next` field. If (flags & JSON_ELEM_IS_HEAD) then prev goes to tail. If
 * (flags & JSON_ELEM_IS_TAIL) then next goes to head.
 */
typedef struct json_node {
  union json_union contents;
  char type;
  char flags;
  struct json_node *prev;
  struct json_node *next;
} JSON_Node;

/* Just a linked list */
/*
struct json_array {
        struct json_array_node **head;
        size_t nodes;
};
*/

/*
 * individual array node
 */
/*
struct json_array_node {
        union json_union *node;
        struct json_array_node *next;
};
*/

/* Linked list for now, eventually will need to be a real hashmap */
/*
struct json_object {
        struct json_array_node **head;
        size_t nodes;
};
*/

/*
 * Pool allocator
 */
struct json_pool {
  JSON_Node *items;
  size_t stored;
  size_t cap;
  JSON_Node *next_free;
  struct json_pool *prev;
};

struct ht {
  char **keys;
  JSON_Node **vals;
  size_t count;
  size_t cap;
};

union path_holds {
  size_t index;
  char *key;
};

struct path {
  union path_holds path;
  uint8_t type;
  struct path *next;
};

/*
 * Initializes this library.
 */
int jsonInit();

/*
 * Opens `filename` and returns root of the JSON document.
 * Fails if the JSON document provided is invalid.
 */
JSON_Node *jsonOpen(const char *fileName);

/*
 * Closes `filename` terminating all associated nodes.
 * Shallow copied nodes derived from members of the file are also terminated.
 */
void jsonClose(const char *fileName);

/*
 * Terminates all resources used by this library.
 */
int jsonEnd();

/*
 * Expresses a string as a key to be used when accessing a object's fields.
 */

// struct path *_KEY(char* key);
#define _KEY(k)                                                                \
  &((struct path){.path.key = k, .type = JSON_OBJECT, .next = NULL})

/*
 * Expresses an offset as an index to be used when accessing an array's fields.
 */
#define _INDEX(i)                                                              \
  &((struct path){.path.index = i, .type = JSON_ARRAY, .next = NULL})

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
JSON_Node *jsonNew();

/*
 * Creates a new node under `root` with the type `type` and the value `val`.
 *
 * Paths are given execl style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
JSON_Node *jsonCreatel(JSON_Node *node, JSON_Node *root, ...);

/*
 * Creates a new node under `root` with the type `type` and the value `val`.
 *
 * Paths are given execv style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
JSON_Node *jsonCreatev(JSON_Node *node, JSON_Node *root, struct path **keys);

/*
 * Returns the node at the provided path below the `root`.
 *
 * Paths are given execl style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
JSON_Node *jsonReadl(JSON_Node *root, ...);

/*
 * Returns the node at the provided path below the `root`.
 *
 * Paths are given execv style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
JSON_Node *jsonReadv(JSON_Node *root, struct path **keys);

/*
 * Returns a deep copy of the node `elem` and its child nodes.
 */
JSON_Node *jsonCopy(JSON_Node *elem);

/*
 * Returns a deep copy of the node and its child nodes at the provided path
 * below the `root`.
 *
 * Paths are given execl style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
#define jsonCopyl(root, args...) jsonCopy(jsonReadl(root, ##args))

/*
 * Returns a deep copy of the node and its child nodes at the provided path
 * below the `root`.
 *
 * Paths are given execv style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
JSON_Node *jsonCopyv(JSON_Node *root, struct path **keys);

/*
 * Updates the provided node `elem` to be type `type` and hold value `val`.
 */
JSON_Node *jsonUpdate(JSON_Node *src, JSON_Node *root);

/*
 * Updates the provided node `elem` to be type `type` and hold value `val`.
 *
 * Paths are given execl style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
#define jsonUpdatel(src, root, args...) jsonUpdate(src, jsonReadl(root, ##args))

/*
 * Updates the provided node `elem` to be type `type` and hold value `val`.
 *
 * Paths are given execv style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
JSON_Node *jsonUpdatev(JSON_Node *src, JSON_Node *root, struct path **keys);

/*
 * Deletes the node `elem`.
 */
JSON_Node *jsonDelete(JSON_Node *elem);

/*
 * Deletes the node `elem`.
 *
 * Paths are given execl style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
#define jsonDeletel(root, args...) jsonDelete(jsonReadl(root, ##args))

/*
 * Deletes the node `elem`.
 *
 * Paths are given execv style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
JSON_Node *jsonDeletev(JSON_Node *root, struct path **keys);

/*
 * Gets the length of the string held by the node `root`.
 */
size_t jsonStrlen(JSON_Node *root);

/*
 * Gets the length of the string held by the node `root`.
 *
 * Paths are given execl style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
#define jsonStrlenl(root, args...) jsonStrlen(jsonReadl(root, ##args))

/*
 * Gets the length of the string held by the node `root`.
 *
 * Paths are given execv style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
size_t jsonStrlenv(JSON_Node *root, struct path **keys);

/*
 * Write the node `elem` as a JSON string to `dest`.
 * If min is anything other than 0 then we minify the output so there is no
 * whitespace.
 */
int jsonString(FILE *dest, char minify, JSON_Node *elem);
int jsonStringRecurse(struct queue *dest, char minify, int offset,
                      JSON_Node *elem);

/*
 * Write the node `elem` as a JSON string to `dest`.
 * If min is anything other than 0 then we minify the output so there is no
 * whitespace.
 *
 * Paths are given execl style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
#define jsonStringl(dest, minify, root, args...)                               \
  jsonString(dest, minify, jsonReadl(root, ##args))

/*
 * Write the node `elem` as a JSON string to `dest`.
 * If min is anything other than 0 then we minify the output so there is no
 * whitespace.
 *
 * Paths are given execv style.
 * The function is smart to figure out whether you want to access a key or
 * index.
 */
int jsonStringv(FILE *dest, char minify, JSON_Node *root, struct path **keys);

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

// pool
int init_pool(struct json_pool *pool, size_t size);
int destroy_pool(struct json_pool *pool);
struct json_pool *double_pool(struct json_pool **pool);

// internal JSON_Node functions
static inline int is_whitespace(char c);
void get_next(char *outer, struct queue *store);
static inline char get_sep(struct queue *store);
static inline int is_json_literal(char *str);
static inline int is_json_str(char *str);
static inline int is_part_of_num(char c);
int is_json_num(char *str);
static inline int is_json_array(char *str);
static inline int is_json_object(char *str);
int identify(char *str, JSON_Node *elem);
static inline char get_json_literal(const char *ptr);
char *get_json_str(struct queue *read, struct queue *scratch);
static inline double get_json_num(char *str);
JSON_Node *new_node(struct json_pool *pool);
JSON_Node *copy_json_node(JSON_Node *dest, JSON_Node *src);
JSON_Node *destroy_node(struct json_pool *pool, JSON_Node *elem);
JSON_Node *process(struct queue *file, JSON_Node *elem);

// array
int array_insert_node(JSON_Node *array, JSON_Node *elem, size_t pos);
int array_add_node(JSON_Node *array, JSON_Node *elem);
int array_insert_node(JSON_Node *array, JSON_Node *elem, size_t pos);
int array_destroy_node(struct json_pool *pool, JSON_Node *array,
                       JSON_Node *elem);
JSON_Node *array_get_nth(JSON_Node *array, size_t n);
JSON_Node *copy_json_array(JSON_Node *dest, JSON_Node *src);
JSON_Node *get_json_array(struct queue *file, struct queue *scratch,
                          JSON_Node *elem);

// hash table
uint64_t fnv(const char *data, size_t len);
static inline uint64_t fnv_str(const char *data);
JSON_Node *ht_insert(struct ht *table, char *key, JSON_Node *val);
JSON_Node *ht_insert_direct(struct ht *table, char *key, JSON_Node *val);
JSON_Node *ht_find(struct ht *table, char *key);
JSON_Node *ht_set(struct ht *table, char *key, JSON_Node *elem);
JSON_Node *ht_del(struct json_pool *pool, struct ht *table, const char *key);
struct ht *ht_grow(struct ht *old, size_t cap);
void ht_destroy(struct json_pool *pool, struct ht *table);
JSON_Node *get_json_object(struct queue *file, struct queue *scratch,
                           JSON_Node *elem);

void read_tests();
void array_tests();
void object_tests();
void copy_tests();
void interface_tests();

int main();
