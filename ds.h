#include <stdint.h>
#include <stddef.h>

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

#ifndef JSON_STRUCTS
#define JSON_STRUCTS 1
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
} JsonNode;

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
  JsonNode *items;
  size_t stored;
  size_t cap;
  JsonNode *next_free;
  struct json_pool *prev;
};

struct ht {
  char **keys;
  JsonNode **vals;
  size_t count;
  size_t cap;
};

union path_holds {
  size_t index;
  char *key;
};

typedef struct path {
  union path_holds path;
  uint8_t type;
  struct path *next;
} JsonPath;
#endif
