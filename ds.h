#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef JSON_STRUCTS
#define JSON_STRUCTS 1
/*
 * json node flags
 * The four leading bits are used to store flags relevent across all json_node
 * types The four trailing bits are used to store flags relevent just to a
 * specific type
 */
#define JSON_ELEM_IS_HEAD (1 << 7)
#define JSON_ELEM_IS_TAIL (1 << 6)
#define JSON_ELEM_CONTENTS_ON_HEAP (1 << 5)
#define JSON_ELEM_IS_OPEN_FILE (1 << 4)
//#define ... (1 << 3)
#define JSON_NUM_IS_INT (1 << 2)
#define JSON_NUM_IS_SCIENTIFIC (1 << 1)
#define JSON_NUM_IS_NUM (1 << 0)

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
#define JSON_CLOSE (1 << 7)

typedef uint8_t jsonType;
typedef uint8_t jsonFlags;
typedef uint8_t jsonLiteral;

/*
 * union so we can store all possible types of json values
 * l, d, s, a, and o are for holding actual json types
 * n is for holding the pointer to the next free node
 */
union json_union {
    jsonLiteral l;
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
    jsonType type;
    jsonFlags flags;
    struct json_node *prev;
    struct json_node *next;
    char *key;
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
    JsonNode **vals;
    size_t count;
    size_t cap;
    JsonNode *head_val;
    JsonNode *tail_val;
};

union path_holds {
    size_t index;
    char *key;
};

/*
typedef struct path {
    union path_holds path;
    uint8_t type;
    struct path *next;
} JsonPath;
*/

struct json_path_partial {
    union path_holds path;
    jsonType type;
    struct json_path_partial *prev;
};

typedef struct json_path {
    struct json_path_partial *head;
    struct json_path_partial *tail;
    size_t members;
} JsonPath;
#endif
