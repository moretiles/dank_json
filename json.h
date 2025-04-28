#include "queue.h"

/* 
 * json element flags
 * The four leading bits are used to store flags relevent across all json_element types
 * The four trailing bits are used to store flags relevent just to a specific type
 */
#define JSON_ELEM_IS_HEAD (1 << 7)
#define JSON_ELEM_IS_TAIL (1 << 6)

#define JSON_NUM_IS_NUM (1 << 7)
#define JSON_NUM_IS_SCIENTIFIC (1 << 1)
#define JSON_NUM_IS_INT (1 << 2)

/* 
 * enum for element types in json
 * 0 and 1 are internal
 * 2 to 6 are actual types
 */
enum json_type {
	META_INVALID = 0,
	META_FREE = 1,
	JSON_LITERAL = 2,
	JSON_STR = 3,
	JSON_NUM = 4,
	JSON_ARRAY = 5,
	JSON_OBJECT = 6
};

/*
 * Maybe
 */
enum json_literal {
	JSON_TRUE = 0,
	JSON_FALSE = 1,
	JSON_NULL = 2
};

/* 
 * union so we can store all possible types of json values 
 * l, d, s, a, and o are for holding actual json types
 * n is for holding the pointer to the next free element
 */
union json_union {
	enum json_literal l;
	double d;
	char *s;
	struct json_element *a;
	struct json_element *o;
	struct json_element *n;
};

/*
 * Actual element
 * The field `contents` stores the data of this element.
 * The field `type` stores the type of this element.
 * The field `flags` stores metadata abouth the type/data.
 *
 * We make the assumption that almost every element is going to be stored in an array or object.
 * As both are implemented as linked lists we include a `prev` and `next` field.
 * If (flags & JSON_ELEM_IS_HEAD) then prev goes to tail.
 * If (flags & JSON_ELEM_IS_TAIL) then next goes to head.
 */
struct json_element {
	union json_union contents;
	enum json_type type;
	char flags;
	struct json_element *prev;
	struct json_element *next;
};

/* Just a linked list */
/*
struct json_array {
	struct json_array_element **head;
	size_t elements;
};
*/

/*
 * individual array element
 */
/*
struct json_array_element {
	union json_union *element;
	struct json_array_element *next;
};
*/

/* Linked list for now, eventually will need to be a real hashmap */
/*
struct json_object {
	struct json_array_element **head;
	size_t elements;
};
*/

/*
 * Pool allocator
 */
struct json_pool {
	struct json_element *items;
	size_t stored;
	size_t cap;
	struct json_element *next_free;
    struct json_pool *prev;
};

int json_lib_init();

/*
 * Init pool
 */
int init_pool(struct json_pool *pool, size_t size);

/*
 * Destroy element
 */
struct json_element *destroy_element(struct json_pool *pool, struct json_element *elem);

int array_add_element(struct json_element *array, struct json_element *elem);

int array_destroy_element(struct json_pool *pool, struct json_element *array, struct json_element *elem);

struct json_element *array_get_nth(struct json_element *array, size_t n);

/*
 * Destroy pool
 */
int destroy_pool(struct json_pool *pool);

/*
 * New element
 */
struct json_element *new_element(struct json_pool *pool);

static inline int is_whitespace(char c);

void get_next(char *outer, struct queue *store);

/*
 * Return first non-whitespace character
 */
char get_sep(struct queue *store);

static inline int is_json_literal(char *str);

static inline int is_json_str(char *str);

static inline int is_part_of_num(char c);

int is_json_num(char *str);

static inline int is_json_array(char *str);

static inline int is_json_object(char *str);

int identify(char *str, struct json_element *elem);

enum json_literal get_json_literal(const char *ptr);

char *get_json_str(struct queue *read, struct queue *scratch);

double get_json_num(char *str);

struct json_element *get_json_array(FILE *file);

struct json_element *get_json_object(FILE *file);

struct json_element *process(FILE *file, struct json_element *elem, char *fragment);

void tests();

int main();
