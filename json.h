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

#define FNV_PRIME (pow(2, 40) + pow(2, 8) + 0x3b)
#define FNV_OFFSET_BASIS (14695981039346656037)

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
	struct ht *o;
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

struct ht {
    char **keys;
    struct json_element **vals;
    size_t count;
    size_t cap;
};


int json_lib_init();
struct json_element *json_open(char *fileName);
int json_lib_close();

/*
 * Init pool
 */
int init_pool(struct json_pool *pool, size_t size);

/*
 * Destroy pool
 */
int destroy_pool(struct json_pool *pool);

/*
 * Double pool
 */
struct json_pool *double_pool(struct json_pool **pool);

/*
 * New element
 */
struct json_element *new_element(struct json_pool *pool);

/*
 * Destroy element
 */
struct json_element *destroy_element(struct json_pool *pool, struct json_element *elem);

/*
 * Array add element
 */
int array_add_element(struct json_element *array, struct json_element *elem);

/*
 * Array destroy element
 */
int array_destroy_element(struct json_pool *pool, struct json_element *array, struct json_element *elem);

/*
 * Array get nth
 */
struct json_element *array_get_nth(struct json_element *array, size_t n);

static inline int is_whitespace(char c);

void get_next(char *outer, struct queue *store);

/*
 * Return first non-whitespace character
 */
static inline char get_sep(struct queue *store);

static inline int is_json_literal(char *str);

static inline int is_json_str(char *str);

static inline int is_part_of_num(char c);

int is_json_num(char *str);

static inline int is_json_array(char *str);

static inline int is_json_object(char *str);

int identify(char *str, struct json_element *elem);

static inline enum json_literal get_json_literal(const char *ptr);

char *get_json_str(struct queue *read, struct queue *scratch);

static inline double get_json_num(char *str);

struct json_element *get_json_array(struct queue *file, struct queue *scratch, struct json_element *elem);

struct json_element *get_json_object(struct queue *file, struct queue *scratch, struct json_element *elem);

struct json_element *process(struct queue *file, struct json_element *elem);

struct json_element *copy_json_array(struct json_element *dest, struct json_element *src);
struct json_element *copy_json_object(struct json_element *dest, struct json_element *src);
struct json_element *copy_json_element(struct json_element *dest, struct json_element *src);

uint64_t fnv(const char *data, size_t len);
static inline uint64_t fnv_str(const char *data);

struct json_element *ht_insert(struct ht *table, char *key, struct json_element *val) ;
struct json_element *ht_insert_direct(struct ht *table, char *key, struct json_element *val);
struct json_element *ht_find(struct ht *table, char *key);
struct json_element *ht_set(struct ht *table, char *key, struct json_element *elem);
struct json_element *ht_del(struct json_pool *pool, struct ht *table, const char *key);
struct ht *ht_grow(struct ht *old, size_t cap);
void ht_destroy(struct json_pool *pool, struct ht *table);

struct json_element;

void read_tests();
void array_tests();
void object_tests();
void copy_tests();

int main();
