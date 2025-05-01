#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#include "json.h"

#ifndef MAX_STR_SIZE
#define MAX_STR_SIZE (4 * 1024 * 1024)
#endif

struct queue scratch;
struct json_pool *elems;

int json_lib_init(){
	void *ptr = NULL;
	/*
	 * Maybe check env variables for max sizes
	 */
	if(scratch.chars != NULL && elems != NULL){
		return 1;
	}

	ptr = malloc(2 * MAX_STR_SIZE);
	if(ptr == NULL){
		return 3;
	}
	scratch.chars = ptr;
	scratch.base = 0;
	scratch.pos = 0;
	scratch.cap = 2 * MAX_STR_SIZE;

    ptr = calloc(1, sizeof(struct json_pool));
    if(!ptr){
        return 4;
    }
    elems = ptr;
    init_pool(elems, 1024 * 1024);

	return 0;
}

struct json_element *json_open(char *fileName){
    struct queue *new = NULL;
    char *chars = NULL;
    FILE *file = NULL;
    struct json_element *root = NULL;

    new = calloc(1, sizeof(struct queue));
    if(new == NULL){
        return NULL;
    }

    file = fopen(fileName, "r");
    if(file == NULL){
        return NULL;
    }

	chars = malloc(2 * MAX_STR_SIZE);
	if(chars == NULL){
        free(new);
		return NULL;
	}

    root = new_element(elems);
	if(root == NULL){
        free(chars);
        free(new);
		return NULL;
	}

	new->chars = chars;
	new->base = 0;
	new->pos = 0;
	new->cap = 2 * MAX_STR_SIZE;
    new->file = file;

    fenqueue(new, 2 * MAX_STR_SIZE);
    process(new, root); 
    fclose(file);
    free(chars);
    free(new);

    return root;
}

int json_lib_close(){
    int ret = 0;

    ret = destroy_pool(elems);
    elems = NULL;
    return ret;
}

/*
 * Init pool
 */
int init_pool(struct json_pool *pool, size_t size){
    if(pool == NULL){
        return 1;
    }

	pool->items = calloc(size, sizeof(struct json_pool));
	if (pool->items == NULL){
		return 2;
	}
	pool->stored = 0;
	pool->cap = size;
	pool->next_free = NULL;
	return 0;
}

/*
 * Destroy pool
 */
int destroy_pool(struct json_pool *pool){
    if(pool == NULL){
        return 1;
    }

    if(pool->prev != NULL){
        destroy_pool(pool->prev);
    }

	size_t i = 0;
	for(i = 0; i < pool->cap; i++){
		destroy_element(pool, &((pool->items)[i]));
	}
    if(pool->items != NULL){
        free(pool->items);
        pool->items = NULL;
    }

    free(pool);
    pool = NULL;

	return 0;
}

struct json_pool *double_pool(struct json_pool **pool){
        struct json_pool *ptr = calloc(1, sizeof(struct json_pool));

        if(!ptr){
            return NULL;
        }

        init_pool(ptr, elems->cap * 2);
        ptr->prev = *pool;
        *pool = ptr;
        return *pool;
}

/*
 * New element
 */
struct json_element *new_element(struct json_pool *pool){
    if(pool == NULL){
        return NULL;
    }

    if(pool->stored == pool->cap){
        double_pool(&elems);
    }

	struct json_element *now_taken = NULL;
	if(pool->next_free){
		now_taken = pool->next_free;
		if(pool->next_free->type == META_FREE && pool->next_free->contents.n){
			pool->next_free = pool->next_free->contents.n;
		} else {
			pool->next_free = NULL;
		}
	} else {
		now_taken = (struct json_element *) (pool->items + sizeof(struct json_element) * pool->stored++);
	}
	memset(now_taken, 0, sizeof(struct json_element));
	return now_taken;
}

/*
 * Destroy element
 */
struct json_element *destroy_element(struct json_pool *pool, struct json_element *elem){
	if(!pool || !elem || elem->type == META_FREE){
		return NULL;
	}

	if(elem->type == JSON_STR && elem->contents.s != NULL){
		free(elem->contents.s);
        elem->contents.s = NULL;
	} else if(elem->type == JSON_ARRAY){
		//json_array_free(elem->contents.a);
	} else if(elem->type == JSON_OBJECT){
		//json_object_free(elem->contents.o);
	}

	elem->contents.n = pool->next_free;
	elem->type = META_FREE;
	elem->flags = 0;
	pool->next_free = elem;
	return elem;
}

int array_add_element(struct json_element *array, struct json_element *elem){
	struct json_element *head = NULL, *tail = NULL;
	if(!elem || !array || array->type != JSON_ARRAY){
		return 1;
	}
	head = array->contents.a;
	if(head && head->prev){
		tail = head->prev;
	};

	if(!head){
		array->contents.a = elem;
		elem->flags |= (JSON_ELEM_IS_HEAD | JSON_ELEM_IS_TAIL);
		elem->prev = NULL;
		elem->next = NULL;
	} else if (head->prev == NULL || head->next == NULL){
		head->prev = elem;
		head->next = elem;
		head->flags &= (0xff - JSON_ELEM_IS_TAIL);
		elem->prev = head;
		elem->next = head;
		elem->flags |= JSON_ELEM_IS_TAIL;
	} else {
		elem->prev = tail;
		tail->flags &= (0xff - JSON_ELEM_IS_TAIL);
		elem->flags |= JSON_ELEM_IS_TAIL;
		elem->next = head;

		tail->next = elem;
		head->prev = elem;
	}

	return 0;
}

int array_destroy_element(struct json_pool *pool, struct json_element *array, struct json_element *elem){
	struct json_element *prev = NULL, *next = NULL;

	/* 
	 * It should always be the case that if prev exists then next exists and vice versa
	 */
	if(!pool || !array || !elem || array->type != JSON_ARRAY){
		return 1;
	}

	if(elem->prev && elem->next){
		prev = elem->prev;
		next = elem->next;

		if(elem->flags & JSON_ELEM_IS_HEAD){
			next->flags |= JSON_ELEM_IS_HEAD;
			array->contents.a = next;
		}
		prev->next = next;
		if(elem->flags & JSON_ELEM_IS_TAIL){
			prev->flags |= JSON_ELEM_IS_HEAD;
		}
		next->prev = prev;
	}
	elem->prev = NULL;
	elem->next = NULL;

	destroy_element(pool, elem);
	return 0;
}

struct json_element *array_get_nth(struct json_element *array, size_t n){
	struct json_element *elem = array; 
    if(array == NULL && array->contents.a){
        return NULL;
    }
    elem = array->contents.a;
	while(n > 0 && elem){
		n--;
		elem = elem->next;
	}
    if(n > 0){
        return NULL;
    } else {
	    return elem;
    }
}

static inline int is_whitespace(char c) {
	return c == ' ' ||
		c == '\n' ||
		c == '\r' ||
		c == '\t';
}

void get_next(char *outer, struct queue *store) {
	if (outer == NULL || store == NULL){
		return;
	}
	strcpy(outer, "");
	char c = ' ';
	size_t read_in = 0;
	//char outer[999] = "";

	while (is_whitespace(c)) {
		//printf("whitespace found %c\n", c);
		dequeuec(store, &c);
	}
	if (c == '"' || c == '[' || c == '{'){
		outer[0] = c;
		outer[1] = '\x00';
		return;
	}
	while (!is_whitespace(c) && read_in < 50) {
		if(c == ',' || c == ':'){
			queueRewind(store, 1);
			break;
		}
		outer[read_in] = c;
		//printf("%s\n", outer);
		if (c == '[' || c == '{'){
			break;
		}
		dequeuec(store, &c);
		read_in += 1;
		//printf("not whitespace found %c\n", c);
	}
	outer[read_in] = '\x00';
}

/*
 * Return first non-whitespace character
 */
static inline char get_sep(struct queue *store){
	char c = ' ';
	while(is_whitespace(c)){
		dequeuec(store, &c);
	}

	return c;
}


static inline int is_json_literal(char *str) {
	return !strcmp(str, "true") ||
		!strcmp(str, "false") ||
		!strcmp(str, "null");
}

static inline int is_json_str(char *str) {
	return strlen(str) >= 1 && str[0] == '"';
}

static inline int is_part_of_num(char c) {
	return c == 'e' || 
		c == 'E' ||
		c == '.' ||
		(c >= '0' && c <= '9');
}

int is_json_num(char *str) {
	char c = '\x00';
	size_t i = 0, e = '\x00', dot = '\x00';
	int ret = 0;
	for(i = 0; i < strlen(str); i++){
		c = str[i];
		if (c == '-' || c == '+'){
			if (i != 0 && str[i - 1] != 'e' && str[i - 1] != 'E'){
				return false;
			}
		}
		else if (!is_part_of_num(c)) {
			return false;
		}

		if (c == 'e' || c == 'E') {
			if (e) {
				return false;
			} else {
				ret |= JSON_NUM_IS_SCIENTIFIC;
				e = i;
			}
		} else if (c == '.') {
			if (dot){
				return false;
			} else {
				dot = i;
			}
		}
	}
	if (!dot && (!(ret & JSON_NUM_IS_SCIENTIFIC) || str[e + 1] != '-')){
		ret |= JSON_NUM_IS_INT;
	}
	return ret |= JSON_NUM_IS_NUM;
}

static inline int is_json_array(char *str) {
	return strlen(str) >= 1 && str[0] == '[';
}

static inline int is_json_object(char *str) {
	return strlen(str) >= 1 && str[0] == '{';
}

static inline enum json_literal get_json_literal(const char *ptr) {
	if(ptr == NULL){
		return JSON_NULL;
	} else {
		if(!strcmp(ptr, "true")){
			return JSON_TRUE;
		} else if (!strcmp(ptr, "false")) {
			return JSON_FALSE;
		} else {
			return JSON_NULL;
		}
	}
}

char *get_json_str(struct queue *read, struct queue *scratch) {
	char *ret;
	char c = '\x00';
	size_t backslash = 0, hex = 0;
	int expect_hex = false;
	if(read == NULL || read->chars == NULL || scratch == NULL || scratch->chars == NULL){
		return NULL;
	}

	while(!dequeuec(read, &c)){
		if (c == '\\') {
			backslash++;
		} else {
			if (backslash % 2){
				//printf("%c\n", c);
				switch (c) {
					case 'u':
						hex = 0;
						expect_hex = true;
						break;
					case '"':
					case '/':
					case 'b':
					case 'f':
					case 'n':
					case 'r':
					case 't':
						break;
					default:
						return NULL;
						break;
				}
			} else {
				if (expect_hex) {
					if(hex >= 4){
						expect_hex = false;
						hex = 0;
					} else if(!('0' <= c && c <= '9') && !('a' <= c && c <= 'f') && !('A' <= c && c <= 'F')){
						return NULL;	
					}
					hex++;
				} else if (c == '"') {
					break;
				}
			}
			backslash = 0;
		}

		if (enqueuec(scratch, c)){
			break;
		}
	}

	ret = malloc(scratch->pos + 1);
	if (ret == NULL){
		return NULL;
	}
	strncpy(ret, scratch->chars, scratch->pos);
    ret[scratch->pos] = '\0';

	scratch->base = 0;
	scratch->pos = 0;	
	return ret;
}

static inline double get_json_num(char *str) {
	double out;
	if(str == NULL){
		return 0.0;
	}

	sscanf(str, "%le", &out);
	return out;
}

struct json_element *get_json_array(struct queue *file, struct queue *scratch) {
	struct json_element *new_array = NULL, *from_pool = NULL;
	struct json_element current;
	char sep = ',', error = 0;

    printf("inside array\n");

    if(file == NULL || scratch == NULL){
        return NULL;
    }
    new_array = new_element(elems);
    new_array->type = JSON_ARRAY;

	while(!error && sep != ']'){
		process(file, &current);
        from_pool = new_element(elems);
        memcpy(from_pool, &current, sizeof(struct json_element));
		array_add_element(new_array, from_pool);

		sep = get_sep(file);
        printf("%c\n", sep);
	}

	if(!error){
        printf("end\n");
		return new_array;
	} else {
		//array_destroy(read, new_array);
		return NULL;
	}
}

struct json_element *get_json_object(struct queue *file, struct queue *scratch) {
	if(file == NULL || scratch == NULL){
		return NULL;
	}
	return NULL;
}

struct json_element *process(struct queue *file, struct json_element *elem) {
    char *fragment = NULL;
    char tmp_flags = 0;

    fragment = malloc(sizeof(char) * 999);

    if(file == NULL || elem == NULL || fragment == NULL || fragment == NULL){
        return NULL;
    }

    get_next(fragment, file);

	if((tmp_flags = is_json_literal(fragment))){
		elem->type = JSON_LITERAL;
	} else if ((tmp_flags = is_json_str(fragment))) {
		elem->type = JSON_STR;
	} else if ((tmp_flags = is_json_num(fragment)) && (tmp_flags & JSON_NUM_IS_NUM)) {
		elem->type = JSON_NUM;
	} else if ((tmp_flags = is_json_array(fragment))) {
		elem->type = JSON_ARRAY;
	} else if ((tmp_flags = is_json_object(fragment))) {
		elem->type = JSON_OBJECT;
	} else { 
		elem->type = META_INVALID;
	}
	elem->flags = tmp_flags;

	switch(elem->type){
		case JSON_LITERAL:
			elem->contents.l = get_json_literal(fragment);
			break;
		case JSON_STR:
			elem->contents.s = get_json_str(file, &scratch);
			break;
		case JSON_NUM:
			elem->contents.d = get_json_num(fragment);
			break;
		case JSON_ARRAY:
			memcpy(elem, get_json_array(file, &scratch), sizeof(struct json_element));
			break;
		case JSON_OBJECT:
            memcpy(elem, get_json_object(file, &scratch), sizeof(struct json_element));
			break;
		default:
			/* print_error_messages_to_stderr(); */
			break;
	}

    free(fragment);
    fragment = NULL;
    
    return elem;
}

void tests(){
	assert(is_whitespace(' '));
	assert(is_whitespace('\n'));
	assert(is_whitespace('\r'));
	assert(is_whitespace('\t'));
	assert(is_whitespace('a') == false);

	assert(is_json_literal("true"));
	assert(is_json_literal("false"));
	assert(is_json_literal("null"));
	assert(is_json_literal("bob") == false);

	assert(is_json_str("\"bob\""));
	assert(is_json_str("\"bob"));
	assert(is_json_str("bob") == false);

	/*
	char test[10];
	FILE *test_file = fopen("./test.txt", "r");
	fgets(test, 10, test_file);
	printf("%s\n", test);
	printf("%i\n", is_json_str(test));
	fgets(test, 10, test_file);
	printf("%s\n", test);
	fclose(test_file);
	*/

	assert(is_part_of_num('0'));
	assert(is_part_of_num('9'));
	assert(is_part_of_num('e'));
	assert(is_part_of_num('E'));
	assert(is_part_of_num('.'));
	assert(is_part_of_num('a') == false);

	assert(is_json_num("123") & JSON_NUM_IS_INT);
	assert(is_json_num("123.33") & JSON_NUM_IS_NUM);
	assert(is_json_num("123E-23") & JSON_NUM_IS_SCIENTIFIC);
	assert(is_json_num("+123.56E-23") & JSON_NUM_IS_NUM);
	assert(is_json_num("-123..E-23") == false);
	assert(is_json_num("-123E.E-23") == false);

	assert(is_json_array("["));
	assert(is_json_array("[ a, b, c ]"));
	assert(is_json_object("{a\": 3 }"));
	assert(is_json_object("{ \"a\": 3 }"));
}

int main() {
	tests();
	json_lib_init();

	struct json_element *array = json_open("./test.json");

	printf("%p\n", &array);
    struct json_element *interior = array_get_nth(array_get_nth(array, 3), 3);
	printf("%f\n", array_get_nth(interior, 0)->contents.d);
	printf("%i\n", array_get_nth(interior, 0)->type);
	printf("%i\n", array_get_nth(interior, 1)->contents.l);
	printf("%i\n", array_get_nth(interior, 1)->type);
	printf("%s\n", array_get_nth(interior, 2)->contents.s);
	printf("%i\n", array_get_nth(interior, 2)->type);

	json_lib_close();
}
