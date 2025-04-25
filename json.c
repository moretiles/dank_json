#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#include "json.h"

struct queue read;
struct queue scratch;

int json_lib_init(){
	char *ptr = NULL;
	/*
	 * Maybe check env variables for max sizes
	 */
	if(read.chars != NULL && scratch.chars != NULL){
		return 1;
	}

	ptr = malloc(sizeof(struct json_element) * 1024 * 1024);
	if(ptr == NULL){
		return 2;
	}
	read.chars = ptr;
	read.base = 0;
	read.pos = 0;
	read.cap = sizeof(struct json_element) * 1024 * 1024;

	ptr = malloc(8 * 1024 * 1024);
	if(ptr == NULL){
		return 2;
	}
	scratch.chars = ptr;
	scratch.base = 0;
	scratch.pos = 0;
	scratch.cap = 8 * 1024 * 1024;

	return 0;
}

/*
 * Init pool
 */
int init_pool(struct json_pool *pool){
    if(pool == NULL){
        return 1;
    }
	struct json_element **storage = malloc(sizeof(struct json_pool) * 1024 * 1024);
	if (storage == NULL){
		return 2;
	}
	pool->items = storage;
	pool->stored = 0;
	pool->cap = 1024 * 1024;
	pool->next_free = NULL;
	return 0;
}

/*
 * Destroy element
 */
struct json_element *destroy_element(struct json_pool *pool, struct json_element *elem){
	if(!pool || !elem || elem->type == META_FREE){
		return NULL;
	}

	if(elem->type == JSON_STR){
		free(elem->contents.s);
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
	if(head->prev){
		tail = array->contents.a->prev;
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
    if(array == NULL){
        return NULL;
    }
	struct json_element *elem = array; 
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

/*
 * Destroy pool
 */
int destroy_pool(struct json_pool *pool){
    if(pool == NULL){
        return 1;
    }

	size_t i = 0;
	for(i = 0; i < pool->cap; i++){
		destroy_element(pool, (pool->items)[i]);
	}
	return 0;
}

/*
 * New element
 */
struct json_element *new_element(struct json_pool *pool){
    if(pool == NULL){
        return NULL;
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
		now_taken = (struct json_element *) (pool + sizeof(struct json_element) * pool->stored);
	}
	memset(now_taken, 0, sizeof(struct json_element));
	return now_taken;
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
	while (!is_whitespace(c)) {
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
	outer[read_in + 1] = '\x00';
}

/*
 * Return first non-whitespace character
 */
char get_sep(struct queue *store){
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

struct json_element identify(char *str) {
	struct json_element elem;
	if((elem.flags = is_json_literal(str))){
		elem.type = JSON_LITERAL;
	} else if ((elem.flags = is_json_str(str))) {
		elem.type = JSON_STR;
	} else if ((elem.flags = is_json_num(str)) && (elem.flags & JSON_NUM_IS_NUM)) {
		elem.type = JSON_NUM;
	} else if ((elem.flags = is_json_array(str))) {
		elem.type = JSON_ARRAY;
	} else if ((elem.flags = is_json_object(str))) {
		elem.type = JSON_OBJECT;
	} else { 
		elem.flags = 0;
		elem.type = META_INVALID;
	}
	return elem;
}

enum json_literal get_json_literal(const char *ptr) {
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

	ret = malloc(sizeof(char) * (scratch->pos + 1));
	if (ret == NULL){
		return NULL;
	}
	strncpy(ret, scratch->chars, scratch->pos);

	scratch->base = 0;
	scratch->pos = 0;	
	return ret;
}

double get_json_num(char *str) {
	double out;
	if(str == NULL){
		return 0.0;
	}

	sscanf(str, "%le", &out);
	return out;
}

struct json_element *get_json_array(FILE *file) {
	struct json_element *new_array;
	struct json_element current;
	char sep = ',', error = 0;

    if(file == NULL){
        return NULL;
    }

	while(!error && sep != ']'){
       		get_next(scratch.chars, &read);
		//printf("%s\n", scratch.chars);
		current = identify(scratch.chars);
		current.contents = process(file, current.type, scratch.chars);
		/*
		Allocate new element from pool;
		array_add_element(new_array, pool_element);
		*/

		sep = get_sep(&read);
	}

	if(!error){
		return new_array;
	} else {
		//array_destroy(read, new_array);
		return NULL;
	}
}

struct json_element *get_json_object(FILE *file) {
	if(file == NULL){
		return NULL;
	}
	return NULL;
}

union json_union process(FILE *file, enum json_type type, char *fragment) {
    union json_union value;
    /*
     * Might need to rethink how I handle get_next and process because right now
     * it is not possible to return an error saying an attempt to process failed.
    if(file == NULL || fragment == NULL){
        return NULL;
    }
    */

	switch(type){
		case JSON_LITERAL:
			value.l = get_json_literal(fragment);
			break;
		case JSON_STR:
			value.s = get_json_str(&read, &scratch);
			break;
		case JSON_NUM:
			value.d = get_json_num(fragment);
			//sscanf(fragment, "%le", &(value.d));
			break;
		case JSON_ARRAY:
			value.a = get_json_array(file);
			break;
		case JSON_OBJECT:
			value.o = get_json_object(file);
			break;
		default:
			/* print_error_messages_to_stderr(); */
			break;
	}
	return value;
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
	//struct json_element root = {};
	//char outer[999];
       	//get_next(outer, stdin);
	//root.type = identify(outer);
	//root.contents = process(stdin, root.type);
	
	tests();

	json_lib_init();
	FILE *actual_json = fopen("./test.json", "r");
	FILE *test_json = fopen("./test2.json", "r");
	fenqueue(test_json, &read, 3 * 1024 * 1024);
	/*
	void *store_chars = malloc(3 * 1024 * 1024);
	if (store_chars == NULL){
		exit(0);
	}
	struct queue store = {store_chars, 0, 0, 3 * 1024 * 1024};
	char outer[99];
	fenqueue(actual_json, &read, 3 * 1024 * 1024);
	get_next(scratch.chars, &read);
	get_next(scratch.chars, &read);	
	get_next(scratch.chars, &read);	
	get_next(scratch.chars, &read);	
	get_next(scratch.chars, &read);	
	*/
//	printf("%s\n", outer);
//	printf("%c\n", fgetc(actual_json));
//	get_next(outer, actual_json);	
//	printf("%s\n", outer);
//	get_next(outer, actual_json);	
//	printf("%s\n", outer);
//	get_next(outer, actual_json);	
//	printf("%s\n", outer);
       	get_next(scratch.chars, &read);
	printf("%s\n", scratch.chars);
	struct json_element root = identify(scratch.chars);
	root.contents = process(actual_json, root.type, scratch.chars);
	printf("%s\n", root.contents.s);
	//printf("%s\n", root.contents.s);
	//printf("%E\n", 3.0);

	fclose(actual_json);
}
