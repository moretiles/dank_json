#include "json.h"

#ifndef MAX_STR_SIZE
#define MAX_STR_SIZE (4 * 1024 * 1024)
#endif

#ifndef OBJECT_STARTING_SIZE
#define OBJECT_STARTING_SIZE (16)
#endif

#ifndef TEST_BUILD
#define TEST_BUILD (0)
#endif

struct queue scratch = { 0 };
struct ht *openFiles = NULL;
struct json_pool *elems = NULL;

int jsonLibInit() {
    void *ptr = NULL;
    // Maybe check env variables for max sizes
    if (scratch.chars != NULL || openFiles != NULL || elems != NULL) {
        return 1;
    }

    ptr = calloc(2 * MAX_STR_SIZE + 1, sizeof(char));
    if (ptr == NULL) {
        return 3;
    }
    scratch.chars = ptr;
    scratch.base = 0;
    scratch.pos = 0;
    scratch.cap = 2 * MAX_STR_SIZE;

    openFiles = ht_init(OBJECT_STARTING_SIZE);

    ptr = calloc(1, sizeof(struct json_pool));
    if (!ptr) {
        return 4;
    }
    elems = ptr;
    init_pool(elems, 1024 * 1024);

    return 0;
}

JsonNode *jsonOpen(const char *fileName) {
    struct queue *new = NULL;
    char *chars = NULL;
    FILE *file = NULL;
    JsonNode *root = NULL;

    new = calloc(1, sizeof(struct queue));
    if (new == NULL) {
        return NULL;
    }

    file = fopen(fileName, "r");
    if (file == NULL) {
        free(new);
        return NULL;
    }

    chars = calloc(2 * MAX_STR_SIZE, sizeof(char));
    if (chars == NULL) {
        fclose(file);
        free(new);
        return NULL;
    }

    root = new_node(elems);
    if (root == NULL) {
        fclose(file);
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

    root->flags |= JSON_ELEM_IS_OPEN_FILE;
    ht_insert_copy(openFiles, fileName, root);

    return root;
}

void jsonClose(const char *fileName) {
    if(fileName != NULL) {
        jsonDelete(ht_find_val(openFiles, fileName));
    }
}

int jsonLibEnd() {
    int ret = 0;

    if (scratch.chars) {
        free(scratch.chars);
        memset(&scratch, 0, sizeof(struct queue));
    }

    ht_destroy(elems, openFiles);
    openFiles = NULL;

    ret = destroy_pool(elems);
    elems = NULL;
    return ret;
}

//JsonNode *jsonCreate() {
JsonNode *_jsonCreate() {
    if (elems == NULL || scratch.chars == NULL) {
        return NULL;
    }

    return new_node(elems);
}

//JsonNode *jsonCreatetd(void *src, char type) {
JsonNode *jsonCreate(const void *src, char type) {
    JsonNode *new = NULL, *ret = NULL;

    new = _jsonCreate();
    ret = _jsonCreate();
    if (new == NULL || ret == NULL ||
            (src == NULL && !(type == JSON_ARRAY || type == JSON_OBJECT))) {
        return NULL;
    }
    new->type = type;
    ret->type = type;

    switch (type) {
    case JSON_STR:
        new->contents.s = (char *)src;
        ret = copy_json_node(ret, new);
        break;

    case JSON_NUM:
        new->contents.d = *(double *)src;
        ret = copy_json_node(ret, new);
        break;

    case JSON_LITERAL:
        new->contents.l = *(char *)src;
        ret = copy_json_node(ret, new);
        break;

    case JSON_ARRAY:
        new->contents.a = NULL;
        break;

    case JSON_OBJECT:
        ret->contents.o = ht_init(OBJECT_STARTING_SIZE);
        ret->type = JSON_OBJECT;
        if (ret->contents.o == NULL) {
            jsonDelete(ret);
            return NULL;
        }
        break;

    default:
        jsonDelete(new);
        jsonDelete(ret);
        return NULL;
        break;
    }

    memset(new, 0, sizeof(JsonNode));
    return ret;
}

// Using a macro to protect against people forgetting NULL
JsonNode *_jsonReadl(JsonNode *root, ...) {
    va_list args;
    struct json_path_partial *path = NULL;
    JsonNode *current = root;

    va_start(args, root);
    path = va_arg(args, struct json_path_partial *);
    while (current != NULL && path != NULL) {
        switch (path->type) {
        case JSON_ARRAY:
            if (current->type != JSON_ARRAY) {
                return NULL;
            }
            current = array_get_nth(current, path->path.index);
            break;

        case JSON_OBJECT:
            if (current->type != JSON_OBJECT) {
                return NULL;
            }
            current = ht_find_val(current->contents.o, path->path.key);
            break;
        }

        path = va_arg(args, struct json_path_partial *);
    }
    va_end(args);

    return current;
}

JsonNode *jsonReads(JsonNode *root, JsonPath *path) {
    if (root == NULL || path == NULL) {
        return NULL;
    }

    return jsonReads_recurse(root, path->tail);
}

JsonNode *jsonReads_recurse(JsonNode *root, struct json_path_partial *path) {
    if(path == NULL) {
        return root;
    }

    if(path->prev != NULL) {
        root = jsonReads_recurse(root, path->prev);
    }

    if(root == NULL || !jsonIsType(path->type, root)) {
        return NULL;
    }

    switch (path->type) {
    case JSON_ARRAY:
        root = array_get_nth(root, path->path.index);
        break;

    case JSON_OBJECT:
        root = ht_find_val(root->contents.o, path->path.key);
        break;

    default:
        return NULL;
        break;
    }

    return root;
}

JsonNode *jsonCreates(const void *src, char type, JsonNode *root, JsonPath *path) {
    JsonNode tmp = { .contents.l = JSON_NULL, .type = JSON_LITERAL, .prev = NULL };
    JsonNode *new = jsonCopys(&tmp, root, path);
    if(new == NULL) {
        return NULL;
    }
    return jsonUpdate(src, type, new);
}

JsonNode *_jsonCopyl(JsonNode *node, JsonNode *root, ...) {
    va_list args;
    struct json_path_partial *prev = NULL, *path = NULL, *child = NULL;
    JsonNode *current = root, *parent = root, *new = NULL;
    int created = 0;

    va_start(args, root);
    path = va_arg(args, struct json_path_partial *);
    if (path == NULL) {
        return NULL;
    }
    child = va_arg(args, struct json_path_partial *);

    if (node == NULL || root == NULL || path == NULL) {
        return NULL;
    }
    prev = path;

    while (path != NULL) {
        switch (path->type) {
        case JSON_ARRAY:
            if (current->type != JSON_ARRAY) {
                return NULL;
            }
            current = array_get_nth(current, path->path.index);
            while(current == NULL) {
                if(child && (!(JSON_ARRAY & child->type) || !(JSON_OBJECT & child->type))) {
                    created = array_add_node(parent, jsonCreate(NULL, child->type));
                } else {
                    jsonLiteral null = JSON_NULL;
                    created = array_add_node(parent, jsonCreate(&null, JSON_LITERAL));
                    //created = array_add_node(parent, _jsonCreate());
                }

                if(created != 0) {
                    // current is always NULL for this branch, thus prev becomes NULL therefore function return NULL
                    break;
                }
                current = array_get_nth(parent, path->path.index);
            }
            prev = path;
            break;

        case JSON_OBJECT:
            if (current->type != JSON_OBJECT) {
                return NULL;
            }
            current = ht_find_val(current->contents.o, path->path.key);
            if(current == NULL) {
                if(child && (!(JSON_ARRAY & child->type) || !(JSON_OBJECT & child->type))) {
                    new = ht_insert_copy(parent->contents.o, path->path.key, jsonCreate(NULL, child->type));
                } else {
                    jsonLiteral null = JSON_NULL;
                    new = ht_insert_copy(parent->contents.o, path->path.key, jsonCreate(&null, JSON_LITERAL));
                    //new = ht_insert_copy(parent->contents.o, path->path.key, _jsonCreate());
                }

                if(new == NULL) {
                    // current is always NULL for this branch, thus prev becomes NULL therefore function return NULL
                    break;
                }
                current = ht_find_val(parent->contents.o, path->path.key);
            }
            prev = path;
            break;

        default:
            break;
            current = NULL;
        }

        if (current == NULL) {
            prev = NULL;
            break;
        }
        parent = current;
        path = child;
        if(path != NULL) {
            child = va_arg(args, struct json_path_partial *);
        }
    }
    va_end(args);

    if (prev == NULL) {
        return NULL;
    }

    return copy_json_node_preserve_references(current, node);
}

JsonNode *jsonCopys(JsonNode *node, JsonNode *root, JsonPath *path) {
    if (root == NULL || node == NULL || path == NULL) {
        return NULL;
    }

    JsonNode *current = jsonCopys_recurse(root, path->tail);

    return copy_json_node_preserve_references(current, node);
}

JsonNode *jsonCopys_recurse(JsonNode *root, struct json_path_partial *path) {
    int new;
    JsonNode *created, *current;
    struct json_path_partial *child;

    if(root == NULL) {
        return NULL;
    }

    if(path == NULL) {
        return root;
    }
    child = path->prev;

    root = jsonCopys_recurse(root, child);
    if (root == NULL) {
        return NULL;
    }

    switch (path->type) {
    case JSON_ARRAY:
        if (root->type != JSON_ARRAY) {
            return NULL;
        }
        current = array_get_nth(root, path->path.index);
        while(current == NULL) {
            if(child && (!(JSON_ARRAY & child->type) || !(JSON_OBJECT & child->type))) {
                new = array_add_node(root, jsonCreate(NULL, child->type));
            } else {
                jsonLiteral null = JSON_NULL;
                new = array_add_node(root, jsonCreate(&null, JSON_LITERAL));
                //new = array_add_node(root, _jsonCreate());
            }

            if(new != 0) {
                root = NULL;
                break;
            }
            current = array_get_nth(root, path->path.index);
        }
        root = array_get_nth(root, path->path.index);
        //prev = path;
        break;

    case JSON_OBJECT:
        if (root->type != JSON_OBJECT) {
            return NULL;
        }
        current = ht_find_val(root->contents.o, path->path.key);
        if(current == NULL) {
            if(child && (!(JSON_ARRAY & child->type) || !(JSON_OBJECT & child->type))) {
                created = ht_insert_copy(root->contents.o, path->path.key, jsonCreate(NULL, child->type));
            } else {
                jsonLiteral null = JSON_NULL;
                created = ht_insert_copy(root->contents.o, path->path.key, jsonCreate(&null, JSON_LITERAL));
                //created = ht_insert_copy(root->contents.o, path->path.key, _jsonCreate());
            }

            if(created == NULL) {
                root = NULL;
                break;
            }
        }
        root = ht_find_val(root->contents.o, path->path.key);
        //prev = path;
        break;

    default:
        break;
        root = NULL;
    }

    return root;
}


JsonNode *jsonCopy(JsonNode *root) {
    JsonNode *dest;
    if(root == NULL) {
        return NULL;
    }

    dest = _jsonCreate();
    if(dest == NULL) {
        return NULL;
    }

    return copy_json_node(dest, root);
}

JsonNode *jsonUpdate(const void *src, char type, JsonNode *root) {
    struct ht *newHt = NULL;

    if ((src == NULL && type != JSON_ARRAY && type != JSON_OBJECT) || root == NULL) {
        return NULL;
    }
    int mask = 0xf0;

    destroy_node_contents(root);

    switch (type) {
    case JSON_STR:
        root->contents.s = cstrndup((char*) src, strlen((char*) src) + 1);
        root->type = type;
        root->flags &= mask;
        break;

    case JSON_NUM:
        root->type = type;
        root->flags &= mask;
        root->contents.d = *(double *)src;
        if ((int)root->contents.d == root->contents.d) {
            root->flags |= JSON_NUM_IS_INT;
        }
        break;

    case JSON_LITERAL:
        root->type = type;
        root->flags &= mask;
        root->contents.l = *(char *)src;
        break;

    case JSON_ARRAY:
        root->type = type;
        root->flags &= mask;
        root->contents.a = NULL;
        break;

    case JSON_OBJECT:
        newHt = ht_init(OBJECT_STARTING_SIZE);
        if(newHt == NULL) {
            return NULL;
        }
        root->contents.o = newHt;
        root->flags &= mask;
        root->type = JSON_OBJECT;
        break;

    default:
        return NULL;
        break;
    }

    return root;
}

JsonNode *jsonUpdates(const void *src, char type, JsonNode *root, JsonPath *path) {
    return jsonUpdate(src, type, jsonReads(root, path));
}


int jsonOut(FILE *dest, char minify, JsonNode *root) {
    char *ptr = calloc(2 * MAX_STR_SIZE + 1, sizeof(char));
    struct queue out = {.file = dest,
                            .chars = ptr,
                            .pos = 0,
                            .base = 0,
                            .cap = 2 * MAX_STR_SIZE + 1
    };

    if (dest == NULL || root == NULL || ptr == NULL) {
        free(ptr);
        return -1;
    }

    json_out_recurse(&out, minify, 0, root);

    fdequeue(&out, out.pos);

    free(ptr);
    out.pos = 0;
    out.base = 0;

    return 0;
}

JsonNode *jsonDelete(JsonNode *elem) {
    if(elem->flags & JSON_ELEM_IS_HEAD && elem->prev != NULL) {
        if(jsonIsType(JSON_ARRAY, elem->prev)) {
            array_destroy_node(elems, elem->prev, elem);
        } else if(jsonIsType(JSON_OBJECT, elem->prev)) {
            // if it is the head then finding is O(1)
            ht_del_by_val(elems, elem->prev->contents.o, elem);
        }
    } else {
	if(elem->prev && elem->next){
		if(elem->prev->next == elem){
			elem->prev->next = elem->next;
		}

		if(elem->next->prev == elem){
			elem->next->prev = elem->prev;
		}
	}
    }

    if(elem->flags & JSON_ELEM_IS_OPEN_FILE) {
        return ht_del_by_val(elems, openFiles, elem);
    } else {
        return destroy_node(elems, elem);
    }
}

JsonNode *jsonDeletes(JsonNode *root, JsonPath *path) {
    return jsonDelete(jsonReads(root, path));
}

int json_out_recurse(struct queue *file, char minify, int offset, JsonNode *root) {
    // char mask = 0xff - (META_INVALID | META_FREE | JSON_ELEMENT);
    JsonNode *current = NULL;
    int i = 0;
    size_t len;

    switch (root->type) {
    case JSON_LITERAL:
        queueEnsureSpace(file, strlen("false"));

        if (root->contents.l == JSON_NULL) {
            enqueue(file, "null", strlen("null"));
        } else if (root->contents.l == JSON_FALSE) {
            enqueue(file, "false", strlen("false"));
        } else {
            enqueue(file, "true", strlen("true"));
        }
        break;

    case JSON_STR:
        if (root->contents.s == NULL) {
            return -3;
        }

        len = strlen(root->contents.s);
        // '"' + len + '"'
        queueEnsureSpace(file, 1 + len + 1);

        enqueuec(file, '"');
        enqueue(file, root->contents.s, len);
        enqueuec(file, '"');
        break;

    case JSON_NUM:
        len = 999;
        queueEnsureSpace(file, len);

        if (root->flags & JSON_NUM_IS_INT) {
            i = (int)root->contents.d;
            snprintf(scratch.chars, len, "%d", i);
        } else if (root->flags & JSON_NUM_IS_SCIENTIFIC) {
            snprintf(scratch.chars, len, "%le", root->contents.d);
        } else {
            snprintf(scratch.chars, len, "%lf", root->contents.d);
        }

        enqueue(file, scratch.chars, strlen(scratch.chars));
        scratch.pos = 0;
        scratch.base = 0;
        break;

    case JSON_ARRAY:
        offset += 2;
        // '[' + '\n' + offset
        len = 1 + 1 + offset;
        queueEnsureSpace(file, len);

        enqueuec(file, '[');
        if (minify == 0) {
            enqueuec(file, '\n');
        }

        if (root->contents.a != NULL) {
            current = array_get_nth(root, i++);
        }
        while (current != NULL) {
            if (minify == 0) {
                enqueuecn(file, ' ', offset);
            }

            json_out_recurse(file, minify, offset, current);

            // len = ',' + '\n' + offset
            len = 1 + 1 + offset;
            queueEnsureSpace(file, len);

            current = array_get_nth(root, i++);
            if (current != NULL) {
                enqueuec(file, ',');
            }

            if (minify == 0) {
                enqueuec(file, '\n');
            }
        }

        offset -= 2;

        // len = offset + ']'
        len = offset + 1;
        queueEnsureSpace(file, len);

        if (minify == 0) {
            enqueuecn(file, ' ', offset);
        }
        enqueuec(file, ']');
        break;

    case JSON_OBJECT:
        offset += 2;

        // '{' + '\n' + offset
        len = 1 + 1 + offset;
        queueEnsureSpace(file, len);

        if (root->contents.o == NULL) {
            return -5;
        }

        enqueuec(file, '{');
        if (minify == 0) {
            enqueuec(file, '\n');
        }

        for(JsonNode *current = root->contents.o->head_val;
                current != NULL;
                current = current->next) {

            if (minify == 0) {
                enqueuecn(file, ' ', offset);
            }

            if(current->key == NULL) {
                return -3;
            }

	    len = strlen(current->key);
	    // '"' + len + '"'
	    queueEnsureSpace(file, 1 + len + 1);

	    enqueuec(file, '"');
	    enqueue(file, current->key, len);
	    enqueuec(file, '"');

            // len = ':' + ' '
            len = 1 + 1;
            queueEnsureSpace(file, len);

            enqueuec(file, ':');

            if (minify == 0) {
                enqueuec(file, ' ');
            }

            json_out_recurse(file, minify, offset, current);

            // len = ',' + '\n' + offset
            len = 1 + 1 + offset;
            queueEnsureSpace(file, len);

            enqueuec(file, ',');
            if (minify == 0) {
                enqueuec(file, '\n');
            }
        }

        // len = '\n'
        len = 1;
        queueEnsureSpace(file, len);

        if(root->contents.o->count != 0) {
            if (minify == 0) {
                queueRedact(file, 2);
                enqueuec(file, '\n');
            } else {
                queueRedact(file, 1);
            }
        }

        offset -= 2;

        // len = offset + '}'
        len = offset + 1;
        queueEnsureSpace(file, len);

        if (minify == 0) {
            enqueuecn(file, ' ', offset);
        }
        enqueuec(file, '}');
        break;

    default:
        return -2;
    }

    return 0;
}

int jsonOuts(FILE *dest, char minify, JsonNode *root, JsonPath *path) {
    return jsonOut(dest, minify, jsonReads(root, path));
}

// New node
JsonNode *new_node(struct json_pool *pool) {
    if (pool == NULL) {
        return NULL;
    }

    if (pool->next_free == NULL && pool->stored == pool->cap) {
        double_pool(&elems);
    }

    JsonNode *now_taken = NULL;
    if (pool->next_free) {
        now_taken = pool->next_free;
        if (pool->next_free->type == META_FREE && pool->next_free->contents.n) {
            pool->next_free = pool->next_free->contents.n;
        } else {
            pool->next_free = NULL;
        }
    } else {
        now_taken = &(pool->items[pool->stored++]);
    }
    memset(now_taken, 0, sizeof(JsonNode));
    return now_taken;
}

// Destroy node
JsonNode *destroy_node(struct json_pool *pool, JsonNode *elem) {
    if (!pool || !elem || elem->type == META_FREE) {
        return NULL;
    }

    if(elem->key != NULL){
	    free(elem->key);
    }
    destroy_node_contents(elem);

    elem->contents.n = pool->next_free;
    elem->type = META_FREE;
    elem->flags = 0;
    pool->next_free = elem;
    return elem;
}

JsonNode *destroy_node_contents(JsonNode *elem) {
    jsonFlags mask = 0xf0;
    if (!elem || elem->type == META_FREE) {
        return NULL;
    }

    if (elem->type == JSON_STR && elem->contents.s != NULL) {
        free(elem->contents.s);
        elem->contents.s = NULL;
    } else if (elem->type == JSON_ARRAY) {
        array_destroy(elems, elem);
        elem->contents.a = NULL;
    } else if (elem->type == JSON_OBJECT) {
        ht_destroy(elems, elem->contents.o);
        elem->contents.o = NULL;
        // json_object_free(elem->contents.o);
    }

    elem->contents.l = JSON_NULL;
    elem->type = JSON_LITERAL;
    elem->flags &= mask;
    return elem;
}

static inline int is_whitespace(char c) {
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

void get_next(char *outer, struct queue *store) {
    if (outer == NULL || store == NULL) {
        return;
    }
    outer[0] = '\x00';
    char c = ' ';
    size_t read_in = 0;
    // char outer[999] = "";

    while (is_whitespace(c)) {
        // printf("whitespace found %c\n", c);
        dequeuec(store, &c);
    }
    if (c == '"' || c == '[' || c == '{' || c == ']' || c == '}') {
        outer[0] = c;
        outer[1] = '\x00';
        return;
    }
    while (!is_whitespace(c) && read_in < 50) {
        if (c == ',' || c == ':') {
            queueRewind(store, 1);
            break;
        }
        outer[read_in] = c;
        // printf("%s\n", outer);
        if (c == '[' || c == '{') {
            break;
        }
        dequeuec(store, &c);
        read_in += 1;
        // printf("not whitespace found %c\n", c);
    }
    outer[read_in] = '\x00';
}

// Return first non-whitespace character
char get_sep(struct queue *store) {
    char c = ' ';
    while (store->base < store->pos && is_whitespace(c)) {
        dequeuec(store, &c);
    }

    return c;
}

static inline int is_json_literal(char *str) {
    return !strcmp(str, "true") || !strcmp(str, "false") || !strcmp(str, "null");
}

static inline int is_json_str(char *str) {
    return strlen(str) >= 1 && str[0] == '"';
}

static inline int is_part_of_num(char c) {
    return c == 'e' || c == 'E' || c == '.' || (c >= '0' && c <= '9');
}

int is_json_num(char *str) {
    char c = '\x00';
    size_t i = 0, e = '\x00', dot = '\x00';
    int ret = 0;
    for (i = 0; i < strlen(str); i++) {
        c = str[i];
        if (c == '-' || c == '+') {
            if (i != 0 && str[i - 1] != 'e' && str[i - 1] != 'E') {
                return false;
            }
        } else if (!is_part_of_num(c)) {
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
            if (dot) {
                return false;
            } else {
                dot = i;
            }
        }
    }
    if (!dot && (!(ret & JSON_NUM_IS_SCIENTIFIC) || str[e + 1] != '-')) {
        ret |= JSON_NUM_IS_INT;
    }
    return ret | JSON_NUM_IS_NUM;
}

static inline int is_json_array(char *str) {
    return strlen(str) >= 1 && str[0] == '[';
}

static inline int is_json_object(char *str) {
    return strlen(str) >= 1 && str[0] == '{';
}

static inline int is_json_end(char *str) {
    return strlen(str) >= 1 && (str[0] == ']' || str[0] == '}');
}


static inline char get_json_literal(const char *ptr) {
    if (ptr == NULL) {
        return JSON_NULL;
    } else {
        if (!strcmp(ptr, "true")) {
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
    if (read == NULL || read->chars == NULL || scratch == NULL ||
            scratch->chars == NULL) {
        return NULL;
    }

    while (!dequeuec(read, &c)) {
        if (c == '\\') {
            backslash++;
        } else {
            if (backslash % 2) {
                // printf("%c\n", c);
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
                    if (hex >= 4) {
                        expect_hex = false;
                        hex = 0;
                    } else if (!('0' <= c && c <= '9') && !('a' <= c && c <= 'f') &&
                               !('A' <= c && c <= 'F')) {
                        return NULL;
                    }
                    hex++;
                } else if (c == '"') {
                    break;
                }
            }
            backslash = 0;
        }

        if (enqueuec(scratch, c)) {
            break;
        }
    }

    ret = calloc(scratch->pos + 1, sizeof(char));
    if (ret == NULL) {
        return NULL;
    }
    cstrncpy(ret, scratch->chars, scratch->pos + 1);
    ret[scratch->pos] = '\0';

    scratch->base = 0;
    scratch->pos = 0;
    return ret;
}

static inline double get_json_num(char *str) {
    double out;
    if (str == NULL) {
        return 0.0;
    }

    sscanf(str, "%le", &out);
    return out;
}

JsonNode *get_json_object(struct queue *file, struct queue *scratch,
                          JsonNode *elem) {
    JsonNode *key = NULL, *val = NULL;
    struct ht *table = NULL;
    char sep = ',', error = 0;
    if (file == NULL || scratch == NULL) {
        return NULL;
    }

    table = ht_init(OBJECT_STARTING_SIZE);
    elem->contents.o = table;
    elem->type = JSON_OBJECT;

    while (!error && sep != '}') {
        if (sep != ',') {
            return NULL;
        }

        key = new_node(elems);
        process(file, key);
        if(key->type == JSON_CLOSE) {
            jsonDelete(key);
            break;
        }
        sep = get_sep(file);
        if (sep != ':') {
            return NULL;
        }

        val = new_node(elems);
        process(file, val);
        ht_insert_copy(table, key->contents.s, val);
        destroy_node(elems, key);

        sep = get_sep(file);
    }

    if (!error) {
        // printf("end\n");
        return elem;

        return NULL;
    } else {
        // array_destroy(read, new_array);
        return NULL;
    }
}

JsonNode *process(struct queue *file, JsonNode *elem) {
    char *fragment = scratch.chars;
    char tmp_flags = 0;

    if (file == NULL || elem == NULL || fragment == NULL || fragment == NULL) {
        return NULL;
    }

    get_next(fragment, file);

    if ((tmp_flags = is_json_literal(fragment))) {
        elem->type = JSON_LITERAL;
    } else if ((tmp_flags = is_json_str(fragment))) {
        elem->type = JSON_STR;
    } else if ((tmp_flags = is_json_num(fragment)) &&
               (tmp_flags & JSON_NUM_IS_NUM)) {
        elem->type = JSON_NUM;
    } else if ((tmp_flags = is_json_array(fragment))) {
        elem->type = JSON_ARRAY;
    } else if ((tmp_flags = is_json_object(fragment))) {
        elem->type = JSON_OBJECT;
    } else if ((tmp_flags = is_json_end(fragment))) {
        elem->type = JSON_CLOSE;
    } else {
        elem->type = META_INVALID;
    }
    elem->flags = tmp_flags;

    switch (elem->type) {
    case JSON_LITERAL:
        elem->contents.l = get_json_literal(fragment);
        break;

    case JSON_STR:
        scratch.pos = 0;
        scratch.base = 0;
        elem->contents.s = get_json_str(file, &scratch);
        break;

    case JSON_NUM:
        elem->contents.d = get_json_num(fragment);
        break;

    case JSON_ARRAY:
        scratch.pos = 0;
        scratch.base = 0;
        get_json_array(elems, file, &scratch, elem);
        break;

    case JSON_OBJECT:
        scratch.pos = 0;
        scratch.base = 0;
        get_json_object(file, &scratch, elem);
        break;

    default:
        break;
    }

    scratch.pos = 0;
    scratch.base = 0;

    return elem;
}

JsonNode *copy_json_node(JsonNode *dest, JsonNode *src) {
    JsonNode *orig_child = NULL, *new_child = NULL;
    struct ht *table = NULL;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    destroy_node_contents(dest);
    memset(dest, 0, sizeof(JsonNode));
    dest->flags = (src->flags & 0x0f);

    switch (src->type) {
    case JSON_LITERAL:
	dest->contents.l = src->contents.l;
	dest->type = JSON_LITERAL;
        break;

    case JSON_NUM:
        dest->contents.d = src->contents.d;
        dest->type = JSON_NUM;
        break;

    case JSON_STR:
        if (src->contents.s == NULL) {
            return NULL;
        }

        dest->contents.s = cstrndup(src->contents.s, strlen(src->contents.s) + 1);
        dest->type = JSON_STR;
        break;

    case JSON_ARRAY:
        if (src == NULL) {
            return NULL;
        }
        if (src->contents.a == NULL) {
            return NULL;
        }
        dest->type = JSON_ARRAY;
        orig_child = array_head(src);
        while (orig_child != NULL) {
            new_child = new_node(elems);
            copy_json_node(new_child, orig_child);
            array_add_node(dest, new_child);

            if (!(orig_child->flags & JSON_ELEM_IS_TAIL)) {
                orig_child = orig_child->next;
            } else {
                orig_child = NULL;
            }
        }
        break;

    case JSON_OBJECT:
        if (src == NULL || src->contents.o == NULL || src->contents.o->vals == NULL) {
            return NULL;
        }

        table = ht_init(OBJECT_STARTING_SIZE);
        dest->contents.o = table;
        dest->type = JSON_OBJECT;
        for (JsonNode *current = src->contents.o->head_val; current != NULL; current = current->next) {
            new_child = new_node(elems);
            copy_json_node(new_child, current);
            ht_insert_copy(dest->contents.o, current->key, new_child);
        }
        break;

    default:
        return NULL;
        break;
    }

    return dest;
}

JsonNode *copy_json_node_preserve_references(JsonNode *dest, JsonNode *src) {
    JsonNode *orig_prev = NULL, *orig_next = NULL;
    jsonType orig_type;
    jsonFlags orig_flags;
    char *orig_key;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    orig_prev = dest->prev;
    orig_next = dest->next;
    orig_type = dest->type;
    orig_flags = dest->flags;
    orig_key = NULL;

    if(dest->key != NULL){
	    orig_key = dest->key;
	    dest->key = NULL;
    }

    copy_json_node(dest, src);

    switch(orig_type) {
    case META_INVALID:
    case META_FREE:
        dest->prev = NULL;
        dest->next = NULL;
	dest->key = NULL;
        break;
    default:
        dest->prev = orig_prev;
        dest->next = orig_next;
        dest->flags |= (orig_flags & JSON_ELEM_IS_HEAD);
        dest->flags |= (orig_flags & JSON_ELEM_IS_TAIL);
	if(dest->key != NULL){
		free(dest->key);
	}
	dest->key = orig_key;
        break;
    }

    return dest;
}

jsonType *jsonCheckType(JsonNode *root) {
    if(root == NULL) {
        return NULL;
    } else {
        return &(root->type);
    }
}

jsonType *jsonCheckTypes(JsonNode *root, JsonPath *path) {
    return jsonCheckType(jsonReads(root, path));
}

bool jsonIsType(jsonType type, JsonNode *root) {
    jsonType *ptr = jsonCheckType(root);
    if(ptr == NULL) {
        return false;
    }

    jsonType val = *ptr;
    if(val == 0 && type == 0 && val == type) {
        return true;
    } else if(val & type) {
        return true;
    }

    return false;
}

bool jsonIsTypes(jsonType type, JsonNode *root, JsonPath *keys) {
    return jsonIsType(type, jsonReads(root, keys));
}

jsonLiteral *jsonReadLiteral(JsonNode *root) {
    if(root == NULL || !jsonIsType(JSON_LITERAL, root)) {
        return NULL;
    }

    return &(root->contents.l);
}

jsonLiteral *jsonReadLiterals(JsonNode *root, JsonPath *path) {
    return jsonReadLiteral(jsonReads(root, path));
}

double *jsonReadDouble(JsonNode *root) {
    if(root == NULL || !jsonIsType(JSON_NUM, root)) {
        return NULL;
    }

    return &(root->contents.d);
}

double *jsonReadDoubles(JsonNode *root, JsonPath *path) {
    return jsonReadDouble(jsonReads(root, path));
}

char *jsonReadStr(JsonNode *root) {
    if(root == NULL || !jsonIsType(JSON_STR, root)) {
        return NULL;
    }

    return root->contents.s;
}

char *jsonReadStrs(JsonNode *root, JsonPath *path) {
    return jsonReadStr(jsonReads(root, path));
}

JsonNode *jsonReadArray(JsonNode *root) {
    if(root == NULL || !jsonIsType(JSON_ARRAY, root)) {
        return NULL;
    }

    return root;
}

JsonNode *jsonReadArrays(JsonNode *root, JsonPath *path) {
    return jsonReadArray(jsonReads(root, path));
}

JsonNode *jsonReadObject(JsonNode *root) {
    if(root == NULL || !jsonIsType(JSON_OBJECT, root)) {
        return NULL;
    }

    return root;
}

JsonNode *jsonReadObjects(JsonNode *root, JsonPath *path) {
    return jsonReadObject(jsonReads(root, path));
}

size_t jsonArrayLength(JsonNode *array){
	if(jsonIsType(JSON_ARRAY, array)){
		return array_length(array);
	} else {
		return 0;
	}
}

size_t jsonArrayLengths(JsonNode *array, JsonPath *path){
	return jsonArrayLength(jsonReads(array, path));
}

#if TEST_BUILD == 1
void read_tests() {
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

void array_tests() {
    jsonLibInit();

    JsonNode *array = jsonOpen("./tests/test.json");

    assert(array != NULL);
    JsonNode *interior = array_get_nth(array_get_nth(array, 3), 3);
    assert(interior != NULL);
    assert(array_get_nth(interior, 0)->type == JSON_NUM);
    assert(array_get_nth(interior, 1)->type == JSON_LITERAL);
    assert(array_get_nth(interior, 2)->type == JSON_STR);
    assert(array_get_nth(interior, 0)->contents.d == -57.638300);
    assert(array_get_nth(interior, 1)->contents.l == JSON_FALSE);
    assert(!strcmp("aab", array_get_nth(interior, 2)->contents.s));

    struct ht *table = ht_init(OBJECT_STARTING_SIZE);

    char *key1 = calloc(99, sizeof(char));
    char *key2 = calloc(99, sizeof(char));
    char *key3 = calloc(99, sizeof(char));
    assert(key1 != NULL && key2 != NULL && key3 != NULL);
    cstrncpy(key1, "0", 99);
    cstrncpy(key2, "yes hello test 1233", 99);
    cstrncpy(key3, "bees bees are the best bees bees", 99);
    // printf("first inserted at %p\n", ht_insert_copy(table, key1,
    // array_get_nth(interior, 0)));
    assert(ht_insert_copy(table, key1, jsonCopy(array_get_nth(interior, 0))) != NULL);
    assert(ht_insert_copy(table, key2, jsonCopy(array_get_nth(interior, 1))) != NULL);
    assert(ht_insert_copy(table, key3, jsonCopy(array_get_nth(interior, 2))) != NULL);
    JsonNode *found = ht_find_val(table, "000000000000000");
    assert(found == NULL);
    assert(ht_find_val(table, key2)->contents.l == JSON_FALSE);
    assert(!strcmp("aab", ht_find_val(table, key3)->contents.s));
    ht_set(table, key2, array_get_nth(interior, 0));
    assert(ht_find_val(table, key2)->contents.d == -57.638300);
    ht_del_by_key(elems, table, key2);
    found = ht_find_val(table, key2);
    assert(found == NULL);

    ht_destroy(elems, table);
    free(key1);
    key1 = NULL;
    free(key2);
    key2 = NULL;
    free(key3);
    key3 = NULL;

    JsonNode *copy = NULL;
    JsonNode *new = new_node(elems);
    assert(new != NULL);
    new = copy_json_node(new, array_get_nth(array, 1));
    assert(new != NULL);
    assert(array_insert_node(array, new, 5) == 0);
    // printf("%s\n", array_get_nth(array, 1)->contents.s);
    // printf("%s\n", array_get_nth(array, 5)->contents.s);
    assert(!strcmp(array_get_nth(array, 1)->contents.s,
                   array_get_nth(array, 5)->contents.s));
    copy = new_node(elems);
    copy = copy_json_node(copy, new);
    assert(array_insert_node(array, copy, 2) == 0);
    assert(!strcmp(array_get_nth(array, 1)->contents.s,
                   array_get_nth(array, 2)->contents.s));
    copy = new_node(elems);
    copy = copy_json_node(copy, new);
    assert(array_insert_node(array, copy, 0) == 0);
    // Add 1 because of shift up
    assert(!strcmp(array_get_nth(array, 0)->contents.s,
                   array_get_nth(array, 1 + 1)->contents.s));

    array_destroy(elems, array);

    jsonLibEnd();
}

void object_tests() {
    jsonLibInit();

    // assert(OBJECT_STARTING_SIZE == 1);

    JsonNode *root = jsonOpen("./tests/object1.json");
    assert(root != NULL && root->contents.o != NULL);
    JsonNode *found_1 = ht_find_val(root->contents.o, "A");
    assert(found_1 != NULL);
    assert(found_1->contents.d == 10.0);
    JsonNode *found_2 = ht_find_val(root->contents.o, "B");
    assert(found_2 != NULL);
    assert(found_2->contents.d == 11.0);
    JsonNode *found_3 = ht_find_val(root->contents.o, "C");
    assert(found_3 != NULL);
    assert(!strcmp(found_3->contents.s, "some text I guess"));
    JsonNode *found_4 = ht_find_val(root->contents.o, "D");
    assert(found_4->type == JSON_ARRAY);
    JsonNode *second = array_get_nth(found_4, 1);
    assert(second != NULL);
    assert(second->type == JSON_NUM);
    assert(second->contents.d == 1.0);

    JsonNode *removed = ht_del_by_key(elems, root->contents.o, "A");

    assert(removed != NULL);
    assert(found_1 == removed);

    JsonNode *place_somewhere = new_node(elems);
    assert(place_somewhere != NULL);
    place_somewhere->contents.d = 3334.54;
    place_somewhere->type = JSON_NUM;
    JsonNode *placed = ht_set(root->contents.o, "B", place_somewhere);
    assert(placed != NULL);
    assert(placed == found_2);
    assert(placed->contents.d == 3334.54);

    jsonLibEnd();
}

void copy_tests() {
    jsonLibInit();

    JsonNode *literal = new_node(elems);
    literal->contents.l = JSON_TRUE;
    literal->type = JSON_LITERAL;
    literal->flags = 0;
    literal->prev = NULL;
    literal->next = NULL;
    JsonNode *new_literal = new_node(elems);
    copy_json_node(new_literal, literal);
    assert(literal != new_literal);
    assert(literal->type == JSON_LITERAL && new_literal->type == JSON_LITERAL);
    assert(literal->contents.l == JSON_TRUE &&
           new_literal->contents.l == JSON_TRUE);

    JsonNode *num = new_node(elems);
    num->contents.d = 333.333311111;
    num->type = JSON_NUM;
    num->flags = 0;
    num->prev = NULL;
    num->next = NULL;
    JsonNode *new_num = new_node(elems);
    copy_json_node(new_num, num);
    assert(num != new_num);
    assert(num->type == JSON_NUM && new_num->type == JSON_NUM);
    assert(num->contents.d == 333.333311111 &&
           new_num->contents.d == 333.333311111);

    char *chars = calloc(50, sizeof(char));
    assert(chars != NULL);
    strncpy(chars, "we are testing now", 50 - 1);
    JsonNode *str = new_node(elems);
    str->contents.s = chars;
    str->type = JSON_STR;
    str->flags = 0;
    str->prev = NULL;
    str->next = NULL;
    JsonNode *new_str = new_node(elems);
    copy_json_node(new_str, str);
    assert(str != new_str && str->contents.s != new_str->contents.s);
    assert(str->type == JSON_STR && new_str->type == JSON_STR);
    assert(!strcmp(str->contents.s, chars) &&
           !strcmp(new_str->contents.s, chars));

    JsonNode *array = jsonOpen("./tests/array1.json");
    JsonNode *object = jsonOpen("./tests/object1.json");
    JsonNode *new_array = new_node(elems);
    JsonNode *new_object = new_node(elems);
    assert(array != NULL && object != NULL && new_array != NULL &&
           new_object != NULL);

    copy_json_node(new_array, array);
    assert(new_array->type == JSON_ARRAY);
    JsonNode *array_first = array_get_nth(array, 0);
    JsonNode *new_array_first = array_get_nth(new_array, 0);
    assert(array_first != new_array_first);
    assert(array_first->type == JSON_NUM && new_array_first->type == JSON_NUM);
    assert(array_first->contents.d == -57.6383 &&
           new_array_first->contents.d == -57.6383);
    JsonNode *array_second = array_get_nth(array, 1);
    JsonNode *new_array_second = array_get_nth(new_array, 1);
    assert(array_second != new_array_second);
    assert(array_second->type == JSON_LITERAL &&
           new_array_second->type == JSON_LITERAL);
    assert(array_second->contents.l == JSON_FALSE &&
           new_array_second->contents.l == JSON_FALSE);
    JsonNode *array_third = array_get_nth(array, 2);
    JsonNode *new_array_third = array_get_nth(new_array, 2);
    assert(array_third != new_array_third);
    assert(array_third->type == JSON_STR && new_array_third->type == JSON_STR);
    assert(!strcmp(array_third->contents.s, new_array_third->contents.s));
    assert(array_get_nth(array, 3) == NULL);
    assert(array_get_nth(new_array, 3) == NULL);

    copy_json_node(new_object, object);
    assert(new_object->type == JSON_OBJECT);
    JsonNode *A = ht_find_val(object->contents.o, "A");
    JsonNode *new_A = ht_find_val(new_object->contents.o, "A");
    assert(A != new_A);
    assert(A->type == JSON_NUM && new_A->type == JSON_NUM);
    assert(A->contents.d == 10.0 && new_A->contents.d == 10.0);
    JsonNode *B = ht_find_val(object->contents.o, "B");
    JsonNode *new_B = ht_find_val(new_object->contents.o, "B");
    assert(B != new_B);
    assert(B->type == JSON_NUM && new_B->type == JSON_NUM);
    assert(B->contents.d == 11.0 && new_B->contents.d == 11.0);
    JsonNode *C = ht_find_val(object->contents.o, "C");
    JsonNode *new_C = ht_find_val(new_object->contents.o, "C");
    assert(C != NULL);
    assert(new_C != NULL);
    assert(C != new_C);
    assert(C->type == JSON_STR && new_C->type == JSON_STR);
    assert(!strcmp(C->contents.s, "some text I guess") &&
           !strcmp(new_C->contents.s, "some text I guess"));
    JsonNode *D = ht_find_val(object->contents.o, "D");
    JsonNode *new_D = ht_find_val(new_object->contents.o, "D");
    assert(D != NULL);
    assert(new_D != NULL);
    assert(D != new_D);
    assert(D->type == JSON_ARRAY && new_D->type == JSON_ARRAY);
    JsonNode *interior_last = array_get_nth(D, 2);
    JsonNode *new_interior_last = array_get_nth(new_D, 2);
    assert(interior_last != NULL);
    assert(new_interior_last != NULL);
    assert(!strcmp(interior_last->contents.s, "yes") &&
           !strcmp(new_interior_last->contents.s, "yes"));

    jsonLibEnd();
}

void jsonRead_tests() {
    jsonLibInit();

    // JsonNode *array = jsonOpen("./tests/array1.json");
    JsonNode *object = jsonOpen("./tests/object1.json");

    // Check string
    {
        char *my_str = NULL;
        JsonNode *exists = jsonReadl(object, jsonPathKey("D"), jsonPathIndex(2), NULL);
        assert(exists != NULL);
        //struct json_path_partial *exists_path[] = {jsonPathKey("D"), jsonPathIndex(2), NULL};
        //JsonNode *exists2 = jsonReadv(object, exists_path);
        //assert(exists2 != NULL);
        JsonPath *exists_json_path = jsonPathPush(NULL, jsonPathKey("D"), jsonPathIndex(2), NULL);
        JsonNode *exists3 = jsonReads(object, exists_json_path);
        assert(exists3 != NULL);

        my_str = jsonReadStr(exists); // Fails if NULL assigned to my_str
        assert(my_str != NULL);
        assert(!strcmp(my_str, "yes"));
        my_str = jsonReadStr(exists3);
        assert(my_str != NULL);
        assert(!strcmp(my_str, "yes"));

        my_str = jsonReadStrl(object, jsonPathKey("D"), jsonPathIndex(2), NULL);
        assert(my_str != NULL);
        assert(!strcmp(my_str, "yes"));
        my_str = jsonReadStrs(object, exists_json_path);
        assert(my_str != NULL);
        assert(!strcmp(my_str, "yes"));

        JsonNode *tmp = jsonReads(object, exists_json_path);
        assert(tmp != NULL);
        assert(jsonReadStr(tmp) != NULL);
        assert(!strcmp(jsonReadStr(tmp), "yes"));
        assert(!strcmp("yes", jsonReadStrs(object, exists_json_path)));
        jsonPathDelete(exists_json_path);
    }

    // Check literal
    {
        jsonType *read_literal = NULL;

        read_literal = jsonReadLiterall(object, jsonPathKey("E"));
        assert(read_literal != NULL);
        assert(*read_literal == JSON_FALSE);

        JsonPath *read_literal_path = jsonPathPush(NULL, jsonPathKey("E"), NULL);
        read_literal = jsonReadLiterals(object, read_literal_path);
        assert(read_literal != NULL);
        assert(*read_literal == JSON_FALSE);
        jsonPathDelete(read_literal_path);

        JsonPath *read_literal_json_path = jsonPathPush(NULL, jsonPathKey("E"), NULL );
        read_literal = jsonReadLiterals(object, read_literal_json_path);
        assert(read_literal != NULL);
        assert(*read_literal == JSON_FALSE);
        jsonPathDelete(read_literal_json_path);
    }

    // Check double
    {
        double *read_double = NULL;

        read_double = jsonReadDoublel(object, jsonPathKey("D"), jsonPathIndex(0), jsonPathKey("A"));
        assert(read_double != NULL);
        assert(*read_double == 10.0);

        JsonPath *read_double_path = jsonPathPush(NULL, jsonPathKey("D"), jsonPathIndex(0), jsonPathKey("A"), NULL);
        read_double = jsonReadDoubles(object, read_double_path);
        assert(read_double != NULL);
        assert(*read_double == 10.0);
        jsonPathDelete(read_double_path);

        JsonPath *read_double_json_path = jsonPathPush(NULL, jsonPathKey("D"), jsonPathIndex(0), jsonPathKey("A"));
        read_double = jsonReadDoubles(object, read_double_json_path);
        assert(read_double != NULL);
        assert(*read_double == 10.0);
        jsonPathDelete(read_double_json_path);
    }

    // Check array
    {
        JsonNode *read_array = NULL;

        read_array = jsonReadArrayl(object, jsonPathKey("D"));
        assert(read_array != NULL);
        double *read_double = jsonReadDoublel(read_array, jsonPathIndex(1));
        assert(read_double != NULL);
        assert(*read_double == 1.0);

        JsonPath *read_array_path = jsonPathPush(NULL, jsonPathKey("D"), NULL);
        read_array = jsonReadArrays(object, read_array_path);
        assert(read_array != NULL);
        read_double = jsonReadDoublel(read_array, jsonPathIndex(1));
        assert(read_double != NULL);
        assert(*read_double == 1.0);
        jsonPathDelete(read_array_path);

        JsonPath *read_array_json_path = jsonPathPush(NULL, jsonPathKey("D"), NULL );
        read_array = jsonReadArrays(object, read_array_json_path);
        assert(read_array != NULL);
        read_array_json_path = jsonPathPush(read_array_json_path, jsonPathIndex(1));
        read_double = jsonReadDoubles(object, read_array_json_path);
        assert(read_double != NULL);
        assert(*read_double == 1.0);
        jsonPathDelete(read_array_json_path);
    }

    // Check object
    {
        JsonNode *read_object = NULL;
        double *read_double = NULL;

        read_object = jsonReadObjectl(object, jsonPathKey("D"), jsonPathIndex(0));
        assert(read_object != NULL);
        read_double = jsonReadDoublel(read_object, jsonPathKey("B"));
        assert(read_double != NULL);
        assert(*read_double == 11.0);

        JsonPath *read_object_path = jsonPathPush(NULL, jsonPathKey("D"), jsonPathIndex(0), NULL);
        read_object = jsonReadObjects(object, read_object_path);
        assert(read_object != NULL);
        read_double = jsonReadDoublel(read_object, jsonPathKey("B"));
        assert(read_double != NULL);
        assert(*read_double == 11.0);
        jsonPathDelete(read_object_path);

        JsonPath *read_object_json_path = jsonPathPush(NULL, jsonPathKey("D"), jsonPathIndex(0), NULL);
        read_object = jsonReadObjects(object, read_object_json_path);
        assert(read_object != NULL);
        jsonPathPop(read_object_json_path);
        jsonPathPop(read_object_json_path);
        jsonPathPop(read_object_json_path);
        jsonPathPop(read_object_json_path);
        jsonPathPop(read_object_json_path);
        read_object_json_path = jsonPathPush(read_object_json_path, jsonPathKey("B"));
        read_double = jsonReadDoubles(read_object, read_object_json_path);
        assert(read_double != NULL);
        assert(*read_double == 11.0);
        jsonPathDelete(read_object_json_path);
        read_object_json_path = jsonPathPush(NULL, jsonPathKey("D"), jsonPathIndex(0), jsonPathKey("B"));
        read_double = jsonReadDoubles(object, read_object_json_path);
        assert(read_double != NULL);
        assert(*read_double == 11.0);
        jsonPathDelete(read_object_json_path);
    }

    FILE *debug_out = fopen("./tmp/jsonRead.debug.json", "w");
    assert(debug_out != NULL);
    jsonOut(debug_out, 0, object);
    assert(fclose(debug_out) == 0);
    jsonLibEnd();
}

void jsonDelete_tests() {
    jsonLibInit();
    const char *array1_path = "./tests/array1.json";
    const char *object1_path = "./tests/object1.json";
    const char *test_path = "./tests/test.json";
    const char *test2_path = "./tests/test2.json";

    JsonNode *array1 = jsonOpen(array1_path);
    JsonNode *object1 = jsonOpen(object1_path);
    JsonNode *test = jsonOpen(test_path);
    JsonNode *test2 = jsonOpen(test2_path);
    assert(array1 != NULL && object1 != NULL && test != NULL && test2 != NULL);

    jsonClose(array1_path);
    assert((array1->type & META_FREE) && !(array1->type & JSON_ELEM_IS_OPEN_FILE));
    assert(ht_find_val(openFiles, array1_path) == NULL);
    jsonDelete(object1);
    assert((object1->type & META_FREE) && !(object1->type & JSON_ELEM_IS_OPEN_FILE));
    assert(ht_find_val(openFiles, object1_path) == NULL);

    jsonLibEnd();
}

void output_tests() {
    jsonLibInit();

    JsonNode *root = jsonOpen("./tests/object1.json");

    FILE *out = fopen("/tmp/json-tests", "w+");
    if (out == NULL) {
        printf("Error opening %s: %s\n", "/tmp/json-tests", strerror(errno));
        assert(false);
    }
    jsonOut(out, 1, root);
    assert(fflush(out) == 0);
    rewind(out);

    char *expected = "{\"A\":10,\"B\":11,\"C\":\"some text I guess\",\"D\":[{\"A\":10,\"B\":11,\"C\":12},1,\"yes\"],\"E\":false}";
    char test[999];
    memset(test, 0, 999);
    // Clang is unhappy about errno even though we check if it is invalid, false positive
    char *ret = fgets(test, 999, out);
    assert(ret == test);
    // printf("%s\n", expected);
    // printf("%s\n", test);
    assert(!strcmp(expected, test));
    assert(jsonOutl(stdin, 1, root, jsonPathKey("D"), jsonPathIndex(0), jsonPathKey("B"), NULL) ==
           0);
    JsonPath *path = jsonPathPush(NULL, jsonPathKey("D"), jsonPathIndex(0), jsonPathKey("B"), NULL);
    assert(jsonOuts(stdin, 1, root, path) == 0);
    jsonPathDelete(path);
    fflush(out);
    fclose(out);
    remove("/tmp/json-tests");

    jsonLibEnd();
}

void jsonCreate_tests() {
    jsonLibInit();
    JsonNode *root = jsonOpen("./tests/test2.json");
    assert(root != NULL);
    JsonNode *new = NULL;

    // Literal
    {
        new = jsonCreate(&JSON_FALSE, JSON_LITERAL);
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);

        new = jsonCreatel(&JSON_FALSE, JSON_LITERAL, root, jsonPathIndex(49));
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);
        new = jsonReadl(root, jsonPathIndex(49), NULL);
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);

        JsonPath *path_object_array = jsonPathPush(NULL, jsonPathIndex(99), NULL);
        new = jsonCreates(&JSON_FALSE, JSON_LITERAL, root, path_object_array);
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);
        new = jsonReads(root, path_object_array);
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);
        jsonPathDelete(path_object_array);

        new = jsonCreatel(&JSON_FALSE, JSON_LITERAL, root, jsonPathIndex(0), jsonPathKey("literal_addedl"));
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);
        new = jsonReadl(root, jsonPathIndex(0), jsonPathKey("literal_addedl"));
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);

        JsonPath *path_object_object = jsonPathPush(NULL, jsonPathIndex(0), jsonPathKey("literal_addedv"), NULL);
        new = jsonCreates(&JSON_FALSE, JSON_LITERAL, root, path_object_object);
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);
        new = jsonReads(root, path_object_object);
        assert(new != NULL);
        assert(*(jsonReadLiteral(new)) == JSON_FALSE);
        jsonPathDelete(path_object_object);
    }

    // Nums
    {
        double val;

        val = 3.0;
        new = jsonCreate(&val, JSON_NUM);
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);

        val = 4.0;
        new = jsonCreatel(&val, JSON_NUM, root, jsonPathIndex(149));
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);
        new = jsonReadl(root, jsonPathIndex(149), NULL);
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);

        val = 5.0;
        JsonPath *path_object_array = jsonPathPush(NULL, jsonPathIndex(199), NULL);
        new = jsonCreates(&val, JSON_NUM, root, path_object_array);
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);
        new = jsonReads(root, path_object_array);
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);
        jsonPathDelete(path_object_array);

        val = 6.0;
        new = jsonCreatel(&val, JSON_NUM, root, jsonPathIndex(0), jsonPathKey("num_addedl"));
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);
        new = jsonReadl(root, jsonPathIndex(0), jsonPathKey("num_addedl"));
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);

        val = 7.0;
        JsonPath *path_object_object = jsonPathPush(NULL, jsonPathIndex(0), jsonPathKey("num_addedv"), NULL);
        new = jsonCreates(&val, JSON_NUM, root, path_object_object);
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);
        new = jsonReads(root, path_object_object);
        assert(new != NULL);
        assert(*(jsonReadDouble(new)) == val);
        jsonPathDelete(path_object_object);
    }

    // Strings
    {
        char *str;

        str = "OK FIRST STRING!";
        new = jsonCreate(str, JSON_STR);
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);

        str = "NOW SECOND STRING!";
        new = jsonCreatel(str, JSON_STR, root, jsonPathIndex(249));
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);
        new = jsonReadl(root, jsonPathIndex(249), NULL);
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);

        str = "TIME FOR THE THIRD";
        JsonPath *path_object_array = jsonPathPush(NULL, jsonPathIndex(299), NULL);
        new = jsonCreates(str, JSON_STR, root, path_object_array);
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);
        new = jsonReads(root, path_object_array);
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);
        jsonPathDelete(path_object_array);

        str = "OK OK THE 4th";
        new = jsonCreatel(str, JSON_STR, root, jsonPathIndex(0), jsonPathKey("str_addedl"));
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);
        new = jsonReadl(root, jsonPathIndex(0), jsonPathKey("str_addedl"));
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);

        str = "AND THE LAST!";
        JsonPath *path_object_object = jsonPathPush(NULL, jsonPathIndex(0), jsonPathKey("str_addedv"), NULL);
        new = jsonCreates(str, JSON_STR, root, path_object_object);
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);
        new = jsonReads(root, path_object_object);
        assert(new != NULL);
        assert(strcmp(str, jsonReadStr(new)) == 0);
        jsonPathDelete(path_object_object);
    }

    // Arrays
    {
        {
            new = jsonCreatel(NULL, JSON_ARRAY, root, jsonPathIndex(349));
            assert(new != NULL);

            new = jsonCreatel(&JSON_TRUE, JSON_LITERAL, root, jsonPathIndex(349), jsonPathIndex(0));
            assert(new != NULL);
            assert(jsonReadLiteral(new) != NULL);
            assert(*jsonReadLiteral(new) == JSON_TRUE);

            double three = 3.0;
            new = jsonCreatel(&three, JSON_NUM, root, jsonPathIndex(349), jsonPathIndex(2));
            assert(new != NULL);
            assert(jsonReadDouble(new) != NULL);
            assert(*jsonReadDouble(new) == three);

            char *four = "This is not the the the the number 4 (:";
            new = jsonCreatel(four, JSON_STR, root, jsonPathIndex(349), jsonPathIndex(1));
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(four, jsonReadStr(new)) == 0);

            new = jsonCreatel(NULL, JSON_ARRAY, root, jsonPathIndex(349), jsonPathIndex(4));
            assert(new != NULL);
            char *awesome = "This means nested arrays are working!";
            new = jsonCreatel(awesome, JSON_STR, root, jsonPathIndex(349), jsonPathIndex(4), jsonPathIndex(3));
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(awesome, jsonReadStr(new)) == 0);

            new = jsonCreatel(NULL, JSON_OBJECT, root, jsonPathIndex(349), jsonPathIndex(5));
            assert(new != NULL);
            char *awesome2 = "This means nested objects are working!";
            new = jsonCreatel(awesome2, JSON_STR, root, jsonPathIndex(349), jsonPathIndex(5), jsonPathKey("3 is key"));
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(awesome2, jsonReadStr(new)) == 0);
        }

        {
            JsonPath *path_initial = jsonPathPush(NULL, jsonPathIndex(399), NULL);
            new = jsonCreates(NULL, JSON_ARRAY, root, path_initial);
            assert(new != NULL);
            jsonPathDelete(path_initial);

            JsonPath *path_a = jsonPathPush(NULL, jsonPathIndex(399), jsonPathIndex(0), NULL);
            new = jsonCreates(&JSON_TRUE, JSON_LITERAL, root, path_a);
            assert(new != NULL);
            assert(jsonReadLiteral(new) != NULL);
            assert(*jsonReadLiteral(new) == JSON_TRUE);
            jsonPathDelete(path_a);

            double three = 3.0;
            JsonPath *path_b = jsonPathPush(NULL, jsonPathIndex(399), jsonPathIndex(2), NULL);
            new = jsonCreates(&three, JSON_NUM, root, path_b);
            assert(new != NULL);
            assert(jsonReadDouble(new) != NULL);
            assert(*jsonReadDouble(new) == three);
            jsonPathDelete(path_b);

            JsonPath *path_c = jsonPathPush(NULL, jsonPathIndex(399), jsonPathIndex(1), NULL);
            char *four = "This is not the the the the number 4 (:";
            new = jsonCreates(four, JSON_STR, root, path_c);
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(four, jsonReadStr(new)) == 0);
            jsonPathDelete(path_c);

            JsonPath *path_d = jsonPathPush(NULL, jsonPathIndex(399), jsonPathIndex(4), NULL);
            new = jsonCreates(NULL, JSON_ARRAY, root, path_d);
            assert(new != NULL);
            JsonPath *path_e = jsonPathPush(NULL, jsonPathIndex(399), jsonPathIndex(4), jsonPathIndex(3), NULL);
            char *awesome = "This means nested arrays are working!";
            new = jsonCreates(awesome, JSON_STR, root, path_e);
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(awesome, jsonReadStr(new)) == 0);
            jsonPathDelete(path_d);
            jsonPathDelete(path_e);

            JsonPath *path_f = jsonPathPush(NULL, jsonPathIndex(399), jsonPathIndex(6), NULL);
            new = jsonCreates(NULL, JSON_OBJECT, root, path_f);
            assert(new != NULL);
            JsonPath *path_g = jsonPathPush(NULL, jsonPathIndex(399), jsonPathIndex(6), jsonPathKey("Checking keys again"), NULL);
            char *awesome2 = "This means nested objects are working!";
            new = jsonCreates(awesome2, JSON_STR, root, path_g);
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(awesome2, jsonReadStr(new)) == 0);
            jsonPathDelete(path_f);
            jsonPathDelete(path_g);
        }
    }

    // Objects
    {
        {
            new = jsonCreatel(NULL, JSON_OBJECT, root, jsonPathIndex(449));
            assert(new != NULL);

            new = jsonCreatel(&JSON_TRUE, JSON_LITERAL, root, jsonPathIndex(449), jsonPathKey("0 is the index"));
            assert(new != NULL);
            assert(jsonReadLiteral(new) != NULL);
            assert(*jsonReadLiteral(new) == JSON_TRUE);

            double three = 3.0;
            new = jsonCreatel(&three, JSON_NUM, root, jsonPathIndex(449), jsonPathKey("2 is a key not an index"));
            assert(new != NULL);
            assert(jsonReadDouble(new) != NULL);
            assert(*jsonReadDouble(new) == three);

            char *four = "This is not the the the the number 4 (:";
            new = jsonCreatel(four, JSON_STR, root, jsonPathIndex(449), jsonPathKey("111111111111111111111"));
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(four, jsonReadStr(new)) == 0);

            new = jsonCreatel(NULL, JSON_OBJECT, root, jsonPathIndex(449), jsonPathKey("4 just 4"));
            assert(new != NULL);
            char *awesome = "This means nested arrays are working!";
            new = jsonCreatel(awesome, JSON_STR, root, jsonPathIndex(449), jsonPathKey("4 just 4"), jsonPathKey("working"));
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(awesome, jsonReadStr(new)) == 0);

            // just to make sure empty objects work fine
            new = jsonCreatel(NULL, JSON_OBJECT, root, jsonPathIndex(449), jsonPathKey("4 just 4"), jsonPathKey("empty"));
            assert(new != NULL);
        }

        {
            JsonPath *path_initial = jsonPathPush(NULL, jsonPathIndex(499), NULL);
            new = jsonCreates(NULL, JSON_OBJECT, root, path_initial);
            assert(new != NULL);
            jsonPathDelete(path_initial);

            JsonPath *path_a = jsonPathPush(NULL, jsonPathIndex(499), jsonPathKey("Almost done with these tests!"), NULL);
            new = jsonCreates(&JSON_TRUE, JSON_LITERAL, root, path_a);
            assert(new != NULL);
            assert(jsonReadLiteral(new) != NULL);
            assert(*jsonReadLiteral(new) == JSON_TRUE);
            jsonPathDelete(path_a);

            double three = 3.0;
            JsonPath *path_b = jsonPathPush(NULL, jsonPathIndex(499), jsonPathKey("Then comes reorganizing more stuff"), NULL);
            new = jsonCreates(&three, JSON_NUM, root, path_b);
            assert(new != NULL);
            assert(jsonReadDouble(new) != NULL);
            assert(*jsonReadDouble(new) == three);
            jsonPathDelete(path_b);

            char *four = "This is not the the the the number 4 (:";
            JsonPath *path_c = jsonPathPush(NULL, jsonPathIndex(499), jsonPathKey("celebrating"), NULL);
            new = jsonCreates(four, JSON_STR, root, path_c);
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(four, jsonReadStr(new)) == 0);
            jsonPathDelete(path_c);

            JsonPath *path_d = jsonPathPush(NULL, jsonPathIndex(499), jsonPathKey("It's too easy"), NULL);
            new = jsonCreates(NULL, JSON_OBJECT, root, path_d);
            assert(new != NULL);
            JsonPath *path_e = jsonPathPush(NULL, jsonPathIndex(499), jsonPathKey("It's too easy"), jsonPathKey("And it's done"), NULL);
            char *awesome = "This means nested objects are working!";
            new = jsonCreates(awesome, JSON_STR, root, path_e);
            assert(new != NULL);
            assert(jsonReadStr(new) != NULL);
            assert(strcmp(awesome, jsonReadStr(new)) == 0);
            jsonPathDelete(path_d);
            jsonPathDelete(path_e);
        }
    }

    FILE *debug_out = fopen("./tmp/jsonCreate.debug.json", "w");
    assert(debug_out != NULL);
    jsonOut(debug_out, 0, root);
    assert(fclose(debug_out) == 0);
    jsonLibEnd();
}

void jsonUpdate_tests() {
    jsonLibInit();
    JsonNode *root = jsonOpen("./tests/test2.json");
    assert(root != NULL);
    JsonNode *new = NULL;

    // Test literals
    {
        jsonType newType = JSON_LITERAL;
        jsonLiteral trueLiteral = JSON_TRUE;
        jsonLiteral falseLiteral = JSON_FALSE;

        assert(jsonUpdatel(&trueLiteral, newType, root, jsonPathIndex(4)));
        new = jsonReadl(root, jsonPathIndex(4));
        assert(new != NULL);
        assert(*(jsonReadLiterall(root, jsonPathIndex(4))) == trueLiteral);

        JsonPath *path_literal = jsonPathPush(NULL, jsonPathIndex(2), NULL);
        assert(jsonUpdates(&falseLiteral, newType, root, path_literal) != NULL);
        new = jsonReads(root, path_literal);
        assert(new != NULL);
        assert(*(jsonReadLiterals(root, path_literal)) == falseLiteral);
        jsonPathDelete(path_literal);

        JsonPath *Path_literal = jsonPathPush(NULL, jsonPathIndex(3));
        assert(jsonUpdates(&falseLiteral, newType, root, Path_literal) != NULL);
        new = jsonReads(root, Path_literal);
        assert(new != NULL);
        assert(*(jsonReadLiterals(root, Path_literal)) == falseLiteral);
        jsonPathDelete(Path_literal);
    }

    // Test doubles
    {
        jsonType newType = JSON_NUM;
        double jsonNum1 = 15.0;
        double jsonNum2 = 35.0;

        assert(jsonUpdatel(&jsonNum1, newType, root, jsonPathIndex(4)));
        new = jsonReadl(root, jsonPathIndex(4));
        assert(new != NULL);
        assert(*(jsonReadDoublel(root, jsonPathIndex(4))) == jsonNum1);

        JsonPath *path_literal = jsonPathPush(NULL, jsonPathIndex(2), NULL);
        assert(jsonUpdates(&jsonNum2, newType, root, path_literal) != NULL);
        new = jsonReads(root, path_literal);
        assert(new != NULL);
        assert(*(jsonReadDoubles(root, path_literal)) == jsonNum2);
        jsonPathDelete(path_literal);

        JsonPath *Path_literal = jsonPathPush(NULL, jsonPathIndex(3), NULL );
        assert(jsonUpdates(&jsonNum2, newType, root, Path_literal) != NULL);
        new = jsonReads(root, Path_literal);
        assert(new != NULL);
        assert(*(jsonReadDoubles(root, Path_literal)) == jsonNum2);
        jsonPathDelete(Path_literal);
    }

    // Test strings
    {
        jsonType newType = JSON_STR;
        char *tmpString = NULL;
        char *jsonStr1 = "here is the first string!";
        char *jsonStr2 = "AND THIS IS THE SECOND!";

        assert(jsonUpdatel(jsonStr1, newType, root, jsonPathIndex(4)));
        new = jsonReadl(root, jsonPathIndex(4));
        assert(new != NULL);
        tmpString = jsonReadStrl(root, jsonPathIndex(4));
        assert(!strcmp(tmpString, jsonStr1));

        JsonPath *path_literal = jsonPathPush(NULL, jsonPathIndex(2), NULL);
        assert(jsonUpdates(jsonStr2, newType, root, path_literal) != NULL);
        new = jsonReads(root, path_literal);
        assert(new != NULL);
        tmpString = jsonReadStrs(root, path_literal);
        assert(!strcmp(tmpString, jsonStr2));
        jsonPathDelete(path_literal);

        JsonPath *Path_literal = jsonPathPush(NULL, jsonPathIndex(3), NULL );
        assert(jsonUpdates(jsonStr2, newType, root, Path_literal) != NULL);
        new = jsonReads(root, Path_literal);
        assert(new != NULL);
        tmpString = jsonReadStrs(root, Path_literal);
        assert(!strcmp(tmpString, jsonStr2));
        jsonPathDelete(Path_literal);
    }

    FILE *debug_out = fopen("./tmp/jsonUpdate.debug.json", "w");
    assert(debug_out != NULL);
    jsonOut(debug_out, 0, root);
    assert(fclose(debug_out) == 0);
    jsonLibEnd();
}

void jsonCopy_tests() {
    jsonLibInit();
    JsonNode *root = jsonOpen("./tests/test2.json");
    assert(root != NULL);
    JsonNode *new = NULL;

    // Test literals
    {
        jsonType newType = JSON_LITERAL;
        jsonLiteral trueLiteral = JSON_TRUE;
        jsonLiteral falseLiteral = JSON_FALSE;
        JsonNode *trueNode = jsonCreate(&trueLiteral, newType);
        JsonNode *falseNode = jsonCreate(&falseLiteral, newType);

        // copy to array
        {
            assert(jsonCopyl(trueNode, root, jsonPathIndex(111)) != NULL);
            new = jsonReadl(root, jsonPathIndex(111));
            assert(trueNode != NULL);
            assert(new != NULL);
            assert(trueNode != new);
            assert(*jsonReadLiteral(trueNode) == *jsonReadLiteral(new));
            assert(*jsonReadLiteral(falseNode) != *jsonReadLiteral(new));

            JsonPath *array_pathv = jsonPathPush(NULL, jsonPathIndex(112), NULL);
            assert(jsonCopys(trueNode, root, array_pathv) != NULL);
            new = jsonReads(root, array_pathv);
            assert(trueNode != NULL);
            assert(new != NULL);
            assert(trueNode != new);
            assert(*jsonReadLiteral(trueNode) == *jsonReadLiteral(new));
            assert(*jsonReadLiteral(falseNode) != *jsonReadLiteral(new));
            jsonPathDelete(array_pathv);

            JsonPath *array_Pathv = jsonPathPush(NULL, jsonPathIndex(113), NULL );
            assert(jsonCopys(trueNode, root, array_Pathv) != NULL);
            new = jsonReads(root, array_Pathv);
            assert(trueNode != NULL);
            assert(new != NULL);
            assert(trueNode != new);
            assert(*jsonReadLiteral(trueNode) == *jsonReadLiteral(new));
            assert(*jsonReadLiteral(falseNode) != *jsonReadLiteral(new));
            jsonPathDelete(array_Pathv);
        }

        // copy to object
        {
            assert(jsonCopyl(trueNode, root, jsonPathIndex(5), jsonPathKey("111")) != NULL);
            new = jsonReadl(root, jsonPathIndex(5), jsonPathKey("111"));
            assert(trueNode != NULL);
            assert(new != NULL);
            assert(trueNode != new);
            assert(*jsonReadLiteral(trueNode) == *jsonReadLiteral(new));
            assert(*jsonReadLiteral(falseNode) != *jsonReadLiteral(new));

            JsonPath *object_pathv = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("112"), NULL);
            assert(jsonCopys(falseNode, root, object_pathv) != NULL);
            new = jsonReads(root, object_pathv);
            assert(falseNode != NULL);
            assert(new != NULL);
            assert(trueNode != new);
            assert(*jsonReadLiteral(trueNode) != *jsonReadLiteral(new));
            assert(*jsonReadLiteral(falseNode) == *jsonReadLiteral(new));
            jsonPathDelete(object_pathv);

            JsonPath *object_Pathv = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("113"), NULL );
            assert(jsonCopys(falseNode, root, object_Pathv) != NULL);
            new = jsonReads(root, object_Pathv);
            assert(falseNode != NULL);
            assert(new != NULL);
            assert(trueNode != new);
            assert(*jsonReadLiteral(trueNode) != *jsonReadLiteral(new));
            assert(*jsonReadLiteral(falseNode) == *jsonReadLiteral(new));
            jsonPathDelete(object_Pathv);
        }
    }

    // Test doubles
    {
        jsonType newType = JSON_NUM;
        double onePointo = 1.0;
        double twoPointo = 2.0;
        double threePointo = 3.0;
        double fourPointo = 4.0;
        JsonNode *oneNode = jsonCreate(&onePointo, newType);
        JsonNode *twoNode = jsonCreate(&twoPointo, newType);
        JsonNode *threeNode = jsonCreate(&threePointo, newType);
        JsonNode *fourNode = jsonCreate(&fourPointo, newType);

        // copy to array
        {
            assert(jsonCopyl(oneNode, root, jsonPathIndex(121)) != NULL);
            new = jsonReadl(root, jsonPathIndex(121));
            assert(oneNode != NULL);
            assert(new != NULL);
            assert(oneNode != new);
            assert(*jsonReadDouble(oneNode) == *jsonReadDouble(new));
            assert(*jsonReadDouble(twoNode) != *jsonReadDouble(new));

            JsonPath *array_pathv = jsonPathPush(NULL, jsonPathIndex(122), NULL);
            assert(jsonCopys(twoNode, root, array_pathv) != NULL);
            new = jsonReads(root, array_pathv);
            assert(twoNode != NULL);
            assert(new != NULL);
            assert(twoNode != new);
            assert(*jsonReadDouble(twoNode) == *jsonReadDouble(new));
            assert(*jsonReadDouble(oneNode) != *jsonReadDouble(new));
            jsonPathDelete(array_pathv);

            JsonPath *array_Pathv = jsonPathPush(NULL, jsonPathIndex(122), NULL );
            assert(jsonCopys(twoNode, root, array_Pathv) != NULL);
            new = jsonReads(root, array_Pathv);
            assert(twoNode != NULL);
            assert(new != NULL);
            assert(twoNode != new);
            assert(*jsonReadDouble(twoNode) == *jsonReadDouble(new));
            assert(*jsonReadDouble(oneNode) != *jsonReadDouble(new));
            jsonPathDelete(array_Pathv);
        }

        // copy to object
        {
            assert(jsonCopyl(threeNode, root, jsonPathIndex(5), jsonPathKey("121")) != NULL);
            new = jsonReadl(root, jsonPathIndex(5), jsonPathKey("121"));
            assert(threeNode != NULL);
            assert(new != NULL);
            assert(threeNode != new);
            assert(*jsonReadDouble(threeNode) == *jsonReadDouble(new));
            assert(*jsonReadDouble(fourNode) != *jsonReadDouble(new));

            JsonPath *object_pathv = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("122"), NULL);
            assert(jsonCopys(fourNode, root, object_pathv) != NULL);
            new = jsonReads(root, object_pathv);
            assert(fourNode != NULL);
            assert(new != NULL);
            assert(fourNode != new);
            assert(*jsonReadDouble(threeNode) != *jsonReadDouble(new));
            assert(*jsonReadDouble(fourNode) == *jsonReadDouble(new));
            jsonPathDelete(object_pathv);

            JsonPath *object_Pathv = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("122"), NULL );
            assert(jsonCopys(fourNode, root, object_Pathv) != NULL);
            new = jsonReads(root, object_Pathv);
            assert(fourNode != NULL);
            assert(new != NULL);
            assert(fourNode != new);
            assert(*jsonReadDouble(threeNode) != *jsonReadDouble(new));
            assert(*jsonReadDouble(fourNode) == *jsonReadDouble(new));
            jsonPathDelete(object_Pathv);
        }
    }

    // Test strings
    {
        jsonType newType = JSON_STR;
        char *oneString = "1.0";
        char *twoString = "2.0";
        char *threeString = "3.0";
        char *fourString = "4.0";
        JsonNode *oneNode = jsonCreate(oneString, newType);
        JsonNode *twoNode = jsonCreate(twoString, newType);
        JsonNode *threeNode = jsonCreate(threeString, newType);
        JsonNode *fourNode = jsonCreate(fourString, newType);

        // copy to array
        {
            assert(jsonCopyl(oneNode, root, jsonPathIndex(131)) != NULL);
            new = jsonReadl(root, jsonPathIndex(131));
            assert(oneNode != NULL);
            assert(new != NULL);
            assert(oneNode != new);
            assert(strcmp(jsonReadStr(oneNode), jsonReadStr(new)) == 0);
            assert(strcmp(jsonReadStr(twoNode), jsonReadStr(new)) != 0);

            JsonPath *array_pathv = jsonPathPush(NULL, jsonPathIndex(132), NULL);
            assert(jsonCopys(twoNode, root, array_pathv) != NULL);
            new = jsonReads(root, array_pathv);
            assert(twoNode != NULL);
            assert(new != NULL);
            assert(twoNode != new);
            assert(strcmp(jsonReadStr(twoNode), jsonReadStr(new)) == 0);
            assert(strcmp(jsonReadStr(oneNode), jsonReadStr(new)) != 0);
            jsonPathDelete(array_pathv);

            JsonPath *array_paths = jsonPathPush(NULL, jsonPathIndex(133), NULL );
            assert(jsonCopys(twoNode, root, array_paths) != NULL);
            new = jsonReads(root, array_paths);
            assert(twoNode != NULL);
            assert(new != NULL);
            assert(twoNode != new);
            assert(strcmp(jsonReadStr(twoNode), jsonReadStr(new)) == 0);
            assert(strcmp(jsonReadStr(oneNode), jsonReadStr(new)) != 0);
            jsonPathDelete(array_paths);
        }

        // copy to object
        {
            assert(jsonCopyl(threeNode, root, jsonPathIndex(5), jsonPathKey("131")) != NULL);
            new = jsonReadl(root, jsonPathIndex(5), jsonPathKey("131"));
            assert(threeNode != NULL);
            assert(new != NULL);
            assert(threeNode != new);
            assert(strcmp(jsonReadStr(threeNode), jsonReadStr(new)) == 0);
            assert(strcmp(jsonReadStr(fourNode), jsonReadStr(new)) != 0);

            JsonPath *object_pathv = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("132"), NULL);
            assert(jsonCopys(fourNode, root, object_pathv) != NULL);
            new = jsonReads(root, object_pathv);
            assert(fourNode != NULL);
            assert(new != NULL);
            assert(fourNode != new);
            assert(strcmp(jsonReadStr(fourNode), jsonReadStr(new)) == 0);
            assert(strcmp(jsonReadStr(threeNode), jsonReadStr(new)) != 0);
            jsonPathDelete(object_pathv);

            JsonPath *object_paths = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("133"), NULL );
            assert(jsonCopys(fourNode, root, object_paths) != NULL);
            new = jsonReads(root, object_paths);
            assert(fourNode != NULL);
            assert(new != NULL);
            assert(fourNode != new);
            assert(strcmp(jsonReadStr(fourNode), jsonReadStr(new)) == 0);
            assert(strcmp(jsonReadStr(threeNode), jsonReadStr(new)) != 0);
            jsonPathDelete(object_paths);
        }
    }

    // Test arrays
    {
        JsonNode *array = jsonReadl(root, jsonPathIndex(0), jsonPathKey("all"));

        // copy to array
        {
            JsonNode *one = NULL;

            assert(jsonCopyl(array, root, jsonPathIndex(141)) != NULL);
            new = jsonReadl(root, jsonPathIndex(141));
            assert(array != NULL);
            assert(new != NULL);
            assert(array != new);
            one = jsonReadl(root, jsonPathIndex(141), jsonPathIndex(0));
            assert(one != NULL);
            assert(jsonReadDouble(one) != NULL);
            assert(*jsonReadDouble(one) == 1.0);

            JsonPath *array_pathv = jsonPathPush(NULL, jsonPathIndex(142), NULL);
            assert(jsonCopys(array, root, array_pathv) != NULL);
            new = jsonReads(root, array_pathv);
            assert(array != NULL);
            assert(new != NULL);
            assert(array != new);
            JsonPath *array_pathv2 = jsonPathPush(NULL, jsonPathIndex(142), jsonPathIndex(0), NULL);
            one = jsonReads(root, array_pathv2);
            assert(one != NULL);
            assert(jsonReadDouble(one) != NULL);
            assert(*jsonReadDouble(one) == 1.0);
            jsonPathDelete(array_pathv);
            jsonPathDelete(array_pathv2);

            JsonPath *array_paths = jsonPathPush(NULL, jsonPathIndex(143), NULL );
            assert(jsonCopys(array, root, array_paths) != NULL);
            new = jsonReads(root, array_paths);
            assert(array != NULL);
            assert(new != NULL);
            assert(array != new);
            JsonPath *array_paths2 = jsonPathPush(NULL, jsonPathIndex(143), jsonPathIndex(0), NULL );
            one = jsonReads(root, array_paths2);
            assert(one != NULL);
            assert(jsonReadDouble(one) != NULL);
            assert(*jsonReadDouble(one) == 1.0);
            jsonPathDelete(array_paths);
            jsonPathDelete(array_paths2);
        }

        // copy to object
        {
            JsonNode *eight = NULL;

            assert(jsonCopyl(array, root, jsonPathIndex(5), jsonPathKey("test_arrayl")) != NULL);
            new = jsonReadl(root, jsonPathIndex(5), jsonPathKey("test_arrayl"));
            assert(array != NULL);
            assert(new != NULL);
            assert(array != new);
            eight = jsonReadl(root, jsonPathIndex(5), jsonPathKey("test_arrayl"), jsonPathIndex(7));
            assert(eight != NULL);
            assert(jsonReadDouble(eight) != NULL);
            assert(*jsonReadDouble(eight) == 8.0);

            JsonPath *array_pathv = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("test_arrayv"), NULL);
            assert(jsonCopys(array, root, array_pathv) != NULL);
            new = jsonReads(root, array_pathv);
            assert(array != NULL);
            assert(new != NULL);
            assert(array != new);
            JsonPath *array_pathv2 = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("test_arrayv"), jsonPathIndex(7), NULL);
            eight = jsonReads(root, array_pathv2);
            assert(eight != NULL);
            assert(jsonReadDouble(eight) != NULL);
            assert(*jsonReadDouble(eight) == 8.0);
            jsonPathDelete(array_pathv);
            jsonPathDelete(array_pathv2);

            JsonPath *array_paths = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("test_arrayv"), NULL);
            assert(jsonCopys(array, root, array_paths) != NULL);
            new = jsonReads(root, array_paths);
            assert(array != NULL);
            assert(new != NULL);
            assert(array != new);
            JsonPath *array_paths2 = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("test_arrayv"), jsonPathIndex(7), NULL);
            eight = jsonReads(root, array_paths2);
            assert(eight != NULL);
            assert(jsonReadDouble(eight) != NULL);
            assert(*jsonReadDouble(eight) == 8.0);
            jsonPathDelete(array_paths);
            jsonPathDelete(array_paths2);
        }
    }

    // Test objects
    {
        // copy to array
        {
            JsonNode *fivefives = NULL;
            JsonNode *object = jsonReadl(root, jsonPathIndex(5));
            assert(object != NULL);

            assert(jsonCopyl(object, root, jsonPathIndex(151)) != NULL);
            new = jsonReadl(root, jsonPathIndex(151));
            assert(object != NULL);
            assert(new != NULL);
            assert(object != new);
            fivefives = jsonReadl(root, jsonPathIndex(151), jsonPathKey("333"));
            assert(fivefives != NULL);
            assert(jsonReadStr(fivefives) != NULL);
            assert(!strcmp("55555", jsonReadStr(fivefives)));

            JsonPath *object_pathv = jsonPathPush(NULL, jsonPathIndex(152), NULL);
            assert(jsonCopys(object, root, object_pathv) != NULL);
            new = jsonReads(root, object_pathv);
            assert(object != NULL);
            assert(new != NULL);
            assert(object != new);
            JsonPath *object_pathv2 = jsonPathPush(NULL, jsonPathIndex(152), jsonPathKey("333"), NULL);
            fivefives = jsonReads(root, object_pathv2);
            assert(fivefives != NULL);
            assert(jsonReadStr(fivefives) != NULL);
            assert(!strcmp("55555", jsonReadStr(fivefives)));
            jsonPathDelete(object_pathv);
            jsonPathDelete(object_pathv2);

            JsonPath *object_paths = jsonPathPush(NULL, jsonPathIndex(153), NULL );
            assert(jsonCopys(object, root, object_paths) != NULL);
            new = jsonReads(root, object_paths);
            assert(object != NULL);
            assert(new != NULL);
            assert(object != new);
            JsonPath *object_paths2 = jsonPathPush(NULL, jsonPathIndex(153), jsonPathKey("333"), NULL );
            fivefives = jsonReads(root, object_paths2);
            assert(fivefives != NULL);
            assert(jsonReadStr(fivefives) != NULL);
            assert(!strcmp("55555", jsonReadStr(fivefives)));
            jsonPathDelete(object_paths);
            jsonPathDelete(object_paths2);
        }

        // copy to object
        {
            JsonNode *object;
            object = jsonReadl(root, jsonPathIndex(0));
            assert(object != NULL);

            JsonNode *seven = NULL;

            assert(jsonCopyl(object, root, jsonPathIndex(5), jsonPathKey("l")) != NULL);
            new = jsonReadl(root, jsonPathIndex(5), jsonPathKey("l"));
            assert(object != NULL);
            assert(new != NULL);
            assert(object != new);
            seven = jsonReadl(root, jsonPathIndex(5), jsonPathKey("l"), jsonPathKey("7"));
            assert(seven != NULL);
            assert(jsonReadDouble(seven) != NULL);
            assert(*jsonReadDouble(seven) == 7.0);

            JsonPath *object_pathv = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("v"), NULL);
            assert(jsonCopys(object, root, object_pathv) != NULL);
            new = jsonReads(root, object_pathv);
            assert(object != NULL);
            assert(new != NULL);
            assert(object != new);
            JsonPath *object_pathv2 = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("v"), jsonPathKey("7"), NULL);
            seven = jsonReads(root, object_pathv2);
            assert(seven != NULL);
            assert(jsonReadDouble(seven) != NULL);
            assert(*jsonReadDouble(seven) == 7.0);
            jsonPathDelete(object_pathv);
            jsonPathDelete(object_pathv2);

            JsonPath *object_paths = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("s"), NULL );
            assert(jsonCopys(object, root, object_paths) != NULL);
            new = jsonReads(root, object_paths);
            assert(object != NULL);
            assert(new != NULL);
            assert(object != new);
            JsonPath *object_paths2 = jsonPathPush(NULL, jsonPathIndex(5), jsonPathKey("s"), jsonPathKey("7"), NULL );
            seven = jsonReads(root, object_paths2);
            assert(seven != NULL);
            assert(jsonReadDouble(seven) != NULL);
            assert(*jsonReadDouble(seven) == 7.0);
            jsonPathDelete(object_paths);
            jsonPathDelete(object_paths2);
        }
    }

    FILE *debug_out = fopen("./tmp/jsonCopy.debug.json", "w");
    assert(debug_out != NULL);
    jsonOut(debug_out, 0, root);
    assert(fclose(debug_out) == 0);
    jsonLibEnd();
}

void accessKey_examples() {
    jsonLibInit();
    JsonNode *root = jsonOpen("./examples/languages.json");

    JsonNode *c = jsonReadl(root, jsonPathIndex(0));
    char *cName = jsonReadStrl(c, jsonPathKey("name"));
    jsonLiteral *cIsCompiled = jsonReadLiterall(c, jsonPathKey("compiled"));
    double *cBirthYear = jsonReadDoublel(c, jsonPathKey("created"));
    //if(c != NULL && cName != NULL && cIsCompiled != NULL && cBirthYear != NULL){
    //printf("Language: %s. Compiled: %s. Birth Year: %0.lf\n", cName, (*cIsCompiled == JSON_TRUE) ? "true" : "false", *cBirthYear);
    // Language: C. Compiled: true. Birth Year: 1972
    //}

    assert(c != NULL);
    assert(cName != NULL);
    assert(!strcmp(cName, "C"));
    assert(cIsCompiled != NULL);
    assert(*cIsCompiled == JSON_TRUE);
    assert(cBirthYear != NULL);
    assert(*cBirthYear == 1972);

    FILE *debug_out = fopen("./tmp/accessKey_examples.debug.json", "w");
    assert(debug_out != NULL);
    jsonOut(debug_out, 0, root);
    assert(fclose(debug_out) == 0);
    jsonLibEnd();
}

void accessKeyProgramatic_examples() {
    jsonLibInit();
    JsonNode *root = jsonOpen("./examples/languages.json");

    JsonPath *cPath = jsonPathPush(NULL, jsonPathIndex(0), jsonPathKey("name"));
    char *cName = jsonReadStrs(root, cPath);
    jsonPathDelete(cPath);

    cPath = jsonPathPush(NULL, jsonPathIndex(0));
    JsonNode *c = jsonReads(root, cPath);
    jsonPathPop(cPath);

    jsonPathPush(cPath, jsonPathKey("compiled"));
    jsonLiteral *cIsCompiled = jsonReadLiterals(c, cPath);
    jsonPathPop(cPath);

    jsonPathPush(cPath, jsonPathKey("created"));
    double *cBirthYear = jsonReadDoubles(c, cPath);
    jsonPathDelete(cPath);

    //if(c != NULL && cName != NULL && cIsCompiled != NULL && cBirthYear != NULL){
    //printf("Language: %s. Compiled: %s. Birth Year: %0.lf\n", cName, (*cIsCompiled == JSON_TRUE) ? "true" : "false", *cBirthYear);
    // Language: C. Compiled: true. Birth Year: 1972
    //}

    assert(c != NULL);
    assert(cName != NULL);
    assert(!strcmp(cName, "C"));
    assert(cIsCompiled != NULL);
    assert(*cIsCompiled == JSON_TRUE);
    assert(cBirthYear != NULL);
    assert(*cBirthYear == 1972);

    FILE *debug_out = fopen("./tmp/accessKeyProgramatic_examples.debug.json", "w");
    assert(debug_out != NULL);
    jsonOut(debug_out, 0, root);
    assert(fclose(debug_out) == 0);
    jsonLibEnd();
}

void setDeleteAndSave_examples() {
    jsonLibInit();
    JsonNode *root = jsonOpen("./examples/languages.json");

    JsonNode *javascript = jsonReadl(root, jsonPathIndex(2));
    size_t arrayLength = jsonArrayLength(root);
    JsonNode *ecmascript = jsonCopyl(javascript, root, jsonPathIndex(arrayLength));
    //if(ecmascript == NULL){
    //  jsonLibEnd();
    //  return 1;
    //}

    jsonCreatel("Ecmascript", JSON_STR, ecmascript, jsonPathKey("name"));
    jsonDeletel(ecmascript, jsonPathKey("name"));
    jsonCreatel("Ecmascript", JSON_STR, ecmascript, jsonPathKey("name"));

    // debug
    assert(jsonReadDoublel(ecmascript, jsonPathKey("created")) != NULL);
    assert(*jsonReadDoublel(ecmascript, jsonPathKey("created")) == 1995);

    jsonOut(stdout, false, root);

    assert(javascript != NULL);
    assert(ecmascript != NULL);
    assert(!strcmp(jsonReadStrl(javascript, jsonPathKey("name")), "Javascript"));
    assert(!strcmp(jsonReadStrl(ecmascript, jsonPathKey("name")), "Ecmascript"));

    FILE *debug_out = fopen("./tmp/setDeleteAndSave_examples.debug.json", "w");
    assert(debug_out != NULL);
    jsonOut(debug_out, 0, root);
    assert(fclose(debug_out) == 0);
    jsonLibEnd();
}

int main() {
    // INternal utility testing
    read_tests();
    array_tests();
    object_tests();
    copy_tests();
    output_tests();

    // JSON manipulation testing
    jsonRead_tests();
    jsonDelete_tests();
    jsonUpdate_tests();
    jsonCopy_tests();
    jsonCreate_tests();

    // Provided example testing
    accessKey_examples();
    accessKeyProgramatic_examples();
    //setDeleteAndSave_examples();

    printf("tests completed\n");
    return 0;
}
#endif
