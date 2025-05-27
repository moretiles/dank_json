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

struct queue scratch;
struct json_pool *elems;

int jsonLibInit() {
  void *ptr = NULL;
  /*
   * Maybe check env variables for max sizes
   */
  if (scratch.chars != NULL && elems != NULL) {
    return 1;
  }

  ptr = calloc(2 * MAX_STR_SIZE, sizeof(char));
  if (ptr == NULL) {
    return 3;
  }
  scratch.chars = ptr;
  scratch.base = 0;
  scratch.pos = 0;
  scratch.cap = 2 * MAX_STR_SIZE;

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

  return root;
}

int jsonLibEnd() {
  int ret = 0;

  if (scratch.chars) {
    free(scratch.chars);
    memset(&scratch, 0, sizeof(struct queue));
  }
  ret = destroy_pool(elems);
  elems = NULL;
  return ret;
}

JsonNode *jsonCreate() {
  if (elems == NULL || scratch.chars == NULL) {
    return NULL;
  }

  return new_node(elems);
}

JsonNode *jsonCreatetd(void *src, char type) {
  char **keys = NULL;
  JsonNode **vals = NULL;
  JsonNode *new = NULL, *ret = NULL;

  new = jsonCreate();
  ret = jsonCreate();
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
    break;

  case JSON_OBJECT:
    ret->contents.o = calloc(1, sizeof(struct ht));
    ret->type = JSON_OBJECT;
    if (ret->contents.o == NULL) {
      jsonDelete(ret);
      return NULL;
    }
    keys = calloc(OBJECT_STARTING_SIZE, sizeof(char *));
    vals = calloc(OBJECT_STARTING_SIZE, sizeof(JsonNode *));
    if (ret->contents.o == NULL || keys == NULL || vals == NULL) {
      free(ret->contents.o);
      free(keys);
      free(vals);
      jsonDelete(ret);
      return NULL;
    }
    ret->contents.o->keys = keys;
    ret->contents.o->vals = vals;
    ret->contents.o->count = 0;
    ret->contents.o->cap = OBJECT_STARTING_SIZE;
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

JsonNode *jsonCreatets(void *src, char type) {
  char **keys = NULL;
  JsonNode **vals = NULL;
  JsonNode *ret = NULL;

  ret = jsonCreate();
  if (ret == NULL ||
      (src == NULL && !(type == JSON_ARRAY || type == JSON_OBJECT))) {
    return NULL;
  }
  ret->type = type;

  switch (type) {
  case JSON_STR:
    ret->contents.s = (char *)src;
    break;

  case JSON_NUM:
    ret->contents.d = *(double *)src;
    break;

  case JSON_LITERAL:
    ret->contents.l = *(char *)src;
    break;

  case JSON_ARRAY:
    break;

  case JSON_OBJECT:
    ret->contents.o = calloc(1, sizeof(struct ht));
    ret->type = JSON_OBJECT;
    if (ret->contents.o == NULL) {
      jsonDelete(ret);
      return NULL;
    }
    keys = calloc(OBJECT_STARTING_SIZE, sizeof(char *));
    vals = calloc(OBJECT_STARTING_SIZE, sizeof(JsonNode *));
    if (ret->contents.o == NULL || keys == NULL || vals == NULL) {
      free(ret->contents.o);
      free(keys);
      free(vals);
      jsonDelete(ret);
      return NULL;
    }
    ret->contents.o->keys = keys;
    ret->contents.o->vals = vals;
    ret->contents.o->count = 0;
    ret->contents.o->cap = OBJECT_STARTING_SIZE;
    break;

  default:
    jsonDelete(ret);
    return NULL;
    break;
  }

  return ret;
}

// Using a macro to protect against people forgetting NULL
JsonNode *jsonReadnsl(JsonNode *root, ...) {
  va_list args;
  struct path *path = NULL;
  JsonNode *current = root;

  va_start(args, root);
  path = va_arg(args, struct path *);
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
      current = ht_find(current->contents.o, path->path.key);
      break;
    }

    path = va_arg(args, struct path *);
  }
  va_end(args);

  return current;
}

JsonNode *jsonReadnsv(JsonNode *root, struct path **keys) {
  struct path *path = NULL;
  JsonNode *current = root;
  size_t n = 0;

  if (keys == NULL) {
    return NULL;
  }

  path = keys[n++];
  while (current != NULL && path != NULL) {
    switch (path->type) {
    case JSON_ARRAY:
      current = array_get_nth(current, path->path.index);
      break;

    case JSON_OBJECT:
      current = ht_find(current->contents.o, path->path.key);
      break;

    default:
      return NULL;
      break;
    }

    path = keys[n++];
  }

  return current;
}

JsonNode *jsonReadnd(JsonNode *root) {
  if (root == NULL) {
    return NULL;
  }
  JsonNode *new = new_node(elems);
  if (new == NULL) {
    return NULL;
  }
  copy_json_node(new, root);
  return new;
}

JsonNode *jsonReadndv(JsonNode *root, struct path **keys) {
  return jsonReadnd(jsonReadnsv(root, keys));
}

JsonNode *jsonCreatetsv(void *src, char type, JsonNode *root, struct path **keys) {
  return jsonCreatensv(jsonCreatets(src, type), root, keys);
}

JsonNode *jsonCreatetdv(void *src, char type, JsonNode *root, struct path **keys) {
  return jsonCreatensv(jsonCreatetd(src, type), root, keys);
}

JsonNode *jsonCreatetdv(void *src, char type, JsonNode *root, struct path **keys);

int jsonReadts(void *dest, char type, JsonNode *root){
	if (dest == NULL || root == NULL || root->type != type) {
    return -1;
  }

  switch (type) {
  case JSON_STR:
		*(char **)dest = root->contents.s;
    break;

  case JSON_NUM:
    *(double *)dest = root->contents.d;
    break;

  case JSON_LITERAL:
    *(char *)dest = root->contents.l;
    break;

  default:
    return -2;
    break;
  }

  return 0;
};

int jsonReadtsv(void *dest, char type, JsonNode *root, struct path **keys){
	return jsonReadts(dest, type, jsonReadnsv(root, keys));
}

JsonNode *jsonCreatendl(JsonNode *node, JsonNode *root, ...) {
  va_list args;
  struct path *path = NULL, *prev = NULL;
  JsonNode *current = root, *parent = root, *new = NULL;

  va_start(args, root);
  path = va_arg(args, struct path *);
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
      prev = path;
      break;

    case JSON_OBJECT:
      if (current->type != JSON_OBJECT) {
        return NULL;
      }
      current = ht_find(current->contents.o, path->path.key);
      prev = path;
      break;

    default:
      break;
      current = NULL;
    }

    if (current == NULL) {
      break;
    }
    parent = current;
    path = va_arg(args, struct path *);
  }
  va_end(args);

  if (prev == NULL) {
    return NULL;
  }

  switch (prev->type) {
  case JSON_ARRAY:
    if (parent->type != JSON_ARRAY) {
      return NULL;
    }
    new = new_node(elems);
    if (new == NULL) {
      return NULL;
    }
    copy_json_node(new, node);
    array_add_node(parent, new);
    break;

  case JSON_OBJECT:
    if (parent->type != JSON_OBJECT || parent->contents.o == NULL) {
      return NULL;
    }
    new = new_node(elems);
    if (new == NULL) {
      return NULL;
    }
    copy_json_node(new, node);
    ht_insert(parent->contents.o, prev->path.key, new);
    break;
  }

  return new;
}

//JsonNode *jsonCreatensv(JsonNode *node, JsonNode *root, struct path **keys){
//	return cmemcpy(node, jsonReadnsv(root, keys), sizeof(JsonNode));
//}

JsonNode *jsonCreatensv(JsonNode *node, JsonNode *root, struct path **keys){
	return cmemcpy(node, jsonCreatendv(&((JsonNode) {.contents.a = NULL, .type = JSON_OBJECT, .next = NULL}), root, keys), sizeof(JsonNode));
}

JsonNode *jsonCreatendv(JsonNode *node, JsonNode *root, struct path **keys) {
  struct path *path = NULL, *prev = NULL;
  JsonNode *current = root, *parent = root, *new = NULL;
  size_t i = 0;

  if (root == NULL || node == NULL || keys == NULL) {
    return NULL;
  }
  path = keys[i++];
  if (path == NULL) {
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
      prev = path;
      break;

    case JSON_OBJECT:
      if (current->type != JSON_OBJECT) {
        return NULL;
      }
      current = ht_find(current->contents.o, path->path.key);
      prev = path;
      break;

    default:
      break;
      current = NULL;
    }

    if (current == NULL) {
      break;
    }
    parent = current;
    path = keys[i++];
  }

  if (prev == NULL) {
    return NULL;
  }

  switch (prev->type) {
  case JSON_ARRAY:
    if (parent->type != JSON_ARRAY) {
      return NULL;
    }
    new = new_node(elems);
    if (new == NULL) {
      return NULL;
    }
    copy_json_node(new, node);
    array_add_node(parent, new);
    break;

  case JSON_OBJECT:
    if (parent->type != JSON_OBJECT || parent->contents.o == NULL) {
      return NULL;
    }
    new = new_node(elems);
    if (new == NULL) {
      return NULL;
    }
    copy_json_node(new, node);
    ht_insert(parent->contents.o, prev->path.key, new);
    break;
  }
  /*
  switch (prev->type) {
  case JSON_ARRAY:
    if (parent->type != JSON_ARRAY) {
      return NULL;
    }
    new = new_node(elems);
    if (new == NULL) {
      return NULL;
    }
    copy_json_node(new, node);
    array_add_node(parent, new);
    break;
  case JSON_OBJECT:
    if (parent->type != JSON_OBJECT || parent->contents.o == NULL) {
      return NULL;
    }
    new = new_node(elems);
    if (new == NULL) {
      return NULL;
    }
    copy_json_node(new, node);
    ht_insert(parent->contents.o, prev->path.key, new);
    break;
  }
  */

  return new;
}

JsonNode *jsonUpdatend(JsonNode *src, JsonNode *root) {
  return copy_json_node(root, src);
}

JsonNode *jsonUpdatendv(JsonNode *src, JsonNode *root, struct path **keys) {
  return jsonUpdatend(src, jsonReadnsv(root, keys));
}

int jsonUpdatetd(void *src, char type, JsonNode *root) {
  if (src == NULL || root == NULL) {
    return -1;
  }
  int mask = 0xf0;

  switch (type) {
  case JSON_STR:
    root->flags &= mask;
    cstrncpy(root->contents.s, src, strlen(root->contents.s) + 1);
    break;

  case JSON_NUM:
    root->flags &= mask;
    root->contents.d = *(double *)src;
    if ((int)root->contents.d == root->contents.d) {
      root->flags |= JSON_NUM_IS_INT;
    }
    break;

  case JSON_LITERAL:
    root->flags &= mask;
    root->contents.l = *(char *)src;
    break;

  default:
    return -2;
    break;
  }

  return 0;
}

int jsonUpdatetdv(void *src, char type, JsonNode *root, struct path **keys) {
  return jsonReadtd(src, type, jsonReadnsv(root, keys));
}

JsonNode *jsonUpdatets(void *src, char type, JsonNode *root){
  JsonNode *ret = NULL, *new = NULL;
  new = jsonCreatets(src, type);
  ret = cmemcpy(root, new, sizeof(JsonNode));
  if(ret == NULL){
    jsonDelete(new);
  }
  return ret;
}

JsonNode *jsonUpdatensv(JsonNode *src, JsonNode *root, struct path **keys){
  return cmemcpy(jsonReadnsv(root, keys), src, sizeof(JsonNode));
}

JsonNode *jsonUpdatetsv(void *src, char type, JsonNode *root, struct path **keys){
  return cmemcpy(jsonReadnsv(root, keys), jsonCreatets(src, type), sizeof(JsonNode));
}

int jsonReadtd(void *dest, char type, JsonNode *root) {
  if (dest == NULL || root == NULL || root->type != type) {
    return -1;
  }

  switch (type) {
  case JSON_STR:
    cstrncpy(dest, root->contents.s, strlen(root->contents.s) + 1);
    break;

  case JSON_NUM:
    *(double *)dest = root->contents.d;
    break;

  case JSON_LITERAL:
    *(char *)dest = root->contents.l;
    break;

  default:
    return -2;
    break;
  }

  return 0;
}

int jsonReadtdv(void *dest, char type, JsonNode *root, struct path **keys) {
  return jsonReadtd(dest, type, jsonReadnsv(root, keys));
}

int jsonOut(FILE *dest, char minify, JsonNode *root) {
  char *ptr = calloc(2 * MAX_STR_SIZE + 1, sizeof(char));
  struct queue out = {.file = dest,
                      .chars = ptr,
                      .pos = 0,
                      .base = 0,
                      .cap = 2 * MAX_STR_SIZE + 1};

  if (dest == NULL || root == NULL || ptr == NULL) {
    free(ptr);
    return -1;
  }

  jsonOutRecurse(&out, minify, 0, root);

  enqueuec(&out, '\n');
  enqueuec(&out, '\x00');

  fdequeue(&out, out.pos);

  free(ptr);
  out.pos = 0;
  out.base = 0;

  return 0;
}

JsonNode *jsonDelete(JsonNode *elem) { return destroy_node(elems, elem); }

JsonNode *jsonDeletev(JsonNode *root, struct path **keys) {
  return jsonDelete(jsonReadnsv(root, keys));
}

int jsonOutRecurse(struct queue *file, char minify, int offset,
                      JsonNode *root) {
  // char mask = 0xff - (META_INVALID | META_FREE | JSON_ELEMENT);
  JsonNode *current = NULL;
  size_t i = 0;

  if (file->pos > ((file->cap - 1) / 2)) {
    fdequeue(file, file->pos);
    file->pos = 0;
    file->base = 0;
  }

  switch (root->type) {
  case JSON_LITERAL:
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

    enqueuec(file, '"');
    enqueue(file, root->contents.s, strlen(root->contents.s));
    enqueuec(file, '"');
    break;

  case JSON_NUM:
    if (root->flags & JSON_NUM_IS_INT) {
      i = (int)root->contents.d;
      snprintf(scratch.chars, 999, "%lu", i);
    } else if (root->flags & JSON_NUM_IS_SCIENTIFIC) {
      snprintf(scratch.chars, 999, "%le", root->contents.d);
    } else {
      snprintf(scratch.chars, 999, "%lf", root->contents.d);
    }

    enqueue(file, scratch.chars, strlen(scratch.chars));
    scratch.pos = 0;
    scratch.base = 0;
    break;

  case JSON_ARRAY:
    offset += 2;

    if (root->contents.a == NULL) {
      return -4;
    }

    enqueuec(file, '[');
    if (minify == 0) {
      enqueuec(file, '\n');
    }

    current = array_get_nth(root, i++);
    while (current != NULL) {
      if (minify == 0) {
        enqueuecn(file, ' ', offset);
      }

      jsonOutRecurse(file, minify, offset, current);

      current = array_get_nth(root, i++);
      if (current != NULL) {
        enqueuec(file, ',');
      }

      if (minify == 0) {
        enqueuec(file, '\n');
      }
    }

    offset -= 2;
    if (minify == 0) {
      enqueuecn(file, ' ', offset);
    }
    enqueuec(file, ']');
    break;

  case JSON_OBJECT:
    if (root->contents.o == NULL) {
      return -5;
    }

    enqueuec(file, '{');
    if (minify == 0) {
      enqueuec(file, '\n');
    }

    offset += 2;

    while (i < root->contents.o->cap) {
      if (root->contents.o->keys[i] != NULL) {
        if (minify == 0) {
          enqueuecn(file, ' ', offset);
        }
        enqueuec(file, '"');
        enqueue(file, root->contents.o->keys[i],
                strlen(root->contents.o->keys[i]));
        enqueuec(file, '"');
        enqueuec(file, ':');

        if (minify == 0) {
          enqueuec(file, ' ');
        }
      }

      current = root->contents.o->vals[i++];
      if (current != NULL) {
        jsonOutRecurse(file, minify, offset, current);

        enqueuec(file, ',');
        if (minify == 0) {
          enqueuec(file, '\n');
        }
      }
    }

    if (minify == 0) {
      file->pos -= (2);
      enqueuec(file, '\n');
    } else {
      file->pos -= (1);
    }
    offset -= 2;
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

int jsonOutv(FILE *dest, char minify, JsonNode *root, struct path **keys) {
  return jsonOut(dest, minify, jsonReadnsv(root, keys));
}

/*
 * New node
 */
JsonNode *new_node(struct json_pool *pool) {
  if (pool == NULL) {
    return NULL;
  }

  if (pool->next_free != NULL && pool->stored == pool->cap) {
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

/*
 * Destroy node
 */
JsonNode *destroy_node(struct json_pool *pool, JsonNode *elem) {
  if (!pool || !elem || elem->type == META_FREE) {
    return NULL;
  }

  if (elem->type == JSON_STR && elem->contents.s != NULL) {
    free(elem->contents.s);
    elem->contents.s = NULL;
  } else if (elem->type == JSON_ARRAY) {
    // json_array_free(elem->contents.a);
  } else if (elem->type == JSON_OBJECT) {
    ht_destroy(elems, elem->contents.o);
    elem->contents.o = NULL;
    // json_object_free(elem->contents.o);
  }

  elem->contents.n = pool->next_free;
  elem->type = META_FREE;
  elem->flags = 0;
  pool->next_free = elem;
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
  if (c == '"' || c == '[' || c == '{') {
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

/*
 * Return first non-whitespace character
 */
char get_sep(struct queue *store) {
  char c = ' ';
  while (is_whitespace(c)) {
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
  char **keys = NULL;
  JsonNode **vals = NULL;
  struct ht *table = NULL;
  char sep = ',', error = 0;
  if (file == NULL || scratch == NULL) {
    return NULL;
  }

  table = calloc(1, sizeof(struct ht));
  keys = calloc(OBJECT_STARTING_SIZE, sizeof(char *));
  vals = calloc(OBJECT_STARTING_SIZE, sizeof(JsonNode *));
  if (table == NULL || keys == NULL || vals == NULL) {
    free(table);
    free(keys);
    free(vals);
    return NULL;
  }
  table->keys = keys;
  table->vals = vals;
  table->count = 0;
  table->cap = OBJECT_STARTING_SIZE;
  elem->contents.o = table;
  elem->type = JSON_OBJECT;

  while (!error && sep != '}') {
    if (sep != ',') {
      return NULL;
    }

    key = new_node(elems);
    process(file, key);
    sep = get_sep(file);
    if (sep != ':') {
      return NULL;
    }

    val = new_node(elems);
    process(file, val);
    ht_insert(table, key->contents.s, val);
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
    /* print_error_messages_to_stderr(); */
    break;
  }

  scratch.pos = 0;
  scratch.base = 0;

  return elem;
}

JsonNode *copy_json_node(JsonNode *dest, JsonNode *src) {
  size_t i = 0;
  char *new_str = NULL;
  JsonNode *orig_child = NULL, *new_child = NULL;
  char **keys = NULL;
  JsonNode **vals = NULL;
  struct ht *table = NULL;

  if (dest == NULL || src == NULL) {
    return NULL;
  }

  switch (src->type) {
  case JSON_LITERAL:
    memcpy(dest, src, sizeof(JsonNode));
    break;

  case JSON_NUM:
    dest->contents.d = src->contents.d;
    dest->type = JSON_NUM;
    dest->flags = src->flags;
    dest->prev = NULL;
    dest->next = NULL;
    break;

  case JSON_STR:
    if (src->contents.s == NULL) {
      memcpy(dest, src, sizeof(JsonNode));
      break;
    }

    new_str = calloc(1 + strlen(src->contents.s), sizeof(char));
    if (new_str == NULL) {
      return NULL;
    }
    cstrncpy(new_str, src->contents.s, strlen(src->contents.s) + 1);
    dest->contents.s = new_str;
    dest->type = JSON_STR;
    dest->flags = src->flags;
    dest->prev = NULL;
    dest->next = NULL;
    break;

  case JSON_ARRAY:
    if (src == NULL) {
      return NULL;
    }
    if (src->contents.a == NULL) {
      return NULL;
    }
    memset(dest, 0, sizeof(JsonNode));
    dest->type = JSON_ARRAY;
    orig_child = src->contents.a;
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
    if (src == NULL || src->contents.o == NULL ||
        src->contents.o->keys == NULL || src->contents.o->vals == NULL) {
      return NULL;
    }

    table = calloc(1, sizeof(struct ht));
    keys = calloc(OBJECT_STARTING_SIZE, sizeof(char *));
    vals = calloc(OBJECT_STARTING_SIZE, sizeof(JsonNode *));
    if (table == NULL || keys == NULL || vals == NULL) {
      free(table);
      free(keys);
      free(vals);
      return NULL;
    }
    memset(dest, 0, sizeof(JsonNode));
    table->keys = keys;
    table->vals = vals;
    table->count = 0;
    table->cap = OBJECT_STARTING_SIZE;
    dest->contents.o = table;
    dest->flags = 0;
    dest->type = JSON_OBJECT;
    for (i = 0; i < src->contents.o->cap; i++) {
      if (src->contents.o->keys[i] == NULL ||
          src->contents.o->vals[i] == NULL) {
        continue;
      }

      new_child = new_node(elems);
      new_str = src->contents.o->keys[i];
      copy_json_node(new_child, src->contents.o->vals[i]);
      ht_insert(dest->contents.o, new_str, new_child);
    }
    break;

  default:
    return NULL;
    break;
  }
  dest->prev = NULL;
  dest->next = NULL;
  return dest;
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

  size_t tmp_cap = 1;
  char **keys = calloc(tmp_cap, sizeof(char *));
  JsonNode **vals = calloc(tmp_cap, sizeof(JsonNode *));
  assert(keys != NULL && vals != NULL);
  struct ht *table = NULL;
  table = calloc(1, sizeof(struct ht));
  assert(table != NULL);
  table->keys = keys;
  table->vals = vals;
  table->count = 0;
  table->cap = tmp_cap;

  char *key1 = calloc(99, sizeof(char));
  char *key2 = calloc(99, sizeof(char));
  char *key3 = calloc(99, sizeof(char));
  assert(key1 != NULL && key2 != NULL && key3 != NULL);
  cstrncpy(key1, "0", 99);
  cstrncpy(key2, "yes hello test 1233", 99);
  cstrncpy(key3, "bees bees are the best bees bees", 99);
  // printf("first inserted at %p\n", ht_insert(table, key1,
  // array_get_nth(interior, 0)));
  assert(ht_insert(table, key1, array_get_nth(interior, 0)) != NULL);
  assert(ht_insert(table, key2, array_get_nth(interior, 1)) != NULL);
  assert(ht_insert(table, key3, array_get_nth(interior, 2)) != NULL);
  JsonNode *found = ht_find(table, "000000000000000");
  assert(found == NULL);
  assert(ht_find(table, key2)->contents.l == JSON_FALSE);
  assert(!strcmp("aab", ht_find(table, key3)->contents.s));
  ht_set(table, key2, array_get_nth(interior, 0));
  assert(ht_find(table, key2)->contents.d == -57.638300);
  ht_del(elems, table, key2);
  found = ht_find(table, key2);
  assert(found == NULL);

  ht_destroy(elems, table);
  free(key1);
  key1 = NULL;
  free(key2);
  key2 = NULL;
  free(key3);
  key3 = NULL;

  JsonNode *new = new_node(elems);
  assert(new != NULL);
  new = copy_json_node(new, array_get_nth(array, 1));
  assert(new != NULL);
  assert(array_insert_node(array, new, 5) == 0);
  // printf("%s\n", array_get_nth(array, 1)->contents.s);
  // printf("%s\n", array_get_nth(array, 5)->contents.s);
  assert(!strcmp(array_get_nth(array, 1)->contents.s,
                 array_get_nth(array, 5)->contents.s));
  assert(array_insert_node(array, new, 2) == 0);
  assert(!strcmp(array_get_nth(array, 1)->contents.s,
                 array_get_nth(array, 2)->contents.s));
  assert(array_insert_node(array, new, 0) == 0);
  // Add 1 because of shift up
  assert(!strcmp(array_get_nth(array, 0)->contents.s,
                 array_get_nth(array, 1 + 1)->contents.s));

  jsonLibEnd();
}

void object_tests() {
  jsonLibInit();

  // assert(OBJECT_STARTING_SIZE == 1);

  JsonNode *root = jsonOpen("./tests/object1.json");
  assert(root != NULL && root->contents.o != NULL);
  JsonNode *found_1 = ht_find(root->contents.o, "A");
  assert(found_1 != NULL);
  assert(found_1->contents.d == 10.0);
  JsonNode *found_2 = ht_find(root->contents.o, "B");
  assert(found_2 != NULL);
  assert(found_2->contents.d == 11.0);
  JsonNode *found_3 = ht_find(root->contents.o, "C");
  assert(found_3 != NULL);
  assert(!strcmp(found_3->contents.s, "some text I guess"));
  JsonNode *found_4 = ht_find(root->contents.o, "D");
  assert(found_4->type == JSON_ARRAY);
  JsonNode *second = array_get_nth(found_4, 1);
  assert(second != NULL);
  assert(second->type == JSON_NUM);
  assert(second->contents.d == 1.0);

  JsonNode *removed = ht_del(elems, root->contents.o, "A");

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
  JsonNode *A = ht_find(object->contents.o, "A");
  JsonNode *new_A = ht_find(new_object->contents.o, "A");
  assert(A != new_A);
  assert(A->type == JSON_NUM && new_A->type == JSON_NUM);
  assert(A->contents.d == 10.0 && new_A->contents.d == 10.0);
  JsonNode *B = ht_find(object->contents.o, "B");
  JsonNode *new_B = ht_find(new_object->contents.o, "B");
  assert(B != new_B);
  assert(B->type == JSON_NUM && new_B->type == JSON_NUM);
  assert(B->contents.d == 11.0 && new_B->contents.d == 11.0);
  JsonNode *C = ht_find(object->contents.o, "C");
  JsonNode *new_C = ht_find(new_object->contents.o, "C");
  assert(C != NULL);
  assert(new_C != NULL);
  assert(C != new_C);
  assert(C->type == JSON_STR && new_C->type == JSON_STR);
  assert(!strcmp(C->contents.s, "some text I guess") &&
         !strcmp(new_C->contents.s, "some text I guess"));
  JsonNode *D = ht_find(object->contents.o, "D");
  JsonNode *new_D = ht_find(new_object->contents.o, "D");
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

void interface_tests() {
  jsonLibInit();

  // JsonNode *array = jsonOpen("./tests/array1.json");
  JsonNode *object = jsonOpen("./tests/object1.json");

  JsonNode *exists = jsonReadnsl(object, _KEY("D"), _INDEX(2), NULL);
  assert(exists != NULL);
  assert(!strcmp(exists->contents.s, "yes"));
  struct path *exists_path[] = {_KEY("D"), _INDEX(2), NULL};
  JsonNode *exists2 = jsonReadnsv(object, exists_path);
  assert(!strcmp(exists2->contents.s, "yes"));

  // jsonOut(stdout, 0, object);
  char my_str[99] = "";
  assert(jsonReadtd(&my_str, JSON_STR, exists) == 0);
  assert(strlen(my_str) == 3);
  assert(jsonReadtd(&my_str, JSON_STR, exists2) == 0);
  assert(strlen(my_str) == 3);
  assert(jsonReadtdl(&my_str, JSON_STR, object, _KEY("D"), _INDEX(2), NULL) == 0);
  assert(strlen(my_str) == 3);
  assert(jsonReadtdv(&my_str, JSON_STR, object, exists_path) == 0);
  assert(strlen(my_str) == 3);
  JsonNode read_from = {0};
  memset(&read_from, 0, sizeof(JsonNode));
  read_from.contents.d = 777.777;
  read_from.type = JSON_NUM;
  double cool = -7777777777777777777777777777777777777.7;
  jsonReadtd(&cool, JSON_NUM, &read_from);
  assert(cool == 777.777);
  read_from.contents.l = JSON_TRUE;
  read_from.type = JSON_LITERAL;
  char cooler = JSON_FALSE;
  jsonReadtd(&cooler, JSON_LITERAL, &read_from);
  assert(cooler == JSON_TRUE);

  double inlined = 3.333;
  JsonNode *set_tree = jsonCreatetd(NULL, JSON_OBJECT);
  JsonNode *breakage = jsonCreatetd(&inlined, JSON_NUM);
  assert(breakage != NULL);
  assert(jsonCreatendl(breakage, set_tree, _KEY("A"), NULL) != NULL);
  // assert(jsonUpdatetdl(&inlined, JSON_NUM, set_tree, _KEY("A"), NULL) == 0);
  //printf("%f\n", jsonReadnsl(set_tree, _KEY("A"), NULL)->contents.d);
  assert(jsonReadnsl(set_tree, _KEY("A"), NULL)->contents.d == inlined);

  char *inlined2 = "very good text much wow!";
  struct path *pathDown[] = {
      _KEY("WE REALLY NEED TO TEST A LONG KEY "
           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHHHHHHHHHHHHHHHHHH"
           "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH!"
           "!!!!!!!!!!!!!"),
      NULL};
  JsonNode *epic_breakage = jsonCreatetd(inlined2, JSON_STR);
  epic_breakage = jsonCreatendv(epic_breakage, set_tree, pathDown);
  assert(epic_breakage != NULL);
  //printf("%s\n", jsonReadnsv(set_tree, pathDown)->contents.s);
  assert(!strcmp(inlined2, jsonReadnsv(set_tree, pathDown)->contents.s));

  JsonNode *new_node = jsonReadnd(exists);
  assert(new_node != exists);
  assert(!strcmp(exists->contents.s, new_node->contents.s));
  new_node = jsonReadndl(object, _KEY("D"), _INDEX(2), NULL);
  assert(new_node != exists);
  assert(!strcmp(exists->contents.s, new_node->contents.s));
  new_node = jsonReadndv(object, exists_path);
  assert(new_node != exists);
  assert(!strcmp(exists->contents.s, new_node->contents.s));

  JsonNode *obj_copy = jsonReadnd(object);
  JsonNode *created_node = jsonCreatendl(new_node, obj_copy, NULL);
  assert(created_node == NULL);
  created_node = NULL;
  created_node = jsonCreatendl(new_node, obj_copy, _KEY("E"), NULL);
  assert(created_node != NULL);
  // printf("%s\n", created_node->contents.s);
  // printf("%s\n", jsonReadnsl(obj_copy, _KEY("E"), NULL)->contents.s);
  assert(!strcmp(created_node->contents.s,
                 jsonReadnsl(obj_copy, _KEY("E"), NULL)->contents.s));
  created_node = NULL;
  created_node = jsonCreatendl(new_node, obj_copy, _KEY("D"), _INDEX(3), NULL);
  assert(created_node != NULL);
  assert(!strcmp(created_node->contents.s,
                 jsonReadnsl(obj_copy, _KEY("D"), _INDEX(3), NULL)->contents.s));
  JsonNode *pre = jsonReadnsl(obj_copy, _KEY("D"), _INDEX(3), NULL);
  assert(jsonDeletel(obj_copy, _KEY("D"), _INDEX(3), NULL) == pre);
  assert(jsonDelete(obj_copy) == obj_copy);

  obj_copy = jsonReadnd(object);
  struct path *invalid[] = {NULL};
  created_node = jsonCreatendv(new_node, obj_copy, invalid);
  assert(created_node == NULL);
  created_node = NULL;
  struct path *depth1[] = {_KEY("E"), NULL};
  created_node = jsonCreatendv(new_node, obj_copy, depth1);
  assert(created_node != NULL);
  // printf("%s\n", created_node->contents.s);
  // printf("%s\n", jsonReadnsl(obj_copy, _KEY("E"), NULL)->contents.s);
  assert(!strcmp(created_node->contents.s,
                 jsonReadnsl(obj_copy, _KEY("E"), NULL)->contents.s));
  created_node = NULL;
  struct path *depth2[] = {_KEY("D"), _INDEX(3), NULL};
  created_node = jsonCreatendv(new_node, obj_copy, depth2);
  assert(created_node != NULL);
  assert(!strcmp(created_node->contents.s,
                 jsonReadnsl(obj_copy, _KEY("D"), _INDEX(3), NULL)->contents.s));
  pre = jsonReadnsv(obj_copy, depth2);
  assert(jsonDeletev(obj_copy, depth2) == pre);
  assert(jsonDelete(obj_copy) == obj_copy);

  // jsonOut(stdout, 0, object);
  jsonUpdatendl(jsonReadnsl(object, _KEY("B"), NULL), object, _KEY("A"), NULL);
  assert(jsonReadnsl(object, _KEY("A"), NULL)->contents.d == 11);
  struct path *inner_C[] = {_KEY("D"), _INDEX(0), _KEY("C"), NULL};
  struct path *outer_C[] = {_KEY("C"), NULL};
  jsonUpdatendv(jsonReadnsv(object, outer_C), object, inner_C);
  assert(!strcmp(jsonReadnsv(object, inner_C)->contents.s, "some text I guess"));
  // jsonOut(stdout, 0, object);

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
  /*
  fclose(out);

  out = fopen("/tmp/json-tests", "r");
  assert(out != NULL);
  */
  char *expected = "{\"D\":[{\"C\":12,\"B\":11,\"A\":10},1,\"yes\"],\"C\":"
                   "\"some text I guess\",\"B\":11,\"A\":10}\n";
  char test[999];
  // Clang is unhappy about errno even though we check if it is invalid, false
  // positive
  char *ret = fgets(test, 999, out);
  assert(ret == test);
  // printf("%s\n", expected);
  // printf("%s\n", test);
  assert(!strcmp(expected, test));
  assert(jsonOutl(stdin, 1, root, _KEY("D"), _INDEX(0), _KEY("B"), NULL) ==
         0);
  struct path *keys[] = {_KEY("D"), _INDEX(0), _KEY("B"), NULL};
  assert(jsonOutv(stdin, 1, root, keys) == 0);
  fflush(out);
  fclose(out);
  remove("/tmp/json-tests");

  jsonLibEnd();
}

int main() {
  read_tests();
  array_tests();
  object_tests();
  copy_tests();
  interface_tests();
  output_tests();
  printf("tests completed\n");
  return 0;
}
#else
int main() {
  printf("this build does nothing\n");
  return 0;
}
#endif
