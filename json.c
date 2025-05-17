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

int jsonInit() {
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

JSON_Node *jsonOpen(const char *fileName) {
  struct queue *new = NULL;
  char *chars = NULL;
  FILE *file = NULL;
  JSON_Node *root = NULL;

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

int jsonEnd() {
  int ret = 0;

  if (scratch.chars) {
    free(scratch.chars);
    memset(&scratch, 0, sizeof(struct queue));
  }
  ret = destroy_pool(elems);
  elems = NULL;
  return ret;
}

JSON_Node *jsonNew() {
  if (elems == NULL || scratch.chars == NULL) {
    return NULL;
  }

  return new_node(elems);
}

// Using a macro to protect against people forgetting NULL
JSON_Node *jsonReadl(JSON_Node *root, ...) {
  va_list args;
  struct path *path = NULL;
  JSON_Node *current = root;

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

JSON_Node *jsonReadv(JSON_Node *root, struct path **keys) {
  struct path *path = NULL;
  JSON_Node *current = root;
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

JSON_Node *jsonCopy(JSON_Node *root) {
  if (root == NULL) {
    return NULL;
  }
  JSON_Node *new = new_node(elems);
  if (new == NULL) {
    return NULL;
  }
  copy_json_node(new, root);
  return new;
}

JSON_Node *jsonCreatel(JSON_Node *node, JSON_Node *root, ...) {
  va_list args;
  struct path *path = NULL, *prev = NULL;
  JSON_Node *current = root, *parent = root, *new = NULL;

  va_start(args, root);
  path = va_arg(args, struct path *);
  if(path == NULL){
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

    if(current == NULL){
      break;
    }
    parent = current;
    path = va_arg(args, struct path *);
  }
  va_end(args);

  if(prev == NULL){
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

JSON_Node *jsonCopyv(JSON_Node *root, struct path **keys) {
  return jsonCopy(jsonReadv(root, keys));
}

JSON_Node *jsonUpdate(JSON_Node *src, JSON_Node *root){
  return copy_json_node(root, src);
}

JSON_Node *jsonUpdatev(JSON_Node *src, JSON_Node *root, struct path **keys){
  return jsonUpdate(src, jsonReadv(root, keys));
}

size_t jsonStrlen(JSON_Node *root) {
  if (root == NULL) {
    return 0;
  }
  return strlen(root->contents.s);
}

size_t jsonStrlenv(JSON_Node *root, struct path **keys) {
  return jsonStrlen(jsonReadv(root, keys));
}

int jsonString(FILE *dest, char minify, JSON_Node *root) {
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

  jsonStringRecurse(&out, minify, 0, root);

  enqueuec(&out, '\n');
  enqueuec(&out, '\x00');

  fdequeue(&out, out.pos);

  free(ptr);
  out.pos = 0;
  out.base = 0;

  return 0;
}

JSON_Node *jsonDelete(JSON_Node *elem){
  return destroy_node(elems, elem);
}

JSON_Node *jsonDeletev(JSON_Node *root, struct path **keys) {
  return jsonDelete(jsonReadv(root, keys));
}

int jsonStringRecurse(struct queue *file, char minify, int offset,
                      JSON_Node *root) {
  // char mask = 0xff - (META_INVALID | META_FREE | JSON_ELEMENT);
  JSON_Node *current = NULL;
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

      jsonStringRecurse(file, minify, offset, current);

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
        jsonStringRecurse(file, minify, offset, current);

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

int jsonStringv(FILE *dest, char minify, JSON_Node *root, struct path **keys) {
  return jsonString(dest, minify, jsonReadv(root, keys));
}

/*
 * Init pool
 */
int init_pool(struct json_pool *pool, size_t size) {
  if (pool == NULL) {
    return 1;
  }

  pool->items = calloc(size, sizeof(JSON_Node));
  if (pool->items == NULL) {
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
int destroy_pool(struct json_pool *pool) {
  if (pool == NULL) {
    return 1;
  }

  if (pool->prev != NULL) {
    destroy_pool(pool->prev);
  }

  size_t i = 0;
  for (i = 0; i < pool->cap; i++) {
    destroy_node(pool, &((pool->items)[i]));
  }
  if (pool->items != NULL) {
    free(pool->items);
    pool->items = NULL;
  }

  free(pool);
  pool = NULL;

  return 0;
}

struct json_pool *double_pool(struct json_pool **pool) {
  struct json_pool *ptr = calloc(1, sizeof(struct json_pool));

  if (!ptr) {
    return NULL;
  }

  init_pool(ptr, elems->cap * 2);
  ptr->prev = *pool;
  *pool = ptr;
  return *pool;
}

/*
 * New node
 */
JSON_Node *new_node(struct json_pool *pool) {
  if (pool == NULL) {
    return NULL;
  }

  if (pool->next_free != NULL && pool->stored == pool->cap) {
    double_pool(&elems);
  }

  JSON_Node *now_taken = NULL;
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
  memset(now_taken, 0, sizeof(JSON_Node));
  return now_taken;
}

/*
 * Destroy node
 */
JSON_Node *destroy_node(struct json_pool *pool, JSON_Node *elem) {
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

int array_add_node(JSON_Node *array, JSON_Node *elem) {
  JSON_Node *head = NULL, *tail = NULL;
  if (!elem || !array || array->type != JSON_ARRAY) {
    return 1;
  }
  head = array->contents.a;
  if (head && head->prev) {
    tail = head->prev;
  };

  if (!head) {
    array->contents.a = elem;
    elem->flags |= (JSON_ELEM_IS_HEAD | JSON_ELEM_IS_TAIL);
    elem->prev = NULL;
    elem->next = NULL;
  } else if (head->prev == NULL || head->next == NULL) {
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

int array_insert_node(JSON_Node *array, JSON_Node *elem, size_t pos) {
  JSON_Node *prev = NULL, *current = NULL, *next = NULL;
  size_t init = pos;

  if (!elem || !array || array->type != JSON_ARRAY ||
      (pos > 0 && array->contents.a == NULL)) {
    return 1;
  }

  if (pos == 0) {
    if (array->contents.a == NULL) {
      array_add_node(array, elem);
      return 0;
    }
  }

  current = array->contents.a;
  prev = current->prev;
  next = current->next;

  while (pos != 0) {
    if (current == NULL) {
      return init - pos;
    }

    prev = current;
    current = next;
    next = current->next;
    pos--;
  }

  elem->prev = prev;
  elem->next = current;

  prev->next = elem;
  current->prev = elem;

  if (init - pos == 0) {
    array->contents.a = elem;
    current->flags &= 0xff - JSON_ELEM_IS_HEAD;
    elem->flags |= JSON_ELEM_IS_HEAD;
  }

  return 0;
}

int array_destroy_node(struct json_pool *pool, JSON_Node *array,
                       JSON_Node *elem) {
  JSON_Node *prev = NULL, *next = NULL;

  /*
   * It should always be the case that if prev exists then next exists and vice
   * versa
   */
  if (!pool || !array || !elem || array->type != JSON_ARRAY) {
    return 1;
  }

  if (elem->prev && elem->next) {
    prev = elem->prev;
    next = elem->next;

    if (elem->flags & JSON_ELEM_IS_HEAD) {
      next->flags |= JSON_ELEM_IS_HEAD;
      array->contents.a = next;
    }
    prev->next = next;
    if (elem->flags & JSON_ELEM_IS_TAIL) {
      prev->flags |= JSON_ELEM_IS_HEAD;
    }
    next->prev = prev;
  }
  elem->prev = NULL;
  elem->next = NULL;

  destroy_node(pool, elem);
  return 0;
}

JSON_Node *array_get_nth(JSON_Node *array, size_t n) {
  JSON_Node *elem = NULL;
  if (array == NULL) {
    return NULL;
  }

  elem = array->contents.a;
  while (n != 0 && elem != NULL && !(elem->flags & JSON_ELEM_IS_TAIL)) {
    n--;
    elem = elem->next;
  }
  if (n == 0) {
    return elem;
  } else {
    return NULL;
  }
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
static inline char get_sep(struct queue *store) {
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

JSON_Node *get_json_array(struct queue *file, struct queue *scratch,
                          JSON_Node *elem) {
  JSON_Node *from_pool = NULL;
  JSON_Node current;
  char sep = ',', error = 0;

  // printf("inside array\n");

  if (file == NULL || scratch == NULL) {
    return NULL;
  }
  elem->contents.a = 0;
  elem->type = JSON_ARRAY;

  while (!error && sep != ']') {
    if (sep != ',') {
      return NULL;
    }
    process(file, &current);
    from_pool = new_node(elems);
    memcpy(from_pool, &current, sizeof(JSON_Node));
    array_add_node(elem, from_pool);

    sep = get_sep(file);
    // printf("%c\n", sep);
  }

  if (!error) {
    // printf("end\n");
    return elem;
  } else {
    // array_destroy(read, new_array);
    return NULL;
  }
}

JSON_Node *get_json_object(struct queue *file, struct queue *scratch,
                           JSON_Node *elem) {
  JSON_Node *key = NULL, *val = NULL;
  char **keys = NULL;
  JSON_Node **vals = NULL;
  struct ht *table = NULL;
  char sep = ',', error = 0;
  if (file == NULL || scratch == NULL) {
    return NULL;
  }

  table = calloc(1, sizeof(struct ht));
  keys = calloc(OBJECT_STARTING_SIZE, sizeof(char *));
  vals = calloc(OBJECT_STARTING_SIZE, sizeof(JSON_Node *));
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

JSON_Node *process(struct queue *file, JSON_Node *elem) {
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
    get_json_array(file, &scratch, elem);
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

JSON_Node *copy_json_node(JSON_Node *dest, JSON_Node *src) {
  size_t i = 0;
  char *new_str = NULL;
  JSON_Node *orig_child = NULL, *new_child = NULL;
  char **keys = NULL;
  JSON_Node **vals = NULL;
  struct ht *table = NULL;

  if (dest == NULL || src == NULL) {
    return NULL;
  }

  switch (src->type) {
  case JSON_LITERAL:
    memcpy(dest, src, sizeof(JSON_Node));
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
      memcpy(dest, src, sizeof(JSON_Node));
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
    /*
       orig_child = new_node(elems);
       new_child = new_node(elems);
       if(src == NULL || orig_child == NULL || new_child == NULL){
       */
    if (src == NULL) {
      return NULL;
    }
    if (src->contents.a == NULL) {
      return NULL;
    }
    memset(dest, 0, sizeof(JSON_Node));
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
    vals = calloc(OBJECT_STARTING_SIZE, sizeof(JSON_Node *));
    if (table == NULL || keys == NULL || vals == NULL) {
      free(table);
      free(keys);
      free(vals);
      return NULL;
    }
    memset(dest, 0, sizeof(JSON_Node));
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

uint64_t fnv(const char *data, size_t len) {
  /* There is no bug here.
   * It is okay for __uint128_t to hold a value that would be to big
   * for some signed numbers.
   */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wimplicitly-unsigned-literal"
#endif
  __uint128_t hash = FNV_OFFSET_BASIS;
#ifdef __clang__
#pragma clang diagnostic pop
#endif
  size_t i = 0;
  if (data == NULL) {
    return hash;
  }

  while (len > 8) {
    hash *= FNV_PRIME;
    hash ^= (uint64_t)data[i];
    len -= 8;
    i += 8;
  }

  if (len > 0) {
    hash *= FNV_PRIME;
    while (len > 0) {
      hash ^= (__uint128_t)data[i] << (8 * (i % 8));
      len--;
      i++;
    }
  }

  return (uint64_t)hash;
}

uint64_t fnv_str(const char *data) { return (uint64_t)fnv(data, strlen(data)); }

JSON_Node *ht_insert(struct ht *table, char *key, JSON_Node *val) {
  if (table == NULL || key == NULL || val == NULL) {
    return NULL;
  }

  char *new_key = NULL;
  struct ht *new = NULL;
  uint64_t hash = fnv_str(key);
  uint32_t offset = (uint32_t)hash;
  uint32_t iterate = (uint32_t)(hash >> 32);
  // uint32_t offset = (uint32_t) (hash >> 32), iterate = (uint32_t) hash;
  size_t max_possible = table->cap;
  while (table->keys[offset % table->cap] != NULL &&
         table->vals[offset % table->cap] != NULL && max_possible > 0) {
    offset += iterate;
    max_possible -= 1;
  }
  if (max_possible == 0) {
    return NULL;
  }
  table->count += 1;
  new_key = calloc(1 + strlen(key), sizeof(char));
  if (new_key == NULL) {
    return NULL;
  }
  memcpy(new_key, key, strlen(key) + 1);
  new_key[strlen(key)] = '\x00';
  table->keys[offset % table->cap] = new_key;
  table->vals[offset % table->cap] = val;
  if (table->count > table->cap / 2) {
    new = ht_grow(table, (size_t)(table->cap * 2));
    if (new != NULL) {
      table = new;
    }
  }
  return ht_find(table, key);
}

JSON_Node *ht_insert_direct(struct ht *table, char *key, JSON_Node *val) {
  if (table == NULL || key == NULL || val == NULL) {
    return NULL;
  }

  struct ht *new = NULL;
  uint64_t hash = fnv_str(key);
  uint32_t offset = (uint32_t)hash;
  uint32_t iterate = (uint32_t)(hash >> 32);
  // uint32_t offset = (uint32_t) (hash >> 32), iterate = (uint32_t) hash;
  size_t max_possible = table->cap;
  while (table->keys[offset % table->cap] != NULL &&
         table->vals[offset % table->cap] != NULL && max_possible > 0) {
    offset += iterate;
    max_possible -= 1;
  }
  if (max_possible == 0) {
    return NULL;
  }
  table->count += 1;
  table->keys[offset % table->cap] = key;
  table->vals[offset % table->cap] = val;
  if (table->count > table->cap / 2) {
    new = ht_grow(table, (size_t)(table->cap * 2));
    if (new != NULL) {
      table = new;
    }
  }
  return ht_find(table, key);
}

JSON_Node *ht_find(struct ht *table, char *key) {
  if (table == NULL || key == NULL) {
    return NULL;
  }

  uint64_t hash = fnv_str(key);
  uint32_t offset = (uint32_t)hash;
  // printf("hash is %lu\n", hash);
  // uint64_t offset = hash;
  uint32_t iterate = (uint32_t)(hash >> 32);
  // uint32_t offset = (uint32_t) (hash >> 32), iterate = (uint32_t) hash;
  // printf("key is %s, offset is %u\n", key, offset);
  // printf("key is %s, iterate is %u\n", key, iterate);
  size_t max_possible = table->cap;
  while (max_possible > 0) {
    // printf("offset is %lu\n", offset);
    if (table->keys[offset % table->cap] != NULL &&
        table->vals[offset % table->cap] != NULL &&
        !strcmp(table->keys[offset % table->cap], key)) {
      return table->vals[offset % table->cap];
    }
    offset += iterate;
    max_possible -= 1;
  }
  return NULL;
}

JSON_Node *ht_set(struct ht *table, char *key, JSON_Node *elem) {
  if (table == NULL || key == NULL || elem == NULL) {
    return NULL;
  }

  JSON_Node *target_val = ht_find(table, key);
  if (target_val != NULL) {
    /*
       uint64_t offset = (uint64_t) (target_val - table->vals[0]) /
    sizeof(JSON_Node*); char **target_key = &(table->keys[offset]);
    //memcpy(target_val, elem, sizeof(JSON_Node));
    new_key = malloc(sizeof(char) * (1 + strlen(key)));
    if(new_key == NULL){
    return NULL;
    }
    strncpy(new_key, key, strlen(key));
     *target_key = new_key;
     */
    copy_json_node(target_val, elem);
  }
  return target_val;
}

JSON_Node *ht_del(struct json_pool *pool, struct ht *table, const char *key) {
  if (table == NULL || key == NULL) {
    return NULL;
  }

  /*
     JSON_Node *elem = ht_find(table, key);
     if(elem == NULL){
     return NULL;
     }
     uint64_t offset = (uint64_t) (elem - table->vals[0]) / sizeof(JSON_Node*);
     free(table->keys[offset]);
     table->keys[offset] = NULL;
     destroy_node(pool, table->vals[offset]);
     table->vals[offset] = NULL;
     */

  JSON_Node *cleared = NULL;
  uint64_t hash = fnv_str(key);
  uint32_t offset = (uint32_t)hash;
  uint32_t iterate = (uint32_t)(hash >> 32);
  // printf("key is %s, offset is %u\n", key, offset);
  // printf("key is %s, iterate is %u\n", key, iterate);
  size_t max_possible = table->cap;
  while (max_possible > 0) {
    // printf("offset is %lu\n", offset);
    if (table->keys[offset % table->cap] != NULL &&
        table->vals[offset % table->cap] != NULL &&
        !strcmp(table->keys[offset % table->cap], key)) {
      cleared = table->vals[offset % table->cap];
      free(table->keys[offset % table->cap]);
      table->keys[offset % table->cap] = NULL;
      destroy_node(pool, table->vals[offset % table->cap]);
      table->vals[offset % table->cap] = NULL;
      return cleared;
    } else if (table->keys[offset % table->cap] == NULL &&
               table->vals[offset % table->cap] == NULL) {
      return NULL;
    }
    offset += iterate;
    max_possible -= 1;
  }
  return NULL;
}

struct ht *ht_grow(struct ht *old, size_t cap) {
  if (old == NULL) {
    return NULL;
  }

  struct ht *new = calloc(1, sizeof(struct ht));
  char **new_keys = calloc(cap, sizeof(char *));
  JSON_Node **new_vals = calloc(cap, sizeof(JSON_Node *));
  size_t i = 0;
  if (new == NULL || new_keys == NULL || new_vals == NULL) {
    free(new);
    free(new_keys);
    free(new_vals);
    return NULL;
  }
  new->keys = new_keys;
  new->vals = new_vals;
  new->cap = cap;
  for (i = 0; i < old->cap; i++) {
    if (old->keys[i] == NULL || old->vals[i] == NULL) {
      continue;
    }

    ht_insert_direct(new, old->keys[i], old->vals[i]);
  }

  free(old->keys);
  old->keys = NULL;
  free(old->vals);
  old->vals = NULL;
  memcpy(old, new, sizeof(struct ht));
  free(new);
  new = NULL;
  return old;
}

void ht_destroy(struct json_pool *pool, struct ht *table) {
  size_t i = 0;

  if (table == NULL) {
    return;
  }

  for (i = 0; i < table->cap; i++) {
    if (table->keys[i] != NULL) {
      free(table->keys[i]);
      table->keys[i] = NULL;
    }

    if (table->vals[i] != NULL) {
      destroy_node(pool, table->vals[i]);
      table->vals[i] = NULL;
    }
  }

  free(table->keys);
  table->keys = NULL;
  free(table->vals);
  table->vals = NULL;
  free(table);
  table = NULL;
  return;
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
  jsonInit();

  JSON_Node *array = jsonOpen("./tests/test.json");

  assert(array != NULL);
  JSON_Node *interior = array_get_nth(array_get_nth(array, 3), 3);
  assert(interior != NULL);
  assert(array_get_nth(interior, 0)->type == JSON_NUM);
  assert(array_get_nth(interior, 1)->type == JSON_LITERAL);
  assert(array_get_nth(interior, 2)->type == JSON_STR);
  assert(array_get_nth(interior, 0)->contents.d == -57.638300);
  assert(array_get_nth(interior, 1)->contents.l == JSON_FALSE);
  assert(!strcmp("aab", array_get_nth(interior, 2)->contents.s));

  size_t tmp_cap = 1;
  char **keys = calloc(tmp_cap, sizeof(char *));
  JSON_Node **vals = calloc(tmp_cap, sizeof(JSON_Node *));
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
  JSON_Node *found = ht_find(table, "000000000000000");
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

  JSON_Node *new = new_node(elems);
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

  jsonEnd();
}

void object_tests() {
  jsonInit();

  // assert(OBJECT_STARTING_SIZE == 1);

  JSON_Node *root = jsonOpen("./tests/object1.json");
  assert(root != NULL && root->contents.o != NULL);
  JSON_Node *found_1 = ht_find(root->contents.o, "A");
  assert(found_1 != NULL);
  assert(found_1->contents.d == 10.0);
  JSON_Node *found_2 = ht_find(root->contents.o, "B");
  assert(found_2 != NULL);
  assert(found_2->contents.d == 11.0);
  JSON_Node *found_3 = ht_find(root->contents.o, "C");
  assert(found_3 != NULL);
  assert(!strcmp(found_3->contents.s, "some text I guess"));
  JSON_Node *found_4 = ht_find(root->contents.o, "D");
  assert(found_4->type == JSON_ARRAY);
  JSON_Node *second = array_get_nth(found_4, 1);
  assert(second != NULL);
  assert(second->type == JSON_NUM);
  assert(second->contents.d == 1.0);

  JSON_Node *removed = ht_del(elems, root->contents.o, "A");

  assert(removed != NULL);
  assert(found_1 == removed);

  JSON_Node *place_somewhere = new_node(elems);
  assert(place_somewhere != NULL);
  place_somewhere->contents.d = 3334.54;
  place_somewhere->type = JSON_NUM;
  JSON_Node *placed = ht_set(root->contents.o, "B", place_somewhere);
  assert(placed != NULL);
  assert(placed == found_2);
  assert(placed->contents.d == 3334.54);

  jsonEnd();
}

void copy_tests() {
  jsonInit();

  JSON_Node *literal = new_node(elems);
  literal->contents.l = JSON_TRUE;
  literal->type = JSON_LITERAL;
  literal->flags = 0;
  literal->prev = NULL;
  literal->next = NULL;
  JSON_Node *new_literal = new_node(elems);
  copy_json_node(new_literal, literal);
  assert(literal != new_literal);
  assert(literal->type == JSON_LITERAL && new_literal->type == JSON_LITERAL);
  assert(literal->contents.l == JSON_TRUE &&
         new_literal->contents.l == JSON_TRUE);

  JSON_Node *num = new_node(elems);
  num->contents.d = 333.333311111;
  num->type = JSON_NUM;
  num->flags = 0;
  num->prev = NULL;
  num->next = NULL;
  JSON_Node *new_num = new_node(elems);
  copy_json_node(new_num, num);
  assert(num != new_num);
  assert(num->type == JSON_NUM && new_num->type == JSON_NUM);
  assert(num->contents.d == 333.333311111 &&
         new_num->contents.d == 333.333311111);

  char *chars = calloc(50, sizeof(char));
  assert(chars != NULL);
  strncpy(chars, "we are testing now", 50 - 1);
  JSON_Node *str = new_node(elems);
  str->contents.s = chars;
  str->type = JSON_STR;
  str->flags = 0;
  str->prev = NULL;
  str->next = NULL;
  JSON_Node *new_str = new_node(elems);
  copy_json_node(new_str, str);
  assert(str != new_str && str->contents.s != new_str->contents.s);
  assert(str->type == JSON_STR && new_str->type == JSON_STR);
  assert(!strcmp(str->contents.s, chars) &&
         !strcmp(new_str->contents.s, chars));

  JSON_Node *array = jsonOpen("./tests/array1.json");
  JSON_Node *object = jsonOpen("./tests/object1.json");
  JSON_Node *new_array = new_node(elems);
  JSON_Node *new_object = new_node(elems);
  assert(array != NULL && object != NULL && new_array != NULL &&
         new_object != NULL);

  copy_json_node(new_array, array);
  assert(new_array->type == JSON_ARRAY);
  JSON_Node *array_first = array_get_nth(array, 0);
  JSON_Node *new_array_first = array_get_nth(new_array, 0);
  assert(array_first != new_array_first);
  assert(array_first->type == JSON_NUM && new_array_first->type == JSON_NUM);
  assert(array_first->contents.d == -57.6383 &&
         new_array_first->contents.d == -57.6383);
  JSON_Node *array_second = array_get_nth(array, 1);
  JSON_Node *new_array_second = array_get_nth(new_array, 1);
  assert(array_second != new_array_second);
  assert(array_second->type == JSON_LITERAL &&
         new_array_second->type == JSON_LITERAL);
  assert(array_second->contents.l == JSON_FALSE &&
         new_array_second->contents.l == JSON_FALSE);
  JSON_Node *array_third = array_get_nth(array, 2);
  JSON_Node *new_array_third = array_get_nth(new_array, 2);
  assert(array_third != new_array_third);
  assert(array_third->type == JSON_STR && new_array_third->type == JSON_STR);
  assert(!strcmp(array_third->contents.s, new_array_third->contents.s));
  assert(array_get_nth(array, 3) == NULL);
  assert(array_get_nth(new_array, 3) == NULL);

  copy_json_node(new_object, object);
  assert(new_object->type == JSON_OBJECT);
  JSON_Node *A = ht_find(object->contents.o, "A");
  JSON_Node *new_A = ht_find(new_object->contents.o, "A");
  assert(A != new_A);
  assert(A->type == JSON_NUM && new_A->type == JSON_NUM);
  assert(A->contents.d == 10.0 && new_A->contents.d == 10.0);
  JSON_Node *B = ht_find(object->contents.o, "B");
  JSON_Node *new_B = ht_find(new_object->contents.o, "B");
  assert(B != new_B);
  assert(B->type == JSON_NUM && new_B->type == JSON_NUM);
  assert(B->contents.d == 11.0 && new_B->contents.d == 11.0);
  JSON_Node *C = ht_find(object->contents.o, "C");
  JSON_Node *new_C = ht_find(new_object->contents.o, "C");
  assert(C != NULL);
  assert(new_C != NULL);
  assert(C != new_C);
  assert(C->type == JSON_STR && new_C->type == JSON_STR);
  assert(!strcmp(C->contents.s, "some text I guess") &&
         !strcmp(new_C->contents.s, "some text I guess"));
  JSON_Node *D = ht_find(object->contents.o, "D");
  JSON_Node *new_D = ht_find(new_object->contents.o, "D");
  assert(D != NULL);
  assert(new_D != NULL);
  assert(D != new_D);
  assert(D->type == JSON_ARRAY && new_D->type == JSON_ARRAY);
  JSON_Node *interior_last = array_get_nth(D, 2);
  JSON_Node *new_interior_last = array_get_nth(new_D, 2);
  assert(interior_last != NULL);
  assert(new_interior_last != NULL);
  assert(!strcmp(interior_last->contents.s, "yes") &&
         !strcmp(new_interior_last->contents.s, "yes"));

  jsonEnd();
}

void interface_tests() {
  jsonInit();

  // JSON_Node *array = jsonOpen("./tests/array1.json");
  JSON_Node *object = jsonOpen("./tests/object1.json");

  JSON_Node *exists = jsonReadl(object, _KEY("D"), _INDEX(2), NULL);
  assert(exists != NULL);
  assert(!strcmp(exists->contents.s, "yes"));
  struct path *exists_path[] = {_KEY("D"), _INDEX(2), NULL};
  JSON_Node *exists2 = jsonReadv(object, exists_path);
  assert(!strcmp(exists2->contents.s, "yes"));

  assert(jsonStrlen(exists) == 3);
  assert(jsonStrlen(exists2) == 3);
  assert(jsonStrlenl(object, _KEY("D"), _INDEX(2), NULL) == 3);
  assert(jsonStrlenv(object, exists_path) == 3);

  JSON_Node *new_node = jsonCopy(exists);
  assert(new_node != exists);
  assert(!strcmp(exists->contents.s, new_node->contents.s));
  new_node = jsonCopyl(object, _KEY("D"), _INDEX(2), NULL);
  assert(new_node != exists);
  assert(!strcmp(exists->contents.s, new_node->contents.s));
  new_node = jsonCopyv(object, exists_path);
  assert(new_node != exists);
  assert(!strcmp(exists->contents.s, new_node->contents.s));

  JSON_Node *created_node = jsonCreatel(new_node, object, NULL);
  assert(created_node == NULL);
  created_node = NULL;
  created_node = jsonCreatel(new_node, object, _KEY("E"), NULL);
  assert(created_node != NULL);
  //printf("%s\n", created_node->contents.s);
  //printf("%s\n", jsonReadl(object, _KEY("E"), NULL)->contents.s);
  assert(!strcmp(created_node->contents.s, jsonReadl(object, _KEY("E"), NULL)->contents.s));
  created_node = NULL;
  created_node = jsonCreatel(new_node, object, _KEY("D"), _INDEX(3), NULL);
  assert(created_node != NULL);
  assert(!strcmp(created_node->contents.s, jsonReadl(object, _KEY("D"), _INDEX(3), NULL)->contents.s));

  jsonEnd();
}

void output_tests() {
  jsonInit();

  JSON_Node *root = jsonOpen("./tests/object1.json");

  FILE *out = fopen("/tmp/json-tests", "w+");
  if (out == NULL) {
    printf("Error opening %s: %s\n", "/tmp/json-tests", strerror(errno));
    assert(false);
  }
  jsonString(out, 1, root);
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
  //printf("%s\n", expected);
  //printf("%s\n", test);
  assert(!strcmp(expected, test));
  assert(jsonStringl(stdin, 1, root, _KEY("D"), _INDEX(0), _KEY("B"), NULL) ==
         0);
  struct path *keys[] = {_KEY("D"), _INDEX(0), _KEY("B"), NULL};
  assert(jsonStringv(stdin, 1, root, keys) == 0);
  fflush(out);
  fclose(out);
  remove("/tmp/json-tests");

  jsonEnd();
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
