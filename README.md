# C library for parsing json

## All basic features now present. Still very unstable.


## How to Build
1. clone or download this git repository.
1. Install any C11 compliant compiler.
1. Install your preferred method of executing Makefiles.
1. From within the root directory run `make release`.
1. You should now have dank\_json.o.


## Examples

### Load file, read key
```c
int main(void) {
    jsonLibInit();
    JsonNode *root = jsonOpen("./examples/languages.json");

    JsonNode *c = jsonReadl(root, jsonPathIndex(0));
    char *cName = jsonReadStrl(c, jsonPathKey("name"));
    jsonLiteral *cIsCompiled = jsonReadLiterall(c, jsonPathKey("compiled"));
    double *cBirthYear = jsonReadDoublel(c, jsonPathKey("created"));

    jsonLibEnd();

    printf("Language: %s. Compiled: %s. Birth Year: %0.lf\n", cName, (*cIsCompiled == JSON_TRUE) ? "true" : "false", *cBirthYear);
    // Language: C. Compiled: true. Birth Year: 1972

    return 0;
}
```

#### Notes
1. On the first line of main jsonLibInit is called before any JSON files can be opened. This is required.
1. When calling jsonReadl we provide the root to start from and then a variable number of arguments describing indexes/keys to travel down.
1. jsonReadl will return a shallow copy. The family of jsonRead{type}l functions, where {type} is any supported type, return a deep copy.
1. Before calling printf we terminate all json nodes loaded using jsonLibEnd since we no longer need them. We could have individually closed the example file with jsonClose.
1. The comment below printf lists the output.
1. To aid readability, error checking is not present. The return value of functions should always be checked.


### Load file, read keys programatically

```c
int main(){
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

    printf("Language: %s. Compiled: %s. Birth Year: %0.lf\n", cName, (*cIsCompiled == JSON_TRUE) ? "true" : "false", *cBirthYear);
    // Language: C. Compiled: true. Birth Year: 1972

    jsonLibEnd();

    return 0;
}
```

#### Notes
1. The output of this example is identical to the last. Using JsonPath is more verbose for trivial cases, however, necessary for more complex path interaction.
1. New JsonPath structs are created using jsonPathPush where the *JsonPath argument is NULL. Keys/Indexes appended as variadic arguments.
1. jsonReads returns shallow copy of a JsonNode. JsonRead{type}s where type is any valid type returns a deep copy.
1. jsonPathDelete deallocates a referenced jsonPath struct.
1. jsonPathPop removes the path component at the current deepest level.
1. To aid readability, error checking is not present. The return value of functions should always be checked.
