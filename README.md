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


## Notes

1. On the first line of main jsonLibInit is called before any JSON files can be opened. This is required.
1. When calling jsonReadl we provide the root to start from and then a variable number of arguments describing indexes/keys to travel down.
1. jsonReadl will return a shallow copy. The family of jsonRead{type}l functions, where {type} is any supported type, return a deep copy.
1. Before calling printf we terminate all json nodes loaded using jsonLibEnd since we no longer need them. We could have individually closed the example file with jsonClose.
1. The comment below printf lists the output.
