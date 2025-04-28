release:
	gcc ${CFLAGS} ${OPTIMIZE} json.c -o json

debug:
	gcc ${CFLAGS} ${DEBUG} ${SAN} json.c -o json

test:
	gcc ${CFLAGS} ${DEBUG} ${SAN} json.c -o json
	./json

CFLAGS=-Wall -Wextra
DEBUG=-g3
SAN=-fsanitize=address -fsanitize=undefined
ANALYZE_GCC=-fanalyzer
ANALYZE_CLANG=-analyze-headers
OPTIMIZE=-O3
