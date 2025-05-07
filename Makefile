CFLAGS=-Wall -Wextra
DEBUG=-g3
SAN=-fsanitize=address -fsanitize=undefined
ANALYZE_GCC=-fanalyzer
ANALYZE_CLANG=-analyze-headers
OPTIMIZE=-O3

release:
	gcc ${CFLAGS} ${OPTIMIZE} json.c -o json

san:
	gcc ${CFLAGS} ${DEBUG} ${SAN} json.c -o json

gdb:
	gcc ${CFLAGS} ${DEBUG} json.c -o json

test:
	gcc ${CFLAGS} ${DEBUG} ${SAN} json.c -o json
	./json

debug:
	gcc ${CFLAGS} ${DEBUG} json.c -o json
	./json
