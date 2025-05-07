CFLAGS=-Wall -Wextra
DEBUG=-g3
SAN=-fsanitize=address -fsanitize=undefined
ANALYZE_GCC=-fanalyzer
ANALYZE_CLANG=-analyze-headers
OPTIMIZE=-O3

START_SMALL=-DOBJECT_STARTING_SIZE=1
TEST_BUILD=-DTEST_BUILD=1

release:
	gcc ${CFLAGS} ${OPTIMIZE} json.c -o json

san:
	gcc ${CFLAGS} ${DEBUG} ${SAN} ${START_SMALL} ${TEST_BUILD} json.c -o json

gdb:
	gcc ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} json.c -o json

test:
	gcc ${CFLAGS} ${DEBUG} ${SAN} ${START_SMALL} ${TEST_BUILD} json.c -o json
	./json

debug:
	gcc ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} json.c -o json
	./json
