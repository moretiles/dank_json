CFLAGS=-Wall -Wextra
DEBUG=-g3
OPTIMIZE=-O3

START_SMALL=-DOBJECT_STARTING_SIZE=1
TEST_BUILD=-DTEST_BUILD=1

ANALYZE_GCC=-fanalyzer
ANALYZE_CLANG=-analyze-headers

DEPENDS=*.c *.h

release: ${DEPENDS}
	${CC} ${CFLAGS} ${OPTIMIZE} json.c -o json

gdb: ${DEPENDS}
ifeq (${TAGS},y)
	@ctags -R .
endif
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} json.c -o json

debug: ${DEPENDS}
ifeq (${TAGS},y)
	@ctags -R .
endif
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} json.c -o json
	@echo '================================='
	@./json
	@echo '================================='

format: ${DEPENDS}
ifeq (${TAGS},y)
	@ctags -R .
endif
	clang-format -i ${DEPENDS}

test: ${DEPENDS}
ifeq (${TAGS},y)
	@ctags -R .
endif
	clang ${START_SMALL} ${TEST_BUILD} -emit-ast json.c json.h queue.h
	clang-extdef-mapping -p . json.c json.h queue.h | sed 's/\.c/\.ast/' | sed 's/\.h/\.h\.pch/g' | sed "s|$(pwd)/||g" > externalDefMap.txt
	clang --analyze ${START_SMALL} ${TEST_BUILD} \
		-Xclang -analyzer-config -Xclang experimental-enable-naive-ctu-analysis=true \
		-Xclang -analyzer-config -Xclang ctu-dir=. \
		-Xclang -analyzer-output=plist-multi-file \
		json.c json.h queue.h
	@echo '================================='
	clang ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} -fsanitize=address -fsanitize=undefined -fsanitize=leak json.c -o json
	@echo '================================='
	@./json
	@echo '================================='
	clang ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} -fsanitize=memory json.c -o json
	@echo '================================='
	@./json
	@echo '================================='
	clang ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} -fsanitize=thread json.c -o json
	@echo '================================='
	@./json
	@echo '================================='
