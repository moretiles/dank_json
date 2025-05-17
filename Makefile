CFLAGS=-Wall -Wextra
DEBUG=-g3
OPTIMIZE=-O3

START_SMALL=-DOBJECT_STARTING_SIZE=1
TEST_BUILD=-DTEST_BUILD=1

ANALYZE_GCC=-fanalyzer
ANALYZE_CLANG=-analyze-headers

DEPENDS=*.c *.h

clean:
	rm -f json tags *.ast *.pch *.plist externalDefMap.txt gmon.out

release: ${DEPENDS}
	${CC} ${CFLAGS} ${OPTIMIZE} json.c -o json

gdb: ${DEPENDS}
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} json.c -o json

debug: ${DEPENDS}
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} json.c -o json
	@echo '================================='
	@./json
	@echo '================================='

format: ${DEPENDS}
	clang-format -i ${DEPENDS}

performance:
	${CC} ${CFLAGS} ${OPTIMIZE} ${TEST_BUILD} -pg json.c -o json
	./json
	gprof ./json gmon.out

test: ${DEPENDS}
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
	clang ${START_SMALL} ${TEST_BUILD} -emit-ast ${DEPENDS}
	clang-extdef-mapping -p . ${DEPENDS} | sed 's/\.c/\.ast/' | sed 's/\.h/\.h\.pch/g' | sed "s|$(pwd)/||g" > externalDefMap.txt
	clang --analyze ${START_SMALL} ${TEST_BUILD} \
		-Xclang -analyzer-config -Xclang experimental-enable-naive-ctu-analysis=true \
		-Xclang -analyzer-config -Xclang ctu-dir=. \
		-Xclang -analyzer-output=plist-multi-file \
		${DEPENDS}
