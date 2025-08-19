CFLAGS=-Wall -Wextra
DEBUG=-g3 -ggdb
OPTIMIZE=-O3

START_SMALL=-DOBJECT_STARTING_SIZE=1
TEST_BUILD=-DTEST_BUILD=1
UNITY_BUILD=-DUNITY_BUILD=1

ANALYZE_GCC=-fanalyzer
ANALYZE_CLANG=-analyze-headers

DEPENDS=*.c *.h

#######################################################################
#                                                                     #
# If you want to actually use this library run `make release`         #
#                                                                     #
#######################################################################
release:
	${CC} ${CFLAGS} ${OPTIMIZE} ${UNITY_BUILD} json.c -o json




## build for development
json: json.o queue.o hash.o array.o pool.o
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} json.o queue.o hash.o array.o pool.o -o json

json.o: json.c
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} json.c -c -o json.o

queue.o: queue.c
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} queue.c -c -o queue.o

hash.o: hash.c
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} hash.c -c -o hash.o

array.o: array.c
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} array.c -c -o array.o

pool.o: pool.c
	${CC} ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} pool.c -c -o pool.o

clean:
	rm -f json tags *.ast *.pch *.plist *.o externalDefMap.txt gmon.out

.PHONY: tags
tags:
	ctags -R .

format: ${DEPENDS}
	clang-format -i ${DEPENDS}

debug: json
	@echo '================================='
	@./json
	@echo '================================='

# kind of a misnomer to test the performance of a "test build" but it's comparative data
performance: json
	./json
	gprof ./json gmon.out

.PHONY: test
test:
	@echo '================================='
	clang ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} ${UNITY_BUILD} -fsanitize=address -fsanitize=undefined -fsanitize=leak json.c -o json
	@echo '================================='
	@./json
	@echo '================================='
	clang ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} ${UNITY_BUILD} -fsanitize=memory json.c -o json
	@echo '================================='
	@./json
	@echo '================================='
	clang ${CFLAGS} ${DEBUG} ${START_SMALL} ${TEST_BUILD} ${UNITY_BUILD} -fsanitize=thread json.c -o json
	@echo '================================='
	@./json
	@echo '================================='
	clang ${START_SMALL} ${TEST_BUILD} -emit-ast ${DEPENDS}
	clang-extdef-mapping ${DEPENDS} | sed 's/\.c/\.ast/' | sed 's/\.h/\.h\.pch/g' > externalDefMap.txt
	clang --analyze ${START_SMALL} ${TEST_BUILD} \
		-Xclang -analyzer-config -Xclang experimental-enable-naive-ctu-analysis=true \
		-Xclang -analyzer-config -Xclang ctu-dir=. \
		-Xclang -analyzer-output=plist-multi-file \
		${DEPENDS}
