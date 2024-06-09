# all: compile

# compile: main.o lexer.o parser.o codegen.o
# 	g++ main.o lexer.o parser.o codegen.o -o compile

# main.o: main.cpp
# 	g++ -c main.cpp -o main.o

# lexer.o: lexer.c parser.tab.h
# 	g++ -c lexer.c -o lexer.o

# lexer.c: lexer.l parser.tab.h
# 	flex -o lexer.c lexer.l

# parser.o: parser.c
# 	g++ -c parser.c -o parser.o

# parser.c: parser.y
# 	bison -d -o parser.c parser.y

# parser.tab.h: parser.y
# 	bison -d -o parser.c parser.y

# codegen.o: codegen.cpp codegen.h
# 	g++ -c codegen.cpp -o codegen.o

# clean:
# 	rm -f *.o parser.c parser.tab.h lexer.c compile

# .PHONY: clean

all: compile

compile: main.o lexer.o parser.o codegen.o
	g++ -g main.o lexer.o parser.o codegen.o -o compile

main.o: main.cpp
	g++ -g -c main.cpp -o main.o

lexer.o: lexer.c parser.tab.h
	g++ -g -c lexer.c -o lexer.o

lexer.c: lexer.l parser.tab.h
	flex -o lexer.c lexer.l

parser.o: parser.c
	g++ -g -DYYDEBUG=0 -c parser.c -o parser.o

parser.c: parser.y
	bison -d -t -o parser.c parser.y

parser.tab.h: parser.y
	bison -d -t -o parser.c parser.y

codegen.o: codegen.cpp codegen.h
	g++ -g -c codegen.cpp -o codegen.o

clean:
	rm -f *.o parser.c parser.tab.h lexer.c compile

.PHONY: clean

