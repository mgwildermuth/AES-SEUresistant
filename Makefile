CC = gcc
#CC = arm-linux-gnueabihf-gcc
CFLAGS = -Wall -Werror

default: test

.SILENT: 
.PHONY: clean

test: test.o aes.o
	$(CC) -o test test.o aes.o
	rm -f test.o aes.o

test.o: test.c aes.h aes.o
	$(CC) -c test.c

aes.o: aes.c aes.h
	$(CC) -c aes.c

clean:
	rm -f test *.o *~