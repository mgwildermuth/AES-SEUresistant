#/mnt/c/users/mgw92/dropbox/pitt/"SHREC SURG '20"/AES-SEUresistant

CC = gcc
ARM_CC = arm-linux-gnueabihf-gcc
CFLAGS = -Wall -Werror

default: test arm_aes

.SILENT: 
.PHONY: clean

arm_aes:
	$(ARM_CC) $(CFLAGS) -o arm_aes test.c aes.c

test: test.o aes.o
	$(CC) $(CFLAGS) -o test test.o aes.o
#	rm -f test.o aes.o

test.o: test.c aes.h aes.o
	$(CC) $(CFLAGS) -c test.c

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c aes.c

input-to-bin: input-to-bin.o
	$(CC) $(CFLAGS) -o inbin input-to-bin.c
#	rm -f test.o aes.o

input-to-bin.o: input-to-bin.c
	$(CC) $(CFLAGS) -c input-to-bin.c

clean:
	rm -f arm_aes test inbin *.o *~