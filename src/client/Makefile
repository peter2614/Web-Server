CC=g++
CFLAGS=-ggdb -std=c++11 -Wall -pedantic -Wno-sign-compare

all: client

client: TCPClient.c DieWithMessage.c
	$(CC) $(CFLAGS) -o client TCPClient.c DieWithMessage.c -lboost_regex

clean:
	rm -rf client client.dSYM
