EXECUTABLESRV = server
EXECUTABLECLI = client
EXEC_LIBS = /usr/local/ssl/lib/libssl.a /usr/local/ssl/lib/libcrypto.a -ldl

CC=g++ -I/usr/local/ssl/include/ -lboost_system -g 
CFLAGS=-Wall -DDEBUG -Wreorder -D_RENEG_ON_
COMPILE=$(CC) $(CFLAGS)

all: server client

server: server.o ssl_process.o
	$(CC) ssl_process.o server.o -o $(EXECUTABLESRV) $(EXEC_LIBS)

client: client.o ssl_process.o
	$(CC) -o $(EXECUTABLECLI) ssl_process.o client.o $(EXEC_LIBS)

ssl_process.o: ssl_process.cpp
	$(COMPILE) -o ssl_process.o -c ssl_process.cpp

server.o: server.cpp
	$(COMPILE) -o server.o -c server.cpp

client.o: client.cpp
	$(COMPILE) -o client.o -c client.cpp

clean:
	rm -rf *.o server client
