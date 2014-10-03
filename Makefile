EXECUTABLE = server
EXECUTABLECLI = client

CC=g++ -lboost_system -lboost_thread -g
CFLAGS=-Wall -DDEBUG -Wreorder -D_RENEG_ON_
COMPILE=$(CC) $(CFLAGS)

all: server client

server: server.o ssl_process.o
	$(CC) -lpthread -lcrypto -lssl ssl_process.o server.o -o $(EXECUTABLE)

client: client.o ssl_process.o
	$(CC) -lpthread -lcrypto -lssl -o $(EXECUTABLECLI) ssl_process.o client.o

ssl_process.o: ssl_process.cpp
	$(COMPILE) -o ssl_process.o -c ssl_process.cpp

server.o: server.cpp
	$(COMPILE) -o server.o -c server.cpp

client.o: client.cpp
	$(COMPILE) -o client.o -c client.cpp

clean:
	rm -rf *.o server client
