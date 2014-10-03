/******************************************************************************/
/**
	\Author 				Krzysztof Kwiatkowski
	\File					client.cpp
	\Description            The SSL client which connects to the server.cpp
                            and initiates renegotitaion after RENEG_INIT_LEN
                            chars exchanged with the server

*******************************************************************************/

#include "client.h"
#include <unistd.h>
#include "defs.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <stdexcept>

using namespace std;

SSL* SSLHandler = 0;
int CharsRead   = 0;

// with this you can block sender thread during renegotiation

bool handle_error_code(int& len, SSL* SSLHandler, int code, const char* func)
{
    switch( SSL_get_error( SSLHandler, code ) )
    {
    case SSL_ERROR_NONE:
        len+=code;
        return false;
    case SSL_ERROR_ZERO_RETURN:
        cout << "CONNETION CLOSE ON WRITE" << endl;
        break;
    case SSL_ERROR_WANT_READ:
        cout << func << " WANT READ" << endl;
        return true;
        break;
    case SSL_ERROR_WANT_WRITE:
        cout << func << " WANT WRITE" << endl;
        return true;
        break;
    case SSL_ERROR_SYSCALL:
        cout << func << " ESYSCALL" << endl;
//        exit(1);
        break;
    case SSL_ERROR_SSL:
        cout << func << " ESSL" << endl;
        return true;
        exit(1);
        break;
    default:
        cout << func << " SOMETHING ELSE" << endl;
        return true;
        exit(1);

    }
    return true;
}


void Client::connect()
{
    struct sockaddr_in echoserver;
    _handler = socket(AF_INET, SOCK_STREAM, 0);
    memset(&echoserver, 0, sizeof(echoserver));
    echoserver.sin_family = AF_INET;
    echoserver.sin_addr.s_addr = inet_addr(IP);
    echoserver.sin_port = htons(PORT);

    /* Establish connection */
    if ( 0 > ::connect(_handler, (struct sockaddr *) &echoserver, sizeof(echoserver)) )
    {
        throw runtime_error("Can't connect to the server");
    }

    SSLHandler = SSL_new(_ctx);

    // if socket is blocking you can set this and forget about looking at SSL_get_error code on I/O calls
    long mode = SSL_CTX_set_mode(_ctx, SSL_MODE_AUTO_RETRY);
    if( ( mode & SSL_MODE_AUTO_RETRY) != SSL_MODE_AUTO_RETRY )
    {
         throw runtime_error("SSL_MODE_AUTO_RETRY couldn't be set");
    }

    SSL_set_fd(SSLHandler, _handler);

    if( SSL_connect(SSLHandler) <= 0)
    {
        cerr << "Can't setup SSL session" << endl;
        exit(1);
    }
}

void Client::start()
{
    char buf[MAX_PACKET_SIZE];
    size_t len=0;
    memcpy(buf, "HELLO", 6);

    // send
    cout << "SSL_write: start" << endl;
    int code = SSL_write(SSLHandler, buf, 6);
    handle_error_code(code, SSLHandler, code, "SSL_write");
    cout << "SSL STATE: " << SSL_state_string(SSLHandler) << endl;

    // receive
    memset(buf,'\0',MAX_PACKET_SIZE);
    len = SSL_read(SSLHandler, buf, MAX_PACKET_SIZE);
    handle_error_code(code, SSLHandler, len, "SSL_read");
    cout << "RECEIVED: " << buf << endl;

    ::close(_handler);
}

void Client::init()
{
    sslInit();
}

// --- MAIN --- //
int main()
{
    try
    {
        Client client;
        client.init();
        client.connect();
        client.start();
    }
    catch(std::runtime_error& e)
    {
        cerr << "ERROR " << e.what() << endl;
    }
    catch(...)
    {
        cerr << "Unknown exception" << endl;
    }
    return 0;
}
