/******************************************************************************/
/**
	\Author 				Krzysztof Kwiatkowski
	\File					client.cpp
	\Description            The SSL client which connects to the server.cpp
                            and initiates renegotitaion after RENEG_INIT_LEN
                            chars exchanged with the server

*******************************************************************************/

#include <stdexcept>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <netinet/in.h>
#include <fcntl.h>
#include <iostream>

#include "defs.h"
#include "ssl_process.h"

using namespace std;

SSL_CTX* ssl_ctx = 0;
int master_fd = 0;

SSL* SSLHandler = 0;
int CharsRead   = 0;


const char *password = NULL;

char *SRP_cb(SSL *ssl, void *arg)
{
    cout << "SRP CB started" << endl;
    char *user = (char*)arg;
    ssize_t promptsize = 256;
    char prompt[promptsize];
    snprintf(prompt, promptsize,
                   "Password for %s: ", user);

    // don't use getpass in production code (use similar implementation as in s_client: ssl_give_srp_client_pwd_cb)
    char *pass = getpass(prompt);
    char *result = OPENSSL_strdup(pass);
    // getpass uses a static buffer, so clear it out after use.
    memset(pass,0,strlen(pass));
    cout << "SRP CB ended" << endl;
    return result;
}

void connect()
{
    struct sockaddr_in echoserver;
    master_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&echoserver, 0, sizeof(echoserver));
    echoserver.sin_family = AF_INET;
    echoserver.sin_addr.s_addr = inet_addr(IP);
    echoserver.sin_port = htons(PORT);

    /* Establish connection */
    if ( 0 > ::connect(master_fd, (struct sockaddr *) &echoserver, sizeof(echoserver)) )
    {
        throw runtime_error("Can't connect to the server");
    }

    // set SRP parameters
    SSL_CTX_set_srp_username(ssl_ctx, (char*)USER_NAME);
    SSL_CTX_set_srp_cb_arg(ssl_ctx,(void*)USER_NAME);
    SSL_CTX_set_srp_client_pwd_callback(ssl_ctx, SRP_cb);
    SSL_CTX_set_cipher_list(ssl_ctx,"SRP");

    SSLHandler = SSL_new(ssl_ctx);

    // if socket is blocking you can set this and forget about looking at SSL_get_error code on I/O calls
    long mode = SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    if( ( mode & SSL_MODE_AUTO_RETRY) != SSL_MODE_AUTO_RETRY )
    {
         throw runtime_error("SSL_MODE_AUTO_RETRY couldn't be set");
    }

    SSL_set_fd(SSLHandler, master_fd);

    int code = 0;
    if( (code=SSL_connect(SSLHandler)) <= 0)
    {
        cerr << "Can't setup SSL session: "  << endl;
        handle_error_code(code, SSLHandler, code, "SSL_connect");

        exit(1);
    }
}

void start()
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

    ::close(master_fd);
}

// --- MAIN --- //
int main()
{
    try
    {
        ssl_init(&ssl_ctx, false);

        connect();
        start();
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
