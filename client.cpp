/******************************************************************************/
/**
	\Author 				Krzysztof Kwiatkowski
	\File					client.cpp
	\Description            Very simple implementation of SRP client that
                            uses OpenSSL API.

*******************************************************************************/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdexcept>
#include <iostream>
#include <sstream>

#include "defs.h"
#include "ssl_process.h"

using namespace std;

// Descriptor of TCP connection
int master_fd = 0;
// Descriptor of SSL session
SSL* ssl_fd = 0;
// SSL session configuration
SSL_CTX* ssl_ctx = 0;

/* -----------------------------------------------------------------------------
 * @brief   SRP_cb - Normally in this method implementation gets somehow user
 *          password ( disk file / by interactively asking user or / whatever else )
 *
 * @param   ssl - initialized SSL context of the TLS session
 *          arg - arbitrary value set by the user with SSL_CTX_set_srp_cb_arg
 *                function
 *
 * @returns Pointer to buffer with the password
 *
-------------------------------------------------------------------------------- */
char *SRP_cb(SSL *ssl, void *arg)
{
    return OPENSSL_strdup(USER_PASS);
}

/* -----------------------------------------------------------------------------
 * @brief   function makes TCP connection with remote host available via IP:PORT
-------------------------------------------------------------------------------- */
void connect()
{
    struct sockaddr_in echoserver;

    // Create regular structure for the socket
    master_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&echoserver, 0, sizeof(echoserver));
    echoserver.sin_family = AF_INET;
    echoserver.sin_addr.s_addr = inet_addr(IP);
    echoserver.sin_port = htons(PORT);

    // Connect to remote peer
    if ( 0 > ::connect(master_fd, (struct sockaddr *) &echoserver, sizeof(echoserver)) )
    {
        throw runtime_error("Couldn't establish connection.");
    }
}


/* -----------------------------------------------------------------------------
 * @brief   establish_TLS_session - method does 3 following actions:
 *          - Configures SSL_CTX for SRP usage
 *          - Configures SSL_CTX for blocking I/O
 *          - Creates SSL session
 *
-------------------------------------------------------------------------------- */
void establish_TLS_session()
{
    long ssl_mode = 0;

    // -------------------------------------------------------------------------
    // SRP specific stuff
    //

    // Username to be used
    SSL_CTX_set_srp_username(ssl_ctx, (char*)USER_NAME);
    // Set callback function that will provide password to be used on SRP
    SSL_CTX_set_srp_client_pwd_callback(ssl_ctx, SRP_cb);
    // This function sets value of second argument with which SRP CB will be called
    SSL_CTX_set_srp_cb_arg(ssl_ctx,(void*) USER_NAME);
    // Use only those ciphers that are on SRP list
    // (we may also specify here concreate cipher to use f.e. SRP-3DES-EDE-CBC-SHA)
    SSL_CTX_set_cipher_list(ssl_ctx,"SRP");

    //
    // -------------------------------------------------------------------------

    // Setting SSL_MODE_AUTO_RETRY makes code much easier to understand.
    // When flag is set for blocking I/O openssl takes care of WANT_READ/WANT_WRITE
    // errors, that may happen during TLS handshake.
    ssl_mode = SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    if( ( ssl_mode & SSL_MODE_AUTO_RETRY) != SSL_MODE_AUTO_RETRY )
    {
         throw runtime_error("SSL_MODE_AUTO_RETRY couldn't be set");
    }

    // Create SSL object from SSL_CTX template
    ssl_fd = SSL_new(ssl_ctx);

    // Tell SSL object that connection is available via master_fd descriptor
    SSL_set_fd(ssl_fd, master_fd);

    // Finally establish session
    if( 0 >= SSL_connect(ssl_fd) )
    {
        cout << SSL_state_string(ssl_fd) << endl;
        throw runtime_error("Couldn't establish SSL session.");
    }
}


/* -----------------------------------------------------------------------------
 * @brief  Function sends some data and blocks until response is received.
 *         Method prints SSL state after each operation and data RECEIVED.
   ----------------------------------------------------------------------------- */
void exchange_data()
{
    char buf[MAX_PACKET_SIZE];

    memcpy(buf, "HELLO", 6);

    // send
    SSL_write(ssl_fd, buf, 6);
    cout << "WRITE: SSL STATE: " << SSL_state_string(ssl_fd) << endl;

    // receive
    memset(buf,'\0',MAX_PACKET_SIZE);
    SSL_read(ssl_fd, buf, MAX_PACKET_SIZE);
    cout << "READ: SSL STATE: " << SSL_state_string(ssl_fd) << endl;

    cout << "RECEIVED: " << buf << endl;
}

/* -----------------------------------------------------------------------------
 * @brief  Main creates SRP-TLS sesion
 *         Sends some data
 *         Ends session and closes connection
   ----------------------------------------------------------------------------- */
int main()
{
    try
    {
        // Init SSL library
        if( !ssl_init(&ssl_ctx, false) )
        {
            ERR_print_errors_fp(stderr);
            throw runtime_error("SSL init failed");
        }

        // TCP connection
        connect();

        // TLS session
        establish_TLS_session();

        // send some data
        exchange_data();

        // Close SSL session
        SSL_shutdown(ssl_fd);

        // Close TCP
        ::close(master_fd);

        cleanup(ssl_ctx, ssl_fd);
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
