#include "defs.h"
#include "ssl_process.h"
#include <openssl/srp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>
#include <utility>

using namespace std;

// needed for new implementation
int master_socket=0;
SSL_CTX* ssl_ctx = NULL;

// This implementation uses OpenSSL's safestack as object for password storage
static SRP_VBASE *srp_store = NULL;

// OpenSSL defines a handy SRP_VBASE type that can be used to store verifiers and we can use SRP_VBASE_init to load in the the verifier file we made earlier

/* -----------------------------------------------------------------------------
 * @brief   initialize_SRP_store
 *          This method creates entry for user USER_NAME. Verifier for the user
 *          is stored in the 'safestack' store implemented by OpenSSL.
 *
 * @param   ctx - SSL context that configures sessions
 *
 * @remarks In production implementation, code should use something else than safestack
 *
-------------------------------------------------------------------------------- */
void initialize_SRP_store(SSL_CTX *ctx)
{
    srp_store = SRP_VBASE_new(NULL);

    // Group generator and exponent N ( N is a large Sophie Germain prime ).
    //
    // If value of gN is changed, passwords won't be correctly verified. That's why, in SRP, value of gN are chosen before any verifier is stored
    // Value of g & N are exchanged in clear text and are known to client, server and potential eavesdropper (and still protocol is secure)
    SRP_gN* gN;
    int res = 0;

    // Now create the verifier for the password.
    // We could get the password from the user at this point.
    BIGNUM *salt = NULL, *verifier = NULL;

    // The structure to put the verifier data and create secret g^N
    SRP_user_pwd *pwd =
       (SRP_user_pwd *)OPENSSL_malloc(sizeof(SRP_user_pwd));
    gN = SRP_get_default_gN(SRP_GROUP);


    // Initialize salt and create verifier
    // This is done when new user is being created
    res = SRP_create_verifier_BN(  USER_NAME,
                                   USER_PASS,
                                   &salt,
                                   &verifier,
                                   gN->N,
                                   gN->g);
    if(res == 0)
    {
        throw runtime_error("Error whie creating verifier");
    }

    // Add user to the store
    //
    // Normally username, salt and verifier is stored in some form of database
    // and (g,N) pair is implementation dependend (hardcoded in some way)

    // This implementation uses OpenSSL's safestack

    // Copy verifier & co into the SRP_user_pwd structure
    pwd->id = OPENSSL_strdup(USER_NAME);
    pwd->g = gN->g;
    pwd->N = gN->N;
    pwd->s = salt;
    pwd->v = verifier;
    pwd->info = NULL;

    // And push it to safestack
    sk_SRP_user_pwd_push(srp_store->users_pwd, pwd);

    cout
        << "USER: "     << pwd->id << " added to DB" << endl
        << " PARAMS "   << endl
        << " G: "       << pwd->g
        << " N: "       << pwd->N
        << " salt: "    << pwd->s
        << " VERIFIER: "<< pwd->v
        << endl;
}


/* -----------------------------------------------------------------------------
 * @brief   SRP_server_callback
 *
 *          This callback is used by the server to get verifier and salt
 *          for user that is trying to authenticate
 *
 * @param
 *          ssl_ctx - context of SSL session
 *          peerinput - not used here (info regarding client)
 *          arg - pointer to object set by SSL_CTX_set_srp_cb_arg
 *
 * @remarks In case of success it returns SSL_ERROR_NONE, otherwise some
 *          kind of error value (f.e. SSL3_AL_FATAL)
 *
-------------------------------------------------------------------------------- */
int SRP_server_callback(SSL *ssl_ctx, int *peerinput, void *arg)
{
    char *username;
    SRP_user_pwd *pwd;
    int ret;

    // Get username from the session
    username = SSL_get_srp_username(ssl_ctx);
    if(username == NULL)
    {
        cerr << "Username not provided" << endl;
        return SSL3_AL_FATAL;
    }

    // Check for users data in the safestack.
    // In real application this would be some form of lookup in DB that stores
    // username, salt and verifier
    pwd = SRP_VBASE_get_by_user(srp_store,username);
    if (pwd == NULL) {
        cerr << "User " << username << " doesn't exist in the store" << endl;
        return SSL3_AL_FATAL;
    }

    // Set verifier data
    ret = SSL_set_srp_server_param( ssl_ctx,
                                    pwd->N,
                                    pwd->g,
                                    pwd->s,
                                    pwd->v,
                                    NULL);
    if(0>ret)
    {
        cerr << "Couldn't set server params correctly (incorrect input)" << endl;
        return SSL3_AL_FATAL;
    }

    cout << "User: " << username << " tries to login" << endl;
    return SSL_ERROR_NONE;
}


/* -----------------------------------------------------------------------------
 * @brief   Binds socket to port defined as PORT and starts to listen for
 *          incomming connections.
-------------------------------------------------------------------------------- */
void listen()
{
    struct sockaddr_in local_address;
    int reuseval = 1;

    master_socket = ::socket(PF_INET, SOCK_STREAM, 0);
    memset(&local_address, 0, sizeof(local_address));

    local_address.sin_family = AF_INET;
    local_address.sin_port = htons(PORT);
    local_address.sin_addr.s_addr = INADDR_ANY;

    setsockopt(master_socket,SOL_SOCKET,SO_REUSEADDR, &reuseval, sizeof(reuseval));

    // Bind to the socket
    if(::bind(master_socket, (struct sockaddr *)&local_address, sizeof(local_address)) != 0)
        throw runtime_error("Couldn't bind to local port");

    if(::listen(master_socket, 2) != 0)
        throw runtime_error("Not possible to get into listen state");
}

/* -----------------------------------------------------------------------------
 * @brief   Accept incomming client TCP connection
-------------------------------------------------------------------------------- */
SSL* accept_ssl()
{
    struct sockaddr_in addr;
    int code = 0;
    int len = 0;
    int tcp_fd = 0;
    SSL *ssl;

    cout << "New connection has arrived" << endl;

    // --------------------------
    // Accept new TCP connection
    // --------------------------

    len = sizeof(addr);
    tcp_fd = accept(master_socket, (struct sockaddr *)&addr, (socklen_t *)&len);
    if(code == -1)
    {
        cerr << "Problem occured when accepting new TCP connection" << endl;
        return NULL;
    }

    // -----------------------
    // Accept new SSL session
    // -----------------------

    // Create SSL object for new session
    ssl = (SSL*) SSL_new(ssl_ctx);

    // Bind connection descriptor with ssl session
    SSL_set_fd(ssl, tcp_fd);

    // Normally this would be in other thread
    if( (code=SSL_accept(ssl)) == -1) {

        // Should never happen as long as SSL_MODE_AUTO_RETRY is set on SSL_CTX
        // and socket is blocking
        if (BIO_sock_should_retry(code))
        {
            throw runtime_error("DELAY: functinality not implemented");
        }

        // This information should never be provided by PRD code (security flaw)
        cerr << "Provided PASSWORD is probably wrong" << endl;
        return NULL;
    }
    return ssl;
}


/* -----------------------------------------------------------------------------
 * @brief  Function waits (blocking-io) for some data and sends back response
 *         Method prints SSL state after each operation and data received.
 * ----------------------------------------------------------------------------- */
void exchange_data(SSL* ssl)
{
    char buf[MAX_PACKET_SIZE];

    // receive
    SSL_read(ssl, buf, MAX_PACKET_SIZE);
    cout << "RECEIVED : " << buf << endl;
    cout << "READ: SSL STATE: " << SSL_state_string_long(ssl) << endl;

    // send rsp
    memcpy(buf, "RESPONSE", 9);
    SSL_write(ssl, buf, 9);
    cout << "WRITE: SSL STATE: " << SSL_state_string_long(ssl) << endl;

}

/* -----------------------------------------------------------------------------
 * @brief   ssl_init_server
 *
 *          Function sets up SSL_CTX object for all connections. It does
 *          following steps:
 *          1. SRP data store
 *          2. Disables any certificate verification, so that no certificates are used
 *          3. Sets list of ciphers to be used only to those which support SRP
 *          4. Configures operations on blocking socket
 *
-------------------------------------------------------------------------------- */
void ssl_init_server()
{
    // Create user and put it in the store
    initialize_SRP_store(ssl_ctx);

    // Sets callback to be called when new user is trying to authenticate (new SSL session is created)
    SSL_CTX_set_srp_username_callback(ssl_ctx, SRP_server_callback);

    // Disables any certificate verification
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    // Use only those ciphers that are on SRP list
    // (we may also specify here concreate cipher to use f.e. SRP-3DES-EDE-CBC-SHA)
    SSL_CTX_set_cipher_list(ssl_ctx,"SRP");

    // SSL_MODE_AUTO_RETRY: this program uses blocking-io, SSL_MODE_AUTO_RETRY set in order to
    // make openssl deal with retries on handshake (no need to checking for WANT_READ, WANT_WRITE)
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
}

int main()
{
    SSL* ssl = NULL;

    try
    {
        if( !ssl_init(&ssl_ctx, true) )
        {
            ERR_print_errors_fp(stderr);
            throw runtime_error("SSL init failed");
        }

        ssl_init_server();

        listen();

        ssl = accept_ssl();
        if(ssl==NULL)
            throw runtime_error("Problem establishing TLS session");

        exchange_data(ssl);

        // close
    }
    catch(runtime_error& e)
    {
        cerr << "ERROR " << e.what() << endl;
    }
    catch(...)
    {
        cerr << "Unknown exception" << endl;
    }
    return 0;
}
