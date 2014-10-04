#include <boost/thread/thread.hpp>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <unistd.h>
#include <vector>
#include <set>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <exception>
#include <netinet/tcp.h>
#include "defs.h"
#include <boost/lockfree/queue.hpp>
#include <iostream>
#include "ssl_process.h"
#include <utility>
#include <openssl/srp.h>

using namespace boost;
using namespace std;

void CHECK( bool test )
{
    if(test) {
        cout << "MAKE IT ASSERT" << endl;
        exit(0);
    }
}

typedef pair<int, SSL*> SocketSSLHandles_t;
SocketSSLHandles_t WriteHandler(0,0);

// Socket Set is a set that keeps sockets on which we can 'select()'
typedef set<SocketSSLHandles_t> SocketSet_t;
SocketSet_t SocketSet;
mutex SocketSetMutex;

typedef boost::lockfree::queue<SocketSSLHandles_t, boost::lockfree::capacity<50> > ReadQueue_t;
ReadQueue_t ReadQueue;

// needed for new implementation
int master_socket=0;
SSL_CTX* ssl_ctx;

static SRP_VBASE *srpData = NULL;

// OpenSSL defines a handy SRP_VBASE type that can be used to store verifiers and we can use SRP_VBASE_init to load in the the verifier file we made earlier
void setup_SRP_data(SSL_CTX *ctx)
{
    srpData = SRP_VBASE_new(NULL);

    // The structure to put the verifier data and create secret g^N
    SRP_user_pwd *p =
       (SRP_user_pwd *)OPENSSL_malloc(sizeof(SRP_user_pwd));
    SRP_gN *gN = SRP_get_default_gN(SRP_GROUP);
    CHECK(gN == NULL);

    // Now create the verifier for the password.
    // We could get the password from the user at this point.
    BIGNUM *salt = NULL, *verifier = NULL;

    // OZAPTF: check what it returns and halt on error
    SRP_create_verifier_BN(USER_NAME,
                           USER_PASS,
                           &salt,
                           &verifier,
                           gN->N,
                           gN->g);
    // Copy into the SRP_user_pwd structure
    p->id = OPENSSL_strdup(USER_NAME);
    p->g = gN->g;
    p->N = gN->N;
    p->s = salt;
    p->v = verifier;
    p->info = NULL;
    // And add in to VBASE stack of user data
    sk_SRP_user_pwd_push(srpData->users_pwd, p);

    cout << "USER: " << p->id << " added to DB" << endl
        << " PARAMS " << endl
        << " G: " << p->g
        << " N: " << p->N
        << " salt: " << p->s
        << " VERIFIER: " << p->v
        << endl;
}

int SRP_server_callback(SSL *s, int *ad, void *arg)
{
    cout << "SRP server callback starts" << endl;
    char *srpusername = SSL_get_srp_username(s);
    CHECK(srpusername == NULL);
    cout << "User: " << srpusername << " tries to login";

    // Get data for user
    SRP_user_pwd *p = SRP_VBASE_get_by_user(srpData,srpusername);
    if (p == NULL) {
        fprintf(stdout, "User %s doesn't exist\n", srpusername);
        return SSL3_AL_FATAL;
    }
    // Set verifier data
    CHECK(SSL_set_srp_server_param(s,
                                    p->N,
                                    p->g,
                                    p->s,
                                    p->v,
                                    NULL) < 0);

    cout << "SRP server callback ends" << endl;

    return SSL_ERROR_NONE;
}

void ssl_init_server()
{
    if( !ssl_init(&ssl_ctx, true) )
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    setup_SRP_data(ssl_ctx);

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1
                        | SSL_OP_ALL
                        | SSL_OP_SINGLE_DH_USE );

    // SSL_MODE_AUTO_RETRY: this program uses blocking-io, SSL_MODE_AUTO_RETRY set in order to
    // make openssl deal with retries on handshake (no need to checking for WANT_READ, WANT_WRITE)
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE,NULL);
    SSL_CTX_set_srp_username_callback(ssl_ctx, SRP_server_callback);
    SSL_CTX_set_srp_cb_arg(ssl_ctx, srpData);
    SSL_CTX_set_cipher_list(ssl_ctx,"ALL:NULL"); // NULL for testing, DON'T use in production systems
}

void listen()
{
    struct sockaddr_in local_address;

    master_socket = ::socket(PF_INET, SOCK_STREAM, 0);
    memset(&local_address, 0, sizeof(local_address));

    local_address.sin_family = AF_INET;
    local_address.sin_port = htons(PORT);
    local_address.sin_addr.s_addr = INADDR_ANY;

    int reuseval = 1;
    setsockopt(master_socket,SOL_SOCKET,SO_REUSEADDR, &reuseval, sizeof(reuseval));

    // Bind to the socket
    if(::bind(master_socket, (struct sockaddr *)&local_address, sizeof(local_address)) != 0)
        throw runtime_error("Couldn't bind to local port");

    // Set a limit on connection queue.
    if(::listen(master_socket, 5) != 0)
        throw runtime_error("Not possible to get into listen state");
}


int accept_socket()
{
    // Open up new connection
    cout << "New connection has arrived" << endl;
    struct sockaddr_in addr;
    int len = sizeof(addr);
    int client = accept(master_socket, (struct sockaddr *)&addr, (socklen_t *)&len);
    if(client == -1)
        perror("accept");
    return client;
}

// bool handle_error_code(int& len, SSL* SSLHandler, int code, const char* func)

SSL* accept_ssl(int iTCPHandle)
{
    SSL *ssl = (SSL*) SSL_new(ssl_ctx);
    SSL_set_fd(ssl, iTCPHandle);

    // normally this would be in other thread
    int code = 0;
    int len = 0;
    if( (code=SSL_accept(ssl)) == -1) {
        handle_error_code(len, ssl, code, "accept_ssl");
        // Should never happen as long as SSL_MODE_AUTO_RETRY is set on SSL_CTX
        if (BIO_sock_should_retry(code))
        {
            cout << "DELAY: functinality not implemented\n" << endl;
            return NULL;
        }
        cout << "PASSWORD probably wrong" << endl;
        return NULL;
    }
    return ssl;
}

void main_loop()
{
    cout << "Entering acceptor loop..." << endl;
    while(1)
    {
        // wait timer for select
        struct timeval tv;
        tv.tv_sec  = 0;
        tv.tv_usec = 10;

        fd_set fd_read;

        // set fd_sets
        FD_ZERO(&fd_read);

        // set max fd for select
        int maxv = master_socket;
        FD_SET(master_socket, &fd_read);

        // add all the sockets to sets
        {
            lock_guard<mutex> guard(SocketSetMutex);
            for(SocketSet_t::const_iterator aIt=SocketSet.begin();
                aIt!=SocketSet.end(); ++aIt)
            {
                FD_SET(aIt->first, &fd_read);
                if(aIt->first > maxv)
                    maxv=aIt->first;
            }
        }

        // wait in select now
        select(maxv+1, &fd_read, NULL, NULL, (struct timeval *)&tv);
        {
            lock_guard<mutex> guard(SocketSetMutex);

            // check if you can read
            SocketSet_t::const_iterator aIt=SocketSet.begin();
            while(aIt!=SocketSet.end())
            {

                SocketSSLHandles_t aTmpHandles = *aIt;
                ++aIt;
                if( FD_ISSET(aTmpHandles.first, &fd_read ) )
                {
                    // you need to erase tmpHd from SocketSet - otherwise it will
                    // be ready to read until SSL_read is not called on it
                    SocketSet.erase(aTmpHandles);
                    ReadQueue.push(aTmpHandles);
                }
            }
        }

        // if master is in fd_read - then it means new connection req
        // has arrived
        if( FD_ISSET(master_socket, &fd_read) )
        {
            int new_fd=accept_socket();
            if( new_fd >= 0 )
            {
                cout << "New socket with ID : " << new_fd
                     << " is going to be added to map" << endl;
                SSL* ssl = accept_ssl(new_fd);
                {
                    lock_guard<mutex> guard(SocketSetMutex);
                    SocketSet.insert(make_pair(new_fd, ssl));
                }
            }
        }
    }
}

/// --- MAIN --- ///
int main() {

    ssl_init_server();
    listen();

    main_loop();

    getchar();
    return 0;
}
