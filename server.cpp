#include "server.h"
#include <vector>
#include <set>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <iostream>
#include <exception>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "defs.h"
#include <boost/lockfree/queue.hpp>

using namespace std;
using namespace boost;


typedef pair<int, SSL*> SocketSSLHandles_t;
SocketSSLHandles_t WriteHandler(0,0);

// Socket Set is a set that keeps sockets on which we can 'select()'
typedef set<SocketSSLHandles_t> SocketSet_t;
SocketSet_t SocketSet;
mutex SocketSetMutex;

// WaitForWrite is a condition variable that is signaled when Sender must start sending the data
condition_variable WaitForWrite;
mutex WaitForWriteMutex;

// mutex that synchronizes access to SSL_read/SSL_write
mutex WriteReadMutex;

typedef boost::lockfree::queue<SocketSSLHandles_t, boost::lockfree::capacity<50> > ReadQueue_t;
ReadQueue_t ReadQueue;

// thread functions to send and receive
void Receive();
void Send();
int Gmaster=0;


// needed for new implementation
int master_socket=0;
SSL_CTX* ssl_ctx;

bool handle_error_code(int& len, SSL* SSLHandler, int code, const char* func)
{
    switch( SSL_get_error( SSLHandler, code ) )
    {
    case SSL_ERROR_NONE:
        len+=code;
        return false;
    case SSL_ERROR_ZERO_RETURN:
        cout << "CONNETION CLOSE ON WRITE" << endl;
        exit(1);
        break;
    case SSL_ERROR_WANT_READ:
        cout << func << " WANT READ" << endl;
        break;
    case SSL_ERROR_WANT_WRITE:
        cout << func << " WANT WRITE" << endl;
        break;
    case SSL_ERROR_SYSCALL:
        cout << func << " ESYSCALL" << endl;
//        exit(1);
        break;
    case SSL_ERROR_SSL:
        cout << func << " ESSL" << endl;
        exit(1);
        break;
    default:
        cout << func << " SOMETHING ELSE" << endl;
    }
    return true;
}

void ssl_init()
{
    // Load algorithms and error strings.
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    // Create new context for server method.
    ssl_ctx = SSL_CTX_new( SSLv23_server_method() );
    if(ssl_ctx == 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }


    // Load certificate & private key
    if ( SSL_CTX_use_certificate_chain_file(ssl_ctx, CERTIFICATE_FILE) <= 0) {
        ERR_print_errors_fp(stderr);
        _exit(1);
    }

    if ( SSL_CTX_use_PrivateKey_file(ssl_ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        _exit(1);
    }

    // Verify if public-private keypair matches
    if ( !SSL_CTX_check_private_key(ssl_ctx) ) {
        fprintf(stderr, "Private key is invalid.\n");
        _exit(1);
    }

    // set weak protocol, so it is easy to debug with wireshark
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2
                        | SSL_OP_NO_TLSv1_1
                        | SSL_OP_NO_TLSv1
                        | SSL_OP_ALL
                        | SSL_OP_SINGLE_DH_USE );
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


void Acceptor::operator()()
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
                aIt++;
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
            int new_fd=openTCPSocket();
            if( new_fd >= 0 )
            {
                int flag =1;
//                setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
                cout << "New socket with ID : " << new_fd
                     << " is going to be added to map" << endl;
                SSL* ssl = openSSLSession(new_fd);
                lock_guard<mutex> guard(SocketSetMutex);
                SocketSet.insert(make_pair(new_fd, ssl));
            }
        }
    }
}

int Acceptor::openTCPSocket()
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

SSL* Acceptor::openSSLSession(int iTCPHandle)
{
    SSL *ssl = (SSL*) SSL_new(_ctx);
    SSL_set_fd(ssl, iTCPHandle);

    // normally this would be in other thread
    if(SSL_accept(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        throw runtime_error("Can't SSL_accept => can't continue");
    }
    return ssl;
}

void Receive()
{
    while(1)
    {
        char buf[1024];
        SocketSSLHandles_t handler;

        // TO-DO: this way it takes 100% CPU, some signal would be usefull
        while (!ReadQueue.empty())
        {
            ReadQueue.pop(handler);

            memset(buf,'\0',1024);
            int len_rcv=0;
            cout << SSL_state_string(handler.second) << endl;
            {
                lock_guard<mutex> lock(WriteReadMutex);
                int flag = 1;
                while( flag!=0 )
                {
                    cout << "SSL_read: start" << endl;
                    len_rcv = SSL_read(handler.second, buf, 1024);
                    flag = SSL_pending(handler.second);
                    cout << "PENDING: " << flag << endl;

//                cout << "SSL_read: stop" << endl;
                    if( !handle_error_code(len_rcv, handler.second, len_rcv, "rcv") )
                    {
                        // dirty thing - if it has \n on the end - remove it
                        if( buf[len_rcv-1] == '\n' )
                            buf[len_rcv-1] = '\0';

                        cout << buf << endl;
                        {
                            // add it back to the socket so that select can use it
                            lock_guard<mutex> guard(SocketSetMutex);
                            SocketSet.insert(handler);

                            // push handler ID and notify sender thread
                            WriteHandler = handler;
                            WaitForWrite.notify_one();
                        }
                        break;
                    }
                }

            }
        }
    }
}

void Send()
{
    while(1)
    {
        SocketSSLHandles_t handler(0,0);
        {
            unique_lock<mutex> lock(WaitForWriteMutex);
            WaitForWrite.wait(lock);
            handler = WriteHandler;
        }

        cout << "Writing to handler " << handler.first << endl;
        string buf(EXCHANGE_STRING);
        for(int i=0; i<SEND_ITERATIONS; ++i)
        {
            int len = 0;
            // wait timer for select
            struct timeval tv;
            tv.tv_sec  = 0;
            tv.tv_usec = 10;

            do
            {
                fd_set fd_write;
                FD_ZERO(&fd_write);
                FD_SET(Gmaster, &fd_write);
                FD_SET(handler.first, &fd_write);

                int maxv=Gmaster;
                if(Gmaster < handler.first)
                    maxv=handler.first;

                select(maxv+1, NULL, &fd_write, NULL, (struct timeval *)&tv);

                if( FD_ISSET(handler.first, &fd_write) )
                {
                    lock_guard<mutex> lock(WriteReadMutex);
//                    cout << "SSL_write: start" << endl;
                    int write_len=SSL_write(handler.second, buf.c_str()+len, buf.size()-len);
//                    cout << "SSL_write: stop " << endl;
                    handle_error_code(len, handler.second, write_len, "write");

                    // for debugging re-neg
                    // cout << "SSL STATE: " << SSL_state_string(handler.second) << endl;
                }

            } while( len != static_cast<int>(buf.size()) );
        }
    }
}


/// --- MAIN --- ///
int main() {

    ssl_init();
    listen();

    Acceptor ac(master_socket, ssl_ctx);
    ac();


  getchar();

  return 0;
}
