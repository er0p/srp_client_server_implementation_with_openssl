#include "ssl_process.h"
#include <iostream>

using namespace std;

bool ssl_init(SSL_CTX** ssl_ctx, bool is_server)
{
    // Load algorithms and error strings.
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    // Create new context for server method.
    *ssl_ctx = SSL_CTX_new(
        is_server ? SSLv23_server_method() : SSLv23_client_method());
    if(*ssl_ctx == 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

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
