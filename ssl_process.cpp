#include "ssl_process.h"
#include <iostream>

using namespace std;

bool ssl_init(SSL_CTX** ssl_ctx, bool is_server)
{
    // Load algorithms and error strings.
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    SSL_library_init();

    // Create new context for server method.
    *ssl_ctx = SSL_CTX_new(
        // TLSv1_server_method needs to be used for SRP
        is_server ? TLSv1_server_method() : TLSv1_client_method());
    if(*ssl_ctx == 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

/* -----------------------------------------------------------------------------
 * @brief   Cleans memory allocated during run
 *
-------------------------------------------------------------------------------- */
void cleanup(SSL_CTX* ssl_ctx, SSL* ssl)
{
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    CRYPTO_set_dynlock_create_callback(0);
    CRYPTO_set_dynlock_lock_callback(0);
    CRYPTO_set_dynlock_destroy_callback(0);
    CRYPTO_set_locking_callback(0);
    CRYPTO_THREADID_set_callback(0);

    ERR_remove_state(0);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
}


bool handle_error_code(int& len, SSL* ssl_handler, int code, const char* func)
{
    switch( SSL_get_error( ssl_handler, code ) )
    {
    case SSL_ERROR_NONE:
        len+=code;
        return false;
    case SSL_ERROR_ZERO_RETURN:
        cout << "CONNETION CLOSE ON WRITE" << endl;
        break;
    case SSL_ERROR_WANT_READ:
        cout << func << " WANT READ" << endl;
        break;
    case SSL_ERROR_WANT_WRITE:
        cout << func << " WANT WRITE" << endl;
        break;
    case SSL_ERROR_SYSCALL:
        cout << func << " ESYSCALL" << endl;
        break;
    case SSL_ERROR_SSL:
        cout << func << " ESSL" << endl;
        break;
    default:
        cout << func << " SOMETHING ELSE" << endl;
    }
    return true;
}
