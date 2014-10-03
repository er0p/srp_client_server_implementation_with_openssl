#include "ssl_process.h"

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
