#include "ssl_process.h"

SSLProcess::SSLProcess(bool isServer)
    : _ctx(0)
    , _isServer(isServer)
{
}

SSLProcess::~SSLProcess()
{
    if(!_ctx)
        SSL_CTX_free(_ctx);
}

void SSLProcess::sslInit()
{
    // Load algorithms and error strings.
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    // Create new context for server method.
    _ctx = SSL_CTX_new(
        _isServer ? SSLv23_server_method() : SSLv23_client_method());
    if(_ctx == 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}
