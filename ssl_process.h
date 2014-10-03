#include <openssl/ssl.h>
#include <openssl/err.h>

bool ssl_init(SSL_CTX** ssl_ctx, bool is_server);
