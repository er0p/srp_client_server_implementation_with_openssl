#include <openssl/ssl.h>
#include <openssl/err.h>

bool ssl_init(SSL_CTX** ssl_ctx, bool is_server);
bool handle_error_code(int& len, SSL* SSLHandler, int code, const char* func);
