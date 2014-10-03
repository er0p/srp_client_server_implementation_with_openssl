#ifndef __SSL_PROCESS__
#define __SSL_PROCESS__

#include <openssl/ssl.h>
#include <openssl/err.h>

class SSLProcess
{
public:
    virtual ~SSLProcess();
    virtual void init() = 0;

protected:
    SSLProcess(bool isServer);

    void sslInit();
    bool isServer()
    { return _isServer; }

    SSL_CTX* _ctx;

private:
    SSLProcess();
    SSLProcess(const SSLProcess&);
    SSLProcess& operator=(const SSLProcess&);

    bool _isServer;
};

#endif // __SSL_PROCESS__
