#ifndef _SSLCLIENT_H_
#define _SSLCLIENT_H_
#include <openssl/ssl.h>
#include "ssl_process.h"

class Client : public SSLProcess
{
    int _handler;


public:
    Client()
        : SSLProcess(false){};

    void init();
    void connect();
    void start();
};

#endif /* _SSLCLIENT_H_ */
