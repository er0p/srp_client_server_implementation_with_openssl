#ifndef __SSL_SERVER_H__
#define __SSL_SERVER_H__

#include "ssl_process.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <map>

#include <boost/thread/thread.hpp>
#include <openssl/ssl.h>

struct Acceptor
{
    int         _master;
    SSL_CTX*    _ctx;

    Acceptor(int iMasterHd, SSL_CTX* iCtx)
        : _master(iMasterHd)
        , _ctx(iCtx)
        { }

    int openTCPSocket();
    SSL* openSSLSession(int);

    void operator()();
};

#endif
