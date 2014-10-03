Example of SRP client server with OpenSSL
=============================

Toy code which shows problems with non-blocking, fullduplex I/O &amp; renegotiation in OpenSSL

What is it:
    This code shows that it is not possible to use SSL_write() and SSL_read() functions in the same
    way as ::send() and ::recv().
    The main difference between SSL_write/read functions and send/recv system calls is that
    SSL_write function may in fact read data from the socket in some situations (similary
    SSL_read may need to write data to the socket). 

How it works:

    Client & Server:
    - it has two threads - sender & receiver
    - writes and reads are mutexed

    Client:
    - I/O is blocking (but can be non-blocking)

    Server:
    - I/O is non-blocking
    - each thread runs it's own select()

    1. After client & server are connected (and SSL handshake done) client sender
    thread starts sending first message (in a loop).

    2. When server receives first query it starts sending string EXCHANGE_STRING for
    SEND_ITERATIONS number of times. So now we have 4 threads that are sending
    and receiving traffic at the same time ( 2 send/receive threads on each
    server and client side )

    3. When client receives RENEG_INIT_LEN number of characters it starts
    renegotiation ( if other one is not pending ). Bug starts to occure here

    BUG:
    Client side: client starts to report SSL_ERROR_SYSCALL
    Server side: server reports SSL_ERROR_WANT_READ when receive function is called

    TCP:
    In TCP exchange we can see that transfer between client & server is OK until
    client sends "Client Hello" packet. This packet is sent when SSL_renegotiate
    is called
