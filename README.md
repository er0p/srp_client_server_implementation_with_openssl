Example of SRP client server with OpenSSL
=========================================

Toy code which shows how establish SRP-TLS session and exchange some data
over blocking socket. Socket is blocking becuase it makes code easier to
understand. Non-blocking solution is ofcourse possible (implementation is
same as for any TLS un.

How it works:

Client:
=======
* Sends user and password via SRP to the server
* After session established some query & reply is exchanged with server

Server:
=======
* Creates verifier and salt for the user that will authenticate with
  login USER_NAME and USER_PASS password
* Opens socket
* When connection arrives, authentication trial is performed

After TLS session is established program exchanges some data in order to
show that connection is working correctly.

In this implementation I don't care about any memory free'ing, closing
session/connection correctly etc. Proper care needs to be taken in production
code.

TODO:
=====
1. Code for adding new users 
