#ifndef _mySocket
#define _mySocket

#include "../myHostInfo/myHostInfo.h"
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <iostream.h>
#include <sys/types.h>
#include <stropts.h>
#include <sys/filio.h>


const int MAX_RECV_LEN = 8096;
const int MAX_MSG_LEN = 1024;
const int PORTNUM = 1200;
const int max_clients = 100;
/**
 * Socket base class 
 */
class mySocket
{
protected:
/**
 * only used when the socket is used for client communication
 * once this is done, the next necessary call is setSocketId(int)
 */
    mySocket() {}
    void setSocketId(int socketFd) { socketId = socketFd; }

protected:
    int portNumber;        // Socket port number    
    int socketId;          // Socket file descriptor

    int blocking;          // Blocking flag
    int bindFlag;          // Binding flag

    struct sockaddr_in clientAddr;    // Address of the client that sent data

public:
    mySocket(int);                       // given a port number, create a socket
    virtual ~mySocket()
    {
    }
public:

    // socket options : ON/OFF
    void setDebug(int);
    void setReuseAddr(int);
    void setKeepAlive(int);
    void setLingerOnOff(bool);
    void setLingerSeconds(int);
    void setSocketBlocking(int);

    // size of the send and receive buffer
    void setSendBufSize(int);
    void setReceiveBufSize(int);

    // retrieve socket option settings
    int  getDebug();
    int  getReuseAddr();
    int  getKeepAlive();
    int  getSendBufSize();
    int  getReceiveBufSize();
    int  getSocketBlocking() { return blocking; }
    int  getLingerSeconds();
    bool getLingerOnOff();
	
    // returns the socket file descriptor
    int getSocketId() { return socketId; }

    // returns the port number
    int getPortNumber() { return portNumber; }

    // show the socket 
    friend ostream& operator<<(ostream&,mySocket&);

private:

	// Gets the system error
	char *sGetError()
	{
           return strerror(errno);
        }
};

class myTcpSocket : public mySocket
{
public:
    /** 
     * Constructor. used for creating instances dedicated to client communication:
     * when accept() is successful, a socketId is generated and returned
     * this socket id is then used to build a new socket using the following
     * constructor, therefore, the next necessary call should be setSocketId()
     * using this newly generated socket fd
     */
     myTcpSocket();
     ~myTcpSocket() {};

     // Constructor.  Used to create a new TCP socket given a port
     myTcpSocket(int portId) : mySocket(portId) { };

     /**
      * Sends a message to a connected host. The number of bytes sent is returned
      * can be either server call or client call
      */
     int sendMessage(string&);

     /**
      * receive messages and stores the message in a buffer
      */
     int recieveMessage(string&);

     /**
      * Binds the socket to an address and port number
      * a server call
      */
     void bindSocket();

     /**
      * accepts a connecting client.  The address of the connected client 
      * is stored in the parameter
      * a server call
      */
     myTcpSocket* acceptClient(string&);

     // Listens to connecting clients, a server call
     void listenToClient(int numPorts = 5);

     // connect to the server, a client call
     virtual void connectToServer(string&,hostType);

     //Handle multiple client sockets with select 
     void handleWithSelect();

private:
     int client_socket[100];
     fd_set readfds;
     int max_sd;
  

};

#endif
        

