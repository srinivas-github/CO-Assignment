#include "mySocket.h"
#include "myException.h"

const int MSG_HEADER_LEN = 6;

mySocket::mySocket(int pNumber)
{
    portNumber = pNumber;
    blocking = 1;

    try
    {
        if ( (socketId=socket(AF_INET,SOCK_STREAM,0)) == -1)
        {
            myException* openUnixSocketException = new myException(0,"unix: error getting host by name");
	    throw openUnixSocketException;
        }
    }
    catch(myException* excp)
    {
        excp->response();
	delete excp;
	exit(1);
    }

    /** 
     * set the initial address of client that shall be communicated with to 
     * any address as long as they are using the same port number. 
     * The clientAddr structure is used in the future for storing the actual
     * address of client applications with which communication is going
     * to start
     */
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    clientAddr.sin_port = htons(portNumber);
}
    
void mySocket::setDebug(int debugToggle)
{
    try 
    {
        if ( setsockopt(socketId,SOL_SOCKET,SO_DEBUG,(char *)&debugToggle,sizeof(debugToggle)) == -1 )
        {
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
            throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
        excp->response();
	delete excp;
        exit(1);
    }
}

void mySocket::setReuseAddr(int reuseToggle)
{
    try 
    {
        if ( setsockopt(socketId,SOL_SOCKET,SO_REUSEADDR,(char *)&reuseToggle,sizeof(reuseToggle)) == -1 )
        {
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
        excp->response();
	delete excp;
	exit(1);
    }
} 

void mySocket::setKeepAlive(int aliveToggle)
{
    try 
    {
        if ( setsockopt(socketId,SOL_SOCKET,SO_KEEPALIVE,(char *)&aliveToggle,sizeof(aliveToggle)) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
        excp->response();
	delete excp;
	exit(1);
    }
} 

void mySocket::setLingerSeconds(int seconds)
{
    struct linger lingerOption;
	
    if ( seconds > 0 )
    {
        lingerOption.l_linger = seconds;
	lingerOption.l_onoff = 1;
    }
    else lingerOption.l_onoff = 0;
	 
    try 
    {
        if ( setsockopt(socketId,SOL_SOCKET,SO_LINGER,(char *)&lingerOption,sizeof(struct linger)) == -1 )
	{
	    myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
}

void mySocket::setLingerOnOff(bool lingerOn)
{
    struct linger lingerOption;

    if ( lingerOn ) lingerOption.l_onoff = 1;
    else lingerOption.l_onoff = 0;

    try 
    {
 	if ( setsockopt(socketId,SOL_SOCKET,SO_LINGER,(char *)&lingerOption,sizeof(struct linger)) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
}

void mySocket::setSendBufSize(int sendBufSize)
{
    try 
    {
        if ( setsockopt(socketId,SOL_SOCKET,SO_SNDBUF,(char *)&sendBufSize,sizeof(sendBufSize)) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
} 

void mySocket::setReceiveBufSize(int receiveBufSize)
{
    try 
    {
        if ( setsockopt(socketId,SOL_SOCKET,SO_RCVBUF,(char *)&receiveBufSize,sizeof(receiveBufSize)) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
}

void mySocket::setSocketBlocking(int blockingToggle)
{
    if (blockingToggle)
    {
        if (getSocketBlocking()) return;
        else blocking = 1;
    }
    else
    {
  	if (!getSocketBlocking()) return;
	else blocking = 0;
    }

    try 
    {
	if (ioctl(socketId,FIONBIO,(char *)&blocking) == -1)
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
	}
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
}

int mySocket::getDebug()
{
    int myOption;
    int myOptionLen = sizeof(myOption);

    try 
    {
   	if ( getsockopt(socketId,SOL_SOCKET,SO_DEBUG,(char *)&myOption,&myOptionLen) == -1 )
  	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
				throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
    
    return myOption;
}

int mySocket::getReuseAddr()
{
    int myOption;        
    int myOptionLen = sizeof(myOption);

    try 
    {
 	if ( getsockopt(socketId,SOL_SOCKET,SO_REUSEADDR,(char *)&myOption,&myOptionLen) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
            throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
    return myOption;
}

int mySocket::getKeepAlive()
{
    int myOption;        
    int myOptionLen = sizeof(myOption);

    try 
    {
        if ( getsockopt(socketId,SOL_SOCKET,SO_KEEPALIVE,(char *)&myOption,&myOptionLen) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
    return myOption;    
}

int mySocket::getLingerSeconds()
{
    struct linger lingerOption;
    int myOptionLen = sizeof(struct linger);

    try 
    {
	if ( getsockopt(socketId,SOL_SOCKET,SO_LINGER,(char *)&lingerOption,&myOptionLen) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
    return lingerOption.l_linger;
}

bool mySocket::getLingerOnOff()
{
    struct linger lingerOption;
    int myOptionLen = sizeof(struct linger);

    try 
    {
        if ( getsockopt(socketId,SOL_SOCKET,SO_LINGER,(char *)&lingerOption,&myOptionLen) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }

    if ( lingerOption.l_onoff == 1 ) return true;
    else return false;
}

int mySocket::getSendBufSize()
{
    int sendBuf;
    int myOptionLen = sizeof(sendBuf);

    try 
    {
 	if ( getsockopt(socketId,SOL_SOCKET,SO_SNDBUF,(char *)&sendBuf,&myOptionLen) == -1 )
	{
            myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	    throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
    return sendBuf;
}    

int mySocket::getReceiveBufSize()
{
    int rcvBuf;
    int myOptionLen = sizeof(rcvBuf);

    try 
    {
	if ( getsockopt(socketId,SOL_SOCKET,SO_RCVBUF,(char *)&rcvBuf,&myOptionLen) == -1 )
	{
             myException* unixSocketOptionException = new myException(0,"unix: error getting host by name");
	     throw unixSocketOptionException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
    return rcvBuf;
}


ostream& operator<<(ostream& io,mySocket& s)
{
	string flagStr = "";

	io << "--------------- Summary of socket settings -------------------" << endl;
	io << "   Socket Id:     " << s.getSocketId() << endl;
	io << "   port #:        " << s.getPortNumber() << endl;
	io << "   debug:         " << (flagStr = s.getDebug()? "true":"false" ) << endl;
	io << "   reuse addr:    " << (flagStr = s.getReuseAddr()? "true":"false" ) << endl;
	io << "   keep alive:    " << (flagStr = s.getKeepAlive()? "true":"false" ) << endl;
	io << "   send buf size: " << s.getSendBufSize() << endl;
	io << "   recv bug size: " << s.getReceiveBufSize() << endl;
	io << "   blocking:      " << (flagStr = s.getSocketBlocking()? "true":"false" ) << endl;
	io << "   linger on:     " << (flagStr = s.getLingerOnOff()? "true":"false" ) << endl;
	io << "   linger seconds: " << s.getLingerSeconds() << endl;
	io << "----------- End of Summary of socket settings ----------------" << endl;
	return io;
}

myTcpSocket::myTcpSocket()
{
    for (i = 0; i < max_clients; i++)  
    {  
        client_socket[i] = 0;  
    }
}

void myTcpSocket::bindSocket()
{
    try
    {
	if (bind(socketId,(struct sockaddr *)&clientAddr,sizeof(struct sockaddr_in))==-1)
	{
            myException* unixSocketBindException = new myException(0,"unix: error calling bind()");
	    throw unixSocketBindException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
}


void myTcpSocket::connectToServer(string& serverNameOrAddr,hostType hType)
{ 
    /** 
     * When this method is called, a client socket has been built already,
     * so we have the socketId and portNumber ready.
     * a myHostInfo instance is created, no matter how the server's name is 
     * given (such as www.yuchen.net) or the server's address is given (such
     * as 169.56.32.35), we can use this myHostInfo instance to get the 
     * IP address of the server
     */
     myHostInfo serverInfo(serverNameOrAddr,hType);
	
    // Store the IP address and socket port number	
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(serverInfo.getHostIPAddress());
    serverAddress.sin_port = htons(portNumber);

    // Connect to the given address
    try 
    {
	if (connect(socketId,(struct sockaddr *)&serverAddress,sizeof(serverAddress)) == -1)
	{
            myException* unixSocketConnectException = new myException(0,"unix: error calling connect()");
	    throw unixSocketConnectException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
}

myTcpSocket* myTcpSocket::acceptClient(string& clientHost)
{
    int newSocket;   // the new socket file descriptor returned by the accept systme call

    // the length of the client's address
    int clientAddressLen = sizeof(struct sockaddr_in);
    struct sockaddr_in clientAddress;    // Address of the client that sent data

    // Accepts a new client connection and stores its socket file descriptor
    try 
    {
	if ((newSocket = accept(socketId, (struct sockaddr *)&clientAddress,&clientAddressLen)) == -1)
	{
            myException* unixSocketAcceptException = new myException(0,"unix: error calling accept()");
	    throw unixSocketAcceptException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	return NULL;
    }
    
    // Get the host name given the address
    char *sAddress = inet_ntoa((struct in_addr)clientAddress.sin_addr);
    myHostInfo clientInfo(string(sAddress),ADDRESS);
    char* hostName = clientInfo.getHostName();
    clientHost += string(hostName);
	
    // Create and return the new myTcpSocket object
    myTcpSocket* retSocket = new myTcpSocket();
    retSocket->setSocketId(newSocket);
    return retSocket;
}

void myTcpSocket::listenToClient(int totalNumPorts)
{
    try 
    {
	if (listen(socketId,totalNumPorts) == -1)
	{
            myException* unixSocketListenException = new myException(0,"unix: error calling listen()");
	    throw unixSocketListenException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
}       

int myTcpSocket::sendMessage(string& message)
{
    int numBytes;  // the number of bytes sent
    /** 
     *   for each message to be sent, add a header which shows how long this message
     *   is. This header, regardless how long the real message is, will always be
     *   of the length MSG_HEADER_LEN.
     */

    char msgLength[MSG_HEADER_LEN+1];
    sprintf(msgLength,"%6d",message.size());
    string sendMsg = string(msgLength);
    sendMsg += message;

    // Sends the message to the connected host
    try 
    {
	if (numBytes = send(socketId,sendMsg.c_str(),sendMsg.size(),0) == -1)
	{
            myException* unixSocketSendException = new myException(0,"unix: error calling send()");
	    throw unixSocketSendException;
        }
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
    return numBytes;
}

int myTcpSocket::recieveMessage(string& message)
{
    int numBytes;  // The number of bytes recieved
    // retrieve the length of the message received
    char msgLength[MSG_HEADER_LEN+1];
    memset(msgLength,0,sizeof(msgLength));
    try
    {
	numBytes = recv(socketId,msgLength,MSG_HEADER_LEN,0);
        if (numBytes == -1)
        {
            myException* unixSocketRecvException = new myException(0,"unix: error calling recv()");
	    throw unixSocketRecvException;
	}
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }

    // receive the real message
    try
    {
	numBytes = recv(socketId,(char*)(message.c_str()),atoi(msgLength),0);
        if (numBytes == -1)
        {
            myException* unixSocketRecvException = new myException(0,"unix: error calling recv()");
	    throw unixSocketRecvException;
	}
    }
    catch(myException* excp)
    {
	excp->response();
	delete excp;
	exit(1);
    }
    return numBytes;
}

void myTcpSocket::handleWithSelect()
{
    // Store the IP address and socket port number
    struct sockaddr_in address;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(serverInfo.getHostIPAddress());
    serverAddress.sin_port = htons(portNumber); 

    int addrLen = sizeof(serverAddress);
    int sd, activity, new_socket;

    while (1)
    {
       FD_ZERO(&readfds); 
       FD_SET(socketId, &readfds);
       max_sd = socketId;
       for (int i = 0; i < max_clients; i++)
       {
          sd = client_socket[i];
          if (sd > 0 )
              FD_SET( sd , &readfds); 
          if (sd > max_sd)
              max_sd = sd;
       }
       //wait for an activity on one of the sockets , timeout is NULL , 
        //so wait indefinitely 
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);  
      
        if ((activity < 0) && (errno!=EINTR))  
        {  
            printf("select error");  
        }
        //If something happened on the master socket , 
        //then its an incoming connection 
        if (FD_ISSET(socketId, &readfds))  
        {  
            if ((new_socket = accept(socketId, 
                    (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)  
            {  
                perror("accept");  
                exit(EXIT_FAILURE);  
            }  
            
            //inform user of socket number - used in send and receive commands 
            printf("New connection , socket fd is %d , ip is : %s , port : %d 
                  \n" , new_socket , inet_ntoa(address.sin_addr) , ntohs
                  (address.sin_port));  
          
            //send new connection greeting message 
            if( send(new_socket, message, strlen(message), 0) != strlen(message) )  
            {  
                perror("send");  
            }  
                
            puts("Welcome message sent successfully");  
                
            //add new socket to array of sockets 
            for (i = 0; i < max_clients; i++)  
            {  
                //if position is empty 
                if( client_socket[i] == 0 )  
                {  
                    client_socket[i] = new_socket;  
                    printf("Adding to list of sockets as %d\n" , i);  
                        
                    break;  
                }  
            }  
        }  
            
        //else its some IO operation on some other socket
        for (i = 0; i < max_clients; i++)  
        {  
            sd = client_socket[i];  
                
            if (FD_ISSET( sd , &readfds))  
            {  
                //Check if it was for closing , and also read the 
                //incoming message 
                if ((valread = read( sd , buffer, 1024)) == 0)  
                {  
                    //Somebody disconnected , get his details and print 
                    getpeername(sd , (struct sockaddr*)&address , \
                        (socklen_t*)&addrlen);  
                    printf("Host disconnected , ip %s , port %d \n" , 
                          inet_ntoa(address.sin_addr) , ntohs(address.sin_port));  
                        
                    //Close the socket and mark as 0 in list for reuse 
                    close( sd );  
                    client_socket[i] = 0;  
                }  
                    
                //Echo back the message that came in 
                else
                {  
                    //set the string terminating NULL byte on the end 
                    //of the data read 
                    buffer[valread] = '\0';  
                    send(sd , buffer , strlen(buffer) , 0 );  
                }  
            }  
        }  
    }  
}
