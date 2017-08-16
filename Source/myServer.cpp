#include "mySocket.h"
#include "myException.h"
#include "myHostInfo.h"


int main()
{

    // get local information if neither the name or the address is given
    myHostInfo uHostAddress;
    string localHostName = uHostAddress.getHostName();
    string localHostAddr = uHostAddress.getHostIPAddress();
    cout << "------------------------------------------------------" << endl;
    cout << "	My local host information:" << endl;
    cout << "		Name:    " << localHostName << endl;
    cout << "		Address: " << localHostAddr << endl;
    cout << "------------------------------------------------------" << endl;
	
    // open socket on the local host
    myTcpSocket myServer(PORTNUM);
    cout << myServer;

    myServer.bindSocket();
    cout   << endl << "server finishes binding process... " << endl;
    myServer.listenToClient();
    cout   << "server is listening to the port ... " << endl;
    
    // wait to accept a client connection.  
    // processing is suspended until the client connects
    cout   << "server is waiting for client connecction ... " << endl;
    myTcpSocket* client;    // connection dedicated for client communication
    string clientHost;      // client name etc. 
    client = myServer.acceptClient(clientHost);
        
    cout   << endl << "==> A client from [" << clientHost << "] is connected!" << endl << endl;
    while(1)
    {
        string clientMessageIn = "";
	// receive from the client
        int numBytes = client->recieveMessage(clientMessageIn);
	if ( numBytes == -99 ) break;
        cout   << "[RECV:" << clientHost << "]: " << clientMessageIn << endl;
  	char sendmsg[MAX_MSG_LEN+1];
 	memset(sendmsg,0,sizeof(sendmsg));
	cout << "[" << localHostName << ":SEND] ";
	cin.getline(sendmsg,MAX_MSG_LEN);

	if ( numBytes == -99 ) break;
	string sendMsg(sendmsg);
	if ( sendMsg.compare("Bye") == 0 || sendMsg.compare("bye") == 0 )
            break;
	client->sendMessage(sendMsg);
    }

    return 1;
}
