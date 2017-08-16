#include "mySocket.h"
#include "myException.h"
#include "myHostInfo.h"

string serverIPAddress = "";

void readServerConfig();
void checkFileExistence(const string&);

int main()
{

    // get local information if neither the name or the address is given

    myHostInfo uHostAddress;
    string localHostName = uHostAddress.getHostName();
    string localHostAddr = uHostAddress.getHostIPAddress();
    cout << "Name: " << localHostName << endl;
    cout << "Address: " << localHostAddr << endl;
    // get server's information
    readServerConfig();

    myHostInfo serverInfo(serverIPAddress,ADDRESS);
    string serverName = serverInfo.getHostName();
    string serverAddr = serverInfo.getHostIPAddress();
    cout << "Name: " << serverName << endl;
    cout << "Address: " << serverAddr << endl;
 
    // an instance of the myTcpSocket is created.  At this point a TCP 
    // socket has been created and a port has been defined.
    myTcpSocket myClient(PORTNUM);
    myClient.setLingerOnOff(true);
    myClient.setLingerSeconds(10);

    cout << myClient;
    // connect to the server.
    cout   << "connecting to the server [" << serverName << "] ... " << endl;
    myClient.connectToServer(serverAddr,ADDRESS);

    int recvBytes = 0;
    while (1)
    {
	// send message to server
        char sendmsg[MAX_MSG_LEN+1];
	memset(sendmsg,0,sizeof(sendmsg));
	cout << "[" << localHostName << ":SEND] ";
	cin.getline(sendmsg,MAX_MSG_LEN);
 	string sendMsg(sendmsg);
        if ( sendMsg.compare("Bye") == 0 || sendMsg.compare("bye") == 0 ) break;
	myClient.sendMessage(sendMsg);

	// receive message from server
	string clientMessageIn = "";
        recvBytes = myClient.recieveMessage(clientMessageIn);
	if ( recvBytes == -99 ) break;

		cout   << "[RECV:" << serverName << "]: " << clientMessageIn << endl;

   }

    return 1;
}

void readServerConfig()
{
    string serverConfigFile = "serverConfig.txt";	
    checkFileExistence(serverConfigFile);
    ifstream serverConfig(serverConfigFile.c_str());

    // read server's IP address
    getline(serverConfig,serverIPAddress);
    //istrstream In(inLine.c_str());
    //In >> serverIPAddress;
    serverConfig.close();
}

void checkFileExistence(const string& fileName)
{
    ifstream file(fileName.c_str());
    if (!file) 
    {
  	cout << "Cannot continue:" << fileName << " does NOT exist!" << endl;
 	exit(1);
    }
    file.close();
}
