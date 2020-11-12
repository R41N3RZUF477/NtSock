#ifndef _NTSOCK_H_
#define _NTSOCK_H_

#include <ntstatus.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef NTSOCK_LARGE_SOCK_CONTEXT
#define SOCK_CONTEXT_BUF_SIZE (sizeof(SOCK_SHARED_INFO)+sizeof(GUID)+sizeof(PVOID)+8+(2*sizeof(SOCKADDR_STORAGE)))
#define SOCK_CONTEXT_ADDR_SIZE (sizeof(SOCKADDR_STORAGE))
#else
#define SOCK_CONTEXT_BUF_SIZE (sizeof(SOCK_SHARED_INFO)+sizeof(GUID)+sizeof(PVOID)+72)
#define SOCK_CONTEXT_ADDR_SIZE (sizeof(SOCKADDR_IN6))
#endif

//#define NTSOCK_SELECT_STACKALLOC (127 * sizeof(AFD_SELECT_DATA_ENTRY) + sizeof(AFD_SELECT_DATA))

#define PORT_DEF_RANGE_MIN_XP    1025
#define PORT_DEF_RANGE_MAX_XP    5000
#define PORT_DEF_RANGE_MIN_VISTA 49152
#define PORT_DEF_RANGE_MAX_VISTA 65535

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT    0x2
#endif
#define MSG_NOBINDCHECK 0x100000
#define MSG_NOTIMEOUT   0x200000
#define MSG_DOANYWAY    0x400000
#define MSG_IMMEDIATE   0x800000

#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS     _WSAIOW(IOC_VENDOR,4)
#endif
#ifndef SIO_RCVALL
#define SIO_RCVALL             _WSAIOW(IOC_VENDOR,1)
#endif
#ifndef SIO_GET_INTERFACE_LIST
#define SIO_GET_INTERFACE_LIST _IOR('t', 127, u_long)
#endif
#ifndef SIO_INDEX_BIND
#define SIO_INDEX_BIND         _WSAIOW(IOC_VENDOR,8)
#endif

// SOCKET_CONTEXT structure from Dr. Memory Github repository (msafdlib.h)
// Small adjustment for x64

typedef enum _SOCKET_STATE
{
	SocketUndefined = -1,
	SocketOpen,
	SocketBound,
	SocketBoundUdp,
	SocketConnected,
	SocketClosed
} SOCKET_STATE, *PSOCKET_STATE;

typedef struct _SOCK_SHARED_INFO {
	SOCKET_STATE                State;
	INT                            AddressFamily;
	INT                            SocketType;
	INT                            Protocol;
	INT                            SizeOfLocalAddress;
	INT                            SizeOfRemoteAddress;
	struct linger                LingerData;
	ULONG                        SendTimeout;
	ULONG                        RecvTimeout;
	ULONG                        SizeOfRecvBuffer;
	ULONG                        SizeOfSendBuffer;
	struct {
		BOOLEAN                    Listening:1;
		BOOLEAN                    Broadcast:1;
		BOOLEAN                    Debug:1;
		BOOLEAN                    OobInline:1;
		BOOLEAN                    ReuseAddresses:1;
		BOOLEAN                    ExclusiveAddressUse:1;
		BOOLEAN                    NonBlocking:1;
		BOOLEAN                    DontUseWildcard:1;
		BOOLEAN                    ReceiveShutdown:1;
		BOOLEAN                    SendShutdown:1;
		BOOLEAN                    UseDelayedAcceptance:1;
		BOOLEAN                    UseSAN:1;
		BOOLEAN                    HasGUID:1;
	} Flags;
	DWORD                        CreateFlags;
	DWORD                        CatalogEntryId;
	DWORD                        ServiceFlags1;
	DWORD                        ProviderFlags;
	GROUP                        GroupID;
	DWORD                        GroupType;
	INT                            GroupPriority;
	INT                            SocketLastError;
	HWND                        hWnd;
	#ifndef _WIN64
	LONG                        Padding;
	#endif
	DWORD                        SequenceNumber;
	UINT                        wMsg;
	LONG                        AsyncEvents;
	LONG                        AsyncDisabledEvents;
} SOCK_SHARED_INFO, *PSOCK_SHARED_INFO;

typedef struct _SOCKET_CONTEXT {
	SOCK_SHARED_INFO SharedData;
	GUID Guid;
	ULONG SizeOfHelperData;
	ULONG Padding;
	SOCKADDR LocalAddress;
	SOCKADDR RemoteAddress;
	PVOID Helper;
} SOCKET_CONTEXT, *PSOCKET_CONTEXT;

typedef struct _SOCKET_CONTEXT_XP {
    SOCK_SHARED_INFO SharedData;
    ULONG SizeOfHelperData;
    ULONG Padding;
	SOCKADDR LocalAddress;
	SOCKADDR RemoteAddress;
	PVOID Helper;
} SOCKET_CONTEXT_XP, *PSOCKET_CONTEXT_XP;

typedef struct _NTPOLLFD {
	SOCKET fd;
	short  events;
	short  revents;
} NTPOLLFD, *PNTPOLLFD;

u_short NtHtons(u_short s);
struct in_addr NtInetAddr(const char *cp);
NTSTATUS GetSocketContext(SOCKET sock, PSOCKET_CONTEXT sockctx, PULONG ctxsize);
NTSTATUS SetSocketContext(SOCKET sock, const PSOCKET_CONTEXT sockctx, ULONG ctxsize);
int NtEnumProtocols(LPINT lpiProtocols, LPWSAPROTOCOL_INFOW lpProtocolBuffer, LPDWORD lpdwBufferLength);
SOCKET NtSocket(int af, int type, int protocol);
int NtBind(SOCKET sock, const struct sockaddr *addr, int addrlen);
int NtAutoBind(SOCKET sock, u_short port);
int NtSend(SOCKET sock, const void *buf, int len, int flags);
int NtRecv(SOCKET sock, void *buf, int len, int flags);
int NtSendTo(SOCKET sock, const void *buf, int len, int flags, const struct sockaddr *to, int tolen);
int NtRecvFrom(SOCKET sock, void *buf, int len, int flags, struct sockaddr *from, int *fromlen);
int NtSelect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const TIMEVAL *timeout);
int NtPoll(NTPOLLFD *fds, ULONG nfds, int timeout);
void NtFDZero(fd_set *fd);
void NtFDSet(SOCKET s, fd_set *fd);
int NtFDIsSet(SOCKET s, fd_set *fd);
int NtSetSockOpt(SOCKET sock, int level, int optname, const char *optval, int optlen);
int NtGetSockOpt(SOCKET sock, int level, int optname, const char *optval, int *optlen);
int NtIoctlSocket(SOCKET sock, long cmd, u_long *argp);
int NtGetSockType(SOCKET sock, int *af, int *type, int *protocol);
int NtGetSockName(SOCKET sock, struct sockaddr *name, int *namelen);
int NtGetPeerName(SOCKET sock, struct sockaddr *name, int *namelen);
int NtListen(SOCKET sock, int backlog);
SOCKET NtAccept(SOCKET sock, struct sockaddr *addr, int *addrlen);
int NtAcceptExLegacy(SOCKET listensock, SOCKET acceptsock, struct sockaddr *addr, int *addrlen);
int NtConnect(SOCKET sock, const struct sockaddr *name, int namelen);
int NtConnectExLegacy(SOCKET sock, const struct sockaddr *name, int namelen);
int NtDisconnect(SOCKET sock, DWORD flags);
int NtShutdown(SOCKET sock, int how);
NTSTATUS NtCloseSocket(SOCKET sock);
int NtGetHostname(char *name,int namelen);
int NtGetDomainName(char *name,int namelen);

#ifdef __cplusplus
}
#endif

#endif
