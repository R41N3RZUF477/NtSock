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
#define SOCK_CONTEXT_BUF_SIZE (sizeof(SOCK_SHARED_INFO)+sizeof(GUID)+sizeof(PVOID)+8+(2*sizeof(SOCKADDR_IN6)))
#define SOCK_CONTEXT_ADDR_SIZE (sizeof(SOCKADDR_IN6))
#endif

//#define NTSOCK_SELECT_STACKALLOC (127 * sizeof(AFD_SELECT_DATA_ENTRY) + sizeof(AFD_SELECT_DATA))

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

u_short NtHtons(u_short s);
struct in_addr NtInetAddr(const char *cp);
int NtEnumProtocols(LPINT lpiProtocols, LPWSAPROTOCOL_INFOW lpProtocolBuffer, LPDWORD lpdwBufferLength);
SOCKET NtSocket(int af, int type, int protocol);
int NtBind(SOCKET sock, const struct sockaddr *addr, int addrlen);
int NtAutoBind(SOCKET sock, u_short port);
int NtSend(SOCKET sock, const void *buf, int len, int flags);
int NtRecv(SOCKET sock, void *buf, int len, int flags);
int NtSendTo(SOCKET sock, const void *buf, int len, int flags, const struct sockaddr *to, int tolen);
int NtRecvFrom(SOCKET sock, void *buf, int len, int flags, struct sockaddr *from, int *fromlen);
int NtSelect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const TIMEVAL *timeout);
void NtFDZero(fd_set *fd);
void NtFDSet(SOCKET s, fd_set *fd);
int NtFDIsSet(SOCKET s, fd_set *fd);
int NtSetSockOpt(SOCKET sock, int level, int optname, const char *optval, int optlen);
int NtGetSockOpt(SOCKET sock, int level, int optname, const char *optval, int *optlen);
int NtIoctlSocket(SOCKET sock, long cmd, u_long *argp);
int NtGetSockName(SOCKET sock, struct sockaddr *name, int *namelen);
int NtGetPeerName(SOCKET sock, struct sockaddr *name, int *namelen);
int NtConnect(SOCKET sock, const struct sockaddr *name, int namelen);
int NtShutdown(SOCKET sock, int how);
NTSTATUS NtCloseSocket(SOCKET sock);

#ifdef __cplusplus
}
#endif

#endif
