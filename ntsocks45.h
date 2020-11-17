#ifndef _NTSOCKS5_H_
#define _NTSOCKS5_H_

#define SOCKS_DEFAULT_PORT 1080

#define NTSOCKS_DEFTIMEOUT 10000

#define NTSOCKS_MAX_STR_LEN 255

#define SOCKS4_VERSION 4
#define SOCKS5_VERSION 5

#define SOCKS4_REQUEST_TCP     1
#define SOCKS4_REQUEST_TCPBIND 2
#define SOCKS5_REQUEST_TCP     1
#define SOCKS5_REQUEST_TCPBIND 2
#define SOCKS5_REQUEST_UDP     3

#define SOCKS4_REQUEST_TYPE_IP  1
#define SOCKS5_REQUEST_TYPE_IP  1
#define SOCKS5_REQUEST_TYPE_DNS 3
#define SOCKS5_REQUEST_TYPE_IP6 4

#define SOCKS4_ANSWER_OK        0x5A
#define SOCKS4_ANSWER_ERROR     0x5B
#define SOCKS4_ANSWER_ERRIDENTD 0x5C
#define SOCKS4_ANSWER_ERRID     0x5D

#define SOCKS5_AUTH_NOAUTH   0
#define SOCKS5_AUTH_GSSAPI   1
#define SOCKS5_AUTH_USERPASS 2
#define SOCKS5_AUTH_NOACCEPT 0xFF

#define SOCKS5_AUTH_UP_VERSION 1

#define SOCKS5_ANSWER_OK          0
#define SOCKS5_ANSWER_SVRFAULT    1
#define SOCKS5_ANSWER_NOTALLOWED  2
#define SOCKS5_ANSWER_NETUNREACH  3
#define SOCKS5_ANSWER_HOSTUNREACH 4
#define SOCKS5_ANSWER_CONREFUSED  5
#define SOCKS5_ANSWER_TTLEXPIRED  6
#define SOCKS5_ANSWER_COMNOTSUPP  7
#define SOCKS5_ANSWER_ADDRNOTSUPP 8

#pragma pack(push, 1)
typedef struct _NTSOCK_SOCKS4_REQUEST {
	BYTE Version;
	BYTE Command;
	USHORT Port;
	struct in_addr Ip;
	BYTE Auth[NTSOCKS_MAX_STR_LEN + 1];
} NTSOCK_SOCKS4_REQUEST, *PNTSOCK_SOCKS4_REQUEST;

typedef struct _NTSOCK_SOCKS4_ANSWER {
	BYTE Reserved1;
	BYTE AnswerCode;
	USHORT Reserved2;
	ULONG Reserved3;
} NTSOCK_SOCKS4_ANSWER, *PNTSOCK_SOCKS4_ANSWER;

typedef struct _NTSOCK_SOCKS5_AUTH_REQUEST {
	BYTE Version;
	BYTE AuthTypesLength;
	BYTE AuthTypes[1];
} NTSOCK_SOCKS5_AUTH_REQUEST, *PNTSOCK_SOCKS5_AUTH_REQUEST;

typedef struct _NTSOCK_SOCKS5_AUTH_ANSWER {
	BYTE Version;
	BYTE AuthType;
} NTSOCK_SOCKS5_AUTH_ANSWER, *PNTSOCK_SOCKS5_AUTH_ANSWER;

typedef struct _NTSOCK_SOCKS5_AUTH_UP_LOGIN {
	BYTE Version;
	union {
		struct {
			BYTE UserLength;
			char Username[NTSOCKS_MAX_STR_LEN];
			BYTE PassLength;
			char Password[NTSOCKS_MAX_STR_LEN];
		};
		BYTE Data[2*(NTSOCKS_MAX_STR_LEN+1)];
	};
} NTSOCK_SOCKS5_AUTH_UP_LOGIN, *PNTSOCK_SOCKS5_AUTH_UP_LOGIN;

typedef struct _NTSOCK_SOCKS5_AUTH_UP_ANSWER {
	BYTE Version;
	BYTE Status;
} NTSOCK_SOCKS5_AUTH_UP_ANSWER, *PNTSOCK_SOCKS5_AUTH_UP_ANSWER;

typedef struct _NTSOCK_SOCKS5_REQUEST {
	BYTE Version;
	BYTE Command;
	BYTE Reserved;
	BYTE AddrType;
	union {
		struct {
			struct in_addr IpAddr;
			USHORT IpPort;
		};
		struct {
			BYTE DnsLength;
			BYTE Dns[NTSOCKS_MAX_STR_LEN];
			USHORT DnsPort;
		};
		struct {
			struct in6_addr Ip6Addr;
			USHORT Ip6Port;
		};
	};
} NTSOCK_SOCKS5_REQUEST, *PNTSOCK_SOCKS5_REQUEST;

typedef struct _NTSOCK_SOCKS5_ANSWER {
	BYTE Version;
	BYTE AnswerCode;
	BYTE Reserved;
	BYTE AddrType;
	union {
		struct {
			struct in_addr IpAddr;
			USHORT IpPort;
		};
		struct {
			BYTE DnsLength;
			BYTE Dns[NTSOCKS_MAX_STR_LEN];
			USHORT DnsPort;
		};
		struct {
			struct in6_addr Ip6Addr;
			USHORT Ip6Port;
		};
	};
} NTSOCK_SOCKS5_ANSWER, *PNTSOCK_SOCKS5_ANSWER;
#pragma pack(pop)

int NtSocks4ClientByTcpSocket(SOCKET sock, struct in_addr *ip, u_short port, u_short reqcommand, void *userid, u_int useridlen, const TIMEVAL *timeout);
SOCKET NtSocks4Client(struct sockaddr *socks4addr, int socks4addrlen, struct in_addr *ip, u_short port, u_short reqcommand, void *userid, u_int useridlen, const TIMEVAL *timeout);
SOCKET NtSimpleSocks4Client(struct sockaddr *socks4addr, int socks4addrlen, struct in_addr *ip, u_short port);
int NtSocks5ClientByTcpSocket(SOCKET sock, u_int addrtype, void *addr, int addrlen, u_short port, u_short reqcommand, char *username, char *password, const TIMEVAL *timeout);
SOCKET NtSocks5Client(struct sockaddr *socks5addr, int socks5addrlen, u_int addrtype, void *addr, int addrlen, u_short port, u_short reqcommand, char *username, char *password, const TIMEVAL *timeout);
SOCKET NtSimpleSocks5Client(struct sockaddr *socks5addr, int socks5addrlen, u_int addrtype, void *addr, int addrlen, u_short port);

#endif
