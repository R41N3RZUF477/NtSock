#ifndef _NTSOCK_DNS_H_
#define _NTSOCK_DNS_H_



#define DNS_CONTROL_RQ 0x0000U
#define DNS_CONTROL_RS 0x8000U
#define DNS_CONTROL_O1 0x4000U
#define DNS_CONTROL_O2 0x2000U
#define DNS_CONTROL_O3 0x1000U
#define DNS_CONTROL_O4 0x0800U
#define DNS_CONTROL_AA 0x0400U
#define DNS_CONTROL_TC 0x0200U
#define DNS_CONTROL_RD 0x0100U
#define DNS_CONTROL_RA 0x0080U
#define DNS_CONTROL_Z  0x0040U
#define DNS_CONTROL_AD 0x0020U
#define DNS_CONTROL_CD 0x0010U
#define DNS_CONTROL_RC 0x000FU

#define DNS_ANSWER_TYPE_IP    0x0001U
#define DNS_ANSWER_TYPE_IPV6  0x001CU
#define DNS_ANSWER_CLASS_INET 0x0001U

#define NTSOCK_DNS_UDP        0x0
#define NTSOCK_DNS_TCP        0x1
#define NTSOCK_DNS_NOUDP      0x2
#define NTSOCK_DNS_PREFER_TCP 0x4

#pragma pack(push, 2)
typedef struct _DNS_HEADER {
	USHORT Identification;
	USHORT Control;
	USHORT QuestionCount;
	USHORT AnswerCount;
	USHORT AuthorityCount;
	USHORT AdditionalCount;
} DNS_HEADER, *PDNS_HEADER;

typedef struct _DNS_ANSWER {
	USHORT Type;
	USHORT Class;
	ULONG Ttl;
	USHORT DataLength;
} DNS_ANSWER, *PDNS_ANSWER;
#pragma pack(pop)

int NtDnsClient(const char *dns, u_short af, void *ipaddresses, int addrlen, const struct sockaddr *dnsserver, int dnssrvlen, const TIMEVAL *timeout, int flags);
int NtSimpleDnsClient(const char *dns, struct sockaddr *addr, int addrlen, const struct sockaddr *dnsserver, int dnssrvlen, int flags);

#endif
