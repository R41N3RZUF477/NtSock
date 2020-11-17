#include "ntsock.h"
#include "ntsockinternal.h"

#include "ntsockdns.h"

#include <string.h>

#define MAX_DNS_BUF 512
#define MAX_EDNS_BUF 2048

#ifdef __cplusplus
extern "C" {
#endif

int CheckDnsAnswerHeader(PNTSOCK_DNS_HEADER dnsheader, USHORT id)
{
	if(!dnsheader)
	{
		return 0;
	}
	if(dnsheader->Identification != id)
	{
		return 0;
	}
	if(dnsheader->Control & NtHtons(DNS_CONTROL_RC))
	{
		return 0;
	}
	if(dnsheader->QuestionCount != NtHtons(1))
	{
		return 0;
	}
	if(!dnsheader->AnswerCount)
	{
		return 0;
	}
	return 1;
}

int ConvertStringToDnsString(char *str)
{
	char *pstr, *pdot;

	if(!str)
	{
		return -1;
	}
	if(str[1] == '\0')
	{
		return -1;
	}
	str[0] = '.';
	for(pstr = str+1, pdot = str; pstr[-1]; ++pstr)
	{
		if((*pstr == '.') || (*pstr == '\0'))
		{
			*pdot = (char)(pstr - (pdot + 1));
			pdot = pstr;
		}
	}
	return (int)(pstr-str);
}

int CmpDnsString(PNTSOCK_DNS_HEADER dnsheader, const char *dnsstr1, const char *dnsstr2)
{
	char *dnsarray = (char*)dnsheader;
	USHORT dnsstrp;
	char *cmpstr1, *cmpstr2;
	int len1, len2;

	if(!dnsheader)
	{
		return -1;
	}
	if(!dnsstr1)
	{
		return -1;
	}
	if(!dnsstr2)
	{
		return 1;
	}
	if(*dnsstr1 & 0xC0)
	{
		dnsstrp = NtHtons(*(u_short*)dnsstr1) & 0x3FFF;
		if(dnsstrp > (MAX_DNS_BUF-2))
		{
			return -1;
		}
		cmpstr1 = &dnsarray[dnsstrp];
	}
	else
	{
		cmpstr1 = (char*)dnsstr1;
	}
	if(*dnsstr2 & 0xC0)
	{
		dnsstrp = NtHtons(*(u_short*)dnsstr2) & 0x3FFF;
		if(dnsstrp > (MAX_DNS_BUF-2))
		{
			return 1;
		}
		cmpstr2 = &dnsarray[dnsstrp];
	}
	else
	{
		cmpstr2 = (char*)dnsstr2;
	}
	if(cmpstr1 == cmpstr2)
	{
		return 0;
	}
	len1 = (int)strlen(cmpstr1);
	len2 = (int)strlen(cmpstr2);
	if(len1 > 256)
	{
		return -1;
	}
	if(len2 > 256)
	{
		return 1;
	}
	if(len1 < len2)
	{
		return -1;
	}
	if(len2 < len1)
	{
		return 1;
	}
	return memcmp(cmpstr1, cmpstr2, len1);
}

int InitDnsHeader(PNTSOCK_DNS_HEADER dnsh, int buflen, u_short af, const char *dns, USHORT id, PNTSOCK_DNS_ANSWER *dnsresp)
{
	PNTSOCK_DNS_ANSWER dnsr;
	BYTE *buffer;
	int slen, mlen;

	if(CheckArrayParameter(dnsh, buflen, sizeof(NTSOCK_DNS_HEADER)))
	{
		return 0;
	}
	if(CheckPointerParameter(dns))
	{
		return 0;
	}
	if(CheckPointerParameter(dnsresp))
	{
		return 0;
	}
	buffer = (BYTE*)dnsh;
	*(ULONG*)&buffer[buflen-sizeof(ULONG)] = 0;
	slen = (int)strlen(dns);
	if(slen > 255)
	{
		return 0;
	}
	mlen = sizeof(NTSOCK_DNS_HEADER)+slen+(2*sizeof(USHORT))+2;
	dnsh->Identification = id;
	dnsh->Control = NtHtons(DNS_CONTROL_RD|DNS_CONTROL_RQ);
	dnsh->QuestionCount = NtHtons(1);
	dnsh->AnswerCount = 0;
	dnsh->AuthorityCount = 0;
	dnsh->AdditionalCount = 0;
	memcpy(&buffer[sizeof(NTSOCK_DNS_HEADER)+1], dns, slen+1);
	if(ConvertStringToDnsString((char*)&buffer[sizeof(NTSOCK_DNS_HEADER)]) == SOCKET_ERROR)
	{
		return 0;
	}
	dnsr = (PNTSOCK_DNS_ANSWER)&buffer[sizeof(NTSOCK_DNS_HEADER)+slen+2];
	dnsr->Type = NtHtons((af == AF_INET6 ? DNS_ANSWER_TYPE_IPV6 : DNS_ANSWER_TYPE_IP));
	dnsr->Class = NtHtons(DNS_ANSWER_CLASS_INET);
	*dnsresp = dnsr;
	return mlen;
}

int ParseDnsAnswer(PNTSOCK_DNS_HEADER dnsh, int alen, u_short af, void *ipaddresses, int addrlen, int mlen, PNTSOCK_DNS_ANSWER dnsr, USHORT id)
{
	char *buffer = (char*)dnsh;
	USHORT numanswers;
	int numentry = 0;
	int anslen = 0;
	char *ansstr;
	PNTSOCK_DNS_ANSWER dnsa;

	if(CheckPointerParameter(dnsh))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(ipaddresses, addrlen, sizeof(struct in_addr)))
	{
		return SOCKET_ERROR;
	}
	if(CheckPointerParameter(dnsr))
	{
		return SOCKET_ERROR;
	}
	if(CheckDnsAnswerHeader(dnsh, id))
	{
		numanswers = NtHtons(dnsh->AnswerCount);
		for(; (mlen < alen) && (numanswers > 0); mlen += sizeof(NTSOCK_DNS_ANSWER), --numanswers)
		{
			ansstr = &buffer[mlen];
			if(buffer[mlen] & 0xC0)
			{
				mlen += sizeof(USHORT);
			}
			else
			{
				mlen += (int)(strlen(ansstr) + 1);
			}
			dnsa = (PNTSOCK_DNS_ANSWER)&buffer[mlen];
			if(!CmpDnsString(dnsh, (char*)&buffer[sizeof(NTSOCK_DNS_HEADER)], ansstr))
			{
				if((dnsr->Type == dnsa->Type) && (dnsr->Class == dnsa->Class))
				{
					if((af == AF_INET) && (NtHtons(dnsr->DataLength >= sizeof(struct in_addr))))
					{
						if((anslen + sizeof(struct in_addr)) <= (unsigned int)addrlen)
						{
							memcpy(&((BYTE*)ipaddresses)[anslen], &buffer[mlen+sizeof(NTSOCK_DNS_ANSWER)], sizeof(struct in_addr));
							anslen += sizeof(struct in_addr);
							++numentry;
						}
					}
					else if((af == AF_INET6) && (NtHtons(dnsr->DataLength >= sizeof(struct in6_addr))))
					{
						if((anslen + sizeof(struct in6_addr)) <= (unsigned int)addrlen)
						{
							memcpy(&((BYTE*)ipaddresses)[anslen], &buffer[mlen+sizeof(NTSOCK_DNS_ANSWER)], sizeof(struct in6_addr));
							anslen += sizeof(struct in6_addr);
							++numentry;
						}
					}
				}
			}
			mlen += NtHtons(dnsa->DataLength);
		}
		return numentry;
	}
	return SOCKET_ERROR;
}

int NtDnsClientByUdpSocket(const char *dns, u_short af, void *ipaddresses, int addrlen, SOCKET sock, const struct sockaddr *dnsserver, int dnssrvlen, const TIMEVAL *timeout)
{
	fd_set fd;
	int mlen, alen = 0, sockerr, recvaddrlen;
	BYTE buffer[MAX_DNS_BUF+sizeof(ULONG)];
	PNTSOCK_DNS_HEADER dnsh;
	ULONG id_calc;
	USHORT id;
	PNTSOCK_DNS_ANSWER dnsr;
	SOCKADDR_IN6 recvaddr;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckPointerParameter(dns))
	{
		return SOCKET_ERROR;
	}
	if((af != AF_INET) && (af != AF_INET6))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(ipaddresses, addrlen, (af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr))))
	{
		return SOCKET_ERROR;
	}
	if(CheckSockAddrParameter(dnsserver, dnssrvlen, 0))
	{
		return SOCKET_ERROR;
	}

	id_calc = (ULONG)(af*(ULONG_PTR)dns*(ULONG_PTR)ipaddresses*(ULONG_PTR)dnsserver);
	id = (USHORT)(((id_calc & 0xFFFF0000) >> 16) + (id_calc & 0xFFFF));
	dnsh = (PNTSOCK_DNS_HEADER)&buffer[0];
	mlen = InitDnsHeader(dnsh, MAX_DNS_BUF+sizeof(ULONG), af, dns, id, &dnsr);
	if(!mlen)
	{
		return SOCKET_ERROR;
	}
	sockerr = NtSendTo(sock, dnsh, mlen, 0, dnsserver, dnssrvlen);
	if(sockerr != SOCKET_ERROR)
	{
		NtFDZero(&fd);
		NtFDSet(sock, &fd);
		sockerr = NtSelect(0, &fd, NULL, NULL, timeout);
		if(sockerr != SOCKET_ERROR)
		{
			sockerr = SOCKET_ERROR;
			if(NtFDIsSet(sock, &fd))
			{
				recvaddrlen = sizeof(SOCKADDR_IN6);
				memcpy(&recvaddr, &dnsserver, dnssrvlen);
				sockerr = NtRecvFrom(sock, dnsh, MAX_DNS_BUF, 0, (struct sockaddr*)&recvaddr, &recvaddrlen);
				if(sockerr != SOCKET_ERROR)
				{
					if((dnssrvlen == recvaddrlen) && (dnsserver->sa_family == recvaddr.sin6_family))
					{
						if(dnsserver->sa_family == AF_INET)
						{
							if((recvaddr.sin6_port == *(USHORT*)&dnsserver->sa_data[0]) && (recvaddr.sin6_flowinfo == *(ULONG*)&dnsserver->sa_data[sizeof(USHORT)]))
							{
								alen = sockerr;
							}
						}
						else if(dnsserver->sa_family == AF_INET6)
						{
							if((recvaddr.sin6_port == *(USHORT*)&dnsserver->sa_data[0]) && (!memcmp(&dnsserver->sa_data[sizeof(USHORT)+sizeof(ULONG)], &recvaddr.sin6_addr, sizeof(IN6_ADDR))))
							{
								alen = sockerr;
							}
						}
					}
				}
			}
		}
	}
	if(sockerr == SOCKET_ERROR)
	{
		return SOCKET_ERROR;
	}
	return ParseDnsAnswer(dnsh, alen, af, ipaddresses, addrlen, mlen, dnsr, id);
}

int NtDnsClientByTcpSocket(const char *dns, u_short af, void *ipaddresses, int addrlen, SOCKET sock, const TIMEVAL *timeout)
{
	fd_set fd;
	int mlen, alen, sockerr;
	BYTE buffer[MAX_DNS_BUF+sizeof(ULONG)];
	PNTSOCK_DNS_HEADER dnsh;
	ULONG id_calc;
	USHORT id;
	PNTSOCK_DNS_ANSWER dnsr;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckPointerParameter(dns))
	{
		return SOCKET_ERROR;
	}
	if((af != AF_INET) && (af != AF_INET6))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(ipaddresses, addrlen, (af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr))))
	{
		return SOCKET_ERROR;
	}

	id_calc = (ULONG)(af*(ULONG_PTR)dns*(ULONG_PTR)ipaddresses*(ULONG_PTR)sock);
	id = (USHORT)(((id_calc & 0xFFFF0000) >> 16) + (id_calc & 0xFFFF));
	dnsh = (PNTSOCK_DNS_HEADER)&buffer[0];
	mlen = InitDnsHeader(dnsh, MAX_DNS_BUF+sizeof(ULONG), af, dns, id, &dnsr);
	if(!mlen)
	{
		return SOCKET_ERROR;
	}
	sockerr = NtSend(sock, dnsh, mlen, 0);
	if(sockerr != SOCKET_ERROR)
	{
		NtFDZero(&fd);
		NtFDSet(sock, &fd);
		sockerr = NtSelect(0, &fd, NULL, NULL, timeout);
		if(sockerr != SOCKET_ERROR)
		{
			sockerr = SOCKET_ERROR;
			if(NtFDIsSet(sock, &fd))
			{
				sockerr = NtRecv(sock, dnsh, MAX_DNS_BUF, 0);
				if(sockerr != SOCKET_ERROR)
				{
					alen = sockerr;
				}
			}
		}
	}
	if(sockerr == SOCKET_ERROR)
	{
		return SOCKET_ERROR;
	}
	return ParseDnsAnswer(dnsh, alen, af, ipaddresses, addrlen, mlen, dnsr, id);
}

int NtDnsClient(const char *dns, u_short af, void *ipaddresses, int addrlen, const struct sockaddr *dnsserver, int dnssrvlen, const TIMEVAL *timeout, int flags)
{
	SOCKET sock;
	fd_set fd;
	int mlen, alen = 0, sockerr;
	BYTE buffer[MAX_DNS_BUF+sizeof(ULONG)];
	PNTSOCK_DNS_HEADER dnsh;
	ULONG id_calc;
	USHORT id;
	PNTSOCK_DNS_ANSWER dnsr;

	if(CheckPointerParameter(dns))
	{
		return SOCKET_ERROR;
	}
	if((af != AF_INET) && (af != AF_INET6))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(ipaddresses, addrlen, (af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr))))
	{
		return SOCKET_ERROR;
	}
	if(CheckSockAddrParameter(dnsserver, dnssrvlen, 0))
	{
		return SOCKET_ERROR;
	}
	if((flags & NTSOCK_DNS_NOUDP) && (!(flags & NTSOCK_DNS_TCP)))
	{
		return SOCKET_ERROR;
	}
	if((flags & NTSOCK_DNS_PREFER_TCP) && (!(flags & NTSOCK_DNS_TCP)))
	{
		return SOCKET_ERROR;
	}

	id_calc = (ULONG)(af*(ULONG_PTR)dns*(ULONG_PTR)ipaddresses*(ULONG_PTR)dnsserver);
	id = (USHORT)(((id_calc & 0xFFFF0000) >> 16) + (id_calc & 0xFFFF));
	dnsh = (PNTSOCK_DNS_HEADER)&buffer[0];
	mlen = InitDnsHeader(dnsh, MAX_DNS_BUF+sizeof(ULONG), af, dns, id, &dnsr);
	if(!mlen)
	{
		return SOCKET_ERROR;
	}
	if((flags & NTSOCK_DNS_PREFER_TCP) || (flags & NTSOCK_DNS_NOUDP))
	{
		sock = NtSocket(dnsserver->sa_family, SOCK_STREAM, IPPROTO_TCP);
	}
	else
	{
		sock = NtSocket(dnsserver->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	}
	if(sock != INVALID_SOCKET)
	{
		sockerr = NtConnect(sock, dnsserver, dnssrvlen);
		if(sockerr != SOCKET_ERROR)
		{
			sockerr = NtSend(sock, dnsh, mlen, 0);
			if(sockerr != SOCKET_ERROR)
			{
				NtFDZero(&fd);
				NtFDSet(sock, &fd);
				sockerr = NtSelect(0, &fd, NULL, NULL, timeout);
				if(sockerr != SOCKET_ERROR)
				{
					sockerr = SOCKET_ERROR;
					if(NtFDIsSet(sock, &fd))
					{
						sockerr = NtRecv(sock, dnsh, MAX_DNS_BUF, 0);
						if(sockerr != SOCKET_ERROR)
						{
							alen = sockerr;
						}
					}
				}
			}
			NtShutdown(sock, SD_BOTH);
		}
		NtCloseSocket(sock);
	}
	else
	{
		sockerr = SOCKET_ERROR;
	}
	if((sockerr == SOCKET_ERROR) && (flags & NTSOCK_DNS_TCP) && (!(flags & NTSOCK_DNS_NOUDP)))
	{
		if(flags & NTSOCK_DNS_PREFER_TCP)
		{
			sock = NtSocket(dnsserver->sa_family, SOCK_DGRAM, IPPROTO_UDP);
		}
		else
		{
			sock = NtSocket(dnsserver->sa_family, SOCK_STREAM, IPPROTO_TCP);
		}
		if(sock != INVALID_SOCKET)
		{
			sockerr = NtConnect(sock, dnsserver, dnssrvlen);
			if(sockerr != SOCKET_ERROR)
			{
				sockerr = NtSend(sock, dnsh, mlen, 0);
				if(sockerr != SOCKET_ERROR)
				{
					NtFDZero(&fd);
					NtFDSet(sock, &fd);
					sockerr = NtSelect(0, &fd, NULL, NULL, timeout);
					if(sockerr != SOCKET_ERROR)
					{
						sockerr = NtRecv(sock, dnsh, MAX_DNS_BUF, 0);
						if(sockerr != SOCKET_ERROR)
						{
							sockerr = SOCKET_ERROR;
							if(NtFDIsSet(sock, &fd))
							{
								alen = sockerr;
							}
							else
							{
								sockerr = SOCKET_ERROR;
							}
						}
					}
				}
				NtShutdown(sock, SD_BOTH);
			}
			NtCloseSocket(sock);
		}
		else
		{
			sockerr = SOCKET_ERROR;
		}
	}
	if(sockerr == SOCKET_ERROR)
	{
		return SOCKET_ERROR;
	}
	return ParseDnsAnswer(dnsh, alen, af, ipaddresses, addrlen, mlen, dnsr, id);
}

int NtSimpleDnsClient(const char *dns, struct sockaddr *addr, int addrlen, const struct sockaddr *dnsserver, int dnssrvlen, int flags)
{
	int numips;
	BYTE *sin_addr;
	int sin_addrlen;
	TIMEVAL timeout;

	if(CheckPointerParameter(dns))
	{
		return SOCKET_ERROR;
	}
	if(CheckSockAddrParameter(addr, addrlen, SOCKADDR_NO_PORT_OK))
	{
		return SOCKET_ERROR;
	}
	if(CheckSockAddrParameter(dnsserver, dnssrvlen, 0))
	{
		return SOCKET_ERROR;
	}
	if(addr->sa_family == AF_INET)
	{
		sin_addr = (BYTE*)&(((struct sockaddr_in*)addr)->sin_addr);
		sin_addrlen = sizeof(struct in_addr);
	}
	else if(addr->sa_family == AF_INET6)
	{
		sin_addr = (BYTE*)&(((struct sockaddr_in6*)addr)->sin6_addr);
		sin_addrlen = sizeof(struct in6_addr);
	}
	else
	{
		return SOCKET_ERROR;
	}
	timeout.tv_sec = 0;
	timeout.tv_usec = NTSOCK_DNS_DEFTIMEOUT;

	numips = NtDnsClient(dns, addr->sa_family, sin_addr, sin_addrlen, dnsserver, dnssrvlen, &timeout, flags);
	if(numips > 0)
	{
		return 0;
	}
	return SOCKET_ERROR;
}

#ifdef __cplusplus
}
#endif
