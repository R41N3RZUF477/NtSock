#include "ntsock.h"
#include "ntsockinternal.h"

#include "ntsockdns.h"

#include <stdio.h>
#include <string.h>

#define MAX_DNS_BUF 512
#define MAX_EDNS_BUF 2048

int CheckDnsAnswerHeader(PDNS_HEADER dnsheader, USHORT id)
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

int CmpDnsString(PDNS_HEADER dnsheader, const char *dnsstr1, const char *dnsstr2)
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
	len1 = strlen(cmpstr1);
	len2 = strlen(cmpstr2);
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

int NtDnsClient(const char *dns, u_short af, void *ipaddresses, int addrlen, const struct sockaddr *dnsserver, int dnssrvlen, const TIMEVAL *timeout, int flags)
{
	SOCKET sock;
	fd_set fd;
	int slen, mlen, alen, sockerr;
	BYTE buffer[MAX_DNS_BUF+sizeof(ULONG)];
	PDNS_HEADER dnsh;
	ULONG id_calc;
	USHORT id;
	PDNS_ANSWER dnsr, dnsa;
	USHORT numanswers;
	int anslen = 0;
	int numentry = 0;
	char *ansstr;

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
	*(ULONG*)&buffer[MAX_DNS_BUF] = 0;
	slen = strlen(dns);
	if(slen > 255)
	{
		return SOCKET_ERROR;
	}
	mlen = sizeof(DNS_HEADER)+slen+(2*sizeof(USHORT))+2;
	id_calc = (ULONG)(af*(ULONG_PTR)dns*(ULONG_PTR)ipaddresses*(ULONG_PTR)dnsserver);
	id = (USHORT)(((id_calc & 0xFFFF0000) >> 16) + (id_calc & 0xFFFF));
	dnsh = (PDNS_HEADER)&buffer[0];
	dnsh->Identification = id;
	dnsh->Control = NtHtons(DNS_CONTROL_RD|DNS_CONTROL_RQ);
	dnsh->QuestionCount = NtHtons(1);
	dnsh->AnswerCount = 0;
	dnsh->AuthorityCount = 0;
	dnsh->AdditionalCount = 0;
	memcpy(&buffer[sizeof(DNS_HEADER)+1], dns, slen+1);
	if(ConvertStringToDnsString((char*)&buffer[sizeof(DNS_HEADER)]) == SOCKET_ERROR)
	{
		return SOCKET_ERROR;
	}
	dnsr = (PDNS_ANSWER)&buffer[sizeof(DNS_HEADER)+slen+2];
	dnsr->Type = NtHtons((af == AF_INET6 ? DNS_ANSWER_TYPE_IPV6 : DNS_ANSWER_TYPE_IP));
	dnsr->Class = NtHtons(DNS_ANSWER_CLASS_INET);
	if((flags & NTSOCK_DNS_PREFER_TCP) || (flags & NTSOCK_DNS_NOUDP))
	{
		sock = NtSocket(af, SOCK_STREAM, IPPROTO_TCP);
	}
	else
	{
		sock = NtSocket(af, SOCK_DGRAM, IPPROTO_UDP);
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
					if(NtFDIsSet(sock, &fd))
					{
						sockerr = NtRecv(sock, dnsh, MAX_DNS_BUF, 0);
						if(sockerr != SOCKET_ERROR)
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
	if((sockerr == SOCKET_ERROR) && (flags & NTSOCK_DNS_TCP) && (!(flags & NTSOCK_DNS_NOUDP)))
	{
		if(flags & NTSOCK_DNS_PREFER_TCP)
		{
			sock = NtSocket(af, SOCK_DGRAM, IPPROTO_UDP);
		}
		else
		{
			sock = NtSocket(af, SOCK_STREAM, IPPROTO_TCP);
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
	if(CheckDnsAnswerHeader(dnsh, id))
	{
		numanswers = NtHtons(dnsh->AnswerCount);
		for(; (mlen < alen) && (numanswers > 0); mlen += sizeof(DNS_ANSWER), --numanswers)
		{
			ansstr = (char*)&buffer[mlen];
			if(buffer[mlen] & 0xC0)
			{
				mlen += sizeof(USHORT);
			}
			else
			{
				mlen += (strlen(ansstr) + 1);
			}
			dnsa = (PDNS_ANSWER)&buffer[mlen];
			if(!CmpDnsString(dnsh, (char*)&buffer[sizeof(DNS_HEADER)], ansstr))
			{
				if((dnsr->Type == dnsa->Type) && (dnsr->Class == dnsa->Class))
				{
					if((af == AF_INET) && (NtHtons(dnsr->DataLength >= sizeof(struct in_addr))))
					{
						if((anslen + sizeof(struct in_addr)) <= addrlen)
						{
							memcpy(&((BYTE*)ipaddresses)[anslen], &buffer[mlen+sizeof(DNS_ANSWER)], sizeof(struct in_addr));
							anslen += sizeof(struct in_addr);
							++numentry;
						}
					}
					if((af == AF_INET6) && (NtHtons(dnsr->DataLength >= sizeof(struct in6_addr))))
					{
						if((anslen + sizeof(struct in6_addr)) <= addrlen)
						{
							memcpy(&((BYTE*)ipaddresses)[anslen], &buffer[mlen+sizeof(DNS_ANSWER)], sizeof(struct in6_addr));
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
	timeout.tv_usec = 2000;

	numips = NtDnsClient(dns, addr->sa_family, sin_addr, sin_addrlen, dnsserver, dnssrvlen, &timeout, flags);
	if(numips > 0)
	{
		return 0;
	}
	return SOCKET_ERROR;
}
