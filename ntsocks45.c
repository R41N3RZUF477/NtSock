#include "ntsock.h"
#include "ntsockinternal.h"

#include "ntsocks45.h"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

int NtSocks4ClientByTcpSocket(SOCKET sock, struct in_addr *ip, u_short port, u_short reqcommand, void *userid, u_int useridlen, const TIMEVAL *timeout)
{
	int sockerr = SOCKET_ERROR;
	NTSOCK_SOCKS4_REQUEST s4r;
	int reqlen;
	NTSOCK_SOCKS4_ANSWER s4a;
	fd_set fd;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckPointerParameter(ip))
	{
		return SOCKET_ERROR;
	}
	if(reqcommand > SOCKS4_REQUEST_TCPBIND)
	{
		return SOCKET_ERROR;
	}

	reqlen = 9;
	s4r.Version = SOCKS4_VERSION;
	s4r.Command = reqcommand;
	s4r.Port = NtHtons(port);
	s4r.Ip.s_addr = ip->s_addr;
	s4r.End = 0;
	if(userid)
	{
		if(useridlen > NTSOCKS_MAX_STR_LEN)
		{
			useridlen = NTSOCKS_MAX_STR_LEN;
		}
		memcpy(&s4r.Auth[0], userid, useridlen);
		s4r.Auth[useridlen] = 0;
		reqlen += useridlen;
	}
	sockerr = NtSend(sock, &s4r, reqlen, 0);
	if(sockerr != SOCKET_ERROR)
	{
		NtFDZero(&fd);
		NtFDSet(sock, &fd);
		sockerr = NtSelect(0, &fd, NULL, NULL, timeout);
		if(sockerr != SOCKET_ERROR)
		{
			if(NtFDIsSet(sock, &fd))
			{
				memset(&s4a, 0, sizeof(NTSOCK_SOCKS4_ANSWER));
				sockerr = NtRecv(sock, &s4a, sizeof(NTSOCK_SOCKS4_ANSWER), 0);
				if(sockerr != SOCKET_ERROR)
				{
					sockerr = SOCKET_ERROR;
					if((s4a.Reserved1 == 0) && (s4a.AnswerCode == SOCKS4_ANSWER_OK))
					{
						sockerr = 0;
					}
				}
			}
		}
	}

	return sockerr;
}

SOCKET NtSocks4Client(struct sockaddr *socks4addr, int socks4addrlen, struct in_addr *ip, u_short port, u_short reqcommand, void *userid, u_int useridlen, const TIMEVAL *timeout)
{
	SOCKET sock = INVALID_SOCKET;
	int sockerr;

	if(CheckSockAddrParameter(socks4addr, socks4addrlen, 0))
	{
		return INVALID_SOCKET;
	}
	if(CheckPointerParameter(ip))
	{
		return INVALID_SOCKET;
	}
	if(reqcommand > SOCKS4_REQUEST_TCPBIND)
	{
		return SOCKET_ERROR;
	}

	sock = NtSocket(socks4addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if(sock != INVALID_SOCKET)
	{
		sockerr = NtConnect(sock, socks4addr, socks4addrlen);
		if(sockerr != SOCKET_ERROR)
		{
			sockerr = NtSocks4ClientByTcpSocket(sock, ip, port, reqcommand, userid, useridlen, timeout);
			if(sockerr != SOCKET_ERROR)
			{
				return sock;
			}
			NtShutdown(sock, SD_BOTH);
		}
		NtCloseSocket(sock);
	}

	return INVALID_SOCKET;
}

SOCKET NtSimpleSocks4Client(struct sockaddr *socks4addr, int socks4addrlen, struct in_addr *ip, u_short port)
{
	TIMEVAL timeout;

	if(CheckSockAddrParameter(socks4addr, socks4addrlen, 0))
	{
		return INVALID_SOCKET;
	}
	if(CheckPointerParameter(ip))
	{
		return INVALID_SOCKET;
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = NTSOCKS_DEFTIMEOUT;

	return NtSocks4Client(socks4addr, socks4addrlen, ip, port, SOCKS4_REQUEST_TCP, NULL, 0, &timeout);
}

int NtSocks5ClientByTcpSocket(SOCKET sock, u_int addrtype, void *addr, int addrlen, u_short port, u_short reqcommand, char *username, char *password, const TIMEVAL *timeout)
{
	int sockerr = SOCKET_ERROR;
	fd_set fd;
	BYTE AuthStartMsg[4];
	PNTSOCK_SOCKS5_AUTH_REQUEST s5ar;
	NTSOCK_SOCKS5_AUTH_ANSWER s5aa;
	NTSOCK_SOCKS5_AUTH_UP_LOGIN s5aupl;
	int userlen, passlen;
	NTSOCK_SOCKS5_AUTH_UP_ANSWER s5aupa;
	NTSOCK_SOCKS5_REQUEST s5r;
	int s5rlen;
	NTSOCK_SOCKS5_ANSWER s5a;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	switch(addrtype)
	{
		case SOCKS5_REQUEST_TYPE_IP:
			if(CheckArrayParameter(addr, addrlen, sizeof(struct in_addr)))
			{
				return SOCKET_ERROR;
			}
			addrlen = sizeof(struct in_addr);
			break;
		case SOCKS5_REQUEST_TYPE_DNS:
			if(CheckArrayParameter(addr, addrlen, 1))
			{
				return SOCKET_ERROR;
			}
			if(addrlen > NTSOCKS_MAX_STR_LEN)
			{
				addrlen = NTSOCKS_MAX_STR_LEN;
			}
			break;
		case SOCKS5_REQUEST_TYPE_IP6:
			if(CheckArrayParameter(addr, addrlen, sizeof(struct in6_addr)))
			{
				return SOCKET_ERROR;
			}
			addrlen = sizeof(struct in6_addr);
			break;
		default:
			return SOCKET_ERROR;
	}
	if(reqcommand > SOCKS5_REQUEST_UDP)
	{
		return SOCKET_ERROR;
	}

	s5ar = (PNTSOCK_SOCKS5_AUTH_REQUEST)&AuthStartMsg[0];
	s5ar->Version = SOCKS5_VERSION;
	s5ar->AuthTypesLength = 1;
	s5ar->AuthTypes[0] = SOCKS5_AUTH_NOAUTH;
	if(username && password)
	{
		s5ar->AuthTypes[s5ar->AuthTypesLength++] = SOCKS5_AUTH_USERPASS;
	}
	sockerr = NtSend(sock, s5ar, sizeof(NTSOCK_SOCKS5_AUTH_REQUEST)-1+s5ar->AuthTypesLength, 0);
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
				s5aa.Version = 0;
				s5aa.AuthType = 0;
				sockerr = NtRecv(sock, &s5aa, sizeof(NTSOCK_SOCKS5_AUTH_ANSWER), 0);
				if((sockerr != SOCKET_ERROR) && (s5aa.Version == SOCKS5_VERSION))
				{
					if(s5aa.AuthType == SOCKS5_AUTH_USERPASS)
					{
						if(!(username && password))
						{
							return SOCKET_ERROR;
						}
						memset(&s5aupl, 0, sizeof(NTSOCK_SOCKS5_AUTH_UP_LOGIN));
						s5aupl.Version = SOCKS5_AUTH_UP_VERSION;
						userlen = strlen(username);
						if(userlen > NTSOCKS_MAX_STR_LEN)
						{
							userlen = NTSOCKS_MAX_STR_LEN;
						}
						passlen = strlen(password);
						if(passlen > NTSOCKS_MAX_STR_LEN)
						{
							passlen = NTSOCKS_MAX_STR_LEN;
						}
						s5aupl.UserLength = userlen;
						memcpy(&s5aupl.Username[0], &username[0], userlen);
						s5aupl.Data[userlen+1] = passlen;
						memcpy(&s5aupl.Data[userlen+2], &password[0], passlen);
						sockerr = NtSend(sock, &s5aupl, 3+userlen+passlen, 0);
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
									s5aupa.Version = 0;
									s5aupa.Status = 0xFF;
									sockerr = NtRecv(sock, &s5aupa, sizeof(NTSOCK_SOCKS5_AUTH_UP_ANSWER), 0);
									if(sockerr != SOCKET_ERROR)
									{
										sockerr = SOCKET_ERROR;
										if((s5aupa.Version == SOCKS5_AUTH_UP_VERSION) && (s5aupa.Status == 0))
										{
											sockerr = 0;
										}
									}
								}
							}
						}
					}
					else if(s5aa.AuthType == SOCKS5_AUTH_NOAUTH)
					{
						sockerr = 0;
					}
					else
					{
						sockerr = SOCKET_ERROR;
					}
					if(sockerr != SOCKET_ERROR)
					{
						s5rlen = 6 + addrlen;
						s5r.Version = SOCKS5_VERSION;
						s5r.Command = reqcommand;
						s5r.Reserved = 0;
						s5r.AddrType = addrtype;
						port = NtHtons(port);
						switch(addrtype)
						{
							case SOCKS5_REQUEST_TYPE_IP:
								memcpy(&s5r.IpAddr, addr, addrlen);
								s5r.IpPort = port;
								break;
							case SOCKS5_REQUEST_TYPE_IP6:
								memcpy(&s5r.Ip6Addr, addr, addrlen);
								s5r.Ip6Port = port;
								break;
							case SOCKS5_REQUEST_TYPE_DNS:
								s5r.DnsLength = addrlen;
								memcpy(&s5r.Dns[0], addr, addrlen);
								*(u_short*)&s5r.Dns[addrlen] = port;
								s5rlen++;
								break;
							default:
								return SOCKET_ERROR;
						}
						sockerr = NtSend(sock, &s5r, s5rlen, 0);
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
									memset(&s5a, 0, sizeof(NTSOCK_SOCKS5_ANSWER));
									sockerr = NtRecv(sock, &s5a, sizeof(NTSOCK_SOCKS5_ANSWER), 0);
									if((sockerr != SOCKET_ERROR) && (s5a.Version == SOCKS5_VERSION) && (s5a.Reserved == 0) && (s5a.AnswerCode == SOCKS5_ANSWER_OK))
									{
										return 0;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return sockerr;
}

SOCKET NtSocks5Client(struct sockaddr *socks5addr, int socks5addrlen, u_int addrtype, void *addr, int addrlen, u_short port, u_short reqcommand, char *username, char *password, const TIMEVAL *timeout)
{
	SOCKET sock = INVALID_SOCKET;
	int sockerr;

	if(CheckSockAddrParameter(socks5addr, socks5addrlen, 0))
	{
		return INVALID_SOCKET;
	}
	switch(addrtype)
	{
		case SOCKS5_REQUEST_TYPE_IP:
			if(CheckArrayParameter(addr, addrlen, sizeof(struct in_addr)))
			{
				return SOCKET_ERROR;
			}
			addrlen = sizeof(struct in_addr);
			break;
		case SOCKS5_REQUEST_TYPE_DNS:
			if(CheckArrayParameter(addr, addrlen, 1))
			{
				return SOCKET_ERROR;
			}
			if(addrlen > NTSOCKS_MAX_STR_LEN)
			{
				addrlen = NTSOCKS_MAX_STR_LEN;
			}
			break;
		case SOCKS5_REQUEST_TYPE_IP6:
			if(CheckArrayParameter(addr, addrlen, sizeof(struct in6_addr)))
			{
				return SOCKET_ERROR;
			}
			addrlen = sizeof(struct in6_addr);
			break;
		default:
			return SOCKET_ERROR;
	}
	if(reqcommand > SOCKS5_REQUEST_UDP)
	{
		return SOCKET_ERROR;
	}

	sock = NtSocket(socks5addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if(sock != INVALID_SOCKET)
	{
		sockerr = NtConnect(sock, socks5addr, socks5addrlen);
		if(sockerr != SOCKET_ERROR)
		{
			sockerr = NtSocks5ClientByTcpSocket(sock, addrtype, addr, addrlen, port, reqcommand, username, password, timeout);
			if(sockerr != SOCKET_ERROR)
			{
				return sock;
			}
			NtShutdown(sock, SD_BOTH);
		}
		NtCloseSocket(sock);
	}

	return INVALID_SOCKET;
}

SOCKET NtSimpleSocks5Client(struct sockaddr *socks5addr, int socks5addrlen, u_int addrtype, void *addr, int addrlen, u_short port)
{
	TIMEVAL timeout;

	if(CheckSockAddrParameter(socks5addr, socks5addrlen, 0))
	{
		return INVALID_SOCKET;
	}
	switch(addrtype)
	{
		case SOCKS5_REQUEST_TYPE_IP:
			if(CheckArrayParameter(addr, addrlen, sizeof(struct in_addr)))
			{
				return SOCKET_ERROR;
			}
			addrlen = sizeof(struct in_addr);
			break;
		case SOCKS5_REQUEST_TYPE_DNS:
			if(CheckArrayParameter(addr, addrlen, 1))
			{
				return SOCKET_ERROR;
			}
			if(addrlen > NTSOCKS_MAX_STR_LEN)
			{
				addrlen = NTSOCKS_MAX_STR_LEN;
			}
			break;
		case SOCKS5_REQUEST_TYPE_IP6:
			if(CheckArrayParameter(addr, addrlen, sizeof(struct in6_addr)))
			{
				return SOCKET_ERROR;
			}
			addrlen = sizeof(struct in6_addr);
			break;
		default:
			return SOCKET_ERROR;
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = NTSOCKS_DEFTIMEOUT;

	return NtSocks5Client(socks5addr, socks5addrlen, addrtype, addr, addrlen, port, SOCKS5_REQUEST_TCP, NULL, NULL, &timeout);
}

#ifdef __cplusplus
}
#endif
