#include "ntsock.h"
#include "ntsockinternal.h"

#ifdef __cplusplus
extern "C" {
#endif

void IncrementStringIntW(WCHAR *wstr, int len)
{
	int i, carry;

	for(i = len-1, carry = 1; (carry > 0) && (i > -1); --i)
	{
		if((wstr[i] < L'0') || (wstr[i] > L'9'))
		{
			wstr[i] = L'1';
			carry = 0;
		}
		else if(wstr[i] == L'9')
		{
			wstr[i] = L'0';
		}
		else
		{
			wstr[i]++;
			carry = 0;
		}
	}
}

NTSTATUS NtGetProtocolForSocket(int af, int type, int protocol, LPWSAPROTOCOL_INFOW protocolinfo)
{
	NTSTATUS status;
	BOOL suitable = FALSE;
	HANDLE key, subkey;
	WCHAR indexkey[13] = L"000000000000";
	UNICODE_STRING us, ussub;
	OBJECT_ATTRIBUTES oa;
	BYTE buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)+MAX_PATH+sizeof(WSAPROTOCOL_INFOW)];
	ULONG buffersize;
	PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)&buffer[0];
	LPWSAPROTOCOL_INFOW wsapi = (LPWSAPROTOCOL_INFOW)&kvpi->Data[MAX_PATH];

	if(!protocolinfo)
	{
		return STATUS_INVALID_PARAMETER;
	}
	us.Length = sizeof(REG_PROTOCOL_ENUM_STR) - sizeof(WCHAR);
	us.MaximumLength = sizeof(REG_PROTOCOL_ENUM_STR);
	us.Buffer = (PWSTR)REG_PROTOCOL_ENUM_STR;
	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = NULL;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.ObjectName = &us;
	status = NtOpenKey(&key, KEY_QUERY_VALUE, &oa);
	if(!status)
	{
		if(protocol == 0)
		{
			switch(type)
			{
				case SOCK_STREAM:
					protocol = IPPROTO_TCP;
					break;
				case SOCK_DGRAM:
					protocol = IPPROTO_UDP;
					break;
				case SOCK_RAW:
					protocol = IPPROTO_RAW;
					break;
				case SOCK_RDM:
					protocol = 113;
				case SOCK_SEQPACKET:
					protocol = IPPROTO_UDP;
				default:
					protocol = IPPROTO_TCP;
			}
		}
		ussub.Length = sizeof(REG_PROTOCOL_VALUE_STR) - sizeof(WCHAR);
		ussub.MaximumLength = sizeof(REG_PROTOCOL_VALUE_STR);
		ussub.Buffer = (PWSTR)REG_PROTOCOL_VALUE_STR;
		us.Length = 12 * sizeof(WCHAR);
		us.MaximumLength = 13 * sizeof(WCHAR);
		us.Buffer = indexkey;
		oa.RootDirectory = key;
		while(!status)
		{
			IncrementStringIntW(indexkey, 12);
			status = NtOpenKey(&subkey, KEY_QUERY_VALUE, &oa);
			if(!status)
			{
				status = NtQueryValueKey(subkey, &ussub, KeyValuePartialInformation, kvpi, sizeof(buffer), &buffersize);
				if(!status)
				{
					buffersize = kvpi->DataLength - MAX_PATH - (sizeof(WCHAR) * (WSAPROTOCOL_LEN+1));
					if(buffersize >= FIELD_OFFSET(WSAPROTOCOL_INFOW, szProtocol))
					{
						if(wsapi->ProtocolChain.ChainLen == 1)
						{
							if(wsapi->iAddressFamily == af)
							{
								if(wsapi->iSocketType == type)
								{
									if(wsapi->iProtocol == protocol)
									{
										memcpy(protocolinfo, &kvpi->Data[MAX_PATH], buffersize);
										NtClose(subkey);
										NtClose(key);
										return 0;
									}
									else if((wsapi->iProtocol == 0) && (!suitable))
									{
										suitable = TRUE;
										wsapi->iProtocol = protocol;
										memcpy(protocolinfo, &kvpi->Data[MAX_PATH], buffersize);
										return 0;
									}
								}
								else if((type == 0) && (wsapi->iSocketType == SOCK_RAW))
								{
									if((protocol == wsapi->iProtocol) || (wsapi->iProtocol == 0))
									{
										if(wsapi->iProtocol == 0)
										{
											wsapi->iProtocol = protocol;
										}
										switch(protocol)
										{
											case IPPROTO_IP:
											case IPPROTO_IPV4:
											case IPPROTO_IPV6:
												wsapi->iProtocol = IPPROTO_TCP;
											case IPPROTO_TCP:
												wsapi->iSocketType = SOCK_STREAM;
												break;
											case IPPROTO_ICMP:
											case IPPROTO_ICMPV6:
											case IPPROTO_RAW:
												wsapi->iSocketType = SOCK_RAW;
												break;
											case IPPROTO_UDP:
												wsapi->iSocketType = SOCK_DGRAM;
												break;
											default:
												wsapi->iSocketType = SOCK_DGRAM;
										}
										memcpy(protocolinfo, &kvpi->Data[MAX_PATH], buffersize);
										NtClose(subkey);
										NtClose(key);
										return 0;
									}
								}
							}
						}
					}
				}
				NtClose(subkey);
			}
		}
		NtClose(key);
	}
	if(suitable)
	{
		return 0;
	}
	return STATUS_NOT_FOUND;
}

NTSTATUS CheckPointerParameter(const void *p)
{
	NTSTATUS status = 0;

	if(!p)
	{
		status = STATUS_INVALID_PARAMETER;
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return status;
}

NTSTATUS CheckArrayParameter(const void *p, int len, int min)
{
	NTSTATUS status = 0;

	if((!p) || (len < min))
	{
		status = STATUS_INVALID_PARAMETER;
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return status;
}

NTSTATUS CheckSocketParameter(SOCKET sock)
{
	NTSTATUS status = 0;

	if(sock == INVALID_SOCKET)
	{
		status = STATUS_INVALID_HANDLE;
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return status;
}

NTSTATUS CheckSockAddrParameter(const struct sockaddr *addr, int len, ULONG flags)
{
	NTSTATUS status = 0;

	if(!addr)
	{
		if(flags & SOCKADDR_NULL_OK)
		{
			RtlSetLastWin32ErrorAndNtStatusFromNtStatus(0);
		return 0;
		}
		else
		{
			RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
			return STATUS_INVALID_PARAMETER;
		}
	}
	if(len < (int)sizeof(struct sockaddr))
	{
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
		return STATUS_INVALID_PARAMETER;
	}
	if(!(flags & SOCKADDR_NO_AF_OK))
	{
		switch(addr->sa_family)
		{
			case 0:
				status = STATUS_INVALID_PARAMETER;
				break;
			case AF_INET6:
				if(len < 28)
				{
					status = STATUS_INVALID_PARAMETER;
				}
				break;
		}
	}
	if((!(flags & SOCKADDR_NO_PORT_OK)) && (!(*(u_short*)&addr->sa_data[0])))
	{
		 status = STATUS_INVALID_PARAMETER;
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return status;
}

ULONG GetSocketContextLength(PSOCKET_CONTEXT sockctx)
{
	ULONG paddsize;

	if(CheckPointerParameter(sockctx))
	{
		return 0;
	}
	paddsize = (sockctx->SharedData.SizeOfLocalAddress & 0x7FFFFFF0) + (((sockctx->SharedData.SizeOfLocalAddress & 0xF) > 0) << 4) + ((!sockctx->SharedData.SizeOfLocalAddress) << 4);
	return sizeof(SOCK_SHARED_INFO)+sizeof(GUID)+8+sizeof(PVOID)+(paddsize << 1);
}

ULONG CreateSocketContext(int af, int type, int protocol, PSOCKET_CONTEXT sockctx)
{
	NTSTATUS status;
	WSAPROTOCOL_INFOW wsapi;
	ULONG sockaddr_paddsize;

	if(CheckPointerParameter(sockctx))
	{
		return 0;
	}
	status = NtGetProtocolForSocket(af, type, protocol, &wsapi);
	if(!status)
	{
		memset(&sockctx->SharedData, 0, sizeof(SOCK_SHARED_INFO));
		sockctx->SharedData.AddressFamily = wsapi.iAddressFamily;
		sockctx->SharedData.SocketType = wsapi.iSocketType;
		sockctx->SharedData.Protocol = wsapi.iProtocol;
		sockctx->SharedData.SizeOfLocalAddress = wsapi.iMinSockAddr;
		sockctx->SharedData.SizeOfRemoteAddress = wsapi.iMinSockAddr;
		sockctx->SharedData.SizeOfRecvBuffer = (1 << 16);
		sockctx->SharedData.SizeOfSendBuffer = (1 << 16);
		sockctx->SharedData.Flags.HasGUID = 1;
		sockctx->SharedData.CreateFlags = 1;
		sockctx->SharedData.CatalogEntryId = wsapi.dwCatalogEntryId;
		sockctx->SharedData.ServiceFlags1 = wsapi.dwServiceFlags1;
		sockctx->SharedData.ProviderFlags = wsapi.dwProviderFlags;
		sockctx->Guid = wsapi.ProviderId;
		sockctx->SizeOfHelperData = sizeof(PVOID);
		sockaddr_paddsize = (wsapi.iMinSockAddr & 0x7FFFFFF0) + (((wsapi.iMinSockAddr & 0xF) > 0) << 4);
		if(sockaddr_paddsize < sizeof(SOCKADDR))
		{
			sockaddr_paddsize = sizeof(SOCKADDR);
		}
		memset(&sockctx->LocalAddress, 0, 2*sockaddr_paddsize);
		*(int*)(((char*)&sockctx->LocalAddress)+(2*sockaddr_paddsize)) = af;
		return sizeof(SOCK_SHARED_INFO)+sizeof(GUID)+8+sizeof(PVOID)+(2*sockaddr_paddsize);
	}
	return 0;
}

NTSTATUS GetSocketContext(SOCKET sock, PSOCKET_CONTEXT sockctx, PULONG ctxsize)
{
	NTSTATUS status;
	HANDLE event;
	IO_STATUS_BLOCK iosb;

	status = CheckSocketParameter(sock);
	if(status)
	{
		return status;
	}
	status = CheckPointerParameter(sockctx);
	if(status)
	{
		return status;
	}
	status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if(!status)
	{
		status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_GET_CONTEXT, NULL, 0, sockctx, *ctxsize);
		NtClose(event);
		if(!status)
		{
			*ctxsize = GetSocketContextLength(sockctx);
			RtlSetLastWin32ErrorAndNtStatusFromNtStatus(0);
			return 0;
		}
	}
	return status;
}

NTSTATUS SetSocketContext(SOCKET sock, PSOCKET_CONTEXT sockctx, ULONG ctxsize)
{
	NTSTATUS status;
	HANDLE event;
	IO_STATUS_BLOCK iosb;
	ULONG len;

	status = CheckSocketParameter(sock);
	if(status)
	{
		return status;
	}
	status = CheckPointerParameter(sockctx);
	if(status)
	{
		return status;
	}
	len = GetSocketContextLength(sockctx);
	if(ctxsize < len)
	{
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_BUFFER_TOO_SMALL);
		return STATUS_BUFFER_TOO_SMALL;
	}
	status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if(!status)
	{
		status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_SET_CONTEXT, sockctx, len, NULL, 0);
		NtClose(event);
	}
	return status;
}

u_short NtHtons(u_short s)
{
	return (s << 8) | (s >> 8);
}

struct in_addr NtInetAddr(const char *cp)
{
	int ipbyte = 0, ndot = 0;
	char *pstr,*ldot = (char*)&cp[-1];
	struct in_addr addr;

	addr.S_un.S_addr = INADDR_NONE;
	if(cp)
	{
		for(pstr = (char*)cp; *pstr; ++pstr)
		{
			if(*pstr == '.')
			{
				if((ldot == pstr-1))
				{
					addr.S_un.S_addr = INADDR_NONE;
					break;
				}
				if(ndot > 3)
				ldot = pstr;
				((u_char*)&addr)[ndot++] = (u_char)ipbyte;
				ipbyte = 0;
				if(ndot > 3)
				{
					break;
				}
			}
			else if((*pstr >= '0') && (*pstr <= '9'))
			{
				ipbyte = (ipbyte * 10) + (*pstr - '0');
				if(ipbyte > 0xFF)
				{
					addr.S_un.S_addr = INADDR_NONE;
					break;
				}
				if(!pstr[1])
				{
					((u_char*)&addr)[ndot] = (u_char)ipbyte;
				}
			}
			else
			{
				addr.S_un.S_addr = INADDR_NONE;
				break;
			}
		}
	}
	return addr;
}

int NtEnumProtocols(LPINT lpiProtocols, LPWSAPROTOCOL_INFOW lpProtocolBuffer, LPDWORD lpdwBufferLength)
{
	return SOCKET_ERROR;
}

SOCKET NtSocket(int af, int type, int protocol)
{
	NTSTATUS status;
	ULONG len;
	BYTE buffer[SOCK_CONTEXT_BUF_SIZE];
	PSOCKET_CONTEXT sockctx;
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa;
	AFD_SOCK_CREATE_EA ea;
	IO_STATUS_BLOCK iosb;
	SOCKET sock = INVALID_SOCKET;

	sockctx = (PSOCKET_CONTEXT)&buffer[0];
	len = CreateSocketContext(af, type, protocol, sockctx);
	if(len > 0)
	{
		us.Length = sizeof(AFD_DEVICE_PATH)-sizeof(WCHAR);
		us.MaximumLength = sizeof(AFD_DEVICE_PATH);
		us.Buffer = (PWSTR)AFD_DEVICE_PATH;
		memset(&oa, 0, sizeof(OBJECT_ATTRIBUTES));
		oa.Length = sizeof(OBJECT_ATTRIBUTES);
		oa.RootDirectory = NULL;
		oa.ObjectName = &us;
		oa.Attributes = OBJ_CASE_INSENSITIVE;
		oa.SecurityDescriptor = NULL;
		oa.SecurityQualityOfService = NULL;
		memset(&ea, 0, sizeof(AFD_SOCK_CREATE_EA));
		ea.unknown1 = 0x001E0F00;
		memcpy(&ea.afdopenstr[0], AfdCommand, sizeof(AfdCommand));
		if(sockctx->SharedData.SocketType == SOCK_DGRAM)
		{
			ea.unknown2 = sockctx->SharedData.Protocol;
		}
		ea.iAdressFamily = sockctx->SharedData.AddressFamily;
		ea.iSocketType = sockctx->SharedData.SocketType;
		ea.iProtocol = sockctx->SharedData.Protocol;
		status = NtCreateFile((PHANDLE)&sock, GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE|WRITE_DAC, &oa, &iosb, NULL, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN_IF, 0, &ea, 0x39);
		if(!status)
		{
			status = SetSocketContext(sock, sockctx, SOCK_CONTEXT_BUF_SIZE);
		}
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	if(status)
	{
		return INVALID_SOCKET;
	}
	return sock;
}

int NtBind(SOCKET sock, const struct sockaddr *addr, int addrlen)
{
	NTSTATUS status;
	ULONG len;
	BYTE buffer[SOCK_CONTEXT_BUF_SIZE];
	HANDLE event;
	IO_STATUS_BLOCK iosb;
	BYTE binddata[sizeof(ULONG)+SOCK_CONTEXT_ADDR_SIZE];
	PAFD_BIND_DATA_NEW abd;
	PSOCKET_CONTEXT sockctx;
	LARGE_INTEGER li;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckSockAddrParameter(addr, addrlen, SOCKADDR_NO_AF_OK|SOCKADDR_NO_PORT_OK))
	{
		return SOCKET_ERROR;
	}
	sockctx = (PSOCKET_CONTEXT)&buffer[0];
	len = SOCK_CONTEXT_BUF_SIZE;
	status = GetSocketContext(sock, sockctx, &len);
	if(!status)
	{
		status = STATUS_BUFFER_OVERFLOW;
		if(sockctx->SharedData.SizeOfLocalAddress <= (INT)SOCK_CONTEXT_ADDR_SIZE)
		{
			if(addrlen >= sockctx->SharedData.SizeOfLocalAddress)
			{
				abd = (PAFD_BIND_DATA_NEW)&binddata[0];
				if(sockctx->SharedData.Flags.ExclusiveAddressUse)
				{
					abd->ShareMode = AFD_SHARE_EXCLUSIVE;
				}
				else if(sockctx->SharedData.Flags.ReuseAddresses)
				{
					abd->ShareMode = AFD_SHARE_REUSE;
				}
				else if(sockctx->SharedData.Flags.DontUseWildcard)
				{
					abd->ShareMode = AFD_SHARE_UNIQUE;
				}
				else
				{
					abd->ShareMode = AFD_SHARE_WILDCARD;
				}
				memcpy(&abd->Addr, addr, sockctx->SharedData.SizeOfLocalAddress);
				status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
				if(!status)
				{
					status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_BIND, abd, sockctx->SharedData.SizeOfLocalAddress+sizeof(ULONG), &sockctx->LocalAddress, sockctx->SharedData.SizeOfLocalAddress);
					if(status == STATUS_PENDING)
					{
						li.QuadPart = 0xFFFFFFFFFFB3B4C0;
						status = NtWaitForSingleObject(event, TRUE, &li);
						if(!status)
						{
							status = iosb.Status;
						}
					}
					NtClose(event);
					if(!status)
					{
						sockctx->SharedData.State = SocketBound;
						status = SetSocketContext(sock, sockctx, len);
					}
				}
			}
			else
			{
				status = STATUS_INVALID_PARAMETER;
			}
		}
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

int NtAutoBind(SOCKET sock, u_short port)
{
	NTSTATUS status;
	BYTE buffer[SOCK_CONTEXT_ADDR_SIZE];
	SOCKADDR_IN *addr;
	BYTE sockctxbuf[20];
	ULONG scbufsize;
	PSOCKET_CONTEXT sockctx;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	sockctx = (PSOCKET_CONTEXT)&sockctxbuf[0];
	scbufsize = sizeof(sockctxbuf);
	status = GetSocketContext(sock, sockctx, &scbufsize);
	if(status == STATUS_BUFFER_OVERFLOW)
	{
		if(sockctx->SharedData.State == SocketOpen)
		{
			if(sockctx->SharedData.SizeOfLocalAddress <= (INT)SOCK_CONTEXT_ADDR_SIZE)
			{
				addr = (SOCKADDR_IN*)&buffer[0];
				memset(addr, 0, sockctx->SharedData.SizeOfLocalAddress);
				addr->sin_family = (short)sockctx->SharedData.AddressFamily;
				if((sockctx->SharedData.AddressFamily == AF_INET) || (sockctx->SharedData.AddressFamily == AF_INET6))
				{
					addr->sin_port = NtHtons(port);
				}
				return NtBind(sock, (struct sockaddr*)addr, sockctx->SharedData.SizeOfLocalAddress);
			}
		}
		else
		{
			status = 0;
		}
	}
	else if(!status)
	{
		status = STATUS_BUFFER_TOO_SMALL;
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

int NtSend(SOCKET sock, const void *buf, int len, int flags)
{
	NTSTATUS status;
	HANDLE event;
	AFD_SEND_INFO asi;
	IO_STATUS_BLOCK iosb;
	AFD_WSABUF wsabuf;
	BYTE buffer[32];
	ULONG bufsize;
	PSOCKET_CONTEXT sockctx;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli = NULL;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(buf, len, 0))
	{
		return SOCKET_ERROR;
	}
	if(!(flags & MSG_NOBINDCHECK))
	{
		if(NtAutoBind(sock, 0) == SOCKET_ERROR)
		{
			return SOCKET_ERROR;
		}
	}
	if((!(flags & MSG_NOTIMEOUT)) && (!(flags & MSG_DONTWAIT)) && (!(flags & MSG_DOANYWAY)))
	{
		sockctx = (PSOCKET_CONTEXT)&buffer[0];
		bufsize = sizeof(buffer);
		status = GetSocketContext(sock, sockctx, &bufsize);
		if(status == STATUS_BUFFER_OVERFLOW)
		{
			li.HighPart = 0;
			li.LowPart = sockctx->SharedData.SendTimeout;
			if(li.LowPart)
			{
				li.QuadPart *= -10000;
				pli = &li;
			}
		}
	}
	memset(&asi, 0, sizeof(AFD_SEND_INFO));
	wsabuf.buf = (PCHAR)buf;
	if(buf)
	{
		wsabuf.len = len;
	}
	else
	{
		wsabuf.len = 0;
	}
	asi.BufferArray = &wsabuf;
	asi.BufferCount = 1;
	if(flags & MSG_IMMEDIATE)
	{
		asi.AfdFlags = AFD_IMMEDIATE;
	}
	status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if(!status)
	{
		status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_SEND, &asi, sizeof(AFD_SEND_INFO), NULL, 0);
		if(status == STATUS_PENDING)
		{
			if(flags & MSG_DOANYWAY)
			{
				status = 0;
			}
			else
			{
				status = NtWaitForSingleObject(event, TRUE, pli);
			}
		}
		NtClose(event);
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	if(status)
	{
		return SOCKET_ERROR;
	}
	return (int)iosb.Information;
}

int NtRecv(SOCKET sock, void *buf, int len, int flags)
{
	NTSTATUS status;
	HANDLE event;
	AFD_RECV_INFO ari;
	IO_STATUS_BLOCK iosb;
	AFD_WSABUF wsabuf;
	BYTE buffer[36];
	ULONG bufsize;
	PSOCKET_CONTEXT sockctx;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli = NULL;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(buf, len, 0))
	{
		return SOCKET_ERROR;
	}
	if((!(flags & MSG_NOTIMEOUT)) && (!(flags & MSG_DONTWAIT)) && (!(flags & MSG_DOANYWAY)))
	{
		sockctx = (PSOCKET_CONTEXT)&buffer[0];
		bufsize = sizeof(buffer);
		status = GetSocketContext(sock, sockctx, &bufsize);
		if(status == STATUS_BUFFER_OVERFLOW)
		{
			li.HighPart = 0;
			li.LowPart = sockctx->SharedData.RecvTimeout;
			if(li.LowPart)
			{
				li.QuadPart *= -10000;
				pli = &li;
			}
		}
	}
	wsabuf.buf = (PCHAR)buf;
	if(buf)
	{
		wsabuf.len = len;
	}
	else
	{
		wsabuf.len = 0;
	}
	ari.BufferArray = &wsabuf;
	ari.BufferCount = 1;
	ari.AfdFlags = 0;
	ari.TdiFlags = TDI_RECEIVE_NORMAL;
	status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if(!status)
	{
		status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &ari, sizeof(AFD_RECV_INFO), NULL, 0);
		if(status == STATUS_PENDING)
		{
			if(flags & MSG_DOANYWAY)
			{
				status = 0;
			}
			else
			{
				status = NtWaitForSingleObject(event, TRUE, pli);
			}
		}
		NtClose(event);
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	if(status)
	{
		return SOCKET_ERROR;
	}
	return (int)iosb.Information;
}

int NtSendTo(SOCKET sock, const void *buf, int len, int flags, const struct sockaddr *to, int tolen)
{
	NTSTATUS status;
	HANDLE event;
	AFD_SEND_INFO_UDP asiu;
	IO_STATUS_BLOCK iosb;
	AFD_WSABUF wsabuf;
	BYTE buffer[32];
	ULONG bufsize;
	PSOCKET_CONTEXT sockctx;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli = NULL;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(buf, len, 0))
	{
		return SOCKET_ERROR;
	}
	if(!(flags & MSG_NOBINDCHECK))
	{
		if(NtAutoBind(sock, 0) == SOCKET_ERROR)
		{
			return SOCKET_ERROR;
		}
	}
	if((!(flags & MSG_NOTIMEOUT)) && (!(flags & MSG_DONTWAIT)) && (!(flags & MSG_DOANYWAY)))
	{
		sockctx = (PSOCKET_CONTEXT)&buffer[0];
		bufsize = sizeof(buffer);
		status = GetSocketContext(sock, sockctx, &bufsize);
		if(status == STATUS_BUFFER_OVERFLOW)
		{
			li.HighPart = 0;
			li.LowPart = sockctx->SharedData.SendTimeout;
			if(li.LowPart)
			{
				li.QuadPart *= -10000;
				pli = &li;
			}
		}
	}
	wsabuf.buf = (PCHAR)buf;
	if(buf)
	{
		wsabuf.len = len;
	}
	else
	{
		wsabuf.len = 0;
	}
	memset(&asiu, 0, sizeof(AFD_SEND_INFO_UDP));
	asiu.BufferArray = &wsabuf;
	asiu.BufferCount = 1;
	if(flags & MSG_IMMEDIATE)
	{
		asiu.AfdFlags = AFD_IMMEDIATE;
	}
	asiu.TdiConnection.RemoteAddressLength = tolen;
	asiu.TdiConnection.RemoteAddress = (PVOID)to;
	status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if(!status)
	{
		status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_SEND_DATAGRAM, &asiu, sizeof(AFD_SEND_INFO_UDP), NULL, 0);
		if(status == STATUS_PENDING)
		{
			if(flags & MSG_DOANYWAY)
			{
				status = 0;
			}
			else
			{
				status = NtWaitForSingleObject(event, TRUE, pli);
			}
		}
		NtClose(event);
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	if(status)
	{
		return SOCKET_ERROR;
	}
	return (int)iosb.Information;
}

int NtRecvFrom(SOCKET sock, void *buf, int len, int flags, struct sockaddr *from, int *fromlen)
{
	NTSTATUS status;
	HANDLE event;
	AFD_RECV_INFO_UDP ariu;
	IO_STATUS_BLOCK iosb;
	AFD_WSABUF wsabuf;
	BYTE buffer[36];
	ULONG bufsize;
	PSOCKET_CONTEXT sockctx;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli = NULL;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(buf, len, 0))
	{
		return SOCKET_ERROR;
	}
	if((!(flags & MSG_NOTIMEOUT)) && (!(flags & MSG_DONTWAIT)) && (!(flags & MSG_DOANYWAY)))
	{
		sockctx = (PSOCKET_CONTEXT)&buffer[0];
		bufsize = sizeof(buffer);
		status = GetSocketContext(sock, sockctx, &bufsize);
		if(status == STATUS_BUFFER_OVERFLOW)
		{
			li.HighPart = 0;
			li.LowPart = sockctx->SharedData.RecvTimeout;
			if(li.LowPart)
			{
				li.QuadPart *= -10000;
				pli = &li;
			}
		}
	}
	wsabuf.buf = (PCHAR)buf;
	if(buf)
	{
		wsabuf.len = len;
	}
	else
	{
		wsabuf.len = 0;
	}
	ariu.BufferArray = &wsabuf;
	ariu.BufferCount = 1;
	ariu.AfdFlags = 0;
	ariu.TdiFlags = TDI_RECEIVE_NORMAL;
	ariu.Address = from;
	ariu.AddressLength = fromlen;
	status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if(!status)
	{
		status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_RECV_DATAGRAM, &ariu, sizeof(AFD_RECV_INFO_UDP), NULL, 0);
		if(status == STATUS_PENDING)
		{
			if(!(flags & MSG_DOANYWAY))
			{
				status = NtWaitForSingleObject(event, TRUE, pli);
			}
			else
			{
				status = 0;
			}
		}
		NtClose(event);
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	if(status)
	{
		return SOCKET_ERROR;
	}
	return (int)iosb.Information;
}

int NtSelect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const TIMEVAL *timeout)
{
	NTSTATUS status;
	HANDLE event;
	IO_STATUS_BLOCK iosb;
	PVOID heap;
	PAFD_SELECT_DATA pasd;
	ULONG buffersize = sizeof(AFD_SELECT_DATA)-sizeof(AFD_SELECT_DATA_ENTRY);
	int signals = SOCKET_ERROR;
	unsigned int i, j;

	if(readfds)
	{
		buffersize += (readfds->fd_count * sizeof(AFD_SELECT_DATA_ENTRY));
	}
	if(writefds)
	{
		if(writefds != readfds)
		{
			buffersize += (writefds->fd_count * sizeof(AFD_SELECT_DATA_ENTRY));
		}
	}
	if(exceptfds)
	{
		if((exceptfds != readfds) && (exceptfds != writefds))
		{
			buffersize += (exceptfds->fd_count * sizeof(AFD_SELECT_DATA_ENTRY));
		}
	}
	if(buffersize < sizeof(AFD_SELECT_DATA_ENTRY))
	{
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
		return SOCKET_ERROR;
	}
	#ifdef NTSOCK_SELECT_STACKALLOC
	if(buffersize <= NTSOCK_SELECT_STACKALLOC)
	{
		pasd = (PAFD_SELECT_DATA)alloca(buffersize);
		memset(pasd, 0, buffersize);
	}
	else
	{
	#endif
		if(!RtlGetProcessHeaps(1, &heap))
		{
			RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NOT_FOUND);
			return SOCKET_ERROR;
		}
		pasd = (PAFD_SELECT_DATA)RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, buffersize);
		if(!pasd)
		{
			RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);
			return SOCKET_ERROR;
		}
	#ifdef NTSOCK_SELECT_STACKALLOC
	}
	#endif
	if(timeout)
	{
		pasd->Timeout.QuadPart = (((LONGLONG)timeout->tv_sec) * 1000 + ((LONGLONG)timeout->tv_usec)) * -10000;
	}
	else
	{
		pasd->Timeout.QuadPart = 0x8000000000000000;
	}
	if(readfds)
	{
		for(i = 0; i < readfds->fd_count; ++i)
		{
			if(readfds->fd_array[i] == INVALID_SOCKET)
			{
				continue;
			}
			for(j = 0; j < pasd->SocketCount; ++j)
			{
				if(pasd->SockEntry[j].sock == readfds->fd_array[i])
				{
					pasd->SockEntry[j].mode |= AFD_SELECT_FILTER_READ;
					break;
				}
			}
			if(j >= pasd->SocketCount)
			{
				pasd->SockEntry[pasd->SocketCount].sock = readfds->fd_array[i];
				pasd->SockEntry[pasd->SocketCount].mode = AFD_SELECT_FILTER_READ;
				++pasd->SocketCount;
			}
		}
	}
	if(writefds)
	{
		for(i = 0; i < writefds->fd_count; ++i)
		{
			if(writefds->fd_array[i] == INVALID_SOCKET)
			{
				continue;
			}
			for(j = 0; j < pasd->SocketCount; ++j)
			{
				if(pasd->SockEntry[j].sock == writefds->fd_array[i])
				{
					pasd->SockEntry[j].mode |= AFD_SELECT_FILTER_WRITE;
					break;
				}
			}
			if(j >= pasd->SocketCount)
			{
				pasd->SockEntry[pasd->SocketCount].sock = writefds->fd_array[i];
				pasd->SockEntry[pasd->SocketCount].mode = AFD_SELECT_FILTER_WRITE;
				++pasd->SocketCount;
			}
		}
	}
	if(exceptfds)
	{
		for(i = 0; i < exceptfds->fd_count; ++i)
		{
			if(exceptfds->fd_array[i] == INVALID_SOCKET)
			{
				continue;
			}
			for(j = 0; j < pasd->SocketCount; ++j)
			{
				if(pasd->SockEntry[j].sock == exceptfds->fd_array[i])
				{
					pasd->SockEntry[j].mode |= AFD_SELECT_FILTER_EXCEPT;
					break;
				}
			}
			if(j >= pasd->SocketCount)
			{
				pasd->SockEntry[pasd->SocketCount].sock = exceptfds->fd_array[i];
				pasd->SockEntry[pasd->SocketCount].mode = AFD_SELECT_FILTER_EXCEPT;
				++pasd->SocketCount;
			}
		}
	}
	status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if(!status)
	{
		status = NtDeviceIoControlFile((HANDLE)pasd->SockEntry[0].sock, event, NULL, NULL, &iosb, IOCTL_AFD_SELECT, pasd, buffersize, pasd, buffersize);
		if(status == STATUS_PENDING)
		{
			status = NtWaitForSingleObject(event, TRUE, &pasd->Timeout);
		}
		NtClose(event);
	}
	if(!status)
	{
		signals = (int)pasd->SocketCount;
		if(readfds)
		{
			readfds->fd_count = 0;
			for(i = 0; i < pasd->SocketCount; ++i)
			{
				if(pasd->SockEntry[i].mode & AFD_SELECT_FILTER_READ)
				{
					readfds->fd_array[readfds->fd_count++] = pasd->SockEntry[i].sock;
				}
			}
		}
		if(writefds)
		{
			writefds->fd_count = 0;
			for(i = 0; i < pasd->SocketCount; ++i)
			{
				if(pasd->SockEntry[i].mode & AFD_SELECT_FILTER_WRITE)
				{
					writefds->fd_array[writefds->fd_count++] = pasd->SockEntry[i].sock;
				}
			}
		}
		if(exceptfds)
		{
			exceptfds->fd_count = 0;
			for(i = 0; i < pasd->SocketCount; ++i)
			{
				if(pasd->SockEntry[i].mode & AFD_SELECT_FILTER_EXCEPT)
				{
					exceptfds->fd_array[exceptfds->fd_count++] = pasd->SockEntry[i].sock;
				}
			}
		}
	}
	#ifdef NTSOCK_SELECT_STACKALLOC
	if(buffersize > NTSOCK_SELECT_STACKALLOC)
	{
	#endif
		RtlFreeHeap(heap, 0, pasd);
	#ifdef NTSOCK_SELECT_STACKALLOC
	}
	#endif
	if(status == STATUS_TIMEOUT)
	{
		signals = 0;
		if(readfds)
		{
			readfds->fd_count = 0;
		}
		if(writefds)
		{
			writefds->fd_count = 0;
		}
		if(exceptfds)
		{
			exceptfds->fd_count = 0;
		}
	}
	else if(status)
	{
		signals = -1;
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return signals;
}

void NtFDZero(fd_set *fd)
{
	fd->fd_count = 0;
}

void NtFDSet(SOCKET s, fd_set *fd)
{
	unsigned int i;

	for(i = 0; i < fd->fd_count; ++i)
	{
		if(fd->fd_array[i] == s)
		{
			break;
		}
	}
	if(i >= fd->fd_count)
	{
		if(fd->fd_count < FD_SETSIZE)
		{
			fd->fd_array[fd->fd_count++] = s;
		}
	}
}

int NtFDIsSet(SOCKET s, fd_set *fd)
{
	unsigned int i;

	for(i = 0; i < fd->fd_count; ++i)
	{
		if(fd->fd_array[i] == s)
		{
			return 1;
		}
	}
	return 0;
}

int NtSetSockOpt(SOCKET sock, int level, int optname, const char *optval, int optlen)
{
	NTSTATUS status;
	BYTE buffer[SOCK_CONTEXT_BUF_SIZE];
	ULONG sctxlen;
	PSOCKET_CONTEXT sockctx;

	if(CheckArrayParameter((PVOID)optval, optlen, sizeof(int)))
	{
		return SOCKET_ERROR;
	}
	sctxlen = SOCK_CONTEXT_BUF_SIZE;
	sockctx = (PSOCKET_CONTEXT)&buffer[0];
	status = GetSocketContext(sock, sockctx, &sctxlen);
	if(!status)
	{
		switch(level)
		{
			case SOL_SOCKET:
				switch(optname)
				{
					case PVD_CONFIG:
						return SOCKET_ERROR;
						break;
					case SO_BROADCAST:
						if(*(BOOL*)optval)
						{
							if(sockctx->SharedData.AddressFamily == AF_INET6)
							{
								return SOCKET_ERROR;
							}
							sockctx->SharedData.Flags.Broadcast = 1;
						}
						else
						{
							sockctx->SharedData.Flags.Broadcast = 0;
						}
						break;
					case SO_CONDITIONAL_ACCEPT:
						sockctx->SharedData.Flags.UseDelayedAcceptance = !!(*(BOOL*)optval);
						break;
					case SO_DEBUG:
						sockctx->SharedData.Flags.Debug = !!(*(BOOL*)optval);
						break;
					case SO_DONTLINGER:
						if(*(BOOL*)optval)
						{
							sockctx->SharedData.LingerData.l_onoff = 0;
						}
						else
						{
							sockctx->SharedData.LingerData.l_onoff = 1;
						}
						break;
					case SO_DONTROUTE:
						return SOCKET_ERROR;
						break;
					case SO_GROUP_PRIORITY:
						return SOCKET_ERROR;
						break;
					case SO_KEEPALIVE:
						return SOCKET_ERROR;
						break;
					case SO_LINGER:
						sockctx->SharedData.LingerData = *(struct linger*)optval;
						break;
					case SO_OOBINLINE:
						return SOCKET_ERROR;
						break;
					case SO_REUSEADDR:
						sockctx->SharedData.Flags.ReuseAddresses = !!(*(BOOL*)optval);
						break;
					case SO_EXCLUSIVEADDRUSE:
						sockctx->SharedData.Flags.ExclusiveAddressUse = !!(*(BOOL*)optval);
						break;
					case SO_SNDBUF:
						sockctx->SharedData.SizeOfSendBuffer = *(int*)optval;
						break;
					case SO_RCVBUF:
						sockctx->SharedData.SizeOfRecvBuffer = *(int*)optval;
						break;
					case SO_SNDTIMEO:
						sockctx->SharedData.SendTimeout = *(DWORD*)optval;
						break;
					case SO_RCVTIMEO:
						sockctx->SharedData.RecvTimeout = *(DWORD*)optval;
						break;
					default:
						return SOCKET_ERROR;
				}
				break;
			default:
				return SOCKET_ERROR;
		}
		status = SetSocketContext(sock, sockctx, sctxlen);
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

int NtGetSockOpt(SOCKET sock, int level, int optname, const char *optval, int *optlen)
{
	NTSTATUS status;
	BYTE buffer[SOCK_CONTEXT_BUF_SIZE];
	ULONG sctxlen;
	PSOCKET_CONTEXT sockctx;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckPointerParameter(optlen))
	{
		return SOCKET_ERROR;
	}
	if(CheckArrayParameter(optval, *optlen, 1))
	{
		return SOCKET_ERROR;
	}
	sockctx = (PSOCKET_CONTEXT)&buffer[0];
	sctxlen = sizeof(buffer);
	status = GetSocketContext(sock, sockctx, &sctxlen);
	if(!status)
	{
		switch(level)
		{
			case SOL_SOCKET:
				switch(optname)
				{
					case PVD_CONFIG:
						return SOCKET_ERROR;
						break;
					default:
						return SOCKET_ERROR;
				}
				break;
			default:
				return SOCKET_ERROR;
		}
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

int NtIoctlSocket(SOCKET sock, long cmd, u_long *argp)
{
	NTSTATUS status;
	HANDLE event;
	IO_STATUS_BLOCK iosb;
	AFD_SOCK_INFO asi;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckPointerParameter(argp))
	{
		return SOCKET_ERROR;
	}
	memset(&asi, 0, sizeof(AFD_SOCK_INFO));
	switch(cmd)
	{
		case FIONBIO:
			asi.cmd = AFD_INFO_BLOCKING_MODE;
			asi.arg = *argp;
			break;
		case FIONREAD:
			break;
		case SIOCATMARK:
			break;
		default:
			status = STATUS_INVALID_PARAMETER;
			break;
	}
	if(asi.cmd)
	{
		status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
		if(!status)
		{
			status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_SET_INFO, &asi, sizeof(AFD_SOCK_INFO), NULL, 0);
			NtClose(event);
		}
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

NTSTATUS NtIoctlSocketEx(SOCKET sock, ULONG cmd, PVOID inbuffer, ULONG inbuflen, PVOID outbuffer, ULONG outbuflen)
{
	NTSTATUS status;
	HANDLE event;
	IO_STATUS_BLOCK iosb;
	AFD_SOCK_INFO asi;

	if(CheckSocketParameter(sock))
	{
		return STATUS_INVALID_PARAMETER;
	}
	memset(&asi, 0, sizeof(AFD_SOCK_INFO));
	switch(cmd)
	{
		case FIONBIO:
			break;
		case FIONREAD:
			break;
		case SIOCATMARK:
			break;
		case SIO_FIND_ROUTE:
			break;
		case SIO_FLUSH:
			break;
		case SIO_KEEPALIVE_VALS:
			break;
		case SIO_RCVALL:
			break;
		case SIO_ROUTING_INTERFACE_QUERY:
			break;
		case SIO_ROUTING_INTERFACE_CHANGE:
			break;
		case SIO_ADDRESS_LIST_QUERY:
			break;
		case SIO_ADDRESS_LIST_SORT:
			break;
		case SIO_ADDRESS_LIST_CHANGE:
			break;
		case SIO_GET_INTERFACE_LIST:
			break;
		case SIO_INDEX_BIND:
			break;
		case SIO_NSP_NOTIFY_CHANGE:
			break;
		default:
			status = STATUS_INVALID_PARAMETER;
			break;
	}
	if(asi.cmd)
	{
		status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
		if(!status)
		{
			status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_SET_INFO, &asi, sizeof(AFD_SOCK_INFO), NULL, 0);
			NtClose(event);
		}
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return status;
}

int NtGetSockName(SOCKET sock, struct sockaddr *name, int *namelen)
{
	NTSTATUS status;
	BYTE buffer[sizeof(SOCK_SHARED_INFO)+sizeof(GUID)+SOCK_CONTEXT_ADDR_SIZE+8];
	ULONG sctxlen;
	PSOCKET_CONTEXT sockctx;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckSockAddrParameter(name, *namelen, SOCKADDR_NO_AF_OK|SOCKADDR_NO_PORT_OK))
	{
		return SOCKET_ERROR;
	}
	sockctx = (PSOCKET_CONTEXT)&buffer[0];
	sctxlen = sizeof(buffer);
	status = GetSocketContext(sock, sockctx, &sctxlen);
	if((!status) || (status == STATUS_BUFFER_OVERFLOW))
	{
		if(sockctx->SharedData.SizeOfLocalAddress <= *namelen)
		{
			*namelen = sockctx->SharedData.SizeOfLocalAddress;
			memcpy(name, &sockctx->LocalAddress, *namelen);
		}
		else
		{
			status = STATUS_BUFFER_TOO_SMALL;
		}
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

int NtGetPeerName(SOCKET sock, struct sockaddr *name, int *namelen)
{
	NTSTATUS status;
	BYTE buffer[SOCK_CONTEXT_BUF_SIZE];
	ULONG sctxlen;
	PSOCKET_CONTEXT sockctx;
	int sa_remote_offset;

	if(sock == INVALID_SOCKET)
	{
		return SOCKET_ERROR;
	}
	if(!name)
	{
		return SOCKET_ERROR;
	}
	if(*namelen < (int)sizeof(struct sockaddr))
	{
		return SOCKET_ERROR;
	}
	sockctx = (PSOCKET_CONTEXT)&buffer[0];
	sctxlen = sizeof(buffer);
	status = GetSocketContext(sock, sockctx, &sctxlen);
	if((!status) || (status == STATUS_BUFFER_OVERFLOW))
	{
		if(sockctx->SharedData.SizeOfRemoteAddress <= *namelen)
		{
			*namelen = sockctx->SharedData.SizeOfRemoteAddress;
			sa_remote_offset = sizeof(SOCK_SHARED_INFO) + sizeof(GUID) + (sockctx->SharedData.SizeOfLocalAddress & 0x7FFFFFF0) + (((sockctx->SharedData.SizeOfLocalAddress & 0xF) > 0) << 4) + 8;
			memcpy(name, &buffer[sa_remote_offset], *namelen);
		}
		else
		{
			status = STATUS_BUFFER_TOO_SMALL;
		}
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

int NtConnect(SOCKET sock, const struct sockaddr *name, int namelen)
{
	NTSTATUS status;
	HANDLE event;
	IO_STATUS_BLOCK iosb;
	BYTE condata[FIELD_OFFSET(AFD_CONNECT_INFO_NEW, Addr)+SOCK_CONTEXT_ADDR_SIZE];
	ULONG conlen = FIELD_OFFSET(AFD_CONNECT_INFO_NEW, Addr);
	PAFD_CONNECT_INFO_NEW aci;
	BYTE buffer[SOCK_CONTEXT_BUF_SIZE];
	ULONG sctxlen;
	PSOCKET_CONTEXT sockctx;
	int sa_remote_offset;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	if(CheckSockAddrParameter(name, namelen, 0))
	{
		return SOCKET_ERROR;
	}
	if(NtAutoBind(sock, 0) == SOCKET_ERROR)
	{
		return SOCKET_ERROR;
	}
	sockctx = (PSOCKET_CONTEXT)&buffer[0];
	sctxlen = SOCK_CONTEXT_BUF_SIZE;
	status = GetSocketContext(sock, sockctx, &sctxlen);
	if(!status)
	{
		if(sockctx->SharedData.SizeOfRemoteAddress <= (INT)SOCK_CONTEXT_ADDR_SIZE)
		{
			if(namelen >= sockctx->SharedData.SizeOfRemoteAddress)
			{
				conlen += sockctx->SharedData.SizeOfRemoteAddress;
				sockctx->SharedData.State = SocketConnected;
				sa_remote_offset = sizeof(SOCK_SHARED_INFO) + sizeof(GUID) + (sockctx->SharedData.SizeOfLocalAddress & 0x7FFFFFF0) + (((sockctx->SharedData.SizeOfLocalAddress & 0xF) > 0) << 4) + 8;
				memcpy(&buffer[sa_remote_offset], name, sockctx->SharedData.SizeOfRemoteAddress);
				aci = (PAFD_CONNECT_INFO_NEW)&condata[0];
				aci->unknown1 = NULL;
				aci->zero1 = NULL;
				aci->unknown2 = NULL;
				memcpy(&aci->Addr, name, sockctx->SharedData.SizeOfRemoteAddress);
				status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
				if(!status)
				{
					status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_CONNECT, aci, conlen, NULL, 0);
					if(status == STATUS_PENDING)
					{
						status = NtWaitForSingleObject(event, TRUE, NULL);
						if(!status)
						{
							status = iosb.Status;
						}
					}
					NtClose(event);
					if(!status)
					{
						status = SetSocketContext(sock, sockctx, sctxlen);
					}
				}
			}
		}
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

int NtShutdown(SOCKET sock, int how)
{
	NTSTATUS status;
	HANDLE event;
	IO_STATUS_BLOCK iosb;
	AFD_DISCONNECT_INFO adi;

	if(CheckSocketParameter(sock))
	{
		return SOCKET_ERROR;
	}
	adi.Timeout.QuadPart = 0xFFFFFFFFFFFFFFFF;
	switch(how)
	{
		case SD_RECEIVE:
			adi.DisconnectType = AFD_DISCONNECT_RECV;
			break;
		case SD_SEND:
			adi.DisconnectType = AFD_DISCONNECT_SEND;
			break;
		case SD_BOTH:
			adi.DisconnectType = AFD_DISCONNECT_SEND|AFD_DISCONNECT_RECV;
			break;
		default:
			RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
			return SOCKET_ERROR;
	}
	status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if(!status)
	{
		status = NtDeviceIoControlFile((HANDLE)sock, event, NULL, NULL, &iosb, IOCTL_AFD_DISCONNECT, &adi, sizeof(AFD_DISCONNECT_INFO), NULL, 0);
		NtClose(event);
	}
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
	return -(!!status);
}

NTSTATUS NtCloseSocket(SOCKET sock)
{
	return NtClose((HANDLE)sock);
}

#ifdef __cplusplus
}
#endif