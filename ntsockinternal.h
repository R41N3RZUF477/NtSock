#ifndef _NTSOCK_INTERNAL_H_
#define _NTSOCK_INTERNAL_H_

#include <ntstatus.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <string.h>
#ifdef NTSOCK_SELECT_STACKALLOC
#include <malloc.h>
#endif

#ifndef _NTSOCK_H_
#include "ntsock.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

#include "afd_shared.h"

#define IOCTL_AFD_DISCONNECTEX 0x000120cb
#define IOCTL_AFD_CONNECTEX    0x000120c7
#define IOCTL_AFD_ACCEPTEX     0x00012083

#ifndef OBJ_INHERIT
#define OBJ_INHERIT 0x00000002L
#endif
#ifndef OBJ_PERMANENT
#define OBJ_PERMANENT 0x00000010L
#endif
#ifndef OBJ_EXCLUSIVE
#define OBJ_EXCLUSIVE 0x00000020L
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifdef _WIN64
#define REG_PROTOCOL_ENUM_STR L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64"
#else
#define REG_PROTOCOL_ENUM_STR L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries"
#endif
#define REG_PROTOCOL_VALUE_STR L"PackedCatalogItem"

#define REG_TCPIP_PARAMETER_STR L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define REG_HOSTNAME_VALUE_STR L"Hostname"
#define REG_DOMAIN_VALUE_STR L"Domain"

#define SOCKADDR_NULL_OK    0x1
#define SOCKADDR_NO_AF_OK   0x2
#define SOCKADDR_NO_PORT_OK 0x4

#define TCP_DEVICE_PATH L"\\Device\\Tcp"
#define UDP_DEVICE_PATH L"\\Device\\Udp"
#define RAWIP_DEVICE_PATH L"\\Device\\RawIp"
#define IP_DEVICE_PATH L"\\Device\\Ip"

#define TCP6_DEVICE_PATH L"\\Device\\Tcp6"
#define UDP6_DEVICE_PATH L"\\Device\\Udp6"
#define RAWIP6_DEVICE_PATH L"\\Device\\RawIp6"
#define IP6_DEVICE_PATH L"\\Device\\Ip6"

#define AFD_DEVICE_PATH L"\\Device\\Afd\\Endpoint"

#define AFD_SELECT_FILTER_READ   0x99
#define AFD_SELECT_FILTER_WRITE  0x4
#define AFD_SELECT_FILTER_EXCEPT 0x102

typedef enum _EVENT_TYPE {
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE, *PEVENT_TYPE;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  } DUMMYUNIONNAME;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/*typedef struct _AFD_SOCK_CREATE_EA {
	ULONG zero1;
	ULONG unknown1;
	CHAR afdopenstr[16];
	ULONG unknown2;
	ULONG zero2;
	INT iAdressFamily;
	INT iSocketType;
	INT iProtocol;
	ULONG zero3;
	ULONG unknown3;
	ULONG unknown4;
	BYTE data[1];
} AFD_SOCK_CREATE_EA, *PAFD_SOCK_CREATE_EA;*/

typedef struct _AFD_SOCK_CREATE_EA_VISTA {
	FILE_FULL_EA_INFORMATION EaInfo;
	CHAR afdopenstr[16];
	ULONG unknown2;
	ULONG zero2;
	INT iAdressFamily;
	INT iSocketType;
	INT iProtocol;
	ULONG zero3;
	ULONG unknown3;
	ULONG unknown4;
	BYTE data[1];
} AFD_SOCK_CREATE_EA_VISTA, *PAFD_SOCK_CREATE_EA_VISTA;

typedef struct _AFD_SOCK_CREATE_EA_XP {
	FILE_FULL_EA_INFORMATION EaInfo;
	CHAR afdopenstr[16];
	ULONG flags;
	LONG groupid;
	ULONG tdnamesize;
	WCHAR tdname[15];
	BYTE data[1];
} AFD_SOCK_CREATE_EA_XP, *PAFD_SOCK_CREATE_EA_XP;

typedef struct _AFD_SOCK_CREATE_EA {
	union {
		FILE_FULL_EA_INFORMATION EaInfo;
		AFD_SOCK_CREATE_EA_VISTA EaVista;
		AFD_SOCK_CREATE_EA_XP EaXp;
		BYTE eabuffer[sizeof(AFD_SOCK_CREATE_EA_XP)];
	};
} AFD_SOCK_CREATE_EA, *PAFD_SOCK_CREATE_EA;

typedef struct _AFD_BIND_DATA_NEW {
	ULONG ShareMode;
	struct sockaddr Addr;
} AFD_BIND_DATA_NEW, *PAFD_BIND_DATA_NEW;

 typedef struct _AFD_RECEIVED_ACCEPT_DATA_NEW {
     ULONG               SequenceNumber;
     struct sockaddr           Address;
 } AFD_RECEIVED_ACCEPT_DATA_NEW, *PAFD_RECEIVED_ACCEPT_DATA_NEW;

typedef struct _AFD_CONNECT_INFO_NEW {
	PVOID unknown1;
	PVOID zero1;
	PVOID unknown2;
	struct sockaddr Addr;
} AFD_CONNECT_INFO_NEW, *PAFD_CONNECT_INFO_NEW;

#pragma pack(push, 1)
typedef struct _AFD_CONNECTEX_INFO_OLD {
	UINT32 unknown1;
	UINT32 zero1;
	USHORT unknown2;
	struct sockaddr Addr;
} AFD_CONNECTEX_INFO_OLD, *PAFD_CONNECTEX_INFO_OLD;
#pragma pack(pop)

typedef struct _AFD_ACCEPTEX_INFO_OLD {
	ULONG unknown1;
	SOCKET sock;
	ULONG unknown2;
	ULONG localaddrsize;
	ULONG remoteaddrsize;
} AFD_ACCEPTEX_INFO_OLD, *PAFD_ACCEPTEX_INFO_OLD;

typedef struct _AFD_SELECT_DATA_ENTRY {
	SOCKET sock;
	ULONG mode;
	ULONG padding1;
} AFD_SELECT_DATA_ENTRY, *PAFD_SELECT_DATA_ENTRY;

#pragma pack(push, 4)
typedef struct _AFD_SELECT_DATA {
	LARGE_INTEGER Timeout;
	ULONG SocketCount;
	ULONG unknown1;
	AFD_SELECT_DATA_ENTRY SockEntry[1];
} AFD_SELECT_DATA, *PAFD_SELECT_DATA;
#pragma pack(pop)

typedef struct _AFD_SOCK_INFO {
	ULONG cmd;
	ULONG padding1;
	ULONG arg;
	ULONG padding2;
} AFD_SOCK_INFO, *PAFD_SOCK_INFO;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

extern WINAPI NTSTATUS NtOpenKey(
	PHANDLE KeyHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);

extern WINAPI NTSTATUS NtQueryValueKey(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID KeyValueInformation,
	ULONG Length,
	PULONG ResultLength
);

extern WINAPI NTSTATUS NtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
);

extern WINAPI NTSTATUS NtCreateEvent(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	EVENT_TYPE EventType,
	BOOLEAN InitialState
);

extern WINAPI NTSTATUS NtClose(
	HANDLE Handle
);

extern WINAPI NTSTATUS NtDeviceIoControlFile(
	HANDLE FileHandle,
	HANDLE Event,
	PVOID ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength
);

extern WINAPI NTSTATUS NtCancelIoFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock
);

extern WINAPI NTSTATUS NtWaitForSingleObject(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
);

extern WINAPI VOID RtlGetNtVersionNumbers(
	DWORD *MajorVersion,
	DWORD *MinorVersion,
	DWORD *BuildNumber
);

extern WINAPI void RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
	NTSTATUS status
);

extern WINAPI ULONG RtlGetProcessHeaps(
	ULONG MaxNumberOfHeaps,
	PVOID *HeapArray
);

extern WINAPI PVOID RtlAllocateHeap(
	PVOID HeapHandle,
	ULONG Flags,
	SIZE_T Size
);

extern WINAPI BOOLEAN RtlFreeHeap(
	PVOID HeapHandle,
	ULONG Flags,
	PVOID HeapBase
);

static DWORD NTSOCK_WINVER[3] = {0, 0, 0};

BOOL AfdVistaOrHigher(void);
void IncrementStringIntW(WCHAR *wstr, int len);
NTSTATUS NtGetProtocolForSocket(int af, int type, int protocol, LPWSAPROTOCOL_INFOW protocolinfo);
NTSTATUS CheckPointerParameter(const void *p);
NTSTATUS CheckArrayParameter(const void *p, int len, int lmin);
NTSTATUS CheckSocketParameter(SOCKET sock);
NTSTATUS CheckSockAddrParameter(const struct sockaddr *addr, int len, ULONG flags);
SOCKET CreateSocketHandle(int af, int type, int protocol);
ULONG GetSocketContextLength(PSOCKET_CONTEXT sockctx);
ULONG CreateSocketContext(int af, int type, int protocol, PSOCKET_CONTEXT sockctx);

#ifdef __cplusplus
}
#endif

#endif
