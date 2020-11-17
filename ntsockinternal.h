#ifndef _NTSOCK_INTERNAL_H_
#define _NTSOCK_INTERNAL_H_

#ifdef _MSC_VER
#include <winternl.h>
#else
#include <ntstatus.h>
#endif
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "ntdll.lib")
#endif

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

#ifndef __UNICODE_STRING_DEFINED
#define __UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

#ifndef __STRING_DEFINED
#define __STRING_DEFINED
typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} STRING, *PSTRING;
typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;
#endif

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

#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF 0x00000003
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

#define REG_TCPIP_LINKAGE_STR L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Linkage"
#define REG_ROUTE_VALUE_STR L"Route"

#define REG_TCPIP_INTERFACES_STR L"Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"
#define REG_ENABLEDHCP_VALUE_STR L"EnableDHCP"
#define REG_DHCPIP_VALUE_STR L"DhcpIPAddress"
#define REG_IP_VALUE_STR L"IPAddress"
#define REG_DHCPDOMAIN_VALUE_STR L"DhcpDomain"
#define REG_DHCPNAMESRV_VALUE_STR L"DhcpNameServer"
#define REG_NAMESRV_VALUE_STR L"NameServer"
#define REG_DHCPSNMASK_VALUE_STR L"DhcpSubnetMask"
#define REG_SNMASK_VALUE_STR L"SubnetMask"
#define REG_DHCPSRV_VALUE_STR L"DhcpServer"
#define REG_DHCPDEFGW_VALUE_STR L"DhcpDefaultGateway"
#define REG_DEFGW_VALUE_STR L"DefaultGateway"

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

#define NTDLL_STR L"ntdll.dll"
#define NTCANCELIOFILEEX_STR "NtCancelIoFileEx"

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

#ifndef __OBJECT_ATTRIBUTES_DEFINED
#define __OBJECT_ATTRIBUTES_DEFINED
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

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
     ULONG SequenceNumber;
     struct sockaddr Address;
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

extern __declspec(dllimport) NTSTATUS WINAPI NtOpenKey(
	PHANDLE KeyHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);

extern __declspec(dllimport) NTSTATUS WINAPI NtQueryValueKey(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID KeyValueInformation,
	ULONG Length,
	PULONG ResultLength
);

extern __declspec(dllimport) NTSTATUS WINAPI NtCreateFile(
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

extern __declspec(dllimport) NTSTATUS WINAPI NtCreateEvent(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	EVENT_TYPE EventType,
	BOOLEAN InitialState
);

extern __declspec(dllimport) NTSTATUS WINAPI NtClose(
	HANDLE Handle
);

extern __declspec(dllimport) NTSTATUS WINAPI NtDeviceIoControlFile(
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

extern __declspec(dllimport) NTSTATUS WINAPI NtCancelIoFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock
);

extern __declspec(dllimport) NTSTATUS WINAPI NtWaitForSingleObject(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
);

extern __declspec(dllimport) VOID WINAPI RtlGetNtVersionNumbers(
	DWORD *MajorVersion,
	DWORD *MinorVersion,
	DWORD *BuildNumber
);

extern __declspec(dllimport) void WINAPI RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
	NTSTATUS status
);

extern __declspec(dllimport) ULONG WINAPI RtlGetProcessHeaps(
	ULONG MaxNumberOfHeaps,
	PVOID *HeapArray
);

extern __declspec(dllimport) PVOID WINAPI RtlAllocateHeap(
	PVOID HeapHandle,
	ULONG Flags,
	SIZE_T Size
);

extern __declspec(dllimport) BOOLEAN WINAPI RtlFreeHeap(
	PVOID HeapHandle,
	ULONG Flags,
	PVOID HeapBase
);

extern __declspec(dllimport) NTSTATUS WINAPI LdrGetDllHandle(
	PWORD pwPath,
	PVOID Unused,
	PUNICODE_STRING ModuleFileName,
	PHANDLE ModuleHandle
);

extern __declspec(dllimport) NTSTATUS WINAPI LdrGetProcedureAddress(
	HANDLE ModuleHandle,
	PANSI_STRING FunctionName,
	WORD Oridinal,
	PVOID *FunctionAddress
);

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

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW 0x80000005
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND 0xC0000225
#endif
#ifndef STATUS_CANNOT_MAKE
#define STATUS_CANNOT_MAKE 0xC00002EA
#endif

#ifdef __cplusplus
}
#endif

#endif
