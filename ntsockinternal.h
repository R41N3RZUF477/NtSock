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

#include "afd_shared.h"

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifdef _WIN64
#define REG_PROTOCOL_ENUM_STR L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64"
#else
#define REG_PROTOCOL_ENUM_STR L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries"
#endif
#define REG_PROTOCOL_VALUE_STR L"PackedCatalogItem"

#define SOCKADDR_NULL_OK    0x1
#define SOCKADDR_NO_AF_OK   0x2
#define SOCKADDR_NO_PORT_OK 0x4

#define AFD_DEVICE_PATH L"\\Device\\Afd\\Endpoint"

#define AFD_SELECT_FILTER_READ   0x99
#define AFD_SELECT_FILTER_WRITE  0x4
#define AFD_SELECT_FILTER_EXCEPT 0x102

typedef enum _SOCKET_STATE
{
	SocketUndefined = -1,
	SocketOpen,
	SocketBound,
	SocketBoundUdp,
	SocketConnected,
	SocketClosed
} SOCKET_STATE, *PSOCKET_STATE;

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

typedef struct _AFD_SOCK_CREATE_EA {
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
} AFD_SOCK_CREATE_EA, *PAFD_SOCK_CREATE_EA;

typedef struct _AFD_BIND_DATA_NEW {
	ULONG ShareMode;
	struct sockaddr Addr;
} AFD_BIND_DATA_NEW, *PAFD_BIND_DATA_NEW;

typedef struct _AFD_CONNECT_INFO_NEW {
	PVOID unknown1;
	PVOID zero1;
	PVOID unknown2;
	struct sockaddr Addr;
} AFD_CONNECT_INFO_NEW, *PAFD_CONNECT_INFO_NEW;

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

extern WINAPI NTSTATUS NtWaitForSingleObject(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
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

void IncrementStringIntW(WCHAR *wstr, int len);
NTSTATUS NtGetProtocolForSocket(int af, int type, int protocol, LPWSAPROTOCOL_INFOW protocolinfo);
NTSTATUS CheckPointerParameter(const void *p);
NTSTATUS CheckArrayParameter(const void *p, int len, int min);
NTSTATUS CheckSocketParameter(SOCKET sock);
NTSTATUS CheckSockAddrParameter(const struct sockaddr *addr, int len, ULONG flags);
ULONG GetSocketContextLength(PSOCKET_CONTEXT sockctx);
ULONG CreateSocketContext(int af, int type, int protocol, PSOCKET_CONTEXT sockctx);
NTSTATUS GetSocketContext(SOCKET sock, PSOCKET_CONTEXT sockctx, PULONG ctxsize);
NTSTATUS SetSocketContext(SOCKET sock, const PSOCKET_CONTEXT sockctx, ULONG ctxsize);

#ifdef __cplusplus
}
#endif

#endif