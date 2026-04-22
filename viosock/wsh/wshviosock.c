/*
 * Winsock Helper DLL entry points
 *
 * Copyright (c) 2026 Virtuozzo International GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "precomp.h"
#include <initguid.h>
#include "wshviosock.h"

#if defined(EVENT_TRACING)
#include "wshviosock.tmh"
#endif

#define SOL_SOCKET_WSH 0xFFFE
#define SO_WSH_CONTEXT 1

static WINSOCK_MAPPING g_WinsockMapping = {
                                                                                                    .Rows = 1,
                                                                                                    .Columns = 3,
                                                                                                    .Mapping = {{.AddressFamily = AF_VSOCK_WSH,
                                                                                                                 .SocketType = SOCK_STREAM,
                                                                                                                 .Protocol = 0}},
};

static WSAPROTOCOL_INFOW g_ProtocolInfoW = {
                                                                                                    .dwServiceFlags1 = XP1_GRACEFUL_CLOSE |
                                                                                                                       XP1_GUARANTEED_DELIVERY |
                                                                                                                       XP1_GUARANTEED_ORDER |
                                                                                                                       XP1_IFS_HANDLES,
                                                                                                    .dwServiceFlags2 = 0,
                                                                                                    .dwServiceFlags3 = 0,
                                                                                                    .dwServiceFlags4 = 0,
                                                                                                    .dwProviderFlags = PFL_MATCHES_PROTOCOL_ZERO,
                                                                                                    .ProviderId = {0},
                                                                                                    .dwCatalogEntryId = 0,
                                                                                                    .ProtocolChain.ChainLen = BASE_PROTOCOL,
                                                                                                    .ProtocolChain.ChainEntries = {0},
                                                                                                    .iVersion = 0,
                                                                                                    .iAddressFamily = AF_VSOCK_WSH,
                                                                                                    .iMaxSockAddr = sizeof(struct
                                                                                                                           sockaddr_vm),
                                                                                                    .iMinSockAddr = sizeof(struct
                                                                                                                           sockaddr_vm),
                                                                                                    .iSocketType = SOCK_STREAM,
                                                                                                    .iProtocol = VSOCK_PROTO,
                                                                                                    .iProtocolMaxOffset = 0,
                                                                                                    .iNetworkByteOrder = LITTLEENDIAN,
                                                                                                    .iSecurityScheme = SECURITY_PROTOCOL_NONE,
                                                                                                    .dwMessageSize = 0,
                                                                                                    .dwProviderReserved = 0,
                                                                                                    .szProtocol = VIOSOCK_PROTOCOL_STREAM,
};

DWORD WSHGetWinsockMapping(_Out_writes_bytes_to_(MappingLength, return) PWINSOCK_MAPPING Mapping,
                           _In_ DWORD MappingLength)
{
    if (MappingLength >= sizeof(g_WinsockMapping))
    {
        memmove(Mapping, &g_WinsockMapping, sizeof(g_WinsockMapping));
    }
    return sizeof(g_WinsockMapping);
}

INT WSHEnumProtocols(_In_opt_ LPINT lpiProtocols,
                     _In_ LPWSTR lpTransportKeyName,
                     _Inout_ LPVOID lpProtocolBuffer,
                     _Inout_ LPDWORD lpdwBufferLength)
{
    static const WCHAR szProtocol[] = VIOSOCK_PROTOCOL_STREAM;
    DWORD cbRequired = sizeof(PROTOCOL_INFOW) + sizeof(szProtocol);
    PROTOCOL_INFOW *pInfo = (PROTOCOL_INFOW *)lpProtocolBuffer;
    INT iResult;

    UNREFERENCED_PARAMETER(lpiProtocols);
    UNREFERENCED_PARAMETER(lpTransportKeyName);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (*lpdwBufferLength >= cbRequired)
    {
        pInfo->dwServiceFlags = XP1_GRACEFUL_CLOSE | XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER;
        pInfo->iAddressFamily = AF_VSOCK_WSH;
        pInfo->iMaxSockAddr = sizeof(SOCKADDR_VM);
        pInfo->iMinSockAddr = sizeof(SOCKADDR_VM);
        pInfo->iSocketType = SOCK_STREAM;
        pInfo->iProtocol = VSOCK_PROTO;
        pInfo->dwMessageSize = 0;
        pInfo->lpProtocol = (LPWSTR)((PCHAR)lpProtocolBuffer + sizeof(PROTOCOL_INFOW));
        StringCchCopyW(pInfo->lpProtocol, ARRAYSIZE(szProtocol), szProtocol);
        iResult = 1;
    }
    else
    {
        iResult = SOCKET_ERROR;
    }

    *lpdwBufferLength = cbRequired;

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return iResult;
}

INT WSHGetSockaddrType(_In_reads_bytes_(SockaddrLength) PSOCKADDR Sockaddr,
                       _In_ DWORD SockaddrLength,
                       _Out_ PSOCKADDR_INFO SockaddrInfo)
{
    PSOCKADDR_VM addr = (PSOCKADDR_VM)Sockaddr;

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (SockaddrLength < sizeof(SOCKADDR_VM))
    {
        return WSAEFAULT;
    }

    if (addr->svm_family != AF_VSOCK_WSH)
    {
        return WSAEAFNOSUPPORT;
    }

    SockaddrInfo->AddressInfo = (addr->svm_cid == VMADDR_CID_ANY)   ? SockaddrAddressInfoWildcard
                             : (addr->svm_cid == VMADDR_CID_LOCAL) ? SockaddrAddressInfoLoopback
                                                                   : SockaddrAddressInfoNormal;

    SockaddrInfo->EndpointType = (addr->svm_port == VMADDR_PORT_ANY) ? SockaddrEndpointInfoWildcard
                                                                     : SockaddrEndpointInfoNormal;

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return NO_ERROR;
}

INT WSHGetWildcardSockaddr(_In_ PVOID HelperDllSocketContext,
                           _Out_writes_bytes_(*SockaddrLength) PSOCKADDR Sockaddr,
                           _Inout_ PINT SockaddrLength)
{
    PSOCKADDR_VM addr = (PSOCKADDR_VM)Sockaddr;

    UNREFERENCED_PARAMETER(HelperDllSocketContext);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if ((DWORD)*SockaddrLength < sizeof(SOCKADDR_VM))
    {
        return WSAEFAULT;
    }

    *SockaddrLength = sizeof(SOCKADDR_VM);
    ZeroMemory(addr, sizeof(SOCKADDR_VM));
    addr->svm_family = AF_VSOCK_WSH;
    addr->svm_cid = (UINT)VMADDR_CID_ANY;
    addr->svm_port = (UINT)VMADDR_PORT_ANY;

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return NO_ERROR;
}

DWORD WSHGetSocketInformation(_In_ PVOID HelperDllSocketContext,
                              _In_ SOCKET SocketHandle,
                              _In_opt_ HANDLE TdiAddressObjectHandle,
                              _In_opt_ HANDLE TdiConnectionObjectHandle,
                              _In_ INT Level,
                              _In_ INT OptionName,
                              _Out_writes_bytes_(*OptionLength) PCHAR OptionValue,
                              _Inout_ PINT OptionLength)
{
    UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle);
    UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (Level != SOL_SOCKET_WSH || OptionName != SO_WSH_CONTEXT)
    {
        return WSAENOPROTOOPT;
    }

    if (OptionValue)
    {
        if ((DWORD)*OptionLength < sizeof(PVOID))
        {
            return WSAEFAULT;
        }
        *(PVOID *)OptionValue = HelperDllSocketContext;
    }

    *OptionLength = sizeof(PVOID);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return NO_ERROR;
}

INT WSHSetSocketInformation(_In_ PVOID HelperDllSocketContext,
                            _In_ SOCKET SocketHandle,
                            _In_opt_ HANDLE TdiAddressObjectHandle,
                            _In_opt_ HANDLE TdiConnectionObjectHandle,
                            _In_ INT Level,
                            _In_ INT OptionName,
                            _In_reads_bytes_(OptionLength) PCHAR OptionValue,
                            _In_ INT OptionLength)
{
    UNREFERENCED_PARAMETER(HelperDllSocketContext);
    UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle);
    UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(OptionValue);
    UNREFERENCED_PARAMETER(OptionLength);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (Level != SOL_SOCKET_WSH)
    {
        return WSAEINVAL;
    }

    if (OptionName != SO_WSH_CONTEXT)
    {
        return WSAEINVAL;
    }

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return NO_ERROR;
}

INT WSHGetWSAProtocolInfo(_In_ LPWSTR ProviderName,
                          _Outptr_result_buffer_(*ProtocolInfoEntries) LPWSAPROTOCOL_INFOW *ProtocolInfo,
                          _Out_ LPDWORD ProtocolInfoEntries)
{
    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (!ProviderName || !ProtocolInfo || !ProtocolInfoEntries)
    {
        return WSAEFAULT;
    }

    if (_wcsicmp(ProviderName, VIOSOCK_PROVIDER_NAME) != 0)
    {
        return WSAEINVAL;
    }

    *ProtocolInfo = &g_ProtocolInfoW;
    *ProtocolInfoEntries = 1;

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return NO_ERROR;
}

INT WSHJoinLeaf(_In_ PVOID HelperDllSocketContext,
                _In_ SOCKET SocketHandle,
                _In_opt_ HANDLE TdiAddressObjectHandle,
                _In_opt_ HANDLE TdiConnectionObjectHandle,
                _In_opt_ PVOID LeafHelperDllSocketContext,
                _In_ SOCKET LeafSocketHandle,
                _In_reads_bytes_(SockaddrLength) PSOCKADDR Sockaddr,
                _In_ DWORD SockaddrLength,
                _In_ DWORD Flags)
{
    UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle);
    UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(LeafHelperDllSocketContext);
    UNREFERENCED_PARAMETER(LeafSocketHandle);
    UNREFERENCED_PARAMETER(Sockaddr);
    UNREFERENCED_PARAMETER(SockaddrLength);
    UNREFERENCED_PARAMETER(Flags);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    return HelperDllSocketContext == NULL ? WSAEINVAL : NO_ERROR;
}

INT WSHIoctl(_In_ PVOID HelperDllSocketContext,
             _In_ SOCKET SocketHandle,
             _In_opt_ HANDLE TdiAddressObjectHandle,
             _In_opt_ HANDLE TdiConnectionObjectHandle,
             _In_ DWORD IoControlCode,
             _In_reads_bytes_(InputBufferLength) LPVOID InputBuffer,
             _In_ DWORD InputBufferLength,
             _Out_writes_bytes_to_(OutputBufferLength, *NumberOfBytesReturned) LPVOID OutputBuffer,
             _In_ DWORD OutputBufferLength,
             _Out_ LPDWORD NumberOfBytesReturned,
             _Inout_opt_ LPWSAOVERLAPPED Overlapped,
             _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine,
             _Out_ LPBOOL NeedsCompletion)
{
    UNREFERENCED_PARAMETER(HelperDllSocketContext);
    UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle);
    UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(IoControlCode);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(NumberOfBytesReturned);
    UNREFERENCED_PARAMETER(Overlapped);
    UNREFERENCED_PARAMETER(CompletionRoutine);
    UNREFERENCED_PARAMETER(NeedsCompletion);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    return WSAEINVAL;
}

INT WSHNotify(_In_ PVOID HelperDllSocketContext,
              _In_ SOCKET SocketHandle,
              _In_opt_ HANDLE TdiAddressObjectHandle,
              _In_opt_ HANDLE TdiConnectionObjectHandle,
              _In_ DWORD NotifyEvent)
{
    UNREFERENCED_PARAMETER(HelperDllSocketContext);
    UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle);
    UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(NotifyEvent);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    return NO_ERROR;
}

INT WSHOpenSocket(_Inout_ PINT AddressFamily,
                  _Inout_ PINT SocketType,
                  _Inout_ PINT Protocol,
                  _Out_ PUNICODE_STRING TransportDeviceName,
                  _Outptr_ PVOID *HelperDllSocketContext,
                  _Out_ PDWORD NotificationEvents)
{
    return WSHOpenSocket2(AddressFamily,
                          SocketType,
                          Protocol,
                          0,
                          0,
                          TransportDeviceName,
                          HelperDllSocketContext,
                          NotificationEvents);
}

INT WSHOpenSocket2(_Inout_ PINT AddressFamily,
                   _Inout_ PINT SocketType,
                   _Inout_ PINT Protocol,
                   _In_ GROUP Group,
                   _In_ DWORD Flags,
                   _Out_ PUNICODE_STRING TransportDeviceName,
                   _Outptr_ PVOID *HelperDllSocketContext,
                   _Out_ PDWORD NotificationEvents)
{
    UNREFERENCED_PARAMETER(Group);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (*AddressFamily != AF_VSOCK_WSH || *SocketType != SOCK_STREAM || *Protocol != VSOCK_PROTO ||
        (Flags & ~(DWORD)WSA_FLAG_OVERLAPPED))
    {
        return WSAEINVAL;
    }

    RtlInitUnicodeString(TransportDeviceName, VIOSOCK_DEVICE_NAME);
    *HelperDllSocketContext = (PVOID)(ULONG_PTR)(USHORT)*AddressFamily;
    *NotificationEvents = 0;

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return NO_ERROR;
}

INT WSHGetProviderGuid(_In_ LPCWSTR ProviderName, _Out_ LPGUID ProviderGuid)
{
    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (!ProviderName || !ProviderGuid)
    {
        return WSAEFAULT;
    }

    if (_wcsicmp(ProviderName, VIOSOCK_PROVIDER_NAME) != 0)
    {
        return WSAEINVAL;
    }

    *ProviderGuid = GUID_VIOSOCK_STREAM;
    return NO_ERROR;
}

INT WSHGetBroadcastSockaddr(_In_ PVOID HelperDllSocketContext,
                            _Out_writes_bytes_(*SockaddrLength) PSOCKADDR Sockaddr,
                            _Inout_ PINT SockaddrLength)
{
    UNREFERENCED_PARAMETER(HelperDllSocketContext);
    UNREFERENCED_PARAMETER(Sockaddr);
    UNREFERENCED_PARAMETER(SockaddrLength);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    return WSAEOPNOTSUPP;
}

INT WSHAddressToString(_In_reads_bytes_(AddressLength) LPSOCKADDR Address,
                       _In_ INT AddressLength,
                       _In_opt_ LPWSAPROTOCOL_INFOW ProtocolInfo,
                       _Out_writes_to_(*AddressStringLength, *AddressStringLength) LPWSTR AddressString,
                       _Inout_ LPDWORD AddressStringLength)
{
    PSOCKADDR_VM addr = (PSOCKADDR_VM)Address;
    size_t cchRemaining;

    UNREFERENCED_PARAMETER(ProtocolInfo);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (!Address || AddressLength < sizeof(SOCKADDR_VM) || !AddressStringLength ||
        (!AddressString && *AddressStringLength))
    {
        return WSAEFAULT;
    }

    if (addr->svm_family != AF_VSOCK_WSH)
    {
        return WSAEINVAL;
    }

    if (FAILED(StringCchPrintfExW(AddressString,
                                  *AddressStringLength,
                                  NULL,
                                  &cchRemaining,
                                  STRSAFE_NO_TRUNCATION,
                                  L"%u:%u",
                                  addr->svm_cid,
                                  addr->svm_port)))
    {
        *AddressStringLength = 0;
        return WSAEFAULT;
    }

    *AddressStringLength = (DWORD)(*AddressStringLength - (DWORD)cchRemaining);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return NO_ERROR;
}

INT WSHStringToAddress(_In_ LPWSTR AddressString,
                       _In_ DWORD AddressFamily,
                       _In_opt_ LPWSAPROTOCOL_INFOW ProtocolInfo,
                       _Out_ LPSOCKADDR Address,
                       _Inout_ LPDWORD AddressStringLength)
{
    PSOCKADDR_VM addr = (PSOCKADDR_VM)Address;
    ULONG cid, port;

    UNREFERENCED_PARAMETER(ProtocolInfo);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "--> %s\n", __FUNCTION__);

    if (AddressFamily != AF_VSOCK_WSH)
    {
        return WSAEINVAL;
    }

    if (!AddressString || !Address || !AddressStringLength || *AddressStringLength < sizeof(SOCKADDR_VM))
    {
        return WSAEFAULT;
    }

    ZeroMemory(addr, sizeof(SOCKADDR_VM));

    if (swscanf_s(AddressString, L"%u:%u", &cid, &port) != 2)
    {
        return WSAEINVAL;
    }

    addr->svm_family = AF_VSOCK_WSH;
    addr->svm_cid = cid;
    addr->svm_port = port;
    *AddressStringLength = sizeof(SOCKADDR_VM);

    TraceEvents(TRACE_LEVEL_VERBOSE, DBG_SOCKET, "<-- %s\n", __FUNCTION__);
    return NO_ERROR;
}
