/*
 * Winsock Helper DLL declarations
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

#ifndef _WSHVIOSOCK_H
#define _WSHVIOSOCK_H

#pragma once

#define AF_VSOCK_WSH (AF_VSOCK + 1)
#define VSOCK_PROTO  0

// {9980498C-E732-482B-9F67-924273A56666}
// DEFINE_GUID(GUID_VIOSOCK_STREAM, 0x9980498c, 0xe732, 0x482b, 0x9f, 0x67, 0x92, 0x42, 0x73, 0xa5, 0x66, 0x66);

// {AAE197C1-F7E1-46EE-962A-C524322AD62E}
DEFINE_GUID(GUID_VIOSOCK_STREAM, 0xaae197c1, 0xf7e1, 0x46ee, 0x96, 0x2a, 0xc5, 0x24, 0x32, 0x2a, 0xd6, 0x2e);

#define VIOSOCK_DEVICE_NAME     L"\\Device\\Viosock"
#define VIOSOCK_PROVIDER_NAME   L"VirtioSocket"
#define VIOSOCK_PROTOCOL_STREAM L"Virtio Vsock STREAM WSH"

typedef enum _SOCKADDR_ADDRESS_INFO
{
    SockaddrAddressInfoNormal,
    SockaddrAddressInfoWildcard,
    SockaddrAddressInfoBroadcast,
    SockaddrAddressInfoLoopback
} SOCKADDR_ADDRESS_INFO;

typedef enum _SOCKADDR_ENDPOINT_INFO
{
    SockaddrEndpointInfoNormal,
    SockaddrEndpointInfoWildcard,
    SockaddrEndpointInfoReserved
} SOCKADDR_ENDPOINT_INFO;

typedef struct WINSOCK_MAPPING
{
    DWORD Rows;
    DWORD Columns;
    struct
    {
        DWORD AddressFamily;
        DWORD SocketType;
        DWORD Protocol;
    } Mapping[ANYSIZE_ARRAY];
} WINSOCK_MAPPING, *PWINSOCK_MAPPING;

typedef struct _SOCKADDR_INFO
{
    SOCKADDR_ADDRESS_INFO AddressInfo;
    SOCKADDR_ENDPOINT_INFO EndpointType;
} SOCKADDR_INFO, *PSOCKADDR_INFO;

DWORD WSHGetWinsockMapping(_Out_writes_bytes_to_(MappingLength, return) PWINSOCK_MAPPING Mapping,
                           _In_ DWORD MappingLength);

INT WSHEnumProtocols(_In_opt_ LPINT lpiProtocols,
                     _In_ LPWSTR lpTransportKeyName,
                     _Inout_ LPVOID lpProtocolBuffer,
                     _Inout_ LPDWORD lpdwBufferLength);

INT WSHGetSockaddrType(_In_reads_bytes_(SockaddrLength) PSOCKADDR Sockaddr,
                       _In_ DWORD SockaddrLength,
                       _Out_ PSOCKADDR_INFO SockaddrInfo);

INT WSHGetWildcardSockaddr(_In_ PVOID HelperDllSocketContext,
                           _Out_writes_bytes_(*SockaddrLength) PSOCKADDR Sockaddr,
                           _Inout_ PINT SockaddrLength);

DWORD WSHGetSocketInformation(_In_ PVOID HelperDllSocketContext,
                              _In_ SOCKET SocketHandle,
                              _In_opt_ HANDLE TdiAddressObjectHandle,
                              _In_opt_ HANDLE TdiConnectionObjectHandle,
                              _In_ INT Level,
                              _In_ INT OptionName,
                              _Out_writes_bytes_(*OptionLength) PCHAR OptionValue,
                              _Inout_ PINT OptionLength);

INT WSHSetSocketInformation(_In_ PVOID HelperDllSocketContext,
                            _In_ SOCKET SocketHandle,
                            _In_opt_ HANDLE TdiAddressObjectHandle,
                            _In_opt_ HANDLE TdiConnectionObjectHandle,
                            _In_ INT Level,
                            _In_ INT OptionName,
                            _In_reads_bytes_(OptionLength) PCHAR OptionValue,
                            _In_ INT OptionLength);

INT WSHGetWSAProtocolInfo(_In_ LPWSTR ProviderName,
                          _Outptr_result_buffer_(*ProtocolInfoEntries) LPWSAPROTOCOL_INFOW *ProtocolInfo,
                          _Out_ LPDWORD ProtocolInfoEntries);

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
             _Out_ LPBOOL NeedsCompletion);

INT WSHNotify(_In_ PVOID HelperDllSocketContext,
              _In_ SOCKET SocketHandle,
              _In_opt_ HANDLE TdiAddressObjectHandle,
              _In_opt_ HANDLE TdiConnectionObjectHandle,
              _In_ DWORD NotifyEvent);

INT WSHOpenSocket(_Inout_ PINT AddressFamily,
                  _Inout_ PINT SocketType,
                  _Inout_ PINT Protocol,
                  _Out_ PUNICODE_STRING TransportDeviceName,
                  _Outptr_ PVOID *HelperDllSocketContext,
                  _Out_ PDWORD NotificationEvents);

INT WSHOpenSocket2(_Inout_ PINT AddressFamily,
                   _Inout_ PINT SocketType,
                   _Inout_ PINT Protocol,
                   _In_ GROUP Group,
                   _In_ DWORD Flags,
                   _Out_ PUNICODE_STRING TransportDeviceName,
                   _Outptr_ PVOID *HelperDllSocketContext,
                   _Out_ PDWORD NotificationEvents);

INT WSHGetProviderGuid(_In_ LPCWSTR ProviderName, _Out_ LPGUID ProviderGuid);

INT WSHJoinLeaf(_In_ PVOID HelperDllSocketContext,
                _In_ SOCKET SocketHandle,
                _In_opt_ HANDLE TdiAddressObjectHandle,
                _In_opt_ HANDLE TdiConnectionObjectHandle,
                _In_opt_ PVOID LeafHelperDllSocketContext,
                _In_ SOCKET LeafSocketHandle,
                _In_reads_bytes_(SockaddrLength) PSOCKADDR Sockaddr,
                _In_ DWORD SockaddrLength,
                _In_ DWORD Flags);

INT WSHGetBroadcastSockaddr(_In_ PVOID HelperDllSocketContext,
                            _Out_writes_bytes_(*SockaddrLength) PSOCKADDR Sockaddr,
                            _Inout_ PINT SockaddrLength);

INT WSHAddressToString(_In_reads_bytes_(AddressLength) LPSOCKADDR Address,
                       _In_ INT AddressLength,
                       _In_opt_ LPWSAPROTOCOL_INFOW ProtocolInfo,
                       _Out_writes_to_(*AddressStringLength, *AddressStringLength) LPWSTR AddressString,
                       _Inout_ LPDWORD AddressStringLength);

INT WSHStringToAddress(_In_ LPWSTR AddressString,
                       _In_ DWORD AddressFamily,
                       _In_opt_ LPWSAPROTOCOL_INFOW ProtocolInfo,
                       _Out_ LPSOCKADDR Address,
                       _Inout_ LPDWORD AddressStringLength);

#endif // _WSHVIOSOCK_H
