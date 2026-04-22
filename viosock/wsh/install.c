/*
 * Socket provider registration
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
#include <ws2spi.h>
#include <initguid.h>
#include "wshviosock.h"
#include "..\inc\install.h"

#if defined(EVENT_TRACING)
#include "install.tmh"
#endif

#define VIOSOCK_HELPER_DLL  L"%SystemRoot%\\System32\\wshviosock.dll"
#define MSWSOCK_DLL_PATH    L"%SystemRoot%\\System32\\mswsock.dll"

#define WINSOCK_PARAMS_KEY  L"SYSTEM\\CurrentControlSet\\Services\\Winsock\\Parameters"
#define VIOSOCK_WINSOCK_KEY L"SYSTEM\\CurrentControlSet\\Services\\VirtioSocket\\Parameters\\Winsock"
#define VIOSOCK_PROTO0_KEY  L"SYSTEM\\CurrentControlSet\\Services\\VirtioSocket\\Parameters\\Winsock\\0"

static BOOL ModifyTransportsList(BOOL bAdd)
{
    HKEY hKey;
    LONG lRes;
    DWORD cbData = 0, dwType;
    BOOL bRes = FALSE;

    lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINSOCK_PARAMS_KEY, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
    if (lRes != ERROR_SUCCESS)
    {
        TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "RegOpenKeyExW failed: %ld\n", lRes);
        SetLastError(lRes);
        return FALSE;
    }

    lRes = RegQueryValueExW(hKey, L"Transports", NULL, &dwType, NULL, &cbData);
    if (lRes != ERROR_SUCCESS || dwType != REG_MULTI_SZ || cbData <= sizeof(WCHAR))
    {
        TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "RegQueryValueExW(Transports) failed: %ld\n", lRes);
        SetLastError(lRes != ERROR_SUCCESS ? lRes : ERROR_INVALID_DATA);
        RegCloseKey(hKey);
        return FALSE;
    }

    DWORD cchName = (DWORD)wcslen(VIOSOCK_PROVIDER_NAME) + 1;
    PWSTR pBuf = HeapAlloc(GetProcessHeap(), 0, cbData + cchName * sizeof(WCHAR));
    if (!pBuf)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        RegCloseKey(hKey);
        return FALSE;
    }

    lRes = RegQueryValueExW(hKey, L"Transports", NULL, NULL, (LPBYTE)pBuf, &cbData);
    if (lRes == ERROR_SUCCESS)
    {
        PWSTR p = pBuf;
        BOOL bFound = FALSE;

        while (*p)
        {
            if (_wcsicmp(p, VIOSOCK_PROVIDER_NAME) == 0)
            {
                bFound = TRUE;
                break;
            }
            p += wcslen(p) + 1;
        }

        if (bAdd && !bFound)
        {
            // p points to the terminating L'\0'; append name before it
            memcpy(p, VIOSOCK_PROVIDER_NAME, cchName * sizeof(WCHAR));
            p[cchName] = L'\0';
            cbData += cchName * sizeof(WCHAR);
            lRes = RegSetValueExW(hKey, L"Transports", 0, REG_MULTI_SZ, (LPBYTE)pBuf, cbData);
            bRes = (lRes == ERROR_SUCCESS);
            if (!bRes)
            {
                TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "RegSetValueExW(Transports) failed: %ld\n", lRes);
                SetLastError(lRes);
            }
        }
        else if (!bAdd && bFound)
        {
            DWORD cbEntry = (DWORD)(wcslen(p) + 1) * sizeof(WCHAR);
            DWORD cbTail = cbData - (DWORD)((PBYTE)(p + cbEntry / sizeof(WCHAR)) - (PBYTE)pBuf);
            memmove(p, (PBYTE)p + cbEntry, cbTail);
            cbData -= cbEntry;
            lRes = RegSetValueExW(hKey, L"Transports", 0, REG_MULTI_SZ, (LPBYTE)pBuf, cbData);
            bRes = (lRes == ERROR_SUCCESS);
            if (!bRes)
            {
                TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "RegSetValueExW(Transports) failed: %ld\n", lRes);
                SetLastError(lRes);
            }
        }
        else
        {
            bRes = TRUE;
        }
    }
    else
    {
        TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "RegQueryValueExW(Transports) failed: %ld\n", lRes);
        SetLastError(lRes);
    }

    HeapFree(GetProcessHeap(), 0, pBuf);
    RegCloseKey(hKey);
    return bRes;
}

BOOL InstallProtocol()
{
    HKEY hKey;
    LONG lRes;
    DWORD dwDisp, dwVal;

    struct
    {
        DWORD Rows;
        DWORD Columns;
        struct
        {
            DWORD AddressFamily;
            DWORD SocketType;
            DWORD Protocol;
        } Entry;
    } mapping = {1, 3, {AF_VSOCK_WSH, SOCK_STREAM, 0}};

    TraceEvents(TRACE_LEVEL_INFORMATION, DBG_INSTALL, "--> %s\n", __FUNCTION__);

    if (!ModifyTransportsList(TRUE))
    {
        TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "ModifyTransportsList failed: %lu\n", GetLastError());
        return FALSE;
    }

    lRes = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                           VIOSOCK_WINSOCK_KEY,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           KEY_WRITE,
                           NULL,
                           &hKey,
                           &dwDisp);
    if (lRes != ERROR_SUCCESS)
    {
        TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "RegCreateKeyExW(%ls) failed: %ld\n", VIOSOCK_WINSOCK_KEY, lRes);
        SetLastError(lRes);
        return FALSE;
    }

    dwVal = sizeof(SOCKADDR_VM);
    RegSetValueExW(hKey, L"MaxSockAddrLength", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    RegSetValueExW(hKey, L"MinSockAddrLength", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    RegSetValueExW(hKey,
                   L"HelperDllName",
                   0,
                   REG_EXPAND_SZ,
                   (LPBYTE)VIOSOCK_HELPER_DLL,
                   (DWORD)((wcslen(VIOSOCK_HELPER_DLL) + 1) * sizeof(WCHAR)));
    RegSetValueExW(hKey, L"ProviderGUID", 0, REG_BINARY, (LPBYTE)&GUID_VIOSOCK_STREAM, sizeof(GUID_VIOSOCK_STREAM));
    dwVal = 1;
    RegSetValueExW(hKey, L"OfflineCapable", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    RegSetValueExW(hKey, L"Mapping", 0, REG_BINARY, (LPBYTE)&mapping, sizeof(mapping));

    RegCloseKey(hKey);

    lRes = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                           VIOSOCK_PROTO0_KEY,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           KEY_WRITE,
                           NULL,
                           &hKey,
                           &dwDisp);
    if (lRes != ERROR_SUCCESS)
    {
        TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "RegCreateKeyExW(%ls) failed: %ld\n", VIOSOCK_PROTO0_KEY, lRes);
        SetLastError(lRes);
        return FALSE;
    }

    dwVal = 2;
    RegSetValueExW(hKey, L"Version", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    dwVal = AF_VSOCK_WSH;
    RegSetValueExW(hKey, L"AddressFamily", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    dwVal = sizeof(SOCKADDR_VM);
    RegSetValueExW(hKey, L"MaxSockAddrLength", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    RegSetValueExW(hKey, L"MinSockAddrLength", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    dwVal = SOCK_STREAM;
    RegSetValueExW(hKey, L"SocketType", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    dwVal = VSOCK_PROTO;
    RegSetValueExW(hKey, L"Protocol", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    dwVal = 0;
    RegSetValueExW(hKey, L"ProtocolMaxOffset", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    RegSetValueExW(hKey, L"ByteOrder", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    RegSetValueExW(hKey, L"MessageSize", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    RegSetValueExW(hKey,
                   L"szProtocol",
                   0,
                   REG_SZ,
                   (LPBYTE)VIOSOCK_PROTOCOL_STREAM,
                   (DWORD)((wcslen(VIOSOCK_PROTOCOL_STREAM) + 1) * sizeof(WCHAR)));
    dwVal = PFL_MATCHES_PROTOCOL_ZERO;
    RegSetValueExW(hKey, L"ProviderFlags", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));
    dwVal = XP1_GRACEFUL_CLOSE | XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_IFS_HANDLES;
    RegSetValueExW(hKey, L"ServiceFlags", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(dwVal));

    RegCloseKey(hKey);

    WSAPROTOCOL_INFOW protocolInfo = {0};
    protocolInfo.dwServiceFlags1        = XP1_GRACEFUL_CLOSE | XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_IFS_HANDLES;
    protocolInfo.dwProviderFlags        = PFL_MATCHES_PROTOCOL_ZERO;
    protocolInfo.ProviderId             = GUID_VIOSOCK_STREAM;
    protocolInfo.ProtocolChain.ChainLen = 1;
    protocolInfo.iVersion               = 2;
    protocolInfo.iAddressFamily         = AF_VSOCK_WSH;
    protocolInfo.iMaxSockAddr           = sizeof(SOCKADDR_VM);
    protocolInfo.iMinSockAddr           = sizeof(SOCKADDR_VM);
    protocolInfo.iSocketType            = SOCK_STREAM;
    protocolInfo.iProtocol              = VSOCK_PROTO;
    StringCchCopyW(protocolInfo.szProtocol, WSAPROTOCOL_LEN + 1, VIOSOCK_PROTOCOL_STREAM);

    INT wsaErr = 0;
    GUID guid = GUID_VIOSOCK_STREAM;
    if (WSCInstallProvider(&guid, MSWSOCK_DLL_PATH, &protocolInfo, 1, &wsaErr) == SOCKET_ERROR)
    {
        TraceEvents(TRACE_LEVEL_ERROR, DBG_INSTALL, "WSCInstallProvider failed: %d\n", wsaErr);
        return FALSE;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, DBG_INSTALL, "<-- %s: protocol installed\n", __FUNCTION__);
    return TRUE;
}

BOOL DeinstallProtocol()
{
    LONG lRes;
    INT wsaErr = 0;
    GUID guid = GUID_VIOSOCK_STREAM;

    TraceEvents(TRACE_LEVEL_INFORMATION, DBG_INSTALL, "--> %s\n", __FUNCTION__);

    if (WSCDeinstallProvider(&guid, &wsaErr) == SOCKET_ERROR)
    {
        TraceEvents(TRACE_LEVEL_WARNING, DBG_INSTALL, "WSCDeinstallProvider failed: %d\n", wsaErr);
    }

    ModifyTransportsList(FALSE);

    lRes = RegDeleteTreeW(HKEY_LOCAL_MACHINE, VIOSOCK_WINSOCK_KEY);
    if (lRes != ERROR_SUCCESS && lRes != ERROR_FILE_NOT_FOUND)
    {
        TraceEvents(TRACE_LEVEL_WARNING, DBG_INSTALL, "RegDeleteTreeW(%ls) failed: %ld\n", VIOSOCK_WINSOCK_KEY, lRes);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, DBG_INSTALL, "<-- %s\n", __FUNCTION__);
    return TRUE;
}
