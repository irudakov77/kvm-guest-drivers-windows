#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory, ParameterSetName='Install')]
    [switch]$Install,

    [Parameter(ParameterSetName='Install')]
    [Parameter(ParameterSetName='Update')]
    [string]$DllPath = "",

    [Parameter(Mandatory, ParameterSetName='Update')]
    [switch]$Update,

    [Parameter(Mandatory, ParameterSetName='Uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------
# Constants (must match wshviosock.h / install.c)
# -----------------------------------------------------------------------
$TransportName     = "VirtioSocket"
$HelperDllName     = "wshviosock.dll"
$ProtocolName      = "Virtio Vsock STREAM WSH"

$AF_VSOCK_WSH      = 41        # AF_VSOCK (40) + 1
$SockaddrSize      = 12        # sizeof(SOCKADDR_VM)
$SOCK_STREAM       = 1
$PFL_PROTO_ZERO    = 0x00000008  # PFL_MATCHES_PROTOCOL_ZERO
$ServiceFlags      = 0x00020026  # XP1_GRACEFUL_CLOSE | XP1_GUARANTEED_DELIVERY |
                                  # XP1_GUARANTEED_ORDER | XP1_IFS_HANDLES

# GUID {AAE197C1-F7E1-46EE-962A-C524322AD62E} as little-endian GUID bytes
$ProviderGUID = [byte[]](
    0xC1,0x97,0xE1,0xAA,        # Data1 (LE DWORD)
    0xE1,0xF7,                   # Data2 (LE WORD)
    0xEE,0x46,                   # Data3 (LE WORD)
    0x96,0x2A,0xC5,0x24,0x32,0x2A,0xD6,0x2E  # Data4
)

# Mapping binary: Rows=1, Columns=3, {AF_VSOCK_WSH, SocketType=0, Protocol=0}
$Mapping = [byte[]](
    0x01,0x00,0x00,0x00,   # Rows = 1
    0x03,0x00,0x00,0x00,   # Columns = 3
    0x29,0x00,0x00,0x00,   # AddressFamily = 41 (AF_VSOCK_WSH)
    0x01,0x00,0x00,0x00,   # SocketType = 1 (SOCK_STREAM)
    0x00,0x00,0x00,0x00    # Protocol = 0
)

$WinsockParamsKey      = "HKLM:\SYSTEM\CurrentControlSet\Services\Winsock\Parameters"
$WinsockMigrationKey   = "HKLM:\SYSTEM\CurrentControlSet\Services\Winsock\Setup Migration"
$WinsockProvidersKey   = "$WinsockMigrationKey\Providers"
$ViosockWinsockKey     = "HKLM:\SYSTEM\CurrentControlSet\Services\$TransportName\Parameters\Winsock"
$ViosockProto0Key      = "$ViosockWinsockKey\0"
$SystemDllDest         = "$env:SystemRoot\System32\$HelperDllName"
$SysWow64DllDest       = "$env:SystemRoot\SysWOW64\$HelperDllName"

# -----------------------------------------------------------------------
function Add-ViosockTransport {
    $current = (Get-ItemProperty -Path $WinsockParamsKey -Name Transports).Transports
    if ($current -contains $TransportName) {
        Write-Host "Transport '$TransportName' already in Transports list"
        return
    }
    Set-ItemProperty -Path $WinsockParamsKey -Name Transports `
        -Value ($current + $TransportName) -Type MultiString
    Write-Host "Added '$TransportName' to Winsock\Parameters\Transports"
}

function Remove-ViosockTransport {
    $prop = Get-ItemProperty -Path $WinsockParamsKey -Name Transports -ErrorAction SilentlyContinue
    $current = if ($prop) { $prop.Transports } else { $null }
    if ($null -eq $current) { return }
    $updated = $current | Where-Object { $_ -ne $TransportName }
    Set-ItemProperty -Path $WinsockParamsKey -Name Transports -Value $updated -Type MultiString
    Write-Host "Removed '$TransportName' from Winsock\Parameters\Transports"
}

function Add-SetupMigration {
    $prop = Get-ItemProperty -Path $WinsockMigrationKey -Name 'Provider List' -ErrorAction SilentlyContinue
    $current = if ($prop) { $prop.'Provider List' } else { @() }
    if ($current -contains $TransportName) {
        Write-Host "Transport '$TransportName' already in Setup Migration\Provider List"
    } else {
        Set-ItemProperty -Path $WinsockMigrationKey -Name 'Provider List' `
            -Value ($current + $TransportName) -Type MultiString
        Write-Host "Added '$TransportName' to Setup Migration\Provider List"
    }

    New-Item -Path "$WinsockProvidersKey\$TransportName" -Force | Out-Null
    Set-ItemProperty -Path "$WinsockProvidersKey\$TransportName" `
        -Name 'WinSock 2.0 Provider ID' -Value $ProviderGUID -Type Binary
    Write-Host "Created Setup Migration\Providers\$TransportName"

    $ver = (Get-ItemProperty -Path $WinsockMigrationKey -Name 'Setup Version').'Setup Version'
    Set-ItemProperty -Path $WinsockMigrationKey -Name 'Setup Version' -Value ($ver + 1) -Type DWord
    Write-Host "Bumped Setup Version to $($ver + 1)"
}

function Remove-SetupMigration {
    $prop = Get-ItemProperty -Path $WinsockMigrationKey -Name 'Provider List' -ErrorAction SilentlyContinue
    $current = if ($prop) { $prop.'Provider List' } else { $null }
    if ($null -ne $current) {
        $updated = $current | Where-Object { $_ -ne $TransportName }
        Set-ItemProperty -Path $WinsockMigrationKey -Name 'Provider List' -Value $updated -Type MultiString
        Write-Host "Removed '$TransportName' from Setup Migration\Provider List"
    }

    $provKey = "$WinsockProvidersKey\$TransportName"
    if (Test-Path $provKey) {
        Remove-Item -Path $provKey -Recurse -Force
        Write-Host "Removed Setup Migration\Providers\$TransportName"
    }

    $ver = (Get-ItemProperty -Path $WinsockMigrationKey -Name 'Setup Version' -ErrorAction SilentlyContinue).'Setup Version'
    if ($null -ne $ver) {
        Set-ItemProperty -Path $WinsockMigrationKey -Name 'Setup Version' -Value ($ver + 1) -Type DWord
        Write-Host "Bumped Setup Version to $($ver + 1)"
    }
}

function Install-ViosockHelper([string]$src, [string]$dest) {
    Copy-Item -Path $src -Destination $dest -Force
    Write-Host "Copied $src -> $dest"
}

# -----------------------------------------------------------------------
if ($Install) {
    # Locate DLL
    if ($DllPath -eq '') {
        $candidates = @(
            (Join-Path $PSScriptRoot "x64\Win10 Release\$HelperDllName"),
            (Join-Path $PSScriptRoot "x64\Win11 Release\$HelperDllName"),
            (Join-Path $PSScriptRoot "Win32\Win10 Release\$HelperDllName"),
            (Join-Path $PSScriptRoot "Win32\Win11 Release\$HelperDllName")
        )
        $DllPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $DllPath) {
            Write-Error "Cannot find $HelperDllName. Specify -DllPath explicitly."
            exit 1
        }
    }

    if (-not (Test-Path $DllPath)) {
        Write-Error "DLL not found: $DllPath"
        exit 1
    }

    Install-ViosockHelper $DllPath $SystemDllDest

    # On 64-bit OS also install 32-bit DLL to SysWOW64 if it exists next to the 64-bit one
    $wow64Src = Join-Path (Split-Path $DllPath) "..\Win32\$(Split-Path $DllPath -Parent | Split-Path -Leaf)\$HelperDllName"
    if (Test-Path $wow64Src) {
        Install-ViosockHelper (Resolve-Path $wow64Src) $SysWow64DllDest
    }

    Add-ViosockTransport
    Add-SetupMigration

    # Parameters\Winsock key
    New-Item -Path $ViosockWinsockKey -Force | Out-Null
    Set-ItemProperty -Path $ViosockWinsockKey -Name MaxSockAddrLength -Value $SockaddrSize    -Type DWord
    Set-ItemProperty -Path $ViosockWinsockKey -Name MinSockAddrLength -Value $SockaddrSize    -Type DWord
    Set-ItemProperty -Path $ViosockWinsockKey -Name HelperDllName     -Value "%SystemRoot%\System32\$HelperDllName" -Type ExpandString
    Set-ItemProperty -Path $ViosockWinsockKey -Name ProviderGUID      -Value $ProviderGUID    -Type Binary
    Set-ItemProperty -Path $ViosockWinsockKey -Name OfflineCapable     -Value 1               -Type DWord
    Set-ItemProperty -Path $ViosockWinsockKey -Name Mapping            -Value $Mapping        -Type Binary
    Write-Host "Created $ViosockWinsockKey"

    # Protocol entry "0"
    New-Item -Path $ViosockProto0Key -Force | Out-Null
    Set-ItemProperty -Path $ViosockProto0Key -Name Version           -Value 2             -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name AddressFamily     -Value $AF_VSOCK_WSH -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name MaxSockAddrLength -Value $SockaddrSize -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name MinSockAddrLength -Value $SockaddrSize -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name SocketType        -Value $SOCK_STREAM  -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name Protocol          -Value 0             -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name ProtocolMaxOffset -Value 0             -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name ByteOrder         -Value 0             -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name MessageSize       -Value 0             -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name szProtocol        -Value $ProtocolName -Type String
    Set-ItemProperty -Path $ViosockProto0Key -Name ProviderFlags     -Value $PFL_PROTO_ZERO -Type DWord
    Set-ItemProperty -Path $ViosockProto0Key -Name ServiceFlags      -Value $ServiceFlags   -Type DWord
    Write-Host "Created $ViosockProto0Key"

    Write-Host "`nwshviosock installed successfully."

} elseif ($Update) {
    if ($DllPath -eq '') {
        $candidates = @(
            (Join-Path $PSScriptRoot "x64\Win10 Release\$HelperDllName"),
            (Join-Path $PSScriptRoot "x64\Win11 Release\$HelperDllName"),
            (Join-Path $PSScriptRoot "Win32\Win10 Release\$HelperDllName"),
            (Join-Path $PSScriptRoot "Win32\Win11 Release\$HelperDllName")
        )
        $DllPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $DllPath) {
            Write-Error "Cannot find $HelperDllName. Specify -DllPath explicitly."
            exit 1
        }
    }
    Install-ViosockHelper $DllPath $SystemDllDest
    Write-Host "`nwshviosock updated successfully."

} elseif ($Uninstall) {
    Remove-ViosockTransport
    Remove-SetupMigration

    if (Test-Path $ViosockWinsockKey) {
        Remove-Item -Path $ViosockWinsockKey -Recurse -Force
        Write-Host "Removed $ViosockWinsockKey"
    }

    foreach ($dest in @($SystemDllDest, $SysWow64DllDest)) {
        if (Test-Path $dest) {
            Remove-Item -Path $dest -Force
            Write-Host "Removed $dest"
        }
    }

    Write-Host "`nwshviosock uninstalled successfully."
}
