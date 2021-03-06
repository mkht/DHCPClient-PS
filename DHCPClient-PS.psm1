using namespace System.Net.Sockets

using module '.\Class\Enums.psm1'
using module '.\Class\DhcpOptionObject.psm1'
using module '.\Class\DhcpPacket.psm1'
using module '.\Class\DhcpDiscoverPacket.psm1'
using module '.\Class\DhcpInformPacket.psm1'
using module '.\Class\DhcpRequestPacket.psm1'
using module '.\Class\DhcpReleasePacket.psm1'

function Send-DhcpPacket {
    [CmdletBinding()]
    [OutputType([DhcpPacket])]
    param (
        [Parameter(Mandatory = $true)]
        [DhcpPacket]$Packet,

        [Parameter()]
        [ValidateNotNull()]
        [ipaddress]$Server = [ipaddress]::Broadcast,

        [Parameter()]
        [byte]$Timeout = 10,

        [Parameter()]
        [switch]$NoReceive,

        [Parameter()]
        [switch]$LongPoll,

        [Parameter()]
        [switch]$NoXidFilter
    )

    try {
        # UDP Port 67 (Client-to-Server)
        $ServerEndPoint = [Net.EndPoint](New-Object Net.IPEndPoint($Server, 67))

        # UDP Port 68 (Server-to-Client)
        $ClientEndPoint = [Net.EndPoint](New-Object Net.IPEndPoint([IPAddress]::Any, 68))

        # Create UDP socket
        $UdpClient = [UdpClient]::new()

        # Set socket options
        $UdpClient.EnableBroadcast = $true
        $UdpClient.ExclusiveAddressUse = $false
        $UdpClient.Client.ReceiveTimeout = $Timeout * 1000
        # Workaround for the issue that the UdpClient socket option SO_REUSEADDR is not set correctly on Linux.
        # https://github.com/dotnet/runtime/issues/27274#issuecomment-528210926
        if ($IsLinux) {
            $UdpClient.Client.SetSocketOption([SocketOptionLevel]::Socket, [SocketOptionName]::ReuseAddress, $true)
            Set-REUSEADDR -Socket $UdpClient
        }

        # Bind local endpoint
        $UdpClient.Client.Bind($ClientEndPoint)

        # Send the packet
        $PacketBytes = $Packet.GetPacketBytes()
        $BytesSent = $UdpClient.Send($PacketBytes, $PacketBytes.Length, $ServerEndPoint)
        Write-Verbose ('{0} bytes packet was sent to {1}.' -f $BytesSent, $ServerEndPoint.ToString())

        # Receive
        if (-not $NoReceive) {
            $PIdx = 0
            $PacketReceived = 0
            while ($true) {
                $BytesReceived = $UdpClient.Receive([ref]$ClientEndPoint)
                if ($BytesReceived.Length -gt 0) {
                    $PIdx++
                    Write-Verbose ('[{0}] {1} bytes packet was received.' -f $PIdx, $BytesReceived.Length)
                    # DHCP packet should be grater equal 240 bytes.
                    if ($BytesReceived.Length -ge 240) {
                        $DhcpPacket = Read-DhcpPacket $BytesReceived
                        Write-Verbose ('[{0}] Parsing DHCP packet succeeded.' -f $PIdx)
                        Write-Verbose ('[{0}] MsgType:{1} | XID:{2} | ServerIP:{3} | AssignedIP:{4}' -f $PIdx, $DhcpPacket.MessageType, ($DhcpPacket.XID -join ','), $DhcpPacket.SIAddr, $DhcpPacket.YIAddr)
                        if ($NoXidFilter -or (IsXidEqual -First $Packet.XID -Second $DhcpPacket.XID)) {
                            $PacketReceived++
                            $DhcpPacket
                        }
                        else {
                            Write-Verbose ('[{0}] Transaction ID of the received packet is not matched with source ID, Dropped it.' -f $PIdx)
                        }
                    }
                    else {
                        Write-Verbose ('[{0}] It is not valid DHCP packet. Ignored.' -f $PIdx)
                    }
                }
                if ((-not $LongPoll) -and ($PacketReceived -ge 1)) { break }
                Start-Sleep -Milliseconds 500
            }
        }
    }
    catch [SocketException] {
        if ($_.Exception.SocketErrorCode -eq [SocketError]::TimedOut) {
            # Timeout
            if (-not $LongPoll) {
                Write-Error -Exception $_.Exception
            }
            else {
                Write-Verbose 'Socket timeout. Polling ended.'
            }
        }
        else {
            Write-Error -Exception $_.Exception
        }
    }
    catch {
        Write-Error -Exception $_.Exception
    }
    finally {
        if ($null -ne $UdpClient) {
            $UdpClient.Close()
            $UdpClient.Dispose()
        }
    }
}


function Invoke-DhcpDiscover {
    [CmdletBinding()]
    [OutputType([DhcpPacket])]
    param (
        # Client MAC Address
        [Parameter()]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress = 'AABBCCDDEEFF',

        # Request IP address (option)
        [Parameter()]
        [ValidateNotNull()]
        [ipaddress]$RequestIPAddress,

        # Transaction-ID (option)
        [Parameter()]
        [ValidateCount(4, 4)]
        [byte[]]$TransactionId,

        # Client-identifier (option)
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId,

        # Parameter request list (option)
        [Parameter()]
        [byte[]]$ParameterRequestList,

        [Parameter()]
        [bool]$BroadcastFlag = $false,

        [Parameter()]
        [ValidateRange(1, 255)]
        [byte]$Timeout = 10,

        [Parameter()]
        [switch]$LongPoll,

        [Parameter()]
        [switch]$NoXidFilter
    )

    [PhysicalAddress]$_MacAddress = [PhysicalAddress]::Parse($MacAddress.Trim().ToUpper() -replace '[\.:-]')

    $Discover = [DhcpDiscoverPacket]::new($_MacAddress)
    $Discover.BroadcastFlag = $BroadcastFlag

    if ($PSBoundParameters.ContainsKey('RequestIPAddress')) {
        $Discover.RequestedIPAddress = $RequestIPAddress
    }

    if ($PSBoundParameters.ContainsKey('TransactionId')) {
        $Discover.XID = $TransactionId
    }

    if ($PSBoundParameters.ContainsKey('ParameterRequestList')) {
        $Discover.ParameterRequestList = $ParameterRequestList
    }

    if ($PSBoundParameters.ContainsKey('ClientId')) {
        $Discover.AddDhcpOptions(
            [DhcpOptionObject]::new(
                [DhcpOption]::ClientId,
                $ClientId
            )
        )
    }

    Write-Verbose 'Trying to send a DHCP Discover packet.'
    Write-Verbose ('MsgType:{0} | XID:{1} | ClientMAC:{2}' -f `
            $Discover.MessageType, ($Discover.XID -join ','), ($Discover.CHAddr.GetAddressBytes().ForEach( { $_.ToString('X2') }) -join '-'))

    Send-DhcpPacket -Packet $Discover -Timeout $Timeout -Server ([IPAddress]::Broadcast) -LongPoll:$LongPoll -NoXidFilter:$NoXidFilter
}

function Invoke-DhcpInform {
    [CmdletBinding(DefaultParameterSetName = 'Property')]
    [OutputType([DhcpPacket])]
    param (
        # DHCP Ack packet
        [Parameter(Mandatory = $true, ValueFromPipeline = $true , ParameterSetName = 'Packet')]
        [ValidateNotNull()]
        [DhcpPacket]$DhcpAckPacket,

        # Client MAC Address (option)
        [Parameter(ParameterSetName = 'Property')]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress = 'AABBCCDDEEFF',

        # Client IP address (mandatory)
        [Parameter(Mandatory = $true, ParameterSetName = 'Property')]
        [ValidateNotNull()]
        [ipaddress]$ClientIPAddress,

        # DHCP Server IP address (option)
        [Parameter(ParameterSetName = 'Property')]
        [ValidateNotNull()]
        [ipaddress]$ServerIPAddress = [ipaddress]::Any,

        # Transaction-ID (option)
        [Parameter()]
        [ValidateCount(4, 4)]
        [byte[]]$TransactionId,

        # Client-identifier (option)
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId,

        # Parameter request list (option)
        [Parameter()]
        [byte[]]$ParameterRequestList,

        [Parameter()]
        [bool]$BroadcastFlag = $false,

        [Parameter()]
        [ValidateRange(1, 255)]
        [byte]$Timeout = 10,

        [Parameter()]
        [switch]$LongPoll,

        [Parameter()]
        [switch]$NoXidFilter
    )

    if ($PSCmdlet.ParameterSetName -eq 'Packet') {
        $p = @{
            CIAddr = $DhcpAckPacket.YIAddr
            CHAddr = $DhcpAckPacket.CHAddr
            SIAddr = if ($sid = $DhcpAckPacket._DhcpOptionsList[[byte][DhcpOption]::ServerId]) { $sid.Value }else { [ipaddress]::Any }
        }
        $ServerIPAddress = $p.SIAddr
        $Inform = [DhcpInformPacket]::new($p.CIAddr, $p.SIAddr, $p.CHAddr)
    }
    else {
        [PhysicalAddress]$_MacAddress = [PhysicalAddress]::Parse($MacAddress.Trim().ToUpper() -replace '[\.:-]')
        if ($PSBoundParameters.ContainsKey('ServerIPAddress')) {
            $Inform = [DhcpInformPacket]::new($ClientIPAddress, $ServerIPAddress, $_MacAddress)
        }
        else {
            $Inform = [DhcpInformPacket]::new($ClientIPAddress, $_MacAddress)
        }
    }

    $Inform.BroadcastFlag = $BroadcastFlag

    if ($PSBoundParameters.ContainsKey('TransactionId')) {
        $Inform.XID = $TransactionId
    }

    if ($PSBoundParameters.ContainsKey('ClientId')) {
        $Inform.AddDhcpOptions(
            [DhcpOptionObject]::new(
                [DhcpOption]::ClientId,
                $ClientId
            )
        )
    }

    if ($PSBoundParameters.ContainsKey('ParameterRequestList')) {
        $Inform.ParameterRequestList = $ParameterRequestList
    }

    Write-Verbose 'Trying to send a DHCP Inform packet.'
    Write-Verbose ('MsgType:{0} | ClientIP:{1} | ServerIP:{2} | ClientMAC:{3}' -f `
            $Inform.MessageType, $Inform.ClientIPAddress, $Inform.ServerIPAddress, ($Inform.CHAddr.GetAddressBytes().ForEach( { $_.ToString('X2') }) -join '-'))

    if ($ServerIPAddress -eq [ipaddress]::Any) {
        $SendTo = [IPAddress]::Broadcast
    }
    else {
        $SendTo = $ServerIPAddress
    }

    Send-DhcpPacket -Packet $Inform -Timeout $Timeout -Server $SendTo -LongPoll:$LongPoll -NoXidFilter:$NoXidFilter
}

function Invoke-DhcpRequest {
    [CmdletBinding(DefaultParameterSetName = 'Property')]
    [OutputType([DhcpPacket])]
    param (
        # DHCP Offer packet
        [Parameter(Mandatory = $true, ValueFromPipeline = $true , ParameterSetName = 'Packet')]
        [ValidateNotNull()]
        [DhcpPacket]$DhcpOfferPacket,

        # Client MAC Address (mandatory)
        [Parameter(Mandatory = $true, ParameterSetName = 'Property')]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress,

        # Request IP address (mandatory)
        [Parameter(Mandatory = $true, ParameterSetName = 'Property')]
        [ValidateNotNull()]
        [ipaddress]$RequestIPAddress,

        # DHCP Server IP address (mandatory)
        [Parameter(Mandatory = $true, ParameterSetName = 'Property')]
        [ValidateNotNull()]
        [ipaddress]$ServerIPAddress,

        # Transaction-ID (option)
        [Parameter()]
        [ValidateCount(4, 4)]
        [byte[]]$TransactionId,

        # Client-identifier (option)
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId,

        # Parameter request list (option)
        [Parameter()]
        [byte[]]$ParameterRequestList,

        [Parameter()]
        [bool]$BroadcastFlag = $false,

        [Parameter()]
        [ValidateRange(1, 255)]
        [byte]$Timeout = 10,

        [Parameter()]
        [switch]$LongPoll,

        [Parameter()]
        [switch]$NoXidFilter
    )

    if ($PSCmdlet.ParameterSetName -eq 'Packet') {
        $Offer = @{
            YIAddr = $DhcpOfferPacket.YIAddr
            CHAddr = $DhcpOfferPacket.CHAddr
            SIAddr = if ($sid = $DhcpOfferPacket._DhcpOptionsList[[byte][DhcpOption]::ServerId]) { $sid.Value }else { [ipaddress]::Any }
        }
        $Request = [DhcpRequestPacket]::new($Offer.YIAddr, $Offer.SIAddr, $Offer.CHAddr)
    }
    else {
        [PhysicalAddress]$_MacAddress = [PhysicalAddress]::Parse($MacAddress.Trim().ToUpper() -replace '[\.:-]')
        $Request = [DhcpRequestPacket]::new($RequestIPAddress, $ServerIPAddress, $_MacAddress)
    }

    $Request.BroadcastFlag = $BroadcastFlag

    if ($PSBoundParameters.ContainsKey('TransactionId')) {
        $Request.XID = $TransactionId
    }

    if ($PSBoundParameters.ContainsKey('ClientId')) {
        $Request.AddDhcpOptions(
            [DhcpOptionObject]::new(
                [DhcpOption]::ClientId,
                $ClientId
            )
        )
    }

    if ($PSBoundParameters.ContainsKey('ParameterRequestList')) {
        $Request.ParameterRequestList = $ParameterRequestList
    }

    Write-Verbose 'Trying to send a DHCP Request packet.'
    Write-Verbose ('MsgType:{0} | RequestIP:{1} | ServerIP:{2} | ClientMAC:{3}' -f `
            $Request.MessageType, $Request.RequestedIPAddress, $Request.ServerIPAddress, ($Request.CHAddr.GetAddressBytes().ForEach( { $_.ToString('X2') }) -join '-'))

    Send-DhcpPacket -Packet $Request -Timeout $Timeout -Server ([IPAddress]::Broadcast) -LongPoll:$LongPoll -NoXidFilter:$NoXidFilter
}

function Invoke-DhcpRelease {
    [CmdletBinding(DefaultParameterSetName = 'Property')]
    [OutputType([void])]
    param (
        # DHCP ACK packet
        [Parameter(Mandatory = $true, ValueFromPipeline = $true , ParameterSetName = 'Packet')]
        [ValidateNotNull()]
        [DhcpPacket]$DhcpAckPacket,

        # Client MAC Address (mandatory)
        [Parameter(Mandatory = $true, ParameterSetName = 'Property')]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress,

        # Client IP address (mandatory)
        [Parameter(Mandatory = $true, ParameterSetName = 'Property')]
        [ValidateNotNull()]
        [ipaddress]$ClientIPAddress,

        # DHCP Server IP address (mandatory)
        [Parameter(Mandatory = $true, ParameterSetName = 'Property')]
        [ValidateNotNull()]
        [ipaddress]$ServerIPAddress,

        # Transaction-ID (option)
        [Parameter()]
        [ValidateCount(4, 4)]
        [byte[]]$TransactionId,

        # Client-identifier (option)
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId
    )

    if ($PSCmdlet.ParameterSetName -eq 'Packet') {
        $p = @{
            YIAddr = $DhcpAckPacket.YIAddr
            CHAddr = $DhcpAckPacket.CHAddr
            SIAddr = if ($sid = $DhcpAckPacket._DhcpOptionsList[[byte][DhcpOption]::ServerId]) { $sid.Value }else { [ipaddress]::Any }
        }
        $Release = [DhcpReleasePacket]::new($p.YIAddr, $p.SIAddr, $p.CHAddr)
        $ServerIPAddress = $p.SIAddr
    }
    else {
        [PhysicalAddress]$_MacAddress = [PhysicalAddress]::Parse($MacAddress.Trim().ToUpper() -replace '[\.:-]')
        $Release = [DhcpReleasePacket]::new($ClientIPAddress, $ServerIPAddress, $_MacAddress)
    }

    if ($PSBoundParameters.ContainsKey('TransactionId')) {
        $Release.XID = $TransactionId
    }

    if ($PSBoundParameters.ContainsKey('ClientId')) {
        $Release.AddDhcpOptions(
            [DhcpOptionObject]::new(
                [DhcpOption]::ClientId,
                $ClientId
            )
        )
    }

    Write-Verbose 'Trying to send a DHCP Release packet.'
    Write-Verbose ('MsgType:{0} | ClientIP:{1} | ServerIP:{2} | ClientMAC:{3}' -f `
            $Release.MessageType, $Release.ClientIPAddress, $Release.ServerIPAddress, ($Release.CHAddr.GetAddressBytes().ForEach( { $_.ToString('X2') }) -join '-'))

    Send-DhcpPacket -Packet $Release -Server $ServerIPAddress -NoReceive
}


function Invoke-DhcpCustomMessage {
    [CmdletBinding(DefaultParameterSetName = 'NoReceive')]
    [OutputType([DhcpPacket])]
    param (
        # DHCP Offer packet
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [DhcpPacket]$DhcpPacket,

        [Parameter()]
        [ValidateNotNull()]
        [ipaddress]$ServerIPAddress = [ipaddress]::Broadcast,

        [Parameter()]
        [ValidateRange(1, 255)]
        [byte]$Timeout = 10,

        [Parameter(ParameterSetName = 'LongPoll')]
        [switch]$LongPoll,

        [Parameter()]
        [switch]$NoXidFilter,

        [Parameter(ParameterSetName = 'NoReceive')]
        [switch]$NoReceive
    )

    Write-Verbose 'Trying to send a DHCP packet.'
    Write-Verbose ('MsgType:{0} | ClientMAC:{1}' -f `
            $DhcpPacket.MessageType, ($DhcpPacket.CHAddr.GetAddressBytes().ForEach( { $_.ToString('X2') }) -join '-'))

    Send-DhcpPacket -Packet $DhcpPacket -Timeout $Timeout -Server $ServerIPAddress -NoReceive:$NoReceive -LongPoll:$LongPoll -NoXidFilter:$NoXidFilter
}

function New-DhcpPacket {
    [CmdletBinding()]
    [OutputType([DhcpPacket])]
    Param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet(
            'DHCPDISCOVER', 'DHCPOFFER', 'DHCPREQUEST',
            'DHCPDECLINE', 'DHCPACK', 'DHCPNAK',
            'DHCPRELEASE', 'DHCPINFORM', 'DHCPFORCERENEW'
        )]
        [DhcpMessageType]$Type,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateCount(4, 4)]
        [byte[]]$TransactionId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress = 'AABBCCDDEEFF',

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [ipaddress]$ServerIPAddress = [ipaddress]::Any,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId,

        [Parameter()]
        [byte[]]$ParameterRequestList,

        [Parameter()]
        [ValidateNotNull()]
        [System.Collections.IDictionary]$Options = @{},

        [Parameter()]
        [bool]$BroadcastFlag = $false
    )

    $DhcpPacket = [DhcpPacket]::new()
    $DhcpPacket.MessageType = $Type

    # Broadcast flag
    $DhcpPacket.BroadcastFlag = $BroadcastFlag

    # XID
    if ($PSBoundParameters.ContainsKey('TransactionId')) {
        $DhcpPacket.XID = $TransactionId
    }
    else {
        [Random]::new().NextBytes($DhcpPacket.XID)
    }

    # MAC address
    [PhysicalAddress]$_MacAddress = [PhysicalAddress]::Parse($MacAddress.Trim().ToUpper() -replace '[\.:-]')
    $DhcpPacket.CHAddr = $_MacAddress
    $DhcpPacket.AddDhcpOptions([DhcpOptionObject]::new([DhcpOption]::ClientId, (([byte[]]0x01) + $_MacAddress.GetAddressBytes())))

    # Server IP
    if ($PSBoundParameters.ContainsKey('ServerIPAddress')) {
        $DhcpPacket.AddDhcpOptions([DhcpOptionObject]::new([DhcpOption]::ServerId, $ServerIPAddress.GetAddressBytes()))
    }

    # Client ID
    if ($PSBoundParameters.ContainsKey('ClientId')) {
        $DhcpPacket.AddDhcpOptions([DhcpOptionObject]::new([DhcpOption]::ClientId, (([byte[]]0x00) + $ClientId)))
    }

    # Parameter request list
    if ($PSBoundParameters.ContainsKey('ParameterRequestList')) {
        $DhcpPacket.AddDhcpOptions([DhcpOptionObject]::new([DhcpOption]::ParameterRequestList, $ParameterRequestList))
    }

    # Options
    $KeyArray = $Options.Keys.ForEach( { $_ })
    $ValueArray = [Object[]]::new($Options.Values.Count)
    $Options.Values.CopyTo($ValueArray, 0)

    for ($i = 0; $i -lt $KeyArray.Count; $i++) {
        if (-not ($KeyArray[$i] -as [byte])) {
            continue
        }

        [byte[]]$ValueObject = $null
        $_v = $ValueArray[$i]
        if ( $null -eq $_v ) {
            $ValueObject = $null
        }
        elseif ( $_v -as [byte[]] ) {
            $ValueObject = ($_v -as [byte[]])
        }
        elseif ($_v -as [string[]] -and ($KeyArray[$i] -in ([dhcpoption]::DomainSearch, [dhcpoption]::SIPServersDHCPOption))) {
            if ($KeyArray[$i] -eq [dhcpoption]::DomainSearch) {
                # RFC 3397
                $ValueObject = [DhcpOptionObject]::ConvertDomainSearchListToBytes([string[]]$_v)
            }
            elseif ($KeyArray[$i] -eq [dhcpoption]::SIPServersDHCPOption) {
                # RFC 3361
                if ($_v -as [ipaddress[]]) {
                    $ValueObject = [byte[]](0x01) + ([ipaddress[]]$_v).ForEach( { $_.GetAddressBytes() })
                }
                else {
                    $ValueObject = [byte[]](0x00) + [DhcpOptionObject]::ConvertDomainSearchListToBytes([string[]]$_v)
                }
            }
        }
        elseif ( $_v -is [string] ) {
            $ValueObject = [System.Text.Encoding]::UTF8.GetBytes($_v)
        }
        elseif ( $_v -is [ipaddress] ) {
            $ValueObject = $_v.GetAddressBytes()
        }
        elseif ( $_v -as [ipaddress[]] ) {
            $ValueObject = ([ipaddress[]]$_v).ForEach( { $_.GetAddressBytes() })
        }
        elseif ( $_v -is [PhysicalAddress] ) {
            $ValueObject = $_v.GetAddressBytes()
        }
        elseif ( $_v -is [timespan] ) {
            if ($KeyArray[$i] -eq [dhcpoption]::TimeOffset) {
                # Int32
                $ValueObject = [System.BitConverter]::GetBytes([ipaddress]::HostToNetworkOrder([int32]($_v.Ticks / 1e7)))[0..3]
            }
            else {
                # UInt32
                # [ipaddress]::HostToNetworkOrder cannot handle UInt32 correctly, so it uses the lower 4 bytes of Int64 to handle it.
                $ValueObject = [System.BitConverter]::GetBytes([ipaddress]::HostToNetworkOrder([int64]($_v.Ticks / 1e7)))[4..7]
            }
        }
        else { continue }

        try {
            $DhcpPacket.AddDhcpOptions([DhcpOptionObject]::new($KeyArray[$i], $ValueObject))
        }
        catch {
            Write-Error -Exception $_.Exception
        }
    }

    # End flag
    $DhcpPacket.AddDhcpOptions([DhcpOptionObject]::new([DhcpOption]::End, $null))

    return $DhcpPacket
}


function Read-DhcpPacket {
    param (
        [byte[]]$Packet
    )

    $DhcpResponse = $null
    try {
        $DhcpResponse = [DhcpPacket]::Parse($Packet)
    }
    catch {
        Write-Error -Exception $_.Exception
    }
    return $DhcpResponse
}

function IsXidEqual {
    param (
        [byte[]]$First,
        [byte[]]$Second
    )
    if ($First.Count -ne 4) { return $false }
    if ($Second.Count -ne 4) { return $false }
    try {
        [UInt32]$FirstInt = [System.BitConverter]::ToUInt32($First, 0)
        [UInt32]$SecondInt = [System.BitConverter]::ToUInt32($Second, 0)
    }
    catch {
        Write-Error -Exception $_.Exception
        return $false
    }
    return ($FirstInt -eq $SecondInt)
}

function Set-REUSEADDR {
    param (
        [UdpClient]$Socket
    )

    try {
        $null = ([SocketFix] -is [type])
    }
    catch {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

public class SocketFix
{
    public unsafe static int SetREUSEADDR(int socket){
        int value = 1;
        return SocketFix.setsockopt(socket, 1, 2, &value, sizeof(int));
    }

    [DllImport("libc", SetLastError = true)]
    private unsafe static extern int setsockopt(int socket, int level, int option_name, void* option_value, uint option_len);
}
'@ -Language CSharp -CompilerOptions @('/unsafe')
    }

    try {
        $null = [SocketFix]::SetREUSEADDR($Socket.Client.Handle.ToInt32())
    }
    catch {
        Write-Error -Exception $_.Exception
    }
}

Export-ModuleMember -Function @(
    'Invoke-DhcpDiscover'
    'Invoke-DhcpInform'
    'Invoke-DhcpRequest'
    'Invoke-DhcpRelease'
    'Invoke-DhcpCustomMessage'
    'New-DhcpPacket'
)
