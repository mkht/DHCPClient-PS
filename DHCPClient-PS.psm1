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
        [ValidateCount(240, 1024)]
        [byte[]]$Packet,

        [Parameter()]
        [ValidateNotNull()]
        [ipaddress]$Server = [ipaddress]::Broadcast,

        [Parameter()]
        [byte]$Timeout = 10,

        [Parameter()]
        [switch]$NoReceive,

        [Parameter()]
        [switch]$LongPoll
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
        $BytesSent = $UdpClient.Send($Packet, $Packet.Length, $ServerEndPoint)
        Write-Verbose ('{0} bytes packet was sent to {1}.' -f $BytesSent, $ServerEndPoint.ToString())

        # Receive
        if (-not $NoReceive) {
            $PacketReceived = 0
            while ($true) {
                $BytesReceived = $UdpClient.Receive([ref]$ClientEndPoint)
                if ($BytesReceived.Length -gt 0) {
                    Write-Verbose ('{0} bytes packet was received.' -f $BytesReceived.Length)
                    # DHCP packet should be grater equal 240 bytes.
                    if ($BytesReceived.Length -ge 240) {
                        $DhcpPacket = Read-DhcpPacket $BytesReceived
                        Write-Verbose 'Parsing DHCP packet succeeded.'
                        Write-Verbose ('MsgType:{0} | ServerIP:{1} | AssignedIP:{2}' -f $DhcpPacket.MessageType, $DhcpPacket.SIAddr, $DhcpPacket.YIAddr)
                        $DhcpPacket
                    }
                    else {
                        Write-Verbose 'It is not valid DHCP packet. Ignored.'
                    }
                }
                $PacketReceived++
                if ((-not $LongPoll) -or ($PacketReceived -gt 10)) { break }
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
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress = 'AABBCCDDEEFF',

        # Request IP address (option)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ipaddress]$RequestIPAddress,

        # Client-identifier (option)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId,

        # Parameter request list (option)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [byte[]]$ParameterRequestList,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [bool]$BroadcastFlag = $false,

        [Parameter()]
        [ValidateRange(1, 255)]
        [byte]$Timeout = 10,

        [Parameter()]
        [switch]$LongPoll
    )

    [PhysicalAddress]$_MacAddress = [PhysicalAddress]::Parse($MacAddress.Trim().ToUpper() -replace '[\.:-]')

    $Discover = [DhcpDiscoverPacket]::new($_MacAddress)
    $Discover.BroadcastFlag = $BroadcastFlag

    if ($PSBoundParameters.ContainsKey('RequestIPAddress')) {
        $Discover.RequestedIPAddress = $RequestIPAddress
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
    Write-Verbose ('MsgType:{0} | ClientMAC:{1}' -f `
            $Discover.MessageType, ($Discover.CHAddr.GetAddressBytes().ForEach( { $_.ToString('X2') }) -join '-'))

    $Message = $Discover.GetPacketBytes()
    Send-DhcpPacket -Packet $Message -Timeout $Timeout -Server ([IPAddress]::Broadcast) -LongPoll:$LongPoll
}

function Invoke-DhcpInform {
    [CmdletBinding(DefaultParameterSetName = 'Packet')]
    [OutputType([DhcpPacket])]
    param (
        # DHCP Ack packet
        [Parameter(Mandatory = $true, ValueFromPipeline = $true , ParameterSetName = 'Packet')]
        [ValidateNotNull()]
        [DhcpPacket]$DhcpAckPacket,

        # Client MAC Address (option)
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress = 'AABBCCDDEEFF',

        # Client IP address (mandatory)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ipaddress]$ClientIPAddress,

        # DHCP Server IP address (option)
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ipaddress]$ServerIPAddress = [ipaddress]::Any,

        # Client-identifier (option)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId,

        # Parameter request list (option)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [byte[]]$ParameterRequestList,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [bool]$BroadcastFlag = $false,

        [Parameter()]
        [ValidateRange(1, 255)]
        [byte]$Timeout = 10,

        [Parameter()]
        [switch]$LongPoll
    )

    if ($PSCmdlet.ParameterSetName -eq 'Packet') {
        $p = @{
            CIAddr = $DhcpAckPacket.YIAddr
            CHAddr = $DhcpAckPacket.CHAddr
            SIAddr = if ($sid = $DhcpAckPacket._DhcpOptionsList[[DhcpOption]::ServerId]) { $sid.Value }else { [ipaddress]::Any }
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

    $Message = $Inform.GetPacketBytes()
    Send-DhcpPacket -Packet $Message -Timeout $Timeout -Server $SendTo -LongPoll:$LongPoll
}

function Invoke-DhcpRequest {
    [CmdletBinding(DefaultParameterSetName = 'Packet')]
    [OutputType([DhcpPacket])]
    param (
        # DHCP Offer packet
        [Parameter(Mandatory = $true, ValueFromPipeline = $true , ParameterSetName = 'Packet')]
        [ValidateNotNull()]
        [DhcpPacket]$DhcpOfferPacket,

        # Client MAC Address (mandatory)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress,

        # Request IP address (mandatory)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ipaddress]$RequestIPAddress,

        # DHCP Server IP address (mandatory)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ipaddress]$ServerIPAddress,

        # Client-identifier (option)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId,

        # Parameter request list (option)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [byte[]]$ParameterRequestList,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [bool]$BroadcastFlag = $false,

        [Parameter()]
        [ValidateRange(1, 255)]
        [byte]$Timeout = 10
    )

    if ($PSCmdlet.ParameterSetName -eq 'Packet') {
        $Offer = @{
            YIAddr = $DhcpOfferPacket.YIAddr
            CHAddr = $DhcpOfferPacket.CHAddr
            SIAddr = if ($sid = $DhcpOfferPacket._DhcpOptionsList[[DhcpOption]::ServerId]) { $sid.Value }else { [ipaddress]::Any }
        }
        $Request = [DhcpRequestPacket]::new($Offer.YIAddr, $Offer.SIAddr, $Offer.CHAddr)
    }
    else {
        [PhysicalAddress]$_MacAddress = [PhysicalAddress]::Parse($MacAddress.Trim().ToUpper() -replace '[\.:-]')
        $Request = [DhcpRequestPacket]::new($RequestIPAddress, $ServerIPAddress, $_MacAddress)
    }

    $Request.BroadcastFlag = $BroadcastFlag

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

    $Message = $Request.GetPacketBytes()
    Send-DhcpPacket -Packet $Message -Timeout $Timeout -Server ([IPAddress]::Broadcast)
}

function Invoke-DhcpRelease {
    [CmdletBinding(DefaultParameterSetName = 'Packet')]
    [OutputType([void])]
    param (
        # DHCP ACK packet
        [Parameter(Mandatory = $true, ValueFromPipeline = $true , ParameterSetName = 'Packet')]
        [ValidateNotNull()]
        [DhcpPacket]$DhcpAckPacket,

        # Client MAC Address (mandatory)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ValidateScript( { ($_.Trim().ToUpper() -replace '[\.:-]') -as [PhysicalAddress] })]
        [string]$MacAddress,

        # Client IP address (mandatory)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ipaddress]$ClientIPAddress,

        # DHCP Server IP address (mandatory)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Property')]
        [ipaddress]$ServerIPAddress,

        # Client-identifier (option)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$ClientId
    )

    if ($PSCmdlet.ParameterSetName -eq 'Packet') {
        $p = @{
            YIAddr = $DhcpAckPacket.YIAddr
            CHAddr = $DhcpAckPacket.CHAddr
            SIAddr = if ($sid = $DhcpAckPacket._DhcpOptionsList[[DhcpOption]::ServerId]) { $sid.Value }else { [ipaddress]::Any }
        }
        $Release = [DhcpReleasePacket]::new($p.YIAddr, $p.SIAddr, $p.CHAddr)
        $ServerIPAddress = $p.SIAddr
    }
    else {
        [PhysicalAddress]$_MacAddress = [PhysicalAddress]::Parse($MacAddress.Trim().ToUpper() -replace '[\.:-]')
        $Release = [DhcpReleasePacket]::new($ClientIPAddress, $ServerIPAddress, $_MacAddress)
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

    $Message = $Release.GetPacketBytes()
    Send-DhcpPacket -Packet $Message -Server $ServerIPAddress -NoReceive
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
        [ipaddress]$ServerIPAddress = [ipaddress]::Broadcast,

        [Parameter()]
        [ValidateRange(1, 255)]
        [byte]$Timeout = 10,

        [Parameter(ParameterSetName = 'LongPoll')]
        [switch]$LongPoll,

        [Parameter(ParameterSetName = 'NoReceive')]
        [switch]$NoReceive
    )

    Write-Verbose 'Trying to send a DHCP packet.'
    Write-Verbose ('MsgType:{0} | ClientMAC:{1}' -f `
            $DhcpPacket.MessageType, ($DhcpPacket.CHAddr.GetAddressBytes().ForEach( { $_.ToString('X2') }) -join '-'))

    $Message = $DhcpPacket.GetPacketBytes()
    Send-DhcpPacket -Packet $Message -Timeout $Timeout -Server $ServerIPAddress -NoReceive:$NoReceive -LongPoll:$LongPoll
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

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [byte[]]$ParameterRequestList,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [HashTable]$Options,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
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
    if ($PSBoundParameters.ContainsKey('ServerIP')) {
        $DhcpPacket.AddDhcpOptions([DhcpOptionObject]::new([DhcpOption]::ServerId, $ServerIP.GetAddressBytes()))
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
    :op_for foreach ($op in $Options.Keys) {
        if (-not ($op -as [DhcpOption])) {
            continue
        }

        [byte[]]$ValueObject = $null
        switch ($Options[$op]) {
            { $null -eq $_ } {
                $ValueObject = $null
                break
            }
            { $_ -as [byte[]] } {
                $ValueObject = ($_ -as [byte[]])
                break
            }
            { $_ -is [string] } {
                $ValueObject = [System.Text.Encoding]::UTF8.GetBytes($_)
                break
            }
            { $_ -is [ipaddress] } {
                $ValueObject = $_.GetAddressBytes()
                break
            }
            { $_ -as [ipaddress[]] } {
                $ValueObject = ([ipaddress[]]$_).ForEach( { $_.GetAddressBytes() })
                break
            }
            { $_ -is [PhysicalAddress] } {
                $ValueObject = $_.GetAddressBytes()
                break
            }
            Default { continue op_for }
        }

        try {
            $DhcpPacket.AddDhcpOptions([DhcpOptionObject]::new($op, $ValueObject))
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
