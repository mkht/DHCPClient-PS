# DHCPClient-PS

## Description
PowerShell DHCP Client module for testing purpose.  
This module can broadcast DHCP discover, request, and release packets with arbitrary parameters, and receive responses from servers. You can test the health of DHCP servers or check for the presence of multiple DHCP servers in a subnet.

## Install
You can install the module from PowerShell Gallery.

```PowerShell
Install-Module -Name DHCPClient-PS
```

## Platforms
+ Windows PowerShell 5.0 and 5.1
+ PowerShell 7.0 and above (Windows, macOS and Linux)

## Usage

- [Invoke-DhcpDiscover](#Invoke-DhcpDiscover)
- [Invoke-DhcpRequest](#Invoke-DhcpRequest)
- [Invoke-DhcpRelease](#Invoke-DhcpRelease)
- [Invoke-DhcpCustomMessage](#Invoke-DhcpCustomMessage)
- [New-DhcpPacket](#New-DhcpPacket)
- [About DhcpPacket class](#About-DhcpPacket-class)

----
### Invoke-DhcpDiscover
Send DHCP Discover message, then receive Offer messages from DHCP server(s).

#### Examples
When you run this function without any parameters, it sends a message with the default MAC address (`AA-BB-CC-DD-EE-FF`) and receive a fastest offer response.

```PowerShell
PS> $Response = Invoke-DhcpDiscover
PS> $Response | Select-Object MessageType, YIAddr, SIAddr, CHAddr, Options

MessageType : DHCPOFFER
YIAddr      : 192.168.0.4
SIAddr      : 192.168.0.1
CHAddr      : AABBCCDDEEFF
Options     : {@{OptionCode=1; Name=SubnetMask; Value=255.255.255.0; Length=4}...}
```

#### Parameters

* **`-MacAddress`**  [string]
Specifies MAC address for the request.  
Default: `AA-BB-CC-DD-EE-FF`

* **`-RequestIPAddress`**  [System.Net.IPAddress]
Specifies IP address that the client requests to be assigned.  
This is corresponding to DHCP option 50.

* **`-ClientId`**  [byte[]]
Specifies the client-identifier value.  
This is corresponding to DHCP option 61.  
Default: The value of MAC address.

* **`-ParameterRequestList`**  [byte[]]
Specifies request values for configuration parameters.  
This is corresponding to DHCP option 55.  
Default: `1, 3, 4, 15, 31, 33, 42, 119, 252`

* **`-Timeout`**  [byte]
Specifies how long seconds to wait until a response is received.  
Default: 10

* **`-LongPoll`**  [switch]
By default, only the first response received will output. If this switch is specified, it will wait until the timeout period and output all responses received. This is useful to check whether there are multiple DHCP servers in a subnet.

#### Outputs
[DhcpPacket](#About-DhcpPacket-class) object

----
### Invoke-DhcpRequest
Send DHCP Request message, then receive ACK messages from DHCP server.

#### Examples
```PowerShell
PS> $Response = Invoke-DhcpRequest -MacAddress AABBCCDDEEFF -RequestIPAddress 192.168.0.4 -ServerIPAddress 192.168.0.1
PS> $Response | Select-Object MessageType, YIAddr, SIAddr, CHAddr, Options

MessageType : DHCPACK
YIAddr      : 192.168.0.4
SIAddr      : 0.0.0.0
CHAddr      : AABBCCDDEEFF
Options     : {@{OptionCode=1; Name=SubnetMask; Value=255.255.255.0; Length=4}...}
```

You can also input DHCP Offer packet object from pipeline.
```PowerShell
PS> Invoke-DhcpDiscover | Invoke-DhcpRequest
```

#### Parameters

* **`-MacAddress`**  [string]
Specifies MAC address for the request.  
This is mandatory parameter.

* **`-RequestIPAddress`**  [System.Net.IPAddress]
Specifies IP address that the client requests to be assigned.  
This is corresponding to DHCP option 50.  
This is mandatory parameter.

* **`-ServerIPAddress`**  [System.Net.IPAddress]
Specifies DHCP server address.  
This is corresponding to DHCP option 54.  
This is mandatory parameter.

* **`-ClientId`**  [byte[]]
Specifies the client-identifier value.  
This is corresponding to DHCP option 61.  
Default: The value of MAC address.

* **`-ParameterRequestList`**  [byte[]]
Specifies request values for configuration parameters.  
This is corresponding to DHCP option 55.  
Default: `1, 3, 4, 15, 31, 33, 42, 119, 252`

* **`-Timeout`**  [byte]
Specifies how long seconds to wait until a response is received.  
Default: 10

#### Outputs
[DhcpPacket](#About-DhcpPacket-class) object

----
### Invoke-DhcpRelease
Send DHCP Release message.

#### Examples
```PowerShell
PS> Invoke-DhcpRelease -MacAddress AABBCCDDEEFF -ClientIPAddress 192.168.0.4 -ServerIPAddress 192.168.0.1
```

You can also input DHCP Ack packet object from pipeline.
```PowerShell
PS> $AckResponse = Invoke-DHCPDiscover | Invoke-DHCPRequest
PS> $AckResponse | Invoke-DhcpRelease
```

#### Parameters

* **`-MacAddress`**  [string]
Specifies MAC address for the request.  
This is mandatory parameter.

* **`-ClientIPAddress`**  [System.Net.IPAddress]
Specifies IP address that the client requests to be released.  
This is mandatory parameter.

* **`-ServerIPAddress`**  [System.Net.IPAddress]
Specifies DHCP server address.  
This is mandatory parameter.

* **`-ClientId`**  [byte[]]
Specifies the client-identifier value.  
This is corresponding to DHCP option 61.  
Default: The value of MAC address.

#### Outputs
This function does not output anything.

----
### Invoke-DhcpCustomMessage
Send any DHCP message. This can be used when you need to specify detailed DHCP options, but requires knowledge of DHCP messages.

#### Examples
```PowerShell
PS> $Options = @{
        12 = 'HOSTNAME'
        50 = [IPAddress]'192.168.0.10'
        55 = [byte[]](1,3,6,15,31,33,43,44)
        60 = 'MSFT 5.0'
        61 = [byte[]](0x01,0x1a,0x2b,0x3c,0x4d,0x5e,0x6f)
    }
PS> $Message = New-DhcpPacket -Type DHCPDISCOVER -TransactionId (0,1,2,3) -MacAddress 1A2B3C4D5E6F -ServerIPAddress 192.168.0.1 -Options $Options
PS> $Response = $Message | Invoke-DhcpCustomMessage
```

#### Parameters

* **`-DhcpPacket`**  [[DhcpPacket](#About-DhcpPacket-class)]
Specifies DHCP packet object that is created by `New-DhcpPacket`.
This is mandatory parameter.

* **`-ServerIPAddress`**  [System.Net.IPAddress]
Specifies IP address to the message will be sent.
Default: `255.255.255.255` (Broadcast address)

* **`-Timeout`**  [byte]
Specifies how long seconds to wait until a response is received.
Default: 10

* **`-LongPoll`**  [switch]
By default, only the first response received will output. If this switch is specified, it will wait until the timeout period and output all responses received. This is useful to check whether there are multiple DHCP servers in a subnet.

* **`-NoReceive`**  [switch]
If this switch is specified, this function will only send a message and not trying to receive any response.

#### Outputs
[DhcpPacket](#About-DhcpPacket-class) object

----
### New-DhcpPacket
Create [DhcpPacket](#About-DhcpPacket-class) object.

#### Examples
```PowerShell
PS> $Options = @{
        12 = 'HOSTNAME'
        50 = [IPAddress]'192.168.0.10'
        55 = [byte[]](1,3,6,15,31,33,43,44)
        60 = 'MSFT 5.0'
        61 = [byte[]](0x01,0x1a,0x2b,0x3c,0x4d,0x5e,0x6f)
    }
PS> $Message = New-DhcpPacket -Type DHCPDISCOVER -TransactionId (0,1,2,3) -MacAddress 1A2B3C4D5E6F -ServerIPAddress 192.168.0.1 -Options $Options
```

#### Parameters

* **`-Type`**  [string]
Specifies DHCP message type.
You can select from `DHCPDISCOVER`, `DHCPOFFER`, `DHCPREQUEST`, `DHCPDECLINE`, `DHCPACK`, `DHCPNAK`, `DHCPRELEASE`, `DHCPINFORM`, `DHCPFORCERENEW`
This is mandatory parameter.

* **`-TransactionId`**  [byte[]]
Specifies transaction ID (xid) as 4-length byte array.
If does not specified, random number will set.

* **`-MacAddress`**  [string]
Specifies MAC address for the request.
Default: `AA-BB-CC-DD-EE-FF`

* **`-ServerIPAddress`**  [System.Net.IPAddress]
Specifies DHCP server address.
Default: `0.0.0.0` (Any address)

* **`-ClientId`**  [byte[]]
Specifies the client-identifier value.
This is corresponding to DHCP option 61.
Default: The value of MAC address.

* **`-ParameterRequestList`**  [byte[]]
Specifies request values for configuration parameters.
This is corresponding to DHCP option 55.

* **`-Options`**  [HashTable]
Specifies DHCP configuration option parameters.
You should specify the param as hashtable that the key as option number and value as bytes. (See example)


#### Outputs
[DhcpPacket](#About-DhcpPacket-class) object

----
### About DhcpPacket class

`[DhcpPacket]` is representation class for DHCP packet.

#### Constructor
This class is not published as public. You should create instance by `New-DhcpPacket` function.

#### Members
Most of the members correspond to the structure of a DHCP packet. See RFC 2131 for details.

|Name|Type|Description|
|:----|:----|:----|
|OpCode|[byte]|Message op code|
|HType|[byte]|Hardware address type|
|HLen|[byte]|Hardware address type|
|Hops|[byte]|Normally client sets to zero.|
|XID|[byte[]]|Transaction ID|
|Secs|[Uint16]|Seconds elapsed since client began address acquisition or renewal process.|
|Flags|[Uint16]|Flags|
|CIAddr|[ipaddress]|Client IP address|
|YIAddr|[ipaddress]|'your' (client) IP address|
|SIAddr|[ipaddress]|IP address of next server to use in bootstrap.|
|GIAddr|[ipaddress]|Relay agent IP address|
|CHAddr|[PhysicalAddress]|Client hardware address|
|SName|[string]|Optional server host name|
|File|[string]|Boot file name|
|MagicCookie|[byte[]]|Magic cookie, Should be `0x63, 0x82, 0x53, 0x63`|
|MessageType|[byte]|DHCP Message type|
|Options|[List<[byte], [byte[]]>]|DHCP Configuration Options (Read-only).|

#### Methods
|Name|Return type|Description|
|:----|:----|:----|
|AddDhcpOptions(byte, byte[])|[void]|Add DHCP Option. 1st parameter is option number, 2nd is value of bytes.|
|GetPacketBytes()|[byte[]]|Returns raw bytes packet.|

