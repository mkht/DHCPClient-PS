# DHCPClient-PS

## Description
PowerShell DHCP Client module for testing purpose.  
This module can broadcast DHCP discover, inform, request, and release packets with arbitrary parameters, and receive responses from servers. You can test the health of DHCP servers or check for the presence of multiple DHCP servers in a subnet.

## Install
You can install the module from [PowerShell Gallery](https://www.powershellgallery.com/packages/DHCPClient-PS).

```PowerShell
Install-Module -Name DHCPClient-PS
```

## Platforms
+ Windows PowerShell 5.0 and 5.1
+ PowerShell 7.0 and above (Windows, macOS and Linux)

## Usage

- [Invoke-DhcpDiscover](#Invoke-DhcpDiscover)
- [Invoke-DhcpInform](#Invoke-DhcpInform)
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

* **`-RequestIPAddress`**  [IPAddress]  
Specifies IP address that the client requests to be assigned.  
This is corresponding to DHCP [option 50](https://tools.ietf.org/html/rfc2132#section-9.1).

* **`-ClientId`**  [byte[]]  
Specifies the client-identifier value.  
This is corresponding to DHCP [option 61](https://tools.ietf.org/html/rfc2132#section-9.14).  
Default: The value of MAC address.

* **`-ParameterRequestList`**  [byte[]]  
Specifies request values for configuration parameters.  
This is corresponding to DHCP [option 55](https://tools.ietf.org/html/rfc2132#section-9.8).  
Default: `1, 3, 4, 15, 31, 33, 42, 119, 252`

* **`-BroadcastFlag`**  [bool]  
Specifies the flag to request the server to broadcast a reply.  
Default: `False`

* **`-Timeout`**  [byte]  
Specifies how long seconds to wait until a response is received.  
Default: 10

* **`-LongPoll`**  [switch]  
By default, only the first response received will output. If this switch is specified, it will wait until the timeout period and output all responses received. This is useful to check whether there are multiple DHCP servers in a subnet.

#### Outputs
[DhcpPacket](#About-DhcpPacket-class) object

----
### Invoke-DhcpInform
Send DHCP Inform message, then receive ACK messages from DHCP server(s).  

#### Examples
```PowerShell
PS> $CurrentIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex 15).IPAddress
PS> $Response =  Invoke-DhcpInform -ClientIPAddress $CurrentIP -ServerIPAddress '192.168.0.1' -MacAddress 'ABCDEF012345'
PS> $Response | Select-Object MessageType, CIAddr, CHAddr, Options

MessageType : DHCPACK
CIAddr      : 192.168.0.8
SIAddr      : 192.168.0.1
CHAddr      : ABCDEF012345
Options     : {@{OptionCode=1; Name=SubnetMask; Value=255.255.255.0; Length=4}...}
```

#### Parameters

* **`-MacAddress`**  [string]  
Specifies MAC address for the request.  
Default: `AA-BB-CC-DD-EE-FF`

* **`-ClientIPAddress`**  [IPAddress]  
Specifies Client IP address.  
This is mandatory parameter.

* **`-ServerIPAddress`**  [IPAddress]  
Specifies DHCP server address.  
Default: `0.0.0.0` (Any)

* **`-ClientId`**  [byte[]]  
Specifies the client-identifier value.  
This is corresponding to DHCP [option 61](https://tools.ietf.org/html/rfc2132#section-9.14).  
Default: The value of MAC address.

* **`-ParameterRequestList`**  [byte[]]  
Specifies request values for configuration parameters.  
This is corresponding to DHCP [option 55](https://tools.ietf.org/html/rfc2132#section-9.8).  
Default: `1, 3, 4, 15, 31, 33, 42, 119, 252`

* **`-BroadcastFlag`**  [bool]  
Specifies the flag to request the server to broadcast a reply.  
Default: `False`

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

* **`-RequestIPAddress`**  [IPAddress]  
Specifies IP address that the client requests to be assigned.  
This is corresponding to DHCP [option 50](https://tools.ietf.org/html/rfc2132#section-9.1).  
This is mandatory parameter.

* **`-ServerIPAddress`**  [IPAddress]  
Specifies DHCP server address.  
This is corresponding to DHCP [option 54](https://tools.ietf.org/html/rfc2132#section-9.7).  
This is mandatory parameter.

* **`-ClientId`**  [byte[]]  
Specifies the client-identifier value.  
This is corresponding to DHCP [option 61](https://tools.ietf.org/html/rfc2132#section-9.14).  
Default: The value of MAC address.

* **`-ParameterRequestList`**  [byte[]]  
Specifies request values for configuration parameters.  
This is corresponding to DHCP [option 55](https://tools.ietf.org/html/rfc2132#section-9.8).  
Default: `1, 3, 4, 15, 31, 33, 42, 119, 252`

* **`-BroadcastFlag`**  [bool]  
Specifies the flag to request the server to broadcast a reply.  
Default: `False`

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

* **`-ClientIPAddress`**  [IPAddress]  
Specifies IP address that the client requests to be released.  
This is mandatory parameter.

* **`-ServerIPAddress`**  [IPAddress]  
Specifies DHCP server address.  
This is mandatory parameter.

* **`-ClientId`**  [byte[]]  
Specifies the client-identifier value.  
This is corresponding to DHCP [option 61](https://tools.ietf.org/html/rfc2132#section-9.14).  
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

* **`-ServerIPAddress`**  [IPAddress]  
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

* **`-ServerIPAddress`**  [IPAddress]  
Specifies DHCP server address.  
Default: `0.0.0.0` (Any address)

* **`-ClientId`**  [byte[]]  
Specifies the client-identifier value.  
This is corresponding to DHCP [option 61](https://tools.ietf.org/html/rfc2132#section-9.14).  
Default: The value of MAC address.

* **`-ParameterRequestList`**  [byte[]]  
Specifies request values for configuration parameters.  
This is corresponding to DHCP [option 55](https://tools.ietf.org/html/rfc2132#section-9.8).

* **`-Options`**  [HashTable]  
Specifies DHCP configuration option parameters.  
You should specify the param as hashtable that the key as option number and value as bytes. (See example)

* **`-BroadcastFlag`**  [bool]  
Specifies the flag to request the server to broadcast a reply.  
Default: `False`


#### Outputs
[DhcpPacket](#About-DhcpPacket-class) object

----
### About DhcpPacket class

`[DhcpPacket]` is representation class for DHCP packet.

#### Constructor
This class is not published as public. You should create instance by `New-DhcpPacket` function.

#### Members
Most of the members correspond to the structure of a DHCP packet. See [RFC 2131](https://tools.ietf.org/html/rfc2131) for details.

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
|BroadcastFlag|[bool]|Flag to request a broadcast response from the server.|

#### Methods
|Name|Return type|Description|
|:----|:----|:----|
|AddDhcpOption(byte, byte[])|[void]|Add DHCP Option. 1st parameter is an option number, 2nd is value of bytes.|
|RemoveDhcpOption(byte)|[bool]|Remove DHCP Option. parameter is an option number.|
|GetPacketBytes()|[byte[]]|Returns raw bytes packet.|


## Change log
+ **Unreleased**
  - Add support for handling DHCP option values that are longer than 255 bytes. (Encoding Long Options as defined in [RFC 3396](https://tools.ietf.org/html/rfc3396))
  - Add `RemoveDhcpOption()` method to `[DhcpPacket]` class.

+ **1.1.3**
  - Fixed: The number of seconds larger than the `[Int32]::MaxValue` is not parsed correctly.

+ **1.1.2**
  - Fixed: `Invoke-DhcpInform` with pipeline input does not function.

+ **1.1.0**
  - Add `Invoke-DhcpInform` function
  - Allow the broadcast flag to be specified. (`-BroadcastFlag` parameter)

+ **1.0.0**
  - First public release
