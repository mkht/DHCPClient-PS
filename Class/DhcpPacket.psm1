using module '.\Enums.psm1'
using module '.\DhcpOptionObject.psm1'

<#
DHCP Packet Format (RFC 2131 - http://www.ietf.org/rfc/rfc2131.txt):

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
+---------------+---------------+---------------+---------------+
|                            xid (4)                            |
+-------------------------------+-------------------------------+
|           secs (2)            |           flags (2)           |
+-------------------------------+-------------------------------+
|                          ciaddr  (4)                          |
+---------------------------------------------------------------+
|                          yiaddr  (4)                          |
+---------------------------------------------------------------+
|                          siaddr  (4)                          |
+---------------------------------------------------------------+
|                          giaddr  (4)                          |
+---------------------------------------------------------------+
|                                                               |
|                          chaddr  (16)                         |
|                                                               |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                          sname   (64)                         |
+---------------------------------------------------------------+
|                                                               |
|                          file    (128)                        |
+---------------------------------------------------------------+
|                                                               |
|                          options (variable)                   |
+---------------------------------------------------------------+

FIELD      OCTETS       DESCRIPTION
-----      ------       -----------

op            1  Message op code / message type.
                 1 = BOOTREQUEST, 2 = BOOTREPLY
htype         1  Hardware address type, see ARP section in "Assigned
                 Numbers" RFC; e.g., '1' = 10mb ethernet.
hlen          1  Hardware address length (e.g.  '6' for 10mb
                 ethernet).
hops          1  Client sets to zero, optionally used by relay agents
                 when booting via a relay agent.
xid           4  Transaction ID, a random number chosen by the
                 client, used by the client and server to associate
                 messages and responses between a client and a
                 server.
secs          2  Filled in by client, seconds elapsed since client
                 began address acquisition or renewal process.
flags         2  Flags (see figure 2).
ciaddr        4  Client IP address; only filled in if client is in
                 BOUND, RENEW or REBINDING state and can respond
                 to ARP requests.
yiaddr        4  'your' (client) IP address.
siaddr        4  IP address of next server to use in bootstrap;
                 returned in DHCPOFFER, DHCPACK by server.
giaddr        4  Relay agent IP address, used in booting via a
                 relay agent.
chaddr       16  Client hardware address.
sname        64  Optional server host name, null terminated string.
file        128  Boot file name, null terminated string; "generic"
                 name or null in DHCPDISCOVER, fully qualified
                 directory-path name in DHCPOFFER.
options     var  Optional parameters field.  See the options
                 documents for a list of defined options.
#>



# DHCP Packet class
class DhcpPacket {
    [OpCode]$OpCode = [OpCode]::BOOTREQUEST
    [byte]$HType = 1
    [byte]$HLen = 6
    [byte]$Hops = 0
    [byte[]]$XID = (New-Object Byte[] 4)
    [UInt16]$Secs = 0
    [UInt16]$Flags = 0
    [ValidateNotNull()][ipaddress]$CIAddr = [ipaddress]::Any
    [ValidateNotNull()][ipaddress]$YIAddr = [ipaddress]::Any
    [ValidateNotNull()][ipaddress]$SIAddr = [ipaddress]::Any
    [ValidateNotNull()][ipaddress]$GIAddr = [ipaddress]::Any
    [ValidateNotNull()][PhysicalAddress]$CHAddr = [PhysicalAddress]::new((New-Object Byte[] 6))
    [string]$SName = ''
    [string]$File = ''
    [byte[]]$MagicCookie = [byte[]](0x63, 0x82, 0x53, 0x63)

    hidden [System.Collections.Specialized.OrderedDictionary]$_DhcpOptionsList = [System.Collections.Specialized.OrderedDictionary]::new()

    DhcpPacket() {
        # Options property (Read-only)
        $this | Add-Member ScriptProperty 'Options' {
            # Getter
            $this._DhcpOptionsList.AsReadOnly()
        }

        # MessageType property
        $this | Add-Member ScriptProperty 'MessageType' {
            # Getter
            [DhcpMessageType]($this._DhcpOptionsList[[byte][DhcpOption]::DHCPMessageType]._Value)
        } {
            # Setter
            param([DhcpMessageType]$MsgType)
            $this.AddDhcpOptions(
                [DhcpOptionObject]::new([DhcpOption]::DHCPMessageType, $MsgType)
            )
        }

        $this | Add-Member ScriptProperty 'BroadcastFlag' {
            # Getter
            [bool]($this.Flags -eq 128)
        } {
            param([bool]$flag)
            # Setter
            if ($flag) { $this.Flags = 128 }else { $this.Flags = 0 }
        }
    }

    [void]AddDhcpOptions([DhcpOptionObject[]]$Options, [bool]$ConcatWhenExist) {
        foreach ($op in $Options) {
            if ($op -isnot [DhcpOptionObject]) { continue }
            if ($op.OptionCode -eq [DhcpOption]::End) { continue }

            if ((-not $ConcatWhenExist) -or ([byte]$op.OptionCode -notin $this._DhcpOptionsList.Keys)) {
                $this._DhcpOptionsList[[byte]$op.OptionCode] = $op
            }
            else {
                $this._DhcpOptionsList[[byte]$op.OptionCode]._Value += $op._Value
            }
        }

        # Ensure End option is last
        if ($this._DhcpOptionsList.Contains([byte][DhcpOption]::End)) {
            $this._DhcpOptionsList.Remove([byte][DhcpOption]::End)
        }
        $this._DhcpOptionsList.Add([byte][DhcpOption]::End, [DhcpOptionObject]::new([DhcpOption]::End, $null))
    }

    [void]AddDhcpOptions([DhcpOptionObject[]]$Options) {
        $this.AddDhcpOptions($Options, $false)
    }

    [void]AddDhcpOption([byte]$OptionCode, [byte[]]$Value, [bool]$ConcatWhenExist) {
        $op = [DhcpOptionObject]::new([byte]$OptionCode, [byte[]]$Value)
        $this.AddDhcpOptions($op, $ConcatWhenExist)
    }

    [void]AddDhcpOption([byte]$OptionCode, [byte[]]$Value) {
        $this.AddDhcpOption($OptionCode, $Value, $false)
    }

    [bool]RemoveDhcpOption([byte]$OptionCode) {
        return $this._DhcpOptionsList.Remove([byte]$OptionCode)
    }

    static [DhcpPacket]Parse([byte[]]$Packet) {
        $DhcpResponse = [DhcpPacket]::new()
        $Reader = [System.IO.BinaryReader]::new((New-Object IO.MemoryStream(@(, $Packet))))
        try {
            # Headers
            $DhcpResponse.OpCode = $Reader.ReadByte()
            $DhcpResponse.HType = $Reader.ReadByte()
            $DhcpResponse.HLen = $Reader.ReadByte()
            $DhcpResponse.Hops = $Reader.ReadByte()
            $DhcpResponse.XID = $Reader.ReadBytes(4)
            $DhcpResponse.Secs = $Reader.ReadUInt16()
            $DhcpResponse.Flags = $Reader.ReadUInt16()

            # IP address
            $DhcpResponse.CIAddr = [ipaddress]::new($Reader.ReadBytes(4))
            $DhcpResponse.YIAddr = [ipaddress]::new($Reader.ReadBytes(4))
            $DhcpResponse.SIAddr = [ipaddress]::new($Reader.ReadBytes(4))
            $DhcpResponse.GIAddr = [ipaddress]::new($Reader.ReadBytes(4))

            # MAC address
            $DhcpResponse.CHAddr = [PhysicalAddress]::new(($Reader.ReadBytes(16))[0..5])

            # SName & File
            $DhcpResponse.SName = [string]::new($Reader.ReadChars(64)).Trim("`0").TrimEnd()
            $DhcpResponse.File = [string]::new($Reader.ReadChars(128)).Trim("`0").TrimEnd()

            # MagicCookie
            $DhcpResponse.MagicCookie = $Reader.ReadBytes(4)

            #  Options
            while ($Reader.BaseStream.Position -lt $Reader.BaseStream.Length) {
                $OpNumber = $Reader.ReadByte()
                if ($OpNumber -eq [DhcpOption]::End) {
                    $OpsObj = [DhcpOptionObject]::new([DhcpOption]::End, $null)
                    $DhcpResponse.AddDhcpOptions($OpsObj)
                    break
                }
                else {
                    $OpLength = $Reader.ReadByte()
                    $OpValue = $Reader.ReadBytes($OpLength)
                    $OpsObj = [DhcpOptionObject]::new($OpNumber, $OpValue)
                    $DhcpResponse.AddDhcpOptions($OpsObj, $true)
                }
            }
        }
        catch {
            throw
        }
        finally {
            $Reader.Close()
        }

        return $DhcpResponse
    }

    [byte[]]GetPacketBytes() {
        $ByteArray = New-Object 'System.Collections.Generic.List[byte]'

        # Headers
        $ByteArray.Add($this.OpCode)
        $ByteArray.Add($this.HType)
        $ByteArray.Add($this.HLen)
        $ByteArray.Add($this.Hops)
        $ByteArray.AddRange($this.XID)
        $ByteArray.AddRange([System.BitConverter]::GetBytes($this.Secs))
        $ByteArray.AddRange([System.BitConverter]::GetBytes($this.Flags))

        # IP address
        $ByteArray.AddRange($this.CIAddr.GetAddressBytes())
        $ByteArray.AddRange($this.YIAddr.GetAddressBytes())
        $ByteArray.AddRange($this.SIAddr.GetAddressBytes())
        $ByteArray.AddRange($this.GIAddr.GetAddressBytes())

        # MAC address
        $ByteArray.AddRange($this.CHAddr.GetAddressBytes())
        $ByteArray.AddRange((New-Object Byte[] 10))

        # SName
        [byte[]]$SNameBytes = [System.Text.Encoding]::UTF8.GetBytes($this.SName)
        if ($SNameBytes.Count -gt 64) {
            $SNameBytes = $SNameBytes[0..63]
        }
        else {
            # Padding
            $SNameBytes += (New-Object byte[] (64 - $SNameBytes.Count))
        }
        $ByteArray.AddRange($SNameBytes)

        # File
        [byte[]]$FileBytes = [System.Text.Encoding]::UTF8.GetBytes($this.SName)
        if ($FileBytes.Count -gt 128) {
            $FileBytes = $FileBytes[0..127]
        }
        else {
            # Padding
            $FileBytes += (New-Object byte[] (128 - $FileBytes.Count))
        }
        $ByteArray.AddRange($FileBytes)

        # Magic Cookie
        $ByteArray.AddRange($this.MagicCookie)

        # Options
        $HasEnd = ($this._DhcpOptionsList.Contains([byte][DhcpOption]::End))
        foreach ($option in $this._DhcpOptionsList.Values) {
            if ($option -is [DhcpOptionObject]) {
                $ByteArray.AddRange($option.GetBytes())
            }
        }

        # End
        if (-not $HasEnd) {
            $End = [DhcpOptionObject]::new([DhcpOption]::End, $null)
            $ByteArray.AddRange($End.GetBytes())
        }

        return $ByteArray.ToArray()
    }
}
