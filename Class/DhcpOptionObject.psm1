using module '.\Enums.psm1'

# DHCP Option object
Class DhcpOptionObject {
    [byte]$OptionCode
    [string]$Name

    [ValidateCount(0, 254)]
    Hidden [byte[]]$_Value

    DhcpOptionObject([byte]$OptionCode, [byte[]]$Value) {
        $this.OptionCode = $OptionCode
        $this._Value = $Value
        $this.Name = ($OptionCode -as [DhcpOption])

        $this | Add-Member ScriptProperty 'Value' {
            $this.ParseValue($this._Value)
        }

        $this | Add-Member ScriptProperty 'Length' {
            [byte]$this._Value.Count
        }
    }

    DhcpOptionObject([byte]$OptionCode) {
        $this.OptionCode = $OptionCode
        $this._Value = $null
        $this.Name = ($OptionCode -as [DhcpOption])

        $this | Add-Member ScriptProperty 'Value' {
            $this.ParseValue($this._Value)
        }

        $this | Add-Member ScriptProperty 'Length' {
            [byte]$this._Value.Count
        }
    }

    [byte[]]GetBytes() {
        $ByteArray = New-Object 'System.Collections.Generic.List[byte]'
        $ByteArray.Add($this.OptionCode)
        $ByteArray.Add($this._Value.Count)
        if ($null -ne $this._Value) {
            $ByteArray.AddRange($this._Value)
        }
        return $ByteArray.ToArray()
    }

    static [DhcpOptionObject]Parse([byte[]]$Bytes) {
        if ($Bytes.Count -le 2) { throw [System.ArgumentException]::new() }
        else {
            $length = $Bytes[1]
            return [DhcpOptionObject]::new($Bytes[0], $Bytes[ - $length..-1])
        }
    }

    Hidden [Object] ParseValue([byte[]]$Value) {
        try {
            switch ($this.OptionCode -as [DhcpOption]) {
                { $_ -in ('SubnetMask', 'ServerId', 'RequestedIPAddress') } {
                    # Single IP address
                    return [ipaddress]::new($Value[0..3])
                }
                { $_ -in ('Router', 'TimeServer', 'NameServer', 'DomainNameServer', 'NTPServers', 'NETBIOSNameSrv') } {
                    # Multiple IP addresses
                    $OptionValue = [ipaddress[]]@()
                    for ($i = 0; ($i + 4) -le $Value.Count; $i += 4) {
                        $OptionValue += [ipaddress]::new($Value[$i..($i + 3)])
                    }
                    return $OptionValue
                }
                { $_ -in ('DomainName', 'Hostname') } {
                    # String
                    return [string]::new($Value)
                }
                { $_ -in ('IPAddressLeaseTime', 'RenewalTime', 'RebindingTime', 'ARPTimeout') } {
                    # TimeSpan
                    # Convert big endian order bytes to UInt32 seconds
                    $Ticks = [int64]([ipaddress]::NetworkToHostOrder([System.BitConverter]::ToInt64(([byte[]]::new(4) + $Value), 0)) * 1e7)
                    return [timespan]::new($Ticks)
                }
                DHCPMessageType {
                    return ($Value[0] -as [DhcpMessageType])
                }
                Default {
                    return $Value
                }
            }
        }
        catch {}
        return $Value
    }

    [string]ToString() {
        return ('{0} ({1})' -f $this.Name, $this.Value)
    }
}
