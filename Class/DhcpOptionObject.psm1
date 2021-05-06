using module '.\Enums.psm1'

# DHCP Option object
Class DhcpOptionObject {
    [byte]$OptionCode
    [string]$Name

    [ValidateCount(0, 1024)]
    Hidden [byte[]]$_Value

    [ValidateRange(1, 255)]
    [byte]$SplitSize = 255

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
        if ($null -eq $this._Value) {
            $ByteArray.Add($this.OptionCode)
            $ByteArray.Add(0)
            return $ByteArray.ToArray()
        }
        else {
            $Reader = [System.IO.BinaryReader]::new((New-Object IO.MemoryStream(@(, $this._Value))))
            try {
                (1..([math]::Ceiling($this._Value.Count / $this.SplitSize))) | ForEach-Object {
                    $ByteArray.Add($this.OptionCode)
                    $Length = [Math]::Min(($Reader.BaseStream.Length - $Reader.BaseStream.Position), $this.SplitSize)
                    $ByteArray.Add($Length)
                    $ByteArray.AddRange($Reader.ReadBytes($Length))
                }
            }
            finally {
                $Reader.Close()
            }
            return $ByteArray.ToArray()
        }
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
                { $_ -in ('DomainSearch') } {
                    # multiple strings
                    # RFC 3397
                    return [DhcpOptionObject]::ParseDomainSearchList($Value)
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

    Hidden static [string[]] ParseDomainSearchList([byte[]]$Value) {
        # Ref: RFC 1035, 3396, 3397
        $DomainSearchList = [System.Collections.Generic.List[string]]::new()
        $Domain = @()
        $NextPosition = 0
        for ($idx = 0; $idx -lt $Value.Length; ) {
            $Length = $Value[$idx++]
            if (0 -eq $Length) {
                # detects end
                if ($NextPosition -gt $idx) {
                    # back to pointer
                    $idx = $NextPosition
                }

                if ($Domain.Count -gt 0) {
                    $DomainSearchList.Add($Domain -join '.')
                }
                $Domain = @()
                continue
            }
            elseif ($Length -ge 0xc0) {
                # detects compression pointer
                $HigherOctet = (($Length -band 0x3f) -shl 8)
                if ($idx -lt $Value.Length) {
                    $LowerOctet = $Value[$idx]
                }
                else { break }
                $CPointer = [int]($HigherOctet + $LowerOctet)
                $NextPosition = ++$idx
                $idx = $CPointer
                continue
            }
            else {
                # continue reading
                $lastIdx = ($idx + $Length - 1)
                if ($lastIdx -lt $Value.Length) {
                    $Domain += [string]::new($Value[$idx..$lastIdx])
                }
                else { break }
                $idx += $Length
                continue
            }
        }

        return $DomainSearchList.ToArray()
    }

    [string] ToString() {
        return ('{0} ({1})' -f $this.Name, $this.Value)
    }
}
