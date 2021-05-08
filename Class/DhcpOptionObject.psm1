using module '.\Enums.psm1'

# DHCP Option object
Class DhcpOptionObject {
    [byte]$OptionCode
    [string]$Name

    [ValidateCount(0, 1024)]
    Hidden [byte[]]$_Value

    [ValidateRange(1, 255)]
    Hidden [byte]$SplitSize = 255

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
                { $_ -in ('DomainName', 'Hostname', 'ClassId', 'WebProxyAutoDiscovery') } {
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

    Hidden static [byte[]] ConvertDomainSearchListToBytes([string[]]$Domains) {
        # Ref: RFC 1035, 3397
        [byte[]]$Result = $null
        $IdnMapping = [System.Globalization.IdnMapping]::new()
        $PointerList = @{}
        $Writer = [System.IO.BinaryWriter]::new([System.IO.MemoryStream]::new())
        try {
            foreach ($Domain in $Domains) {
                while (-not [string]::IsNullOrWhiteSpace($Domain)) {
                    # Convert internationalized domain names to Punycode
                    $Domain = $IdnMapping.GetAscii($Domain.Trim("`0", '.').Trim())

                    if ($PointerList.ContainsKey($Domain)) {
                        if ($PointerList[$Domain] -ge 0 -and $PointerList[$Domain] -le 0x3fff) {
                            # Compression pointer (2 bytes big endian)
                            $Pointer = [System.BitConverter]::GetBytes([ipaddress]::NetworkToHostOrder([Int32]((0xc0 -shl 8) + $PointerList[$Domain])))[2..3]
                            $Writer.Write([byte[]]$Pointer)
                            break
                        }
                    }

                    if ($Domain.IndexOf('.') -le 0) {
                        $PointerList[$Domain] = $Writer.BaseStream.Position
                        $TLDBytes = [System.Text.Encoding]::UTF8.GetBytes($Domain)
                        $Writer.Write([byte]$TLDBytes.Length)
                        $Writer.Write([byte[]]$TLDBytes)
                        # End flag
                        $Writer.Write([byte]0x00)
                        break
                    }
                    else {
                        $PointerList[$Domain] = $Writer.BaseStream.Position
                        $SplitDomain = $Domain.Split('.', 2, 1)
                        $Domain = $SplitDomain[1]
                        $LLD = $SplitDomain[0].Trim("`0").Trim()
                        $LLDBytes = [System.Text.Encoding]::UTF8.GetBytes($LLD)
                        $Writer.Write([byte]$LLDBytes.Length)
                        $Writer.Write([byte[]]$LLDBytes)
                    }
                }
            }
        }
        finally {
            $Result = $Writer.BaseStream.ToArray()
            $Writer.Close()
        }

        return $Result
    }

    [string] ToString() {
        return ('{0} ({1})' -f $this.Name, $this.Value)
    }
}
