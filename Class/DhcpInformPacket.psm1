using module '.\Enums.psm1'
using module '.\DhcpOptionObject.psm1'
using module '.\DhcpPacket.psm1'

# DHCP Inform Packet class
class DhcpInformPacket : DhcpPacket {
    [byte[]]$ParameterRequestList = @(
        [DhcpOption]::SubnetMask,
        [DhcpOption]::Router,
        [DhcpOption]::DomainNameServer,
        [DhcpOption]::DomainName,
        [DhcpOption]::RouterDiscovery,
        [DhcpOption]::StaticRoute,
        [DhcpOption]::NTPServers,
        [DhcpOption]::DomainSearch,
        [DhcpOption]::WebProxyAutoDiscovery
    )

    [ipaddress]$ClientIPAddress = [ipaddress]::Any
    [ipaddress]$ServerIPAddress = [ipaddress]::Broadcast

    DhcpInformPacket([IPAddress]$ClientIPAddress, [IPAddress]$ServerIPAddress , [PhysicalAddress]$MacAddress) : base() {
        [Random]::new().NextBytes($this.XID)
        $this.ClientIPAddress = $ClientIPAddress
        $this.ServerIPAddress = $ServerIPAddress
        $this.CIAddr = $this.ClientIPAddress
        $this.CHAddr = $MacAddress
        $this.AddDhcpOptions(@(
                [DhcpOptionObject]::new([DhcpOption]::DHCPMessageType, [DhcpMessageType]::DHCPINFORM),
                [DhcpOptionObject]::new([DhcpOption]::ServerId, $this.ServerIPAddress.GetAddressBytes()),
                [DhcpOptionObject]::new([DhcpOption]::ParameterRequestList, $this.ParameterRequestList),
                [DhcpOptionObject]::new([DhcpOption]::End, $null)
            ))
    }

    DhcpInformPacket([IPAddress]$ClientIPAddress, [PhysicalAddress]$MacAddress) : base() {
        [Random]::new().NextBytes($this.XID)
        $this.ClientIPAddress = $ClientIPAddress
        $this.CIAddr = $this.ClientIPAddress
        $this.CHAddr = $MacAddress
        $this.AddDhcpOptions(@(
                [DhcpOptionObject]::new([DhcpOption]::DHCPMessageType, [DhcpMessageType]::DHCPINFORM),
                [DhcpOptionObject]::new([DhcpOption]::ParameterRequestList, $this.ParameterRequestList),
                [DhcpOptionObject]::new([DhcpOption]::End, $null)
            ))
    }

    [byte[]]GetPacketBytes() {
        if (-not ($this._DhcpOptionsList.Keys -eq 61)) {
            $this.AddDhcpOptions(
                [DhcpOptionObject]::new([DhcpOption]::ClientId, (([byte[]]0x01) + $this.CHAddr.GetAddressBytes()))
            )
        }

        $this.AddDhcpOptions(@(
                [DhcpOptionObject]::new([DhcpOption]::ParameterRequestList, $this.ParameterRequestList)
            ))

        return ([DhcpPacket]$this).GetPacketBytes()
    }
}
