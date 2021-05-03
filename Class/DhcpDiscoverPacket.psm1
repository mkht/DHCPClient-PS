using module '.\Enums.psm1'
using module '.\DhcpOptionObject.psm1'
using module '.\DhcpPacket.psm1'

# DHCP Discover Packet class
class DhcpDiscoverPacket : DhcpPacket {
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

    [ipaddress]$RequestedIPAddress = [ipaddress]::Any

    DhcpDiscoverPacket([PhysicalAddress]$MacAddress) : base() {
        [Random]::new().NextBytes($this.XID)
        $this.CHAddr = $MacAddress
        $this.AddDhcpOptions(@(
                [DhcpOptionObject]::new([DhcpOption]::DHCPMessageType, [DhcpMessageType]::DHCPDISCOVER),
                [DhcpOptionObject]::new([DhcpOption]::RequestedIPAddress, $this.RequestedIPAddress.GetAddressBytes()),
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
                [DhcpOptionObject]::new([DhcpOption]::RequestedIPAddress, $this.RequestedIPAddress.GetAddressBytes()),
                [DhcpOptionObject]::new([DhcpOption]::ParameterRequestList, $this.ParameterRequestList)
            ))

        return ([DhcpPacket]$this).GetPacketBytes()
    }
}
