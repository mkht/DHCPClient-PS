using module '.\Enums.psm1'
using module '.\DhcpOptionObject.psm1'
using module '.\DhcpPacket.psm1'

# DHCP Request Packet class
class DhcpRequestPacket : DhcpPacket {
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

    [ValidateNotNull()][ipaddress]$RequestedIPAddress = [ipaddress]::None
    [ValidateNotNull()][ipaddress]$ServerIPAddress = [ipaddress]::Any

    DhcpRequestPacket([IPAddress]$RequestIPAddress, [IPAddress]$ServerIPAddress , [PhysicalAddress]$MacAddress) : base() {
        [Random]::new().NextBytes($this.XID)
        $this.CHAddr = $MacAddress
        $this.RequestedIPAddress = $RequestIPAddress
        $this.ServerIPAddress = $ServerIPAddress
        $this.AddDhcpOptions(@(
                [DhcpOptionObject]::new([DhcpOption]::DHCPMessageType, [DhcpMessageType]::DHCPREQUEST),
                [DhcpOptionObject]::new([DhcpOption]::RequestedIPAddress, $this.RequestedIPAddress.GetAddressBytes()),
                [DhcpOptionObject]::new([DhcpOption]::ServerId, $this.ServerIPAddress.GetAddressBytes()),
                [DhcpOptionObject]::new([DhcpOption]::ParameterRequestList, $this.ParameterRequestList)
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
                [DhcpOptionObject]::new([DhcpOption]::ServerId, $this.ServerIPAddress.GetAddressBytes()),
                [DhcpOptionObject]::new([DhcpOption]::ParameterRequestList, $this.ParameterRequestList)
            ))

        return ([DhcpPacket]$this).GetPacketBytes()
    }
}
