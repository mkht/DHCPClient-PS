using module '.\Enums.psm1'
using module '.\DhcpOptionObject.psm1'
using module '.\DhcpPacket.psm1'

# DHCP Release Packet class
class DhcpReleasePacket : DhcpPacket {
    [ipaddress]$ClientIPAddress = [ipaddress]::None
    [ipaddress]$ServerIPAddress = [ipaddress]::None

    DhcpReleasePacket([ipaddress]$ClientIPAddress, [IPAddress]$ServerIPAddress, [PhysicalAddress]$MacAddress) : base() {
        [Random]::new().NextBytes($this.XID)
        $this.CHAddr = $MacAddress
        $this.ClientIPAddress = $ClientIPAddress
        $this.ServerIPAddress = $ServerIPAddress
        $this.CIAddr = $this.ClientIPAddress
        $this.AddDhcpOptions(@(
                [DhcpOptionObject]::new([DhcpOption]::DHCPMessageType, [DhcpMessageType]::DHCPRELEASE),
                [DhcpOptionObject]::new([DhcpOption]::ServerId, $this.ServerIPAddress.GetAddressBytes()),
                [DhcpOptionObject]::new([DhcpOption]::End, $null)
            ))
    }

    [byte[]]GetPacketBytes() {
        $this.CIAddr = $this.ClientIPAddress

        if (-not ($this._DhcpOptionsList.Keys -eq 61)) {
            $this.AddDhcpOptions(
                [DhcpOptionObject]::new([DhcpOption]::ClientId, (([byte[]]0x01) + $this.CHAddr.GetAddressBytes()))
            )
        }

        $this.AddDhcpOptions(@(
                [DhcpOptionObject]::new([DhcpOption]::ServerId, $this.ServerIPAddress.GetAddressBytes())
            ))

        return ([DhcpPacket]$this).GetPacketBytes()
    }
}
