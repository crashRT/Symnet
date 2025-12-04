host :: FromDevice() -> HostIPAddress(192.168.180.2 - 192.168.183.254)-> EtherEncap(2048, 0000.5e00.5312, 0000.5e00.5300) -> nic_o :: ToDevice()
nic_i :: FromDevice() -> Null -> host_o :: ToDevice()