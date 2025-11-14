lan3_i :: FromDevice();
lan3_o :: ToDevice();

lan1_i :: FromDevice();
lan1_o :: ToDevice();

cpu :: Null

lan1_i -> lan1_tag :: IPClassifier(vlantag 10, vlantag 20, -)
lan1_tag[0] -> VLANDecap() -> vlan10
lan1_tag[1] -> VLANDecap() -> vlan20
lan1_tag[2] -> VLANDecap() -> Discard

lan3_i -> EtherDecap() -> routing

vlan10 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5311)
vlan10[0] -> EtherDecap() -> routing
vlan10[1] -> vlan10_out

vlan20 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5312)
vlan20[0] -> EtherDecap() -> routing
vlan20[1] -> vlan20_out

routing :: LinearIPLookup(192.168.127.1/32 0 onlink, 192.168.127.0/24 1 onlink, 192.168.180.1/32 0 onlink, 192.168.180.0/22 2 onlink, 0.0.0.0/0 3 10.0.0.1)

routing[0] -> cpu
routing[1] -> vlan10_nexthop :: IPClassifier(nexthop 192.168.127.2, -)
routing[2] -> vlan20_nexthop :: IPClassifier(nexthop 192.168.180.2, -)

vlan10_nexthop[0] -> EtherEncap(2048, 0000.5e00.5300, 0000.5e00.5311) -> vlan10_out
vlan10_nexthop[1] -> Discard

vlan20_nexthop[0] -> EtherEncap(2048, 0000.5e00.5300, 0000.5e00.5312) -> vlan20_out
vlan20_nexthop[1] -> Discard

vlan10_out :: VLANEncap(10) -> lan1_o
vlan20_out :: VLANEncap(20) -> lan1_o

routing[3] -> lan3_o
