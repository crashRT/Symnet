lan3_i :: FromDevice();
lan3_o :: ToDevice();

lan1_i :: FromDevice();
lan1_o :: ToDevice();

cpu :: Null

routing :: LinearIPLookup(192.168.127.1/32 0, 192.168.127.0/24 1, 192.168.180.1/32 0, 192.168.180.0/22 2, 0.0.0.0/0 3)

vlan10 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5311)

vlan20 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5312)

lan1_i -> lan1_tag :: IPClassifier(vlantag 10, vlantag 20, -)
lan1_tag[0] -> VLANDecap() -> vlan10
lan1_tag[1] -> VLANDecap() -> vlan20
lan1_tag[2] -> VLANDecap() -> Discard

lan3_i -> Paint(3) -> routing

vlan10[0] -> Paint(10) -> routing
vlan10[1] -> vlan10_out

vlan20[0] -> Paint(20) -> routing
vlan20[1] -> vlan20_out

lan1_pc :: IPClassifier(paint color 1, -)

vlan10_out :: VLANEncap(10) -> lan1_pc
vlan20_out :: VLANEncap(20) -> lan1_pc

lan1_pc[0] -> Discard
lan1_pc[1] -> lan1_o

routing[0] -> cpu
routing[1] -> routing1_pc :: IPClassifier(paint color 10, -)
routing[2] -> routing2_pc :: IPClassifier(paint color 20, -)

routing1_pc[0] -> Discard
routing1_pc[1] -> vlan10

routing2_pc[0] -> Discard
routing2_pc[1] -> vlan20

routing[3] -> lan3_pc :: IPClassifier(paint color 3, -)
lan3_pc[0] -> Discard
lan3_pc[1] -> lan3_o
