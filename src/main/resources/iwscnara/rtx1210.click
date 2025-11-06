lan3_i :: FromDevice();
lan3_o :: ToDevice();

lan1_i :: FromDevice();
lan1_o :: ToDevice();

cpu :: Null

routing :: LinearIPLookup(192.168.127.1/32 0, 192.168.127.0/24 1, 192.168.180.1/32 0, 192.168.180.0/22 2)

vlan10 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5310)

vlan20 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5312)

lan1_i -> Paint(1) -> lan1_tag :: IPClassifier(vlantag 10, vlantag 20)
lan1_tag[0] -> vlan10
lan1_tag[1] -> vlan20

vlan10[0] -> routing
vlan10[1] -> vlan10_out

vlan20[0] -> routing
vlan20[1] -> vlan20_out

lan1_outqueue :: IPClassifier(paint color 1, -)

vlan10_out :: VLANEncap(10) -> lan1_outqueue
vlan20_out :: VLANEncap(20) -> lan1_outqueue

lan1_outqueue[0] -> Discard
lan1_outqueue[1] -> lan1_o

routing[0] -> cpu
routing[1] -> vlan10
routing[2] -> vlan20