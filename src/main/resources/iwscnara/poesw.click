port1_i :: FromDevice()
port1_o :: ToDevice()

port8_i :: FromDevice()
port8_o :: ToDevice()

vlan10 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5310)
vlan20 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5312)

tag :: IPClassifier(vlantag 10, vlantag 20, -)

port1_i -> tag
port8_i -> tag

tag[0] -> VLANDecap() -> vlan10
tag[1] -> VLANDecap() -> vlan20
tag[2] -> VLANDecap() -> Discard

vlan10[0] -> VLANEncap(10) -> port8_o
vlan10[1] -> VLANEncap(10) -> port1_o

vlan20[0] -> VLANEncap(20) -> port8_o
vlan20[1] -> VLANEncap(20) -> port1_o