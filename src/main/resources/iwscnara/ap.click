wlan_i :: FromDevice()
wlan_o :: ToDevice()

wifi1_i :: FromDevice()
wifi1_o :: ToDevice()

wifi2_i :: FromDevice()
wifi2_o :: ToDevice()

vlan10 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5310)
vlan20 :: IPClassifier (ether dst 0000.5e00.5300, ether dst 0000.5e00.5312)

tag :: IPClassifier(vlantag 10, vlantag 20, -)

wlan_i -> tag
wifi1_i -> vlan10
wifi2_i -> vlan20

tag[0] -> VLANDecap() -> vlan10
tag[1] -> VLANDecap() -> vlan20
tag[2] -> VLANDecap() -> Discard

vlan10[0] -> VLANEncap(10) -> wlan_o
vlan10[1] -> wifi1_o

vlan20[0] -> VLANEncap(20) -> wlan_o
vlan20[1] -> wifi2_o