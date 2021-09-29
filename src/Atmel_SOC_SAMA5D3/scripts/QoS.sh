exec > logfile.txt

initialize ()
{
	echo "Delete the bridge"
	ip link set br0 down
	brctl delbr br0
}

begin_fresh ()
{
	echo "Delete the QDiscs that were previously active"
	tc qdisc del dev lan1 clsact

	echo "Enable the clsact Qdisc"
	tc qdisc add dev lan1 clsact
}

#'***************************************************************************************************'
echo "Test IPV6_DIP_TCP_DPORT_DROP"

initialize
begin_fresh

echo "Test Sequence Begins .. "
tc filter add dev lan1 ingress protocol ipv6 flower skip_sw dst_ip 2001:db8:3333:4444:5555:6666:7777:8889 ip_proto tcp dst_port 82 action drop

echo "sending packet that matches the rule .. "
/usr/bin/pkt_io -tx_if lan1 -tx_num 10000 -rx_num 10000 -rx_if lan4 -vlan_ethtype 0 -dst_ip6 2001:db8:3333:4444:5555:6666:7777:8889 -ip_proto tcp -dst_port 82

echo "sending packet that doesnt match the rule .. "
/usr/bin/pkt_io -tx_if lan1 -tx_num 10000 -rx_num 10000 -rx_if lan4 -vlan_ethtype 0 -dst_ip6 2001:db8:3333:4444:5555:6666:7777:0000 -ip_proto tcp -dst_port 82

echo "sending packet that doesnt match the rule .. "
/usr/bin/pkt_io -tx_if lan1 -tx_num 10000 -rx_num 10000 -rx_if lan4 -vlan_ethtype 0 -dst_ip6 2001:db8:3333:4444:5555:6666:7777:8889 -ip_proto tcp -dst_port FFFF

echo "Test case finished"

#'***************************************************************************************************'

echo "Test IPV6_SIP_TCP_SPORT_DROP"

initialize
begin_fresh

echo "Test Sequence Begins .. "
tc filter add dev lan1 ingress protocol ipv6 flower skip_sw src_ip 2001:db8:3333:4444:5555:6666:7777:8889 ip_proto tcp src_port 82 action drop

echo "sending packet that matches the rule .. "
/usr/bin/pkt_io -tx_if lan1 -tx_num 10000 -rx_num 10000 -rx_if lan4 -vlan_ethtype 0 -src_ip6 2001:db8:3333:4444:5555:6666:7777:8889 -ip_proto tcp -src_port 82

echo "sending packet that doesnt match the rule .. "
/usr/bin/pkt_io -tx_if lan1 -tx_num 10000 -rx_num 10000 -rx_if lan4 -vlan_ethtype 0 -src_ip6 2001:db8:3333:4444:5555:6666:7777:0000 -ip_proto tcp -src_port 82

echo "sending packet that doesnt match the rule .. "
/usr/bin/pkt_io -tx_if lan1 -tx_num 10000 -rx_num 10000 -rx_if lan4 -vlan_ethtype 0 -src_ip6 2001:db8:3333:4444:5555:6666:7777:8889 -ip_proto tcp -src_port FFFF

echo "Test case finished"

#'***************************************************************************************************'





