tx_iface=$2
rx_iface=$1

echo "Port Under Test/Rx Port: ${rx_iface} \n Packets Generated from Port: ${tx_iface}"

initialize ()
{
        echo "Delete the bridge"
        ip link set br0 down
        brctl delbr br0
}

begin_fresh ()
{
        echo "Delete the QDiscs that were previously active"
        tc qdisc del dev ${rx_iface} clsact

        echo "Enable the clsact Qdisc"
        tc qdisc add dev ${rx_iface} clsact
}

#'***************************************************************************************************'
echo "Test QoS_IPv4_TCP_DPORT"

initialize
begin_fresh

echo "Test Sequence Begins .. "
tc filter add dev ${rx_iface} ingress protocol ipv4 flower skip_sw ip_proto tcp dst_port 82 action drop

sleep 5

echo "sending Ipv4 packet with tcp dport 82 that matches the rule .. "
/usr/bin/pkt_io --tx_if ${tx_iface} --tx_num 10 --rx_num 10 --rx_if $rx_iface --vlan_ethtype 1 --ip_proto tcp --dst_port 82 -E 0

rc=$?
if [ $rc-ne 0 ]; then
echo " FAIL: Packets not dropped as expected"
else
echo "PASS: QoS_IPv4_TCP_DPORT"
fi

sleep 5

echo "sending Ipv4 packet with tcp dport 80 that does not matches the rule .. "
/usr/bin/pkt_io --tx_if ${tx_iface} --tx_num 10 --rx_num 10 --rx_if $rx_iface --vlan_ethtype 1 --ip_proto tcp --dst_port 80 -E 10

rc=$?
if [ $rc-ne 0 ]; then
echo " FAIL: when sending Ipv4 packet with tcp dport 80 that does not matches the rule .."
else
echo "PASS: Packets not dropped as expected"
fi

sleep 5

echo "sending Ipv6 packet with tcp dport 82 that does not matches the rule .. "
/usr/bin/pkt_io --tx_if ${tx_iface} --tx_num 10 --rx_num 10 --rx_if $rx_iface --vlan_ethtype 0 --ip_proto tcp --dst_port 82 -E 10

rc=$?
if [ $rc-ne 0 ]; then
echo " FAIL: when sending Ipv6 packet with tcp dport 82 that does not matches the rule .."
else
echo "PASS: Packets not dropped as expected"
fi

sleep 5

