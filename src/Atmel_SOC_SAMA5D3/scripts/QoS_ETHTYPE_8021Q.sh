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
echo "Test ETHTYPE_8021Q"

initialize
begin_fresh

echo "Test Sequence Begins .. "
echo "ip_proto should be dont cared "
tc filter add dev ${rx_iface} ingress protocol 802.1Q flower skip_sw action drop


sleep 5

echo "sending 802.1Q packet that matches the rule .. "
/usr/bin/pkt_io --tx_if ${tx_iface} --tx_num 10 --rx_num 10 --rx_if $rx_iface --vlan_ethtype 2 --ip_proto tcp --dst_port 82 -E 0

rc=$?
if [ $rc-ne 0 ]; then
echo "FAIL: 802.1Q Packets Not Dropped"
else
echo "PASS: 802.1Q Packets Dropped"
fi

sleep 5

echo "sending IPv4 packet that should not match the rule .. "
/usr/bin/pkt_io --tx_if ${tx_iface} --tx_num 10 --rx_num 10 --rx_if $rx_iface --vlan_ethtype 1 --ip_proto tcp --dst_port 82 -E 10

rc=$?
if [ $rc-ne 0 ]; then
echo " FAIL: IPv4 Packets are affected by the rule"
else
echo "PASS: IPV4 Packets not affected"
fi

sleep 5

echo "sending IPv6 packets that should not match the rule .. "
/usr/bin/pkt_io --tx_if ${tx_iface} --tx_num 10 --rx_num 10 --rx_if $rx_iface --vlan_ethtype 0 --ip_proto tcp --dst_port 82 -E 10

rc=$?
if [ $rc-ne 0 ]; then
echo " FAIL: Ipv6 Packets are affected by the rule"
else
echo "PASS: IPv6 Packets not affected"
fi

sleep 5

