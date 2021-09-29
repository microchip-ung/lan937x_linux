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
echo "Test QoS_VLAN_PRIO_DROP"

initialize
begin_fresh

echo "Test Sequence Begins .. "
tc filter add dev ${rx_iface} ingress protocol 802.1Q flower skip_sw vlan_prio 5 action drop

sleep 5

echo "sending packet that matches the rule .. "
/usr/bin/pkt_io --tx_if ${tx_iface} --tx_num 10 --rx_num 10 --rx_if $rx_iface --vlan_prio 5 --vlan_ethtype 0 -E 0

rc=$?
if [ $rc-ne 0 ]; then
echo " FAIL: when sending vlan priority as 5 that matches the rule .."
else
echo "PASS: Ipv6 QoS_VLAN_PRIO_DROP"
fi

sleep 5

echo "sending Ipv4 packet with vlan priority as 4 that does not matches the rule .. "
/usr/bin/pkt_io --tx_if ${tx_iface} --tx_num 10 --rx_num 10 --rx_if $rx_iface --vlan_prio 5 --vlan_ethtype 1 -E 10

rc=$?
if [ $rc-ne 0 ]; then
echo " FAIL: when sending vlan priority as 4 that does not matches the rule .."
else
echo "PASS: Packets not dropped as expected"
fi

sleep 5


