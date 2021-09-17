chmod +x /scripts/QoS_VLAN_ID_DROP.sh
chmod +x /scripts/QoS_IPv4_TCP_DPORT.sh
chmod +x /scripts/QoS_IPv4_UDP_SPORT.sh
chmod +x /scripts/QoS_IPv6_TCP_DPORT.sh
chmod +x /scripts/QoS_IPv6_UDP_SPORT.sh
chmod +x /scripts/QoS_ETHTYPE_IPV4_IPTOS_TEST.sh
chmod +x /scripts/QoS_ETHTYPE_IPV4_IPTTL.sh
chmod +x /scripts/QoS_ETHTYPE_IPV6_IPTOS_TEST.sh
chmod +x /scripts/QoS_ETHTYPE_IPV6_IPTTL_TEST.sh

/scripts/disable_br0.sh
read -p "Press enter to continue"
/scripts/QoS_VLAN_ID_DROP.sh lan2 lan4
read -p "Press enter to continue"
/scripts/QoS_IPv4_TCP_DPORT.sh lan2 lan4
read -p "Press enter to continue"
/scripts/QoS_IPv4_UDP_SPORT.sh lan2 lan4
read -p "Press enter to continue"
/scripts/QoS_IPv6_TCP_DPORT.sh lan2 lan4
read -p "Press enter to continue"
/scripts/QoS_IPv6_UDP_SPORT.sh lan2 lan4
read -p "Press enter to continue"
/scripts/QoS_ETHTYPE_IPV4_IPTOS_TEST.sh lan2 lan4
read -p "Press enter to continue"
/scripts/QoS_ETHTYPE_IPV4_IPTTL.sh lan2 lan4
read -p "Press enter to continue"
/scripts/QoS_ETHTYPE_IPV6_IPTOS_TEST.sh lan2 lan4
read -p "Press enter to continue"
/scripts/QoS_ETHTYPE_IPV6_IPTTL_TEST.sh lan2 lan4
read -p "Press enter to continue"

