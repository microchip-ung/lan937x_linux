 
#Test Setup
#lan3 - Traffic to be sent to this port 
#lan4 - Traffic received on lan3 will be mirrored on this port. 



#Create a bridge 
#Bridge is avaiable by default using init.d buildroot scripts
 
echo "Configure Port Mirroring"

#Add new mac address for lan1, so that if traffic sent to lan3, it wil be dedicated to lan1 
bridge fdb add 01:02:03:04:05:06 dev lan1 master temp 


#After above command, send traffic with dest mac 01:02:03:04:05:06 to lan3 and monitor lan4, there will be no traffic in lan4. 
#Because 01:02:03:04:05:06 belongs to lan1 

 
#brought up lan4 
ip link set up dev lan4 
 

#create clsact qdisc and attach lan3 
tc qdisc add dev lan3 clsact 


#mirror lan3 ingress packet to lan4 
tc filter add dev lan3 ingress matchall skip_sw action mirred egress mirror dev lan4 

echo "Completed"
# Enable if required - mirror lan3 egress packet to lan4 
#tc filter add dev lan3 egress matchall skip_sw action mirred egress mirror dev lan4 