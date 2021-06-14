#!/bin/sh

if [ $1 = "1" ]; then
	tc qdisc add dev lan3 root handle 1: mqprio num_tc 8 map 0 1 2 3 4 5 6 7 hw 1
elif [ $1 = "2" ]; then
	tc qdisc replace dev lan3 parent 1:1 handle 11 cbs idleslope 10000 sendslope -90000 locredit 0x0606 hicredit 0x606 offload 1
        tc qdisc replace dev lan3 parent 1:2 handle 22 cbs idleslope 20000 sendslope -80000 locredit 0x0606 hicredit 0x606 offload 1
        tc qdisc replace dev lan3 parent 1:3 handle 33 cbs idleslope 30000 sendslope -70000 locredit 0x0606 hicredit 0x606 offload 1
        tc qdisc replace dev lan3 parent 1:4 handle 44 cbs idleslope 40000 sendslope -60000 locredit 0x0606 hicredit 0x606 offload 1
        tc qdisc replace dev lan3 parent 1:5 handle 55 cbs idleslope 50000 sendslope -50000 locredit 0x0606 hicredit 0x606 offload 1
        tc qdisc replace dev lan3 parent 1:6 handle 66 cbs idleslope 60000 sendslope -40000 locredit 0x0606 hicredit 0x606 offload 1
        tc qdisc replace dev lan3 parent 1:7 handle 77 cbs idleslope 70000 sendslope -30000 locredit 0x0606 hicredit 0x606 offload 1
        tc qdisc replace dev lan3 parent 1:8 handle 88 cbs idleslope 80000 sendslope -20000 locredit 0x0606 hicredit 0x606 offload 1
elif [ $1 = "3" ]; then
	tc qdisc show
elif [ $1 = "4" ]; then
	tc qdisc del dev lan3 root
elif [ $1 = "5" ]; then
	ip link set dev br0 type bridge vlan_filtering 1
	bridge vlan add dev br0 self vid 5 pvid untagged
	bridge vlan add dev lan3 vid 5 pvid untagged
	bridge vlan show
fi
