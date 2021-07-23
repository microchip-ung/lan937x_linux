cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/ksz_common.c drivers/net/dsa/microchip/ksz_common.c
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/ksz9477.c drivers/net/dsa/microchip/ksz9477.c
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/ksz8795.c drivers/net/dsa/microchip/ksz8795.c

git add drivers/net/dsa/microchip/ksz_common.c drivers/net/dsa/microchip/ksz9477.c drivers/net/dsa/microchip/ksz8795.c

git commit -m "

net: dsa: move mib->cnt_ptr reset code to ksz_common.c

mib->cnt_ptr resetting is handled in multiple places as part of
port_init_cnt(). Hence moved mib->cnt_ptr code to ksz common layer 
and removed from individual product files.

"

