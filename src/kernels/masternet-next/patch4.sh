cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/Kconfig drivers/net/dsa/microchip/
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/Makefile  drivers/net/dsa/microchip/
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/ksz_common.h drivers/net/dsa/microchip/
cp -f ../../../patch_new/patch4/lan937x_dev.c drivers/net/dsa/microchip/
cp -f ../../../patch_new/patch4/lan937x_dev.h drivers/net/dsa/microchip/
cp -f ../../../patch_new/patch4/lan937x_main.c drivers/net/dsa/microchip/
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/lan937x_reg.h drivers/net/dsa/microchip/
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/lan937x_spi.c drivers/net/dsa/microchip/

 
git add drivers/net/dsa/microchip/Kconfig drivers/net/dsa/microchip/Makefile drivers/net/dsa/microchip/ksz_common.h drivers/net/dsa/microchip/lan937x_dev.c drivers/net/dsa/microchip/lan937x_dev.h drivers/net/dsa/microchip/lan937x_main.c drivers/net/dsa/microchip/lan937x_reg.h drivers/net/dsa/microchip/lan937x_spi.c

git commit -m "

net: dsa: microchip: add DSA support for microchip lan937x

Basic DSA driver support for lan937x and the device will be
configured through SPI interface.

drivers/net/dsa/microchip/ path is already part of MAINTAINERS &
the new files come under this path. Hence no update needed to the
MAINTAINERS

Reused KSZ APIs for port_bridge_join() & port_bridge_leave() and
added support for port_stp_state_set() & port_fast_age().

lan937x_flush_dyn_mac_table() which gets called from
port_fast_age() of KSZ common layer, hence added support for it.

"
