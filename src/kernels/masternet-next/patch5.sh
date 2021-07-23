cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/lan937x_dev.c drivers/net/dsa/microchip/
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/dsa/microchip/lan937x_dev.h drivers/net/dsa/microchip/
cp -f ../../../patch_new/patch5/lan937x_main.c drivers/net/dsa/microchip/
 
git add drivers/net/dsa/microchip/lan937x_main.c drivers/net/dsa/microchip/lan937x_dev.c drivers/net/dsa/microchip/lan937x_dev.h

git commit -m "

net: dsa: microchip: add support for phylink management

Support for phylink_validate() and reused KSZ commmon API for
phylink_mac_link_down() operation

lan937x_phylink_mac_config configures the interface using 
lan937x_mac_config and lan937x_phylink_mac_link_up configures
the speed/duplex/flow control.

Currently SGMII & in-band neg are not supported & it will be
added later.

"