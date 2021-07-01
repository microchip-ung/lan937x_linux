cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/phy/microchip_t1.c drivers/net/phy/

git add drivers/net/phy/microchip_t1.c

git commit -m "

net: phy: Add support for LAN937x T1 phy driver

Added support for Microchip LAN937x T1 phy driver. The sequence of
initialization is used commonly for both LAN87xx and LAN937x 
drivers. The new initialization sequence is an improvement to 
existing LAN87xx and the same is shared with LAN937x.

"
