cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/drivers/net/phy/microchip_t1.c drivers/net/phy/

git add drivers/net/phy/microchip_t1.c

git commit -m "

net: phy: Add support for LAN937x T1 phy driver

Added support for Microchip LAN937x T1 phy driver. The sequence of
initialization is used commonly for both LAN87xx and LAN937x 
drivers. The new initialization sequence is an improvement to 
existing LAN87xx and it is shared with LAN937x. 

Also relevant comments are added in the existing code and existing
soft-reset customized code has been replaced with 
genphy_soft_reset().

access_ereg_clr_poll_timeout() API is introduced for polling phy
bank write and this is linked with PHYACC_ATTR_MODE_POLL.

Finally introduced function table for LAN937X_T1_PHY_ID along with
microchip_t1_phy_driver struct.

"
