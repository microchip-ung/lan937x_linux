
cp -f ../../../patch_new/patch7/lan937x_main.c drivers/net/dsa/microchip/
 
git add drivers/net/dsa/microchip/lan937x_main.c

git commit -m "

net: dsa: microchip: add support for port mirror operations

Added support for port_mirror_add() and port_mirror_del operations

Sniffing is limited to one port & alert the user if any new
sniffing port is selected 

"
