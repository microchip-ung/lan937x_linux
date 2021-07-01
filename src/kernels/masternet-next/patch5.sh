
cp -f ../../../patch_new/patch5/lan937x_main.c drivers/net/dsa/microchip/
 
git add drivers/net/dsa/microchip/lan937x_main.c

git commit -m "

net: dsa: microchip: add support for phylink management

Support for phylink_validate() and reused KSZ commmon API for
phylink_mac_link_down() operation

"
