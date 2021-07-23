
cp -f ../../../patch_new/patch9/lan937x_main.c drivers/net/dsa/microchip/
 
git add drivers/net/dsa/microchip/lan937x_main.c

git commit -m "

net: dsa: microchip: add support for vlan operations

Support for VLAN add, del, prepare and filtering operations.

The VLAN aware is a global setting. Mixed vlan filterings 
are not supported. vlan_filtering_is_global is made as true
in lan937x_setup function.

"
