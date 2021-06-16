
cp -f ../../../patch_new/patch9/lan937x_main.c drivers/net/dsa/microchip/
 
git add drivers/net/dsa/microchip/lan937x_main.c

git commit -m "

net: dsa: microchip: add support for vlan operations

Support for VLAN add, del, prepare and filtering operations.

It aligns with latest update of removing switchdev
transactional logic from VLAN objects

"
