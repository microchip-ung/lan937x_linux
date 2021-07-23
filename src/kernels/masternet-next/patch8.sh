
cp -f ../../../patch_new/patch8/lan937x_main.c drivers/net/dsa/microchip/
 
git add drivers/net/dsa/microchip/lan937x_main.c

git commit -m "

net: dsa: microchip: add support for fdb and mdb management

Support for fdb_add, mdb_add, fdb_del, mdb_del and
fdb_dump operations

"