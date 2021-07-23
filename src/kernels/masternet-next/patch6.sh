
cp -f ../../../patch_new/patch6/lan937x_main.c drivers/net/dsa/microchip/
 
git add drivers/net/dsa/microchip/lan937x_main.c

git commit -m "

net: dsa: microchip: add support for ethtool port counters

Reused the KSZ common APIs for get_ethtool_stats() & get_sset_count()
along with relevant lan937x hooks for KSZ common layer and added
support for get_strings()

"