cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/include/net/dsa.h include/net/
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/net/dsa/Kconfig net/dsa
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/net/dsa/tag_ksz.c net/dsa
 
git add include/net/dsa.h net/dsa/Kconfig net/dsa/tag_ksz.c

git commit -m "

net: dsa: tag_ksz: add tag handling for Microchip LAN937x

The Microchip LAN937X switches have a tagging protocol which is
very similar to KSZ tagging. So that the implementation is added to
tag_ksz.c and reused common APIs

"
