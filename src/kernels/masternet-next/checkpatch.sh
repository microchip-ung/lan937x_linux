git checkout master
git branch -D testbranch
git checkout -b testbranch

./copy_from_buildroot.sh

git add -N MAINTAINERS drivers/net/dsa/microchip/Kconfig drivers/net/dsa/microchip/Makefile drivers/net/dsa/microchip/ksz_common.h drivers/net/phy/microchip_t1.c include/net/dsa.h net/dsa/Kconfig net/dsa/tag_ksz.c

git add -N drivers/net/dsa/microchip/lan937x_dev.c drivers/net/dsa/microchip/lan937x_dev.h drivers/net/dsa/microchip/lan937x_main.c drivers/net/dsa/microchip/lan937x_reg.h drivers/net/dsa/microchip/lan937x_spi.c Documentation/devicetree/bindings/net/dsa/microchip,lan937x.yaml

git diff >my_fixes.patch

./scripts/checkpatch.pl my_fixes.patch --max-line-length=80 >output.txt --fix --strict

gedit output.txt


