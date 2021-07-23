git checkout master
git branch -D testbranch
git checkout -b testbranch

rm op1.txt op2_0.txt op2.txt op3.txt op4.txt op5.txt op6.txt op7.txt op8.txt op9.txt

./patch1.sh
make ARCH=arm sama5_lan937x_dsa_defconfig
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op1.txt

./patch2_0.sh
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op2_0.txt

./patch2.sh
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op2.txt

./patch3.sh
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op3.txt


./patch4.sh
make ARCH=arm sama5_lan937x_dsa_defconfig
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op4.txt

./patch5.sh
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op5.txt

./patch6.sh
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op6.txt

./patch7.sh
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op7.txt

./patch8.sh
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op8.txt

./patch9.sh
make ARCH=arm CROSS_COMPILE="arm-linux-gnueabihf-" 2>&1 | tee op9.txt

