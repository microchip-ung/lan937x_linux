git checkout master
git branch -D testbranch
git checkout -b testbranch

cp ../../../patch_new/patch1.sh .
chmod 0777 patch1.sh
./patch1.sh

cp ../../../patch_new/patch2_0.sh .
chmod 0777 patch2_0.sh
./patch2_0.sh

cp ../../../patch_new/patch2.sh .
chmod 0777 patch2.sh
./patch2.sh

cp ../../../patch_new/patch3.sh .
chmod 0777 patch3.sh
./patch3.sh

cp ../../../patch_new/patch4/patch4.sh .
chmod 0777 patch4.sh
./patch4.sh

cp ../../../patch_new/patch5/patch5.sh .
chmod 0777 patch5.sh
./patch5.sh
 
cp ../../../patch_new/patch6/patch6.sh .
chmod 0777 patch6.sh 
./patch6.sh

cp ../../../patch_new/patch7/patch7.sh .
chmod 0777 patch7.sh
./patch7.sh
 
cp ../../../patch_new/patch8/patch8.sh .
chmod 0777 patch8.sh 
./patch8.sh

cp ../../../patch_new/patch9/patch9.sh .
chmod 0777 patch9.sh 
./patch9.sh
