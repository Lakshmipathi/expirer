echo "Moving giis-ext4 binary"
mv -v ./expirer ./bin
mv -v ./expirerd ./bin
cp -v ui/expirer-gui ./bin
cp -v bin/expirer /usr/sbin
cp -v bin/expirerd /usr/sbin
cp -v bin/expirer-gui /usr/sbin

echo "done."
