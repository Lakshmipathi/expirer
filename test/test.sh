for i in {1..10};do
dd if=/dev/urandom of=/home/laks/testdir/file$i.txt bs=1024 count=1
sync
sync
sync
sync
sleep 5
/usr/sbin/expirer -d  /dev/sda7 -f /home/laks/testdir/file$i.txt -t $i

done
