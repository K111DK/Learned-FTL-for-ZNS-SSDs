rm -f ./vmlinux
rm -f ./dm-zftl.ko
sshpass -p femu rsync -avz -e "ssh -p 8080" /home/log/Desktop/dm-LZFTL/$(ls) femu@localhost:/tmp/dm-zoned