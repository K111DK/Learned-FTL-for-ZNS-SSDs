device="/dev/nvme0n1"
cache_device="/dev/nvme1n1"
echo deadline > /sys/block/nvme0n1/queue/scheduler
sudo make
insmod dm-zftl-target.ko
echo "0 `blockdev --getsize ${device}` zftl ${cache_device} ${device} "| sudo dmsetup create zns
