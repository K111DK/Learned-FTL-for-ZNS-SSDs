mapper_path="/dev/mapper/"
device="/dev/nvme0n1"
cache_device="/dev/nvme1n1"
target_device="ZFTL"
echo deadline > /sys/block/nvme0n1/queue/scheduler

seq_write_test(){
  filename=${mapper_path}${target_device}
  ioengine='libaio'
  bs='4k'
  direct=1
  iodepth=1
  size='40k'
  numjobs=1
  rw='write'
  fio --filename=${filename} --ioengine=${ioengine} --bs=${bs} \
      --direct=${direct} --rw=${rw} --numjobs=${numjobs} --size=${size} --iodepth=${iodepth}
}

compile_install(){
  dmsetup remove_all
  rmmod dm-zftl.ko
  insmod dm-zftl.ko
}

switch_dir(){
  cd /tmp/dm-zoned
}

setup_target(){
  echo "0 `blockdev --getsize ${device}` zftl ${cache_device} ${device} "| sudo dmsetup create ${target_device}
}

switch_dir
compile_install
setup_target
echo "Target set up"
