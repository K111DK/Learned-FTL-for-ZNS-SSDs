install_mod(){
  if [ $(lsmod | grep dm_zap | wc -l) == 0 ]
  then
    insmod dm-zap.ko
  else
    rmmod dm-zap.ko
  fi
}

setup_dm(){
  device="/dev/nvme0n1"
  # Number of conventional zones of the given device
  conv="0"
  # Overprovisioning rate (in %)
  op_rate="30"
  # Class 0 threshold of Fast Cost-Benefit (affects dm-zap GC only when
  # victim_selection_method="2" is set)
  class_0_cap="125"
  # Class 0 optimal of Fast Cost-Benefit (affects dm-zap GC only when
  # victim_selection_method="2" is set)
  class_0_optimal="25"
  # Pick a GC victim selection method (0: Greedy, 1: Cost-Benefit,
  # 2: Fast Cost-Benefit, 3: Approximative Cost-Benefit, 4: Constant Greedy,
  # 5: Constant Cost-Benefit, 6: FeGC, 7: FaGC+)
  victim_selection_method="0"
  # Limit of free zones (in %) when the GC should start reclaiming space
  reclaim_limit="10"
  # q limit of Approximative Cost-Benefit victim selection (affects dm-zap GC
  # only when victim_selection_method="3" is set)
  q_cap="0"
  echo "0 `blockdev --getsize ${device}` zap ${device} ${conv} ${op_rate} ${class_0_cap} ${class_0_optimal} ${victim_selection_method} ${reclaim_limit} ${q_cap}" | sudo dmsetup create dmzap
}

echo "Install mod to kernel..."
dmsetup remove_all
install_mod
echo "Setup dmzap..."
setup_dm
echo "Setup finished!"
