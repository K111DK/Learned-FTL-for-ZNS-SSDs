obj-m := dm-zap.o
dm-zap-y := dm-zap-target.o dm-zap-reclaim.o dm-zap-map.o dm-zap-heap.o dm-zap-conv-io.o
.PHONY: all
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean