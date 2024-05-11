obj-m += dm-zftl.o
dm-zftl-y += dm-zftl-target.o dm-zftl-reclaim.o dm-zftl-l2p.o
dm-zftl-y += dm-zftl-leaftl.o

.PHONY: all
all:
	make -w -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY: debug
debug:
	make -w -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY: clean
clean:
	make -w -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


