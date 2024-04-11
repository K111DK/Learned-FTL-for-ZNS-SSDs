obj-m += dm-zftl.o
dm-zftl-y += dm-zftl-target.o dm-zftl-reclaim.o
dm-zftl-y += /DM-LZFTL


.PHONY: all
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY: debug
debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


