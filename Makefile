obj-m := dm-zftl.o
dm-zftl-y := dm-zftl-target.o dm-zftl-reclaim.o dm-zftl-leaftl.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}
.PHONY: all
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY: debug
debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


