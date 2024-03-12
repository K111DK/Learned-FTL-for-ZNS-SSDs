obj-m += dm-zftl-target.o

.PHONY: all
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean