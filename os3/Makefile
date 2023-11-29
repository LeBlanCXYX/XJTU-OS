CONFIG_MODULE_SIG=n

ifneq ($(KERNELRELEASE),)
        obj-m :=dev.o
else
        KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
endif