ifneq ($(KERNELRELEASE),)
    #kbuild syntax. dependency relationshsip of files and target modules are listed here.
    obj-m += snf.o
    snf-objs := main.o file.o hash.o
else
    ccflags-y := -std=gnu99
    PWD       := $(shell pwd)
    KVER      ?= $(shell uname -r)
    KDIR      := /lib/modules/$(KVER)/build
all:
	$(MAKE) -C $(KDIR) M=$(PWD)
clean:
	rm -rf .*.cmd *.o *.mod.c *.ko .tmp_versions
endif
