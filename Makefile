ifneq ($(KERNELRELEASE),)

# kbuild
ccflags-y := -march=armv7-a
ccflags-y += -I$(srctree)/drivers/crypto
obj-m += mxs-dcp.o

else

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
GO ?= go

.PHONY: dcp_tool

all:
	make -C ${KERNEL_SRC} M=$(CURDIR) modules

modules_install:
	make -C ${KERNEL_SRC} M=$(CURDIR) modules_install

clean:
	make -C ${KERNEL_SRC} M=$(CURDIR) clean

dcp_tool:
	GOARCH=arm GO111MODULE=auto ${GO} build -ldflags "-s -w" -o dcp_tool dcp_tool.go
endif
