ifneq ($(KERNELRELEASE),)

# kbuild
ccflags-y := -march=armv7-a
ccflags-y += -I$(srctree)/drivers/crypto
obj-m += mxs-dcp.o

else

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
GO ?= go

.PHONY: dcp_aes_kdf

all:
	make -C ${KERNEL_SRC} M=$(CURDIR) modules

modules_install:
	make -C ${KERNEL_SRC} M=$(CURDIR) modules_install

clean:
	make -C ${KERNEL_SRC} M=$(CURDIR) clean

dcp_aes_kdf:
	@if [ ! -f "$(CURDIR)/go.mod" ]; then \
		$(GO) mod init github.com/usbarmory/mxs-dcp && \
		$(GO) mod tidy; \
	fi
	${GO} build -ldflags "-s -w" -o dcp_aes_kdf dcp_aes_kdf.go
endif
