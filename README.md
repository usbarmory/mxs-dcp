NXP Data Co-Processor (DCP) - Linux driver
==========================================

The NXP Data Co-Processor (DCP) is a built-in hardware module for specific NXP
SoCs¹ that implements a dedicated AES cryptographic engine for
encryption/decryption operations.

A device specific random 256-bit OTPMK key is fused in each SoC at
manufacturing time, this key is unreadable and can only be used by the DCP for
AES encryption/decryption of user data, through the Secure Non-Volatile Storage
(SNVS) companion block.

This directory contains a Linux kernel driver for the DCP, with the specific
functionality of encrypting/decrypting a data blob (typically an encryption
key) with the OTPMK made available by the SNVS.

The module allows DCP supported symmetric ciphers and hash functions to be used
through the Linux Crypto API, available algorithms are listed in
`/proc/crypto`.

The driver is a customized version of the mainline Linux kernel
[mxs-dcp](https://github.com/torvalds/linux/blob/master/drivers/crypto/mxs-dcp.c)
driver, patched to allow use of the OTPMK released by the SNVS.

Ensure the `CONFIG_CRYPTO_DEV_MXS_DCP` option is not built-in in your kernel.

¹i.MX23, i.MX28, i.MX6SL, i.MX6SLL, i.MX6ULL, i.MX6ULZ

Authors
=======

Marek Vasut (original driver)  
marex@denx.de  

Andrea Barisani (OTP key support and userspace tool)  
andrea.barisani@f-secure.com | andrea@inversepath.com  

Compiling
=========

The following instructions assume compilation on a native armv7 architecture,
when cross compiling adjust `ARCH` and `CROSS_COMPILE` variables accordingly.

```
# the Makefile attempts to locate your Linux kernel source tree, if this fails
# it can be passed with a Makefile variable (e.g. `make KERNEL_SRC=path`)
git clone https://github.com/f-secure-foundry/mxs-dcp
cd mxs-dcp
make
make modules_install
```

Once installed the resulting module can be loaded in the traditional manner:

```
modprobe mxs_dcp
```

The probing of the driver depends on the DCP Device Tree (dts) inclusion in
the running Linux kernel, on modern kernel
[dts](https://github.com/torvalds/linux/blob/v5.0/arch/arm/boot/dts/imx6ull.dtsi#L42-L50)
files this should already be the case for SoCs that support it (e.g. i.MX6ULL).

Operation
=========

**IMPORTANT**: the unique OTPMK internal key is available only when Secure Boot
(HAB) is enabled, otherwise a Non-volatile Test Key (NVTK), identical for each
SoC, is used. The secure operation of the DCP and SNVS, in production
deployments, should always be paired with Secure Boot activation.

The `mxs_dcp` module, when not in Trusted or Secure State, issues the
following warning at load time:

```
mxs_dcp: WARNING - not in Trusted or Secure State, Non-volatile Test Key in effect
```

When in Trusted or Secure State the module issues a corresponding log message
at load time:

```
mxs_dcp: Trusted State detected
```

The driver exposes hardware accelerated symmetric ciphers AES-128-ECB
(`ecb-aes-dcp`) and AES-128-CBC (`cbc-aes-dcp`). When a key of length 0 is set
through `ALG_SET_KEY` then the OTPMK derived hardware key (`UNIQUE KEY`) is
selected, otherwise the passed key is used.

Additionally the driver also exposes hardware accelerated hash functions SHA1
(`sha1-dcp`) and SHA256 (`sha256-dcp`).

The [INTERLOCK](https://github.com/f-secure-foundry/interlock) file encryption
front-end supports the DCP through this driver, providing a Go userspace
implementation reference.

A standalone Go tool, for encryption and decryption, is also available in the
[dcp_tool.go](https://github.com/f-secure-foundry/mxs-dcp/blob/master/dcp_tool.go)
file.

License
=======

NXP Data Co-Processor (DCP) - Linux driver
https://github.com/f-secure-foundry/mxs-dcp

Copyright (c) F-Secure Corporation  
Copyright (c) 2013 Marek Vasut <marex@denx.de>  

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation under version 3 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

See accompanying LICENSE file for full details.
