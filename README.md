NXP Data Co-Processor (DCP) - Linux driver
==========================================

**WARNING**: This is a work in progress and this README file is incomplete.

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
git clone https://github.com/inversepath/mxs-dcp
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

A standalone Go tool, for encryption and decryption, is also available in the
[dcp_tool.go](https://github.com/inversepath/mxs-dcp/blob/master/dcp_tool.go)
file.

License
=======

NXP Data Co-Processor (DCP) - Linux driver
https://github.com/inversepath/mxs-dcp

Copyright (c) F-Secure Corporation  
Copyright (c) 2013 Marek Vasut <marex@denx.de>  

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation under version 3 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

See accompanying LICENSE file for full details.
