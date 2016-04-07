#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2012 by Delphix. All rights reserved.
#

The vmxnet3s driver is a paravirtualized GLDv3 NIC driver designed to
be used on VMware virtual machines version 7 and later.

This version of the driver was initially based on the "stable-8.6.x" branch
of the VMware open-vm-tools which can be obtained from:

https://github.com/vmware/open-vm-tools

Current changes include:

* cstyle and lint cleanup: the driver is lint clean with two categorical
  exceptions for which warnings are disabled in the Makefile

* added support for dladm mtu property
* added support for VLANs
* LSO fix contributed by Michael Tsymbalyuk <mtzaurus@gmail.com>
