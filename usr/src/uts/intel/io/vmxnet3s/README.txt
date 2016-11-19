#
# CDDL HEADER START
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
# CDDL HEADER END
#
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
#

The vmxnet3s driver is a paravirtualized GLDv3 NIC driver designed to
be used on VMware virtual machines version 7 and later.  This version
of the driver is based on the "stable-10.0.x" branch of the VMware
open-vm-tools which can be obtained from:

https://github.com/vmware/open-vm-tools

Changes from stable-10.0.x include:

* add support for VLANs
* enable building in the illumos gate
* enable building with the Sun Studio compiler
* lint cleanup: the driver is lint clean with two categorical
  exceptions for which warnings are disabled in the Makefile

The driver remains in the original C style to facilitate potential
future synchronization with upstream.
