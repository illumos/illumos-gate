#! /usr/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Efcode cleanup
# Disable efdaemon on target systems not supporting Embedded Fcode Interpreter
# Enable  efdaemon on target systems supporting Embedded Fcode Interpreter
#
# We may need to enable/disable the efdaemon services in SMF.  This could
# happen if the system the flash was created on and the target system support
# different hotplug implementations.
#
ARCH=`/usr/bin/uname -m`

# 
# arch == sun4u
#
# Not all sun4u platforms support efcode. 
# Daemon support is based upon finding the 
# "pcicfg.e (PCIe/PCI Config (EFCode Enabled)"
# module in the modinfo output
#
if [ `/usr/sbin/modinfo | /usr/bin/grep -c pcicfg` != "0" ]; then
	echo "/usr/sbin/svcadm enable /platform/${ARCH}/efdaemon:default" >> \
	    ${FLASH_ROOT}/var/svc/profile/upgrade
else
	echo "/usr/sbin/svcadm disable /platform/${ARCH}/efdaemon:default" >> \
	    ${FLASH_ROOT}/var/svc/profile/upgrade
fi
