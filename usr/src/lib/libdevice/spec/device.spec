#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libdevice/spec/device.spec

function	devctl_release
include		<sys/types.h>, <libdevice.h>
declaration	void devctl_release(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end		

function	devctl_device_online
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_device_online(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end		

function	devctl_device_offline
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_device_offline(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end		

function	devctl_device_getstate
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_device_getstate(devctl_hdl_t hdl, uint_t *statep)
version		SUNWprivate_1.1
end		

function	devctl_device_reset
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_device_reset(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end		

function	devctl_bus_quiesce
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_bus_quiesce(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end		

function	devctl_bus_unquiesce
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_bus_unquiesce(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end		

function	devctl_bus_getstate
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_bus_getstate(devctl_hdl_t hdl, uint_t *statep)
version		SUNWprivate_1.1
end		

function	devctl_bus_reset
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_bus_reset(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end		

function	devctl_bus_resetall
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_bus_resetall(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end		

function	devctl_bus_acquire
include		<sys/types.h>, <libdevice.h>
declaration	devctl_hdl_t devctl_bus_acquire(char *devfs_path, uint_t flags)
version		SUNWprivate_1.1
end		

function	devctl_bus_configure
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_bus_configure(devctl_hdl_t dcp)
version		SUNWprivate_1.1
end		

function	devctl_bus_unconfigure
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_bus_unconfigure(devctl_hdl_t dcp)
version		SUNWprivate_1.1
end		

function	devctl_device_acquire
include		<sys/types.h>, <libdevice.h>
declaration	devctl_hdl_t devctl_device_acquire(char *devfs_path, \
			uint_t flags)
version		SUNWprivate_1.1
end		

function	devctl_device_remove
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_device_remove(devctl_hdl_t dcp)
version		SUNWprivate_1.1
end		

function	devctl_ap_acquire
include		<libdevice.h>
declaration	devctl_hdl_t devctl_ap_acquire(char *devfs_path, uint_t flags)
version		SUNWprivate_1.1
end

function	devctl_pm_dev_acquire
include		<libdevice.h>
declaration	devctl_hdl_t devctl_pm_dev_acquire(char *devfs_path, uint_t flags)
version		SUNWprivate_1.1
end

function	devctl_pm_bus_acquire
include		<libdevice.h>
declaration	devctl_hdl_t devctl_pm_bus_acquire(char *devfs_path, uint_t flags)
version		SUNWprivate_1.1
end		

function	devctl_ap_insert
include		<libdevice.h>
declaration	int devctl_ap_insert(devctl_hdl_t hdl, nvlist_t *ap_data)
version		SUNWprivate_1.1
end		

function	devctl_ap_remove
include		<libdevice.h>
declaration	int devctl_ap_remove(devctl_hdl_t hdl, nvlist_t *ap_data)
version		SUNWprivate_1.1
end		

function	devctl_ap_connect
include		<libdevice.h>
declaration	int devctl_ap_connect(devctl_hdl_t hdl, nvlist_t *ap_data)
version		SUNWprivate_1.1
end		

function	devctl_ap_disconnect
include		<libdevice.h>
declaration	int devctl_ap_disconnect(devctl_hdl_t hdl,	\
			nvlist_t *ap_data)
version		SUNWprivate_1.1
end		

function	devctl_ap_configure
include		<libdevice.h>
declaration	int devctl_ap_configure(devctl_hdl_t hdl,	\
			nvlist_t *ap_data)
version		SUNWprivate_1.1
end		

function	devctl_ap_unconfigure
include		<libdevice.h>
declaration	int devctl_ap_unconfigure(devctl_hdl_t hdl,	\
			nvlist_t *ap_data)
version		SUNWprivate_1.1
end		

function	devctl_ap_getstate
include		<libdevice.h>
declaration	int devctl_ap_getstate(devctl_hdl_t hdl,	\
			nvlist_t *ap_data, devctl_ap_state_t *statep)
version		SUNWprivate_1.1
end		

function	devctl_ddef_alloc
include		<sys/types.h>, <libdevice.h>
declaration	devctl_ddef_t devctl_ddef_alloc(char *, int)
version		SUNWprivate_1.1
end		

function	devctl_ddef_free
include		<libdevice.h>
declaration	void devctl_ddef_free(devctl_ddef_t)
version		SUNWprivate_1.1
end		

function	devctl_ddef_int
include		<libdevice.h>
declaration	int devctl_ddef_int(devctl_ddef_t, char *, int32_t)
version		SUNWprivate_1.1
end		

function	devctl_ddef_int_array
include		<libdevice.h>
declaration	int devctl_ddef_int_array(devctl_ddef_t, \
		    char *, int, int32_t *)
version		SUNWprivate_1.1
end		

function	devctl_ddef_string
include		<libdevice.h>
declaration	int devctl_ddef_string(devctl_ddef_t, char *, char *)
version		SUNWprivate_1.1
end		

function	devctl_ddef_string_array
include		<libdevice.h>
declaration	int devctl_ddef_string_array(devctl_ddef_t, \
		    char *, int, char **)
version		SUNWprivate_1.1
end		

function	devctl_ddef_byte_array
include		<libdevice.h>
declaration	int devctl_ddef_byte_array(devctl_ddef_t, \
		    char *, int, uchar_t *)
version		SUNWprivate_1.1
end		

function	devctl_bus_dev_create
include		<libdevice.h>
declaration	int devctl_bus_dev_create(devctl_hdl_t, \
		    devctl_ddef_t, uint_t, devctl_hdl_t *)
version		SUNWprivate_1.1
end		

function	devctl_get_pathname
include		<libdevice.h>
declaration	char * devctl_get_pathname(devctl_hdl_t, char *, size_t)
version		SUNWprivate_1.1
end

function	devctl_pm_raisepower
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_raisepower(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_changepowerlow
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_changepowerlow(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_changepowerhigh
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_changepowerhigh(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_idlecomponent
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_idlecomponent(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_busycomponent
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_busycomponent(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_testbusy
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_testbusy(devctl_hdl_t hdl, uint_t *busyp)
version		SUNWprivate_1.1
end

function	devctl_pm_failsuspend
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_failsuspend(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_bus_teststrict
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_bus_teststrict(devctl_hdl_t hdl, uint_t *strict)
version		SUNWprivate_1.1
end

function	devctl_pm_device_changeonresume
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_device_changeonresume(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_device_no_lower_power
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_device_no_lower_power(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_bus_no_invol
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_bus_no_invol(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end

function	devctl_pm_device_promprintf
include		<sys/types.h>, <libdevice.h>
declaration	int devctl_pm_device_promprintf(devctl_hdl_t hdl)
version		SUNWprivate_1.1
end
