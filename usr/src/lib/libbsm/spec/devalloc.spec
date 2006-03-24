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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libbsm/spec/devalloc.spec

function	getdadmline
include		<bsm/devices.h>
declaration	int getdadmline(char *, int, FILE *)
version		SUNWprivate_1.1
end		

function	getdmapdfield
include		<bsm/devices.h>
declaration	char *getdmapdfield(char *)
version		SUNWprivate_1.1
end		

function	setdaent
include		<bsm/devices.h>
declaration	void setdaent(void)
version		SUNWprivate_1.1
end		

function	enddaent
include		<bsm/devices.h>
declaration	void enddaent(void)
version		SUNWprivate_1.1
end		

function	setdafile
include		<bsm/devices.h>
declaration	void setdafile(char *)
version		SUNWprivate_1.1
end		

function	freedaent
include		<bsm/devices.h>
declaration	void freedaent(devalloc_t *)
version		SUNWprivate_1.1
end

function	getdaent
include		<bsm/devices.h>
declaration	devalloc_t *getdaent(void)
version		SUNWprivate_1.1
end		

function	getdanam
include		<bsm/devices.h>
declaration	devalloc_t *getdanam(char *)
version		SUNWprivate_1.1
end		

function	getdatype
include		<bsm/devices.h>
declaration	devalloc_t *getdatype(char *)
version		SUNWprivate_1.1
end		

function	setdmapent
include		<bsm/devices.h>
declaration	void setdmapent(void)
version		SUNWprivate_1.1
end		

function	enddmapent
include		<bsm/devices.h>
declaration	void enddmapent(void)
version		SUNWprivate_1.1
end		

function	setdmapfile
include		<bsm/devices.h>
declaration	void setdmapfile(char *)
version		SUNWprivate_1.1
end		

function	freedmapent
include		<bsm/devices.h>
declaration	void freedmapent(devmap_t *)
version		SUNWprivate_1.1
end

function	getdmapent
include		<bsm/devices.h>
declaration	devmap_t *getdmapent(void)
version		SUNWprivate_1.1
end		

function	getdmapnam
include		<bsm/devices.h>
declaration	devmap_t *getdmapnam(char *)
version		SUNWprivate_1.1
end		

function	getdmapdev
include		<bsm/devices.h>
declaration	devmap_t *getdmapdev(char *)
version		SUNWprivate_1.1
end		

function	getdmaptype
include		<bsm/devices.h>
declaration	devmap_t *getdmaptype(char *)
version		SUNWprivate_1.1
end		

function	getdmapfield
include		<bsm/devices.h>
declaration	char *getdmapfield(char *)
version		SUNWprivate_1.1
end		

function	setdadefent
include		<bsm/devalloc.h>
declaration	void setdadefent(void)
version		SUNWprivate_1.1
end		

function	enddadefent
include		<bsm/devalloc.h>
declaration	void enddadefent(void)
version		SUNWprivate_1.1
end		

function	freedadefent
include		<bsm/devalloc.h>
declaration	void freedadefent(da_defs_t *)
version		SUNWprivate_1.1
end

function	getdadefent
include		<bsm/devalloc.h>
declaration	da_defs_t *getdadefent(void)
version		SUNWprivate_1.1
end		

function	getdadeftype
include		<bsm/devalloc.h>
declaration	da_defs_t *getdadeftype(char *)
version		SUNWprivate_1.1
end		

function	da_is_on
include		<bsm/devalloc.h>
declaration	int da_is_on(void)
version		SUNWprivate_1.1
end

function	da_check_logindevperm
include		<bsm/devalloc.h>
declaration	int da_check_logindevperm(char *)
version		SUNWprivate_1.1
end

function	da_open_devdb
include		<bsm/devalloc.h>
declaration	int da_open_devdb(char *, FILE **, FILE **, int)
version		SUNWprivate_1.1
end

function	da_update_device
include		<bsm/devalloc.h>
declaration	int da_update_device(da_args *)
version		SUNWprivate_1.1
end

function	da_update_defattrs
include		<bsm/devalloc.h>
declaration	int da_update_defattrs(da_args *)
version		SUNWprivate_1.1
end

function	da_add_list
include		<bsm/devalloc.h>
declaration	int da_add_list(devlist_t *, char *, int, int)
version		SUNWprivate_1.1
end

function	da_remove_list
include		<bsm/devalloc.h>
declaration	int da_remove_list(devlist_t *, char *, int, char *, int)
version		SUNWprivate_1.1
end

function	da_print_device
include		<bsm/devalloc.h>
declaration	void da_print_device(int, devlist_t *)
version		SUNWprivate_1.1
end

function	getdevicerange
include		<sys/tsol/label.h> <bsm/devices.h>
declaration	int getdevicerange(const char *, brange_t *);
version		SUNWprivate_1.1
end
