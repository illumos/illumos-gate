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
# lib/devid/spec/devid.spec

#
# Stable: PSARC/1995/352
#
function	devid_get
include		<sys/types.h>, <libdevid.h>
declaration	int devid_get(int fd, ddi_devid_t *devid)
version		SUNW_1.1
end		

function	devid_free
include		<sys/types.h>, <libdevid.h>
declaration	void devid_free(ddi_devid_t devid)
version		SUNW_1.1
end		

function	devid_get_minor_name
include		<sys/types.h>, <libdevid.h>
declaration	int devid_get_minor_name(int fd, char **minor_name)
version		SUNW_1.1
end		

function	devid_sizeof
include		<sys/types.h>, <libdevid.h>
declaration	size_t devid_sizeof(ddi_devid_t devid)
version		SUNW_1.1
end		

function	devid_compare
include		<sys/types.h>, <libdevid.h>
declaration	int devid_compare(ddi_devid_t id1, ddi_devid_t id2)
version		SUNW_1.1
end		

function	devid_deviceid_to_nmlist
include		<sys/types.h>, <libdevid.h>
declaration	int devid_deviceid_to_nmlist( char *search_path, \
			ddi_devid_t devid, char *minor_name, \
			devid_nmlist_t  **retlist)
version		SUNW_1.1
end		

function	devid_free_nmlist
include		<sys/types.h>, <libdevid.h>
declaration	void devid_free_nmlist(devid_nmlist_t *list)
version		SUNW_1.1
end		

#
# Stable: PSARC/2000/480
#
function	devid_valid
include		<sys/types.h>, <libdevid.h>
declaration	int devid_valid(ddi_devid_t devid)
version		SUNW_1.2
end		

function	devid_str_encode
include		<sys/types.h>, <libdevid.h>
declaration	char *devid_str_encode(ddi_devid_t devid, char *minor_name)
version		SUNW_1.2
end		

function	devid_str_decode
include		<sys/types.h>, <libdevid.h>
declaration	int devid_str_decode(char *devidstr, ddi_devid_t *devidp, \
			char **minor_namep)
version		SUNW_1.2
end		

function	devid_str_free
include		<sys/types.h>, <libdevid.h>
declaration	void devid_str_free(char *devidstr)
version		SUNW_1.2
end		

#
# Consolidation private: PSARC/2000/480
#
function	devid_str_compare
include		<sys/types.h>, <libdevid.h>
declaration	int devid_str_compare(char *id1_str, char *id2_str)
version		SUNWprivate_1.1
end

#
# Consolidation private: PSARC/2004/504
#
function	devid_scsi_encode
include		<sys/types.h>, <libdevid.h>
declaration	int devid_scsi_encode(int version, char *driver_name, \
		uchar_t *inq, size_t inq_len, uchar_t *inq80, \
		size_t inq80_len, uchar_t *inq83, \
		size_t inq83_len, ddi_devid_t *devid);
version         SUNWprivate_1.1
end

function	devid_to_guid
include		<sys/types.h>, <libdevid.h>
declaration	char *devid_to_guid(ddi_devid_t devid);
version		SUNWprivate_1.1
end

function	devid_free_guid
include		<sys/types.h>, <libdevid.h>
declaration	void devid_free_guid(char *guid);
version		SUNWprivate_1.1
end
