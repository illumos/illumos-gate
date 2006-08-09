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
# lib/libsmedia/library/spec/smedia.spec

function	smedia_get_device_info
declaration 	int32_t smedia_get_device_info(smedia_handle_t handle, smdevice_info_t *smdevinfop)	
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_free_device_info
declaration 	int32_t smedia_free_device_info(smedia_handle_t handle, smdevice_info_t *smdevinfop)	
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_get_medium_property
declaration 	int32_t smedia_get_medium_property(smedia_handle_t handle, smmedium_prop_t *smpropp)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_get_protection_status
declaration 	int32_t smedia_get_protection_status(smedia_handle_t handle, smwp_state_t *wpstatep)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_set_protection_status
declaration 	int32_t smedia_set_protection_status(smedia_handle_t handle, smwp_state_t *wpstatep)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_raw_read
declaration 	size_t smedia_raw_read(smedia_handle_t handle, diskaddr_t blockno, caddr_t buffer, size_t nbytes)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_raw_write
declaration 	size_t smedia_raw_write(smedia_handle_t handle, diskaddr_t blockno, caddr_t buffer, size_t nbytes)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_format
declaration 	int32_t smedia_format(smedia_handle_t handle, uint32_t flavor, uint32_t mode)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_check_format_status
declaration 	int32_t smedia_check_format_status(smedia_handle_t handle)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_format_track
declaration 	int32_t smedia_format_track(smedia_handle_t handle, uint_t trackno, uint_t head, uint_t density)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_eject
declaration 	int32_t smedia_eject(smedia_handle_t handle)
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_reassign_block
declaration 	int32_t smedia_reassign_block(smedia_handle_t handle, diskaddr_t blockno);
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_get_handle
declaration 	smedia_handle_t smedia_get_handle(int);
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_release_handle
declaration 	int32_t smedia_release_handle(smedia_handle_t handle);
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		

function	smedia_uscsi_cmd
declaration 	int32_t smedia_uscsi_cmd(smedia_handle_t handle, struct uscsi_cmd *cmd);
version		SUNWprivate_1.1
include 	"../../inc/smedia.h"
errno		EIO
end		
