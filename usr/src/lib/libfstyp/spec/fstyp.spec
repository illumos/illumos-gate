#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libfstyp/spec/fstyp.spec

# fstyp initialize
function	fstyp_init
include		<sys/types.h>
declaration	int fstyp_init(int fd, off_t offset, char *module_dir, fstyp_handle_t *handle)
version		SUNW_1.1
exception	$return != 0
end		

# fstyp finalize
function	fstyp_fini
declaration	void fstyp_fini(fstyp_handle_t handle)
version		SUNW_1.1
end		

# fstyp identify
function	fstyp_ident
declaration	int fstyp_ident(fstyp_handle_t handle, const char *fsname, char **ident)
version		SUNW_1.1
exception	$return != 0
end		

# fstyp get attributes
function	fstyp_get_attr
include		<libnvpair.h>
declaration	int fstyp_get_attr(fstyp_handle_t handle, nvlist_t **attr)
version		SUNW_1.1
exception	$return != 0
end		

# fstyp dump fs info
function	fstyp_dump
include		<stdio.h>
declaration	int fstyp_dump(fstyp_handle_t handle, FILE *fout, FILE *ferr)
version		SUNW_1.1
exception	$return != 0
end		

# fstyp error string
function	fstyp_strerror
declaration	const char *fstyp_strerror(int error)
version		SUNW_1.1
end

