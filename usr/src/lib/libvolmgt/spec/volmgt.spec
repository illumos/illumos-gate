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
# lib/libvolmgt/spec/volmgt.spec

function	media_getid
version		SUNW_0.7
end		

function	volmgt_acquire
version		SUNW_1.1
end		

function	volmgt_feature_enabled
version		SUNW_1.1
end		

function	volmgt_ownspath
version		SUNW_0.7
end		

function	volmgt_release
version		SUNW_1.1
end		

function	media_findname
include		<volmgt.h>
declaration	char *media_findname(char *start)
version		SUNW_0.7
errno		ENXIO
exception	$return == 0
end		

function	media_getattr
declaration	char *media_getattr(char *vol_path, char *attr)
version		SUNW_0.7
errno		ENXIO EINTR
exception	$return == 0
end		

function	media_setattr
declaration	int media_setattr(char *vol_path, char *attr, char *value)
version		SUNW_0.7
errno		ENXIO EINTR
exception	$return == 0
end		

function	volmgt_check
include		<volmgt.h>
declaration	int volmgt_check(char *pathname)
version		SUNW_0.7
errno		ENXIO EINTR 
exception	$return == 0
end		

function	volmgt_inuse
include		<volmgt.h>
declaration	int volmgt_inuse(char *pathname)
version		SUNW_0.7
errno		ENXIO EINTR 
exception	$return == 0
end		

function	volmgt_root
declaration	const char *volmgt_root(void)
version		SUNW_0.7
exception	$return == 0
end		

function	volmgt_running
include		<volmgt.h>
declaration	int volmgt_running(void)
version		SUNW_0.7
errno		ENXIO EINTR 
exception	$return == 0
end		

function	volmgt_symname
include		<volmgt.h>
declaration	char *volmgt_symname(char *pathname)
version		SUNW_0.7
errno		ENXIO EINTR
exception	$return != 0
end		

function	volmgt_symdev
include		<volmgt.h>
declaration	char *volmgt_symdev(char *symname)
version		SUNW_0.7
errno		ENXIO EINTR
exception	$return != 0
end		

function	_dev_mounted
version		SUNWprivate_1.1
end		

function	_dev_unmount
version		SUNWprivate_1.1
end		

function	_media_oldaliases
version		SUNWprivate_1.1
end		

function	_media_printaliases
version		SUNWprivate_1.1
end		

