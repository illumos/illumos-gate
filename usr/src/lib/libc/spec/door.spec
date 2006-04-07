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

function	door_bind
include		<door.h>
declaration	int door_bind(int d)
version		SUNW_1.23
end

function	door_call
include		<door.h>
declaration	int door_call(int did, door_arg_t *arg)
version		SUNW_1.23
exception	$return == -1
end

function	door_create
include		<door.h>
declaration	int door_create( \
			void (*server_procedure)(void *cookie, char *argp, \
				size_t arg_size, door_desc_t *dp, \
				uint_t n_desc), \
			void *cookie, uint_t attributes)
version		SUNW_1.23
exception	$return == -1
end

function	door_cred
include		<door.h>
declaration	int door_cred(door_cred_t *dc)
version		SUNW_1.23
end

function	door_ucred
include		<door.h>
declaration	int door_ucred(ucred_t **)
version		SUNW_1.23
end

function	door_info
include		<door.h>
declaration	int door_info(int did, door_info_t *di)
version		SUNW_1.23
exception	$return == -1
end

function	door_return
include		<door.h>
declaration	int door_return(char *data_ptr, size_t data_size, \
			door_desc_t *desc_ptr, uint_t desc_size)
version		SUNW_1.23
exception	$return == -1
end

function	door_revoke
include		<door.h>
declaration	int door_revoke(int did)
version		SUNW_1.23
exception	$return == -1
end

#
# Header uses door_server_func_t, spec2trace does not interpret
# typedefs, so we use an alternate binary equivalent for delaration
#   declaration	door_server_func_t *door_server_create(door_server_func_t *)
#
function	door_server_create
include		<door.h>
declaration	void (*door_server_create(void(*create_proc)(door_info_t*))) \
			(door_info_t *)
version		SUNW_1.23
end

function	door_unbind
include		<door.h>
declaration	int door_unbind(void)
version		SUNW_1.23
end

function	door_getparam
include		<door.h>
declaration	int door_getparam(int fd, int type, size_t *out)
version		SUNW_1.23
end

function	door_setparam
include		<door.h>
declaration	int door_setparam(int fd, int type, size_t val)
version		SUNW_1.23
end

function	_door_bind
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_call
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_create
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_cred
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_ucred
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_info
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_return
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_revoke
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_server_create
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_unbind
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_getparam
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_door_setparam
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

