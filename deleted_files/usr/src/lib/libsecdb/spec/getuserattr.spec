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
# lib/libsecdb/spec/getuserattr.spec

function	getuserattr
include		<user_attr.h>
declaration	userattr_t *getuserattr()
version		SUNW_1.1
exception	$return == NULL
end

function	fgetuserattr
include		<user_attr.h>
declaration	userattr_t *fgetuserattr(FILE *f)
version		SUNW_1.1
exception	$return == NULL
end

function	getusernam
include		<user_attr.h>
declaration	userattr_t *getusernam(const char *name)
version		SUNW_1.1
exception	$return == NULL
end

function	getuseruid
include		<user_attr.h>
declaration	userattr_t *getuseruid(uid_t u)
version		SUNW_1.1
exception	$return == NULL
end

function	setuserattr
include		<user_attr.h>
declaration	void setuserattr()
version		SUNW_1.1
end

function	enduserattr
include		<user_attr.h>
declaration	void enduserattr()
version		SUNW_1.1
end

function	free_userattr
include		<user_attr.h>
declaration	void free_userattr(userattr_t *user)
version		SUNW_1.1
end
