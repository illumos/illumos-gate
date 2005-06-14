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
# lib/libsecdb/spec/getexecattr.spec

function	getexecattr
include		<exec_attr.h>
declaration	execattr_t *getexecattr()
version		SUNW_1.1
exception	$return == NULL
end

function	getexecprof
include		<exec_attr.h>
declaration	execattr_t *getexecprof(const char *name, const char *type, \
	const char *id, int search_flag)
version		SUNW_1.1
exception	$return == NULL
end

function	getexecuser
include		<exec_attr.h>
declaration	execattr_t *getexecuser(const char *username, const char *type,\
	const char *id, int search_flag)
version		SUNW_1.1
exception	$return == NULL
end

function	match_execattr
include		<exec_attr.h>
declaration	execattr_t *match_execattr(execattr_t *exec, \
	const char *profname, const char *type, const char *id)
version		SUNW_1.1
exception	$return == NULL
end

function	setexecattr
include		<exec_attr.h>
declaration	void setexecattr()
version		SUNW_1.1
end

function	endexecattr
include		<exec_attr.h>
declaration	void endexecattr()
version		SUNW_1.1
end

function	free_execattr
include		<exec_attr.h>
declaration	void free_execattr(execattr_t *exec)
version		SUNW_1.1
end
