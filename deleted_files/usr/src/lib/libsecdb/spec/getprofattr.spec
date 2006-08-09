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
# lib/libsecdb/spec/getprofattr.spec

function	getprofattr
include		<prof_attr.h>
declaration	profattr_t *getprofattr()
version		SUNW_1.1
exception	$return == NULL
end

function	getprofnam
include		<prof_attr.h>
declaration	profattr_t *getprofnam(const char *name)
version		SUNW_1.1
exception	$return == NULL
end

function	setprofattr
include		<prof_attr.h>
declaration	void setprofattr()
version		SUNW_1.1
end

function	endprofattr
include		<prof_attr.h>
declaration	void endprofattr()
version		SUNW_1.1
end

function	free_profattr
include		<prof_attr.h>
declaration	void free_profattr(profattr_t *prof)
version		SUNW_1.1
end

function        getproflist
include         <auth_attr.h>, <exec_attr.h>, <prof_attr.h>
declaration     void getproflist(const char *, char **, int *)
version         SUNW_1.1
end

function        free_proflist
include         <auth_attr.h>, <exec_attr.h>, <prof_attr.h>
declaration     void free_proflist(char **, int)
version         SUNW_1.1
end
