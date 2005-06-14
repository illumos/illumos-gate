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
# lib/libsecdb/spec/getauthattr.spec

function	getauthattr
include		<auth_attr.h>
declaration	authattr_t *getauthattr()
version		SUNW_1.1
exception	$return == NULL
end

function	getauthnam
include		<auth_attr.h>
declaration	authattr_t *getauthnam(const char *name)
version		SUNW_1.1
exception	$return == NULL
end

function	setauthattr
include		<auth_attr.h>
declaration	void setauthattr()
version		SUNW_1.1
end

function	endauthattr
include		<auth_attr.h>
declaration	void endauthattr()
version		SUNW_1.1
end

function	free_authattr
include		<auth_attr.h>
declaration	void free_authattr(authattr_t *auth)
version		SUNW_1.1
end
