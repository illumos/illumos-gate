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
# usr/src/lib/passwdutil/spec/passwdutil.spec
#
# ident	"%Z%%M%	%I%	%E% SMI"

function	__set_authtoken_attr
include		"../../passwdutil.h"
declaration	int __set_authtoken_attr(char *name, char *oldpw, \
				char *oldrpcpw, pwu_repository_t *rep, \
				attrlist *items, int *updated_reps)
version		SUNWprivate_1.1
end

function	__get_authtoken_attr
include		"../../passwdutil.h"
declaration	int __get_authtoken_attr(char *name, pwu_repository_t *rep, \
				attrlist *items)
version		SUNWprivate_1.1
end

function	__user_to_authenticate
include		"../../passwdutil.h"
declaration	int __user_to_authenticate(char *user, pwu_repository_t *rep, \
				char **auth_user, int *privileged)
version		SUNWprivate_1.1
end

function	__verify_rpc_passwd
include		"../../passwdutil.h"
declaration	int __verify_rpc_passwd(char *name, char *oldpw, \
				pwu_repository_t *rep)
version		SUNWprivate_1.1
end

function	__check_history
include		"../../passwdutil.h"
declaration	int __check_history(char *user, char *passwd, \
				pwu_repository_t *rep)
version		SUNWprivate_1.1
end

function	__incr_failed_count
include		"../../passwdutil.h"
declaration	int __incr_failed_count(char *user, char *rep, int max_failed)
version		SUNWprivate_1.1
end

function	__rst_failed_count
include		"../../passwdutil.h"
declaration	int __rst_failed_count(char *user, char *rep)
version		SUNWprivate_1.1
end
