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
# lib/libsecdb/spec/private.spec

function	_argv_to_csl
include		<secdb.h>
declaration	char *_argv_to_csl(char **src)
execption	$return == NULL
version		SUNWprivate_1.1
end		

function	_auth_match
include		<secdb.h>
declaration	int _auth_match(const char *pattern, const char *auth)
version		SUNWprivate_1.1
end

function	_csl_to_argv
include		<secdb.h>
declaration	char **_csl_to_argv(char *csl)
execption	$return == NULL
version		SUNWprivate_1.1
end		

function	_do_unescape
include		<secdb.h>
declaration	char *_do_unescape(char *src)
execption	$return == NULL
version		SUNWprivate_1.1
end		

function	_free_argv
include		<secdb.h>
declaration	void _free_argv()
version		SUNWprivate_1.1
end		

function	_get_auth_policy
include		<secdb.h>
declaration	int _get_auth_policy(char **def_auth, char **def_prof)
version		SUNWprivate_1.1
end

function	_insert2kva
include		<secdb.h>
declaration	int _insert2kva(kva_t *kva, char *key, char *value)
execption	$return == 0
version		SUNWprivate_1.1
end		

function	_kva2str
include		<secdb.h>
declaration	int _kva2str(kva_t *kva, char *buf, int buflen, char *ass, \
	char *del)
execption	$return == 0
version		SUNWprivate_1.1
end		

function	_kva_dup
include		<secdb.h>
declaration	kva_t *_kva_dup(kva_t *old_kva)
version		SUNWprivate_1.1
end		

function	_kva_free
include		<secdb.h>
declaration	void _kva_free(kva_t *kva)
version		SUNWprivate_1.1
end		

function	_new_kva
include		<secdb.h>
declaration	kva_t *_new_kva(int size)
execption	$return == NULL
version		SUNWprivate_1.1
end		

function	_str2kva
include		<secdb.h>
declaration	kva_t *_str2kva(char *s, char *ass, char *del)
execption	$return == NULL
version		SUNWprivate_1.1
end		
