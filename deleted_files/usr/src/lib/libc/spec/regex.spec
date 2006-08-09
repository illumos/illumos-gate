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
# lib/libc/spec/regex.spec

function	glob 
include		<glob.h>
declaration	int glob(const char *_RESTRICT_KYWD pattern, \
		int flags, int (*errfunc)(const char *epath, int eerrno), \
		glob_t *_RESTRICT_KYWD pglob)
version		SUNW_0.8 
exception	$return != 0
end		

function	globfree 
include		<glob.h>
declaration	void globfree(glob_t *pglob)
version		SUNW_0.8 
end		

function	re_comp 
include		<re_comp.h>
declaration	char *re_comp(const char *string)
version		SUNW_0.9 
exception	$return != 0
end		

function	re_exec 
include		<re_comp.h>
declaration	int re_exec(const char *string)
version		SUNW_0.9 
exception	$return == 1 || $return == -1
end		

function	wordexp 
include		<wordexp.h>
declaration	int wordexp(const char *_RESTRICT_KYWD words, \
		wordexp_t *_RESTRICT_KYWD pwordexp, int flags)
version		SUNW_0.8 
exception	$return == 0
end		

function	wordfree 
include		<wordexp.h>
declaration	void wordfree(wordexp_t *pwordexp)
version		SUNW_0.8 
end		

