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
# lib/libipp/spec/libipp.spec

function	ipp_action_create
include		<libipp.h>
declaration	int ipp_action_create(const char *, const char *, \
		    nvlist_t **, ipp_flags_t)
version		SUNWprivate_1.1
end

function	ipp_action_destroy
include		<libipp.h>
declaration	int ipp_action_destroy(const char *, ipp_flags_t)
version		SUNWprivate_1.1
end

function	ipp_action_modify
include		<libipp.h>
declaration	int ipp_action_modify(const char *, nvlist_t **, ipp_flags_t)
version		SUNWprivate_1.1
end

function	ipp_action_info
include		<libipp.h>
declaration	int ipp_action_info(const char *, int (*f)(nvlist_t *, \
		    void *), void *, ipp_flags_t)
version		SUNWprivate_1.1
end

function	ipp_action_mod
include		<libipp.h>
declaration	int ipp_action_mod(const char *, char **);
version		SUNWprivate_1.1
end

function	ipp_list_mods
include		<libipp.h>
declaration	int ipp_list_mods(char ***, int *);
version		SUNWprivate_1.1
end

function	ipp_mod_list_actions
include		<libipp.h>
declaration	int ipp_mod_list_actions(const char *, char ***, int *);
version		SUNWprivate_1.1
end

function	ipp_free
include		<libipp.h>
declaration	void ipp_free(char *);
version		SUNWprivate_1.1
end

function	ipp_free_array
include		<libipp.h>
declaration	void ipp_free_array(char **, int);
version		SUNWprivate_1.1
end
