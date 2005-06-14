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

function	dladm_link
include		<libdladm.h>
declaration	int	dladm_link(const char *, dladm_attr_t *, \
			int, const char *, dladm_diag_t *)
version		SUNWprivate_1.1
end

function	dladm_up
include		<libdladm.h>
declaration	int	dladm_up(const char *, dladm_diag_t *)
version		SUNWprivate_1.1
end

function	dladm_unlink
include		<libdladm.h>
declaration	int	dladm_unlink(const char *, boolean_t, const char *, \
			dladm_diag_t *)
version		SUNWprivate_1.1
end

function	dladm_down
include		<libdladm.h>
declaration	int	dladm_down(const char *, dladm_diag_t *)
version		SUNWprivate_1.1
end

function	dladm_walk
include		<libdladm.h>
declaration	int	dladm_walk(void (*fn)(void *, const char *), \
			void *)
version		SUNWprivate_1.1
end

function	dladm_info
include		<libdladm.h>
declaration	int	dladm_info(const char *, dladm_attr_t *)
version		SUNWprivate_1.1
end

function	dladm_db_walk
include		<libdladm.h>
declaration	int	dladm_db_walk(void (*)(void *, const char *,
			dladm_attr_t *), void *)
version		SUNWprivate_1.1
end

function	dladm_sync
include		<libdladm.h>
declaration	void	dladm_sync(void)
version		SUNWprivate_1.1
end

function	dladm_diag
include		<libdladm.h>
declaration	const char *	dladm_diag(dladm_diag_t)
version		SUNWprivate_1.1
end
