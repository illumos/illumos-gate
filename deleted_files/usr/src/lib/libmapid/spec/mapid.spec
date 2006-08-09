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
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# $(SRC)/lib/libmapid/spec/mapid.spec

function	mapid_stdchk_domain
include         <nfs/mapid.h>
declaration	int mapid_stdchk_domain(const char *)
version		SUNWprivate_1.1
end		

function	mapid_get_domain
include         <nfs/mapid.h>
declaration	char *mapid_get_domain(void)
version		SUNWprivate_1.1
end		

function	mapid_reeval_domain
include         <nfs/mapid.h>
declaration	void mapid_reeval_domain(cb_t *)
version		SUNWprivate_1.1
end		

function	mapid_derive_domain
include         <nfs/mapid.h>
declaration	char *mapid_derive_domain(void)
version		SUNWprivate_1.1
end		
