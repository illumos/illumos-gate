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
# ident	"%Z%%M%	%I%	%E% SMI"
#


function	lgrp_affinity_get
include		<sys/lgrp_user.h>
declaration	lgrp_affinity_t lgrp_affinity_get(idtype_t idtype, id_t id, lgrp_id_t lgrp)
version		SUNW_1.1
end		

function	lgrp_affinity_set
include		<sys/lgrp_user.h>
declaration	int lgrp_affinity_set(idtype_t idtype, id_t id, lgrp_id_t lgrp, lgrp_affinity_t aff)
version		SUNW_1.1
end		

function	lgrp_children
include		<sys/lgrp_user.h>
declaration	int lgrp_children(lgrp_cookie_t cookie, lgrp_id_t lgrp, lgrp_id_t *children, uint_t count)
version		SUNW_1.1
end		

function	lgrp_cookie_stale
include		<sys/lgrp_user.h>
declaration	int lgrp_cookie_stale(lgrp_cookie_t cookie)
version		SUNW_1.1
end		

function	lgrp_cpus
include		<sys/lgrp_user.h>
declaration	int lgrp_cpus(lgrp_cookie_t cookie, lgrp_id_t lgrp, processorid_t *cpuids, uint_t count, lgrp_content_t content)
version		SUNW_1.1
end		

function	lgrp_fini
include		<sys/lgrp_user.h>
declaration	int lgrp_fini(lgrp_cookie_t)
version		SUNW_1.1
end		

function	lgrp_home
include		<sys/lgrp_user.h>
declaration	lgrp_id_t lgrp_home(idtype_t idtype, id_t id)
version		SUNW_1.1
end		

function	lgrp_init
include		<sys/lgrp_user.h>
declaration	lgrp_cookie_t lgrp_init(lgrp_view_t view)
version		SUNW_1.1
end		

function	lgrp_latency
include		<sys/lgrp_user.h>
declaration	int lgrp_latency(lgrp_id_t from, lgrp_id_t to)
version		SUNW_1.1
end		

function	lgrp_latency_cookie
include		<sys/lgrp_user.h>
declaration	int lgrp_latency_cookie(lgrp_cookie_t, lgrp_id_t from, lgrp_id_t to, lgrp_lat_between_t between)
version		SUNW_1.2
end		

function	lgrp_mem_size
include		<sys/lgrp_user.h>
declaration	lgrp_mem_size_t lgrp_mem_size(lgrp_cookie_t cookie, lgrp_id_t lgrp, lgrp_mem_size_flag_t type, lgrp_content_t content)
version		SUNW_1.1
end		

function	lgrp_nlgrps
include		<sys/lgrp_user.h>
declaration	int lgrp_nlgrps(lgrp_cookie_t)
version		SUNW_1.1
end		

function	lgrp_parents
include		<sys/lgrp_user.h>
declaration	int lgrp_parents(lgrp_cookie_t cookie, lgrp_id_t lgrp, lgrp_id_t *parents, uint_t count)
version		SUNW_1.1
end		

function	lgrp_resources
include		<sys/lgrp_user.h>
declaration	int lgrp_resources(lgrp_cookie_t cookie, lgrp_id_t lgrp, lgrp_id_t *lgrps, uint_t count, int type)
version		SUNW_1.2
end		

function	lgrp_root
include		<sys/lgrp_user.h>
declaration	lgrp_id_t lgrp_root(lgrp_cookie_t)
version		SUNW_1.1
end		

function	lgrp_version
include		<sys/lgrp_user.h>
declaration	int	lgrp_version(int version)
version		SUNW_1.1
end		

function	lgrp_view
include		<sys/lgrp_user.h>
declaration	lgrp_view_t lgrp_view(lgrp_cookie_t cookie)
version		SUNW_1.1
end		

#
# Interfaces approved as stable PSARC 2003/034

#
#
