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

function	laadm_create
include		<liblaadm.h>
declaration	int laadm_create(uint32_t, uint32_t, laadm_port_attr_db_t *, \
			uint32_t, boolean_t, uchar_t *, \
			aggr_lacp_mode_t, aggr_lacp_timer_t, boolean_t, \
			const char *, laadm_diag_t *); 
version		SUNWprivate_1.1
end

function	laadm_delete
include		<liblaadm.h>
declaration	int laadm_delete(uint32_t, boolean_t, const char *, \
		laadm_diag_t *);
version		SUNWprivate_1.1
end

function	laadm_add
include		<liblaadm.h>
declaration	int laadm_add(uint32_t, uint32_t, laadm_port_attr_db_t *, \
			boolean_t, const char *, laadm_diag_t *);
version		SUNWprivate_1.1
end

function	laadm_remove
include		<liblaadm.h>
declaration	int laadm_remove(uint32_t, uint32_t, laadm_port_attr_db_t *, \
			boolean_t, const char *, laadm_diag_t *);
version		SUNWprivate_1.1
end

function	laadm_modify
include		<liblaadm.h>
declaration	int laadm_modify(uint32_t, uint32_t, uint32_t, boolean_t, \
			uchar_t *, aggr_lacp_mode_t, aggr_lacp_timer_t, \
			boolean_t, const char *, laadm_diag_t *)
version		SUNWprivate_1.1
end

function	laadm_up
include		<liblaadm.h>
declaration	int laadm_up(uint32_t, const char *, laadm_diag_t *);
version		SUNWprivate_1.1
end

function	laadm_down
include		<liblaadm.h>
declaration	int laadm_down(uint32_t);
version		SUNWprivate_1.1
end

function	laadm_str_to_policy
include		<liblaadm.h>
declaration	boolean_t laadm_str_to_policy(const char *, uint32_t *)
version		SUNWprivate_1.1
end

function	laadm_policy_to_str
include		<liblaadm.h>
declaration	char *laadm_policy_to_str(uint32_t, char *)
version		SUNWprivate_1.1
end

function	laadm_str_to_mac_addr
include		<liblaadm.h>
declaration	boolean_t laadm_str_to_mac_addr(const char *, boolean_t *, \
			uchar_t *);
version		SUNWprivate_1.1
end

function	laadm_mac_addr_to_str
include		<liblaadm.h>
declaration	char *laadm_mac_addr_to_str(unsigned char *, char *);
version		SUNWprivate_1.1
end

function	laadm_str_to_lacp_mode
include		<liblaadm.h>
declaration	boolean_t laadm_str_to_lacp_mode(const char *, \
			aggr_lacp_mode_t *)
version		SUNWprivate_1.1
end

function	laadm_lacp_mode_to_str
include		<liblaadm.h>
declaration	char *laadm_lacp_mode_to_str(aggr_lacp_mode_t)
version		SUNWprivate_1.1
end

function	laadm_str_to_lacp_timer
include		<liblaadm.h>
declaration	boolean_t laadm_str_to_lacp_timer(const char *, \
			aggr_lacp_timer_t *)
version		SUNWprivate_1.1
end

function	laadm_lacp_timer_to_str
include		<liblaadm.h>
declaration	char *laadm_lacp_timer_to_str(aggr_lacp_timer_t)
version		SUNWprivate_1.1
end

function	laadm_walk_sys
include		<liblaadm.h>
declaration	int laadm_walk_sys(int (*)(void *, laadm_grp_attr_sys_t *), \
			void *)
version		SUNWprivate_1.1
end

function	laadm_diag
include		<liblaadm.h>
declaration	const char *laadm_diag(laadm_diag_t)
version		SUNWprivate_1.1
end
