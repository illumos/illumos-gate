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

function        ipmp_open
include         <ipmp.h>
declaration	int ipmp_open(ipmp_handle_t *handlep);
version         SUNWprivate_1.1
end

function        ipmp_close
include         <ipmp.h>
declaration	void ipmp_close(ipmp_handle_t handle);
version         SUNWprivate_1.1
end

function        ipmp_errmsg
include         <ipmp.h>
declaration	const char *ipmp_errmsg(int error);
version         SUNWprivate_1.1
end

function        ipmp_setqcontext
include		<ipmp_query.h>
declaration	int ipmp_setqcontext(ipmp_handle_t handle, \
		    ipmp_qcontext_t qcontext);
version         SUNWprivate_1.1
end

function        ipmp_getgrouplist
include		<ipmp_query.h>
declaration	int ipmp_getgrouplist(ipmp_handle_t handle, \
		    ipmp_grouplist_t **grlistpp);
version         SUNWprivate_1.1
end

function        ipmp_freegrouplist
include		<ipmp_query.h>
declaration	void ipmp_freegrouplist(ipmp_grouplist_t *grlistp);
version         SUNWprivate_1.1
end

function        ipmp_getgroupinfo
include		<ipmp_query.h>
declaration	int ipmp_getgroupinfo(ipmp_handle_t handle, \
		    const char *grname, ipmp_groupinfo_t **grinfopp);
version         SUNWprivate_1.1
end

function        ipmp_freegroupinfo
include		<ipmp_query.h>
declaration	void ipmp_freegroupinfo(ipmp_groupinfo_t *grinfop);
version         SUNWprivate_1.1
end

function        ipmp_getifinfo
include		<ipmp_query.h>
declaration	int ipmp_getifinfo(ipmp_handle_t handle, const char *ifname, \
		    ipmp_ifinfo_t **ifinfopp);
version         SUNWprivate_1.1
end

function        ipmp_freeifinfo
include		<ipmp_query.h>
declaration	void ipmp_freeifinfo(ipmp_ifinfo_t *ifinfop);
version         SUNWprivate_1.1
end

function        ipmp_ifinfo_create
include		<ipmp_query_impl.h>
declaration	ipmp_ifinfo_t *ipmp_ifinfo_create(const char *name, \
		    const char *group, ipmp_if_state_t state, \
		    ipmp_if_type_t type)
version         SUNWprivate_1.1
end

function        ipmp_groupinfo_create
include		<ipmp_query_impl.h>
declaration	ipmp_groupinfo_t *ipmp_groupinfo_create(const char *name, \
		    uint64_t sig, ipmp_group_state_t state, unsigned int nif, \
		    char (*ifs)[LIFNAMSIZ])
version         SUNWprivate_1.1
end

function        ipmp_grouplist_create
include		<ipmp_query_impl.h>
declaration	ipmp_grouplist_t *ipmp_grouplist_create(uint64_t sig, \
		    unsigned int ngroup, char (*groups)[LIFGRNAMSIZ])
version         SUNWprivate_1.1
end

function        ipmp_snap_free
include		<ipmp_query_impl.h>
declaration	void ipmp_snap_free(ipmp_snap_t *)
version         SUNWprivate_1.1
end

function        ipmp_snap_create
include		<ipmp_query_impl.h>
declaration	ipmp_snap_t *ipmp_snap_create(void)
version         SUNWprivate_1.1
end

function        ipmp_snap_addgroupinfo
include		<ipmp_query_impl.h>
declaration	int ipmp_snap_addgroupinfo(ipmp_snap_t *snap, \
		    ipmp_groupinfo_t *grinfop)
version         SUNWprivate_1.1
end

function        ipmp_snap_addifinfo
include		<ipmp_query_impl.h>
declaration	int ipmp_snap_addifinfo(ipmp_snap_t *snap, \
		    ipmp_ifinfo_t *ifinfop)
version         SUNWprivate_1.1
end

function        ipmp_read
include		<ipmp_mpathd.h>
declaration	int ipmp_read(int fd, void *buffer, size_t buflen, \
		    const struct timeval *endtp)
version         SUNWprivate_1.1
end

function        ipmp_write
include		<ipmp_mpathd.h>
declaration	int ipmp_write(int fd, const void *buffer, size_t buflen)
version         SUNWprivate_1.1
end

function        ipmp_writetlv
include		<ipmp_mpathd.h>
declaration	int ipmp_writetlv(int fd, ipmp_infotype_t type, size_t len, \
		    void *value)
version         SUNWprivate_1.1
end
