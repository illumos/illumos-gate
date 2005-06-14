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
# lib/librpcsvc/spec/rpcsvc.spec

function	rstat
include		<rpc/rpc.h>, <rpcsvc/rstat.h>
declaration	enum clnt_stat rstat(char *host, struct statstime *statp )
version		SUNW_0.7
exception	$return != RPC_SUCCESS
end		

function	havedisk
include		<rpc/rpc.h>, <rpcsvc/rstat.h>
declaration	int havedisk(char *host )
version		SUNW_0.7
exception	$return == 0
end		

function	rusers
include		<rpc/rpc.h>, <rpcsvc/rusers.h>
declaration	enum clnt_stat rusers(char	*host, struct utmpidlearr *up )
version		SUNW_0.7
exception	$return != 0
end		

function	rnusers
include		<rpc/rpc.h>, <rpcsvc/rusers.h>
declaration	int rnusers(char *host )
version		SUNW_0.7
exception	$return != 0
end		

function	rwall
include		<rpc/rpc.h>, <rpcsvc/rwall.h>
declaration	enum clnt_stat rwall(char *host, char *msg )
version		SUNW_0.7
exception	$return != RPC_SUCCESS
end		

function	xdr_statstime
version		SUNW_0.7
end		

function	xdr_statsvar
version		SUNW_0.7
end		

function	xdr_utmpidlearr
version		SUNW_0.7
end		

function	__clnt_bindresvport
version		SUNWprivate_1.1
end		

function	xdr_bp_address
version		SUNWprivate_1.1
end		

function	xdr_bp_fileid_t
version		SUNWprivate_1.1
end		

function	xdr_bp_getfile_arg
version		SUNWprivate_1.1
end		

function	xdr_bp_getfile_res
version		SUNWprivate_1.1
end		

function	xdr_bp_machine_name_t
version		SUNWprivate_1.1
end		

function	xdr_bp_path_t
version		SUNWprivate_1.1
end		

function	xdr_bp_whoami_arg
version		SUNWprivate_1.1
end		

function	xdr_bp_whoami_res
version		SUNWprivate_1.1
end		

function	xdr_dirpath
version		SUNWprivate_1.1
end		

function	xdr_exportnode
version		SUNWprivate_1.1
end		

function	xdr_exports
version		SUNWprivate_1.1
end		

function	xdr_fhandle
version		SUNWprivate_1.1
end		

function	xdr_fhandle3
version		SUNWprivate_1.1
end		

function	xdr_fhstatus
version		SUNWprivate_1.1
end		

function	xdr_fsh4_access
version		SUNWprivate_1.1
end		

function	xdr_fsh4_mode
version		SUNWprivate_1.1
end		

function	xdr_fsh_access
version		SUNWprivate_1.1
end		

function	xdr_fsh_mode
version		SUNWprivate_1.1
end		

function	xdr_groupnode
version		SUNWprivate_1.1
end		

function	xdr_groups
version		SUNWprivate_1.1
end		

function	xdr_int32
version		SUNWprivate_1.1
end		

function	xdr_int64
version		SUNWprivate_1.1
end		

function	xdr_ip_addr_t
version		SUNWprivate_1.1
end		

function	xdr_mon
version		SUNWprivate_1.1
end		

function	xdr_mon_id
version		SUNWprivate_1.1
end		

function	xdr_mountbody
version		SUNWprivate_1.1
end		

function	xdr_mountlist
version		SUNWprivate_1.1
end		

function	xdr_mountres3
version		SUNWprivate_1.1
end		

function	xdr_mountres3_ok
version		SUNWprivate_1.1
end		

function	xdr_mountstat3
version		SUNWprivate_1.1
end		

function	xdr_my_id
version		SUNWprivate_1.1
end		

function	xdr_name
version		SUNWprivate_1.1
end		

function	xdr_nlm4_cancargs
version		SUNWprivate_1.1
end		

function	xdr_nlm4_holder
version		SUNWprivate_1.1
end		

function	xdr_nlm4_lock
version		SUNWprivate_1.1
end		

function	xdr_nlm4_lockargs
version		SUNWprivate_1.1
end		

function	xdr_nlm4_notify
version		SUNWprivate_1.1
end		

function	xdr_nlm4_res
version		SUNWprivate_1.1
end		

function	xdr_nlm4_share
version		SUNWprivate_1.1
end		

function	xdr_nlm4_shareargs
version		SUNWprivate_1.1
end		

function	xdr_nlm4_shareres
version		SUNWprivate_1.1
end		

function	xdr_nlm4_stat
version		SUNWprivate_1.1
end		

function	xdr_nlm4_stats
version		SUNWprivate_1.1
end		

function	xdr_nlm4_testargs
version		SUNWprivate_1.1
end		

function	xdr_nlm4_testres
version		SUNWprivate_1.1
end		

function	xdr_nlm4_testrply
version		SUNWprivate_1.1
end		

function	xdr_nlm4_unlockargs
version		SUNWprivate_1.1
end		

function	xdr_nlm_cancargs
version		SUNWprivate_1.1
end		

function	xdr_nlm_holder
version		SUNWprivate_1.1
end		

function	xdr_nlm_lock
version		SUNWprivate_1.1
end		

function	xdr_nlm_lockargs
version		SUNWprivate_1.1
end		

function	xdr_nlm_notify
version		SUNWprivate_1.1
end		

function	xdr_nlm_res
version		SUNWprivate_1.1
end		

function	xdr_nlm_share
version		SUNWprivate_1.1
end		

function	xdr_nlm_shareargs
version		SUNWprivate_1.1
end		

function	xdr_nlm_shareres
version		SUNWprivate_1.1
end		

function	xdr_nlm_stat
version		SUNWprivate_1.1
end		

function	xdr_nlm_stats
version		SUNWprivate_1.1
end		

function	xdr_nlm_testargs
version		SUNWprivate_1.1
end		

function	xdr_nlm_testres
version		SUNWprivate_1.1
end		

function	xdr_nlm_testrply
version		SUNWprivate_1.1
end		

function	xdr_nlm_unlockargs
version		SUNWprivate_1.1
end		

function	xdr_ppathcnf
version		SUNWprivate_1.1
end		

function	xdr_res
version		SUNWprivate_1.1
end		

function	xdr_rstat_timeval
version		SUNWprivate_1.1
end		

function	xdr_rusers_utmp
version		SUNWprivate_1.1
end		

function	xdr_sm_name
version		SUNWprivate_1.1
end		

function	xdr_sm_stat
version		SUNWprivate_1.1
end		

function	xdr_sm_stat_res
version		SUNWprivate_1.1
end		

function	xdr_sprayarr
version		SUNWprivate_1.1
end		

function	xdr_spraycumul
version		SUNWprivate_1.1
end		

function	xdr_spraytimeval
version		SUNWprivate_1.1
end		

function	xdr_stat_chge
version		SUNWprivate_1.1
end		

function	xdr_status
version		SUNWprivate_1.1
end		

function	xdr_timeval
version		SUNWprivate_1.1
end		

function	xdr_uint32
version		SUNWprivate_1.1
end		

function	xdr_uint64
version		SUNWprivate_1.1
end		

function	xdr_utmp_array
version		SUNWprivate_1.1
end		

function	xdr_reg1args
version		SUNWprivate_1.1
end		

function	xdr_reg1res
version		SUNWprivate_1.1
end		

function	xdr_unreg1args
version		SUNWprivate_1.1
end		

function	xdr_unreg1res
version		SUNWprivate_1.1
end		

