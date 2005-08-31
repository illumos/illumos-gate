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
# lib/librac/spec/rpc_rac.spec

function	rac_drop
include		<rpc/rpc.h>, <rpc/rac.h>
declaration	void rac_drop(CLIENT *cl, void *h )
version		SUNW_0.7
end		

function	rac_poll
include		<rpc/rpc.h>, <rpc/rac.h>
declaration	enum clnt_stat rac_poll(CLIENT *cl, void *h )
version		SUNW_0.7
exception	$return != RPC_SUCCESS
end		

function	rac_recv
include		<rpc/rpc.h>, <rpc/rac.h>
declaration	enum clnt_stat rac_recv(CLIENT *cl, void *h )
version		SUNW_0.7
exception	$return != RPC_SUCCESS
end		

function	rac_send
include		<rpc/rpc.h>, <rpc/rac.h>
declaration	void  *rac_send(CLIENT *cl, rpcproc_t proc, xdrproc_t  xargs, void *argsp, xdrproc_t xresults, void *resultsp, struct timeval timeout)
version		SUNW_0.7
exception	$return == 0
end		

function	__rpc_control
version		SUNWprivate_1.1 
end		

function	__rpc_dtbsize
version		SUNWprivate_1.1 
end		

function	__rpc_endconf
version		SUNWprivate_1.1 
end		

function	__rpc_get_a_size
version		SUNWprivate_1.1 
end		

function	__rpc_get_t_size
version		SUNWprivate_1.1 
end		

function	__rpc_getconf
version		SUNWprivate_1.1 
end		

function	__rpc_getconfip
version		SUNWprivate_1.1 
end		

function	__rpc_select_to_poll
version		SUNWprivate_1.1 
end		

function	__rpc_setconf
version		SUNWprivate_1.1 
end		

function	__rpc_timeval_to_msec
version		SUNWprivate_1.1 
end		

function	__seterr_reply
version		SUNWprivate_1.1 
end		

function	_rpctypelist
version		SUNWprivate_1.1 
end		

function	clnt_create
version		SUNW_0.7
end		

function	clnt_create_vers
version		SUNW_0.7
end		

function	clnt_dg_create
version		SUNW_0.7
end		

function	clnt_tli_create
version		SUNW_0.7
end		

function	clnt_tp_create
version		SUNW_0.7
end		

function	clnt_vc_create
version		SUNW_0.7
end		

function	rac_senderr
version		SUNW_0.7
end		

function	rpcb_getaddr
version		SUNW_0.7
end		

function	rpcb_getmaps
version		SUNW_0.7
end		

function	rpcb_gettime
version		SUNW_0.7
end		

function	rpcb_rmtcall
version		SUNW_0.7
end		

function	rpcb_set
version		SUNW_0.7
end		

function	rpcb_taddr2uaddr
version		SUNWprivate_1.1
end		

function	rpcb_uaddr2taddr
version		SUNWprivate_1.1
end		

function	rpcb_unset
version		SUNW_0.7
end		

function	xdrrec_create
version		SUNW_0.7
end		

function	xdrrec_endofrecord
version		SUNW_0.7
end		

function	xdrrec_eof
version		SUNW_0.7
end		

function	xdrrec_readbytes
version		SUNW_0.7
end		

function	xdrrec_skiprecord
version		SUNW_0.7
end		

