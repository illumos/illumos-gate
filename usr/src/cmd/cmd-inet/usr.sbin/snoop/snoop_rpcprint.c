/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <string.h>
#include <sys/types.h>
#include <sys/tiuser.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include "snoop.h"

#define	RPC_TRANSIENT_START	0x40000000
#define	RPC_TRANSIENT_END	0x5fffffff

int rpcsec_gss_control_proc(int type, int flags, int xid);

int rpcsec_gss_pre_proto(int type, int flags, int xid,
				int prog, int vers, int proc);

void rpcsec_gss_post_proto(int flags, int xid);

void
protoprint(flags, type, xid, prog, vers, proc, data, len)
	ulong_t xid;
	int flags, type, prog, vers, proc;
	char *data;
	int len;
{
	char *name;
	void (*interpreter)(int, int, int, int, int, char *, int);

	switch (prog) {
	case 100000:	interpreter = interpret_pmap;		break;
	case 100001:	interpreter = interpret_rstat;		break;
	case 100003:	interpreter = interpret_nfs;		break;
	case 100004:	interpreter = interpret_nis;		break;
	case 100005:	interpreter = interpret_mount;		break;
	case 100007:	interpreter = interpret_nisbind;	break;
	case 100011:	interpreter = interpret_rquota;		break;
	case 100021:	interpreter = interpret_nlm;		break;
	case 100026:	interpreter = interpret_bparam;		break;
	case 100227:	interpreter = interpret_nfs_acl;	break;
	case 150006:	interpreter = interpret_solarnet_fw;	break;
	default:	interpreter = NULL;
	}

	/*
	 * if rpc in transient range and proc is 0 or 1, then
	 * guess that it is the nfsv4 callback protocol
	 */
	if (prog >= RPC_TRANSIENT_START && prog <= RPC_TRANSIENT_END &&
	    (proc == 0 || proc == 1))
		interpreter = interpret_nfs4_cb;

	/*
	 *  If the RPC header indicates it's using the RPCSEC_GSS_*
	 *  control procedure, print it.
	 */
	if (rpcsec_gss_control_proc(type, flags, xid)) {
			return;
	}

	if (interpreter == NULL) {
		if (!(flags & F_SUM))
			return;
		name = nameof_prog(prog);
		if (*name == '?' || strcmp(name, "transient") == 0)
			return;
		(void) sprintf(get_sum_line(), "%s %c",
			name,
			type == CALL ? 'C' : 'R');
	} else {
		/* Pre-processing based on different RPCSEC_GSS services. */
		if (rpcsec_gss_pre_proto(type, flags, xid, prog, vers, proc))
			return;

		(*interpreter) (flags, type, xid, vers, proc, data, len);

		/* Post-processing based on different RPCSEC_GSS services. */
		rpcsec_gss_post_proto(flags, xid);
	}
}
