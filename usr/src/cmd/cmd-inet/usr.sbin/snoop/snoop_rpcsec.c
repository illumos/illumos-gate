/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2017 Gary Mills
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/tiuser.h>
#include <setjmp.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/rpcsec_gss.h>
#include <string.h>
#include "snoop.h"

extern jmp_buf xdr_err;

struct cache_struct *find_xid();
char *nameof_prog(int prog);
static void print_rpc_gss_init_arg(int, struct cache_struct *);
static void print_rpc_gss_init_res(int);

char *
rpcsec_gss_proc_to_string(unsigned int proc)
{
	switch (proc) {
	case RPCSEC_GSS_DATA:	return "RPCSEC_GSS_DATA"; break;
	case RPCSEC_GSS_INIT:	return "RPCSEC_GSS_INIT"; break;
	case RPCSEC_GSS_CONTINUE_INIT:
				return ("RPCSEC_GSS_CONTINUE_INIT");
	case RPCSEC_GSS_DESTROY:
				return ("RPCSEC_GSS_DESTROY");
	default:		return ("unknown");

	}
}


char *
rpcsec_gss_service_to_string(rpc_gss_service_t service)
{
	switch (service) {
	case rpc_gss_svc_none:	return "none"; break;
	case rpc_gss_svc_integrity: return "integrity"; break;
	case rpc_gss_svc_privacy: return "privacy"; break;
	default:		return "unknown";	  break;

	}
}

/*
 *  Print detailed RPCSEC_GSS cred data.
 */
void
print_rpcsec_gss_cred(int xid, int authlen)
{
	unsigned int seq_num;
	unsigned int handle_len;
	unsigned int rpcsec_gss_ver;
	rpc_gss_service_t rpcsec_gss_service;
	unsigned int rpcsec_gss_proc;
	char *handle, *line;
	struct cache_struct *x;
	int pos;

	pos = getxdr_pos();
	rpcsec_gss_ver = getxdr_u_long();

	/* see if we know this version or not */

	if (rpcsec_gss_ver != 1) {
		(void) showxdr_hex(authlen, "[%s]");
		return;
	}

	rpcsec_gss_proc   = getxdr_u_long();
	seq_num    = getxdr_u_long();
	rpcsec_gss_service    = getxdr_enum();

	(void) sprintf(get_line(pos, getxdr_pos()),
	    "   version = %u",  rpcsec_gss_ver);

	(void) sprintf(get_line(pos, getxdr_pos()),
	    "   gss control procedure = %u (%s)",
	    rpcsec_gss_proc,
	    rpcsec_gss_proc_to_string(rpcsec_gss_proc));

	(void) sprintf(get_line(pos, getxdr_pos()),
	    "   sequence num = %u", seq_num);

	(void) sprintf(get_line(pos, getxdr_pos()),
	    "   service = %d (%s)", rpcsec_gss_service,
	    rpcsec_gss_service_to_string(rpcsec_gss_service));
	pos = getxdr_pos();
	handle_len = getxdr_u_long();
	handle = getxdr_hex(handle_len);
	line = get_line(pos, getxdr_pos());
	sprintf(line, "   handle: length = %d, data = [%s]",
	    handle_len, handle);
	x = find_xid(xid);
	if (x) {
		x->xid_gss_proc    = rpcsec_gss_proc;
		x->xid_gss_service = rpcsec_gss_service;
	}
}

/*
 *  Based on different RPCSEC_GSS services supported, maybe a
 *  special handling is needed before printing the arguments.
 *
 *  For integrity service : print the sequence number.
 *  For privacy service : do not print the arguments.
 */
int
rpcsec_gss_pre_proto(int type, int flags, int xid,
					int prog, int vers, int proc)
{
	int seq;
	struct cache_struct *x;

	if (! (x = find_xid(xid)))
		return (0);

	switch (x->xid_gss_service) {
	case rpc_gss_svc_default:
	case rpc_gss_svc_none:
		break; /* standard call args */
	case rpc_gss_svc_integrity:
		/* length of rpc_gss_data_t encoded in the databody_integ */
		getxdr_u_long();
		/* read the seq number */
		seq = getxdr_u_long();
		if (flags & F_ALLSUM) {
			(void) sprintf(get_sum_line(), "%s %c seq_num = %u",
			    "RPC RPCSEC_GSS", type == CALL ? 'C' : 'R',
			    seq);
		} else if (flags & F_DTAIL) {
			sprintf(get_line(0, 0),
			    "RPCSEC_GSS data seq_num = %u", seq);
			show_space();
		}
		/* call args follow */
		break;
	case rpc_gss_svc_privacy: {
		char *progname = nameof_prog(prog);
		char prognum[32];

		if (*progname == '?') {
			sprintf(prognum, "%d", prog);
			progname = prognum;
		}

		if (flags & F_SUM || flags & F_ALLSUM) {
			(void) sprintf(get_sum_line(),
			    "%s %c %s ver(%d) proc(%d) (data encrypted) ",
			    "RPC RPCSEC_GSS", type == CALL ? 'C' : 'R',
			    progname, vers, proc);
		} else if (flags & F_DTAIL) {
			unsigned int args_len;

			args_len = getxdr_u_long();
			sprintf(get_line(0, 0),
			    "RPCSEC_GSS %s ver(%d) proc(%d)",
			    progname, vers, proc);
			sprintf(get_line(0, 0),
			    "(%s args encrypted, len = %d bytes)",
			    type == CALL ? "CALL" : "REPLY", args_len);
			show_space();
		}
		}
		return (1);

	default:
		break;
	}
	return (0);
}

/*
 *  Based on different RPCSEC_GSS services supported, maybe a
 *  special handling is needed after printing the arguments.
 *
 *  For integrity service : print the checksum.
 */
void
rpcsec_gss_post_proto(int flags, int xid)
{
	char *line;

	struct cache_struct *x;

	if (! (x = find_xid(xid)))
		return;

	switch (x->xid_gss_service) {
	case rpc_gss_svc_default:
	case rpc_gss_svc_none:
	case rpc_gss_svc_privacy:
		/* nothing left */
		break;
	case rpc_gss_svc_integrity:
		if (flags & F_ALLSUM) {
			line = get_sum_line();
			sprintf(line, "RPC RPCSEC_GSS C (checksum)");
		} else if (flags & F_DTAIL) {
			unsigned int checksum_len;
			char *checksum;

			show_header("RPC:  ", "RPCSEC_GSS", 0);
			show_space();
			checksum_len = getxdr_u_long();
			checksum = getxdr_hex(checksum_len);
			sprintf(get_line(0, 0),
			    "checksum: len = %d", checksum_len);
			sprintf(get_line(0, 0), "[%s]", checksum);
			show_trailer();
		}
		break;
	default:
		break;
	}
}

/*
 *  Print RPCSEC_GSS control procedures protocol data,
 *  No-op for RPCSEC_GSS_DATA.
 */
int
rpcsec_gss_control_proc(int type, int flags, int xid)
{
	int seq;

	struct cache_struct *x;

	if (! (x = find_xid(xid)))
		return (0);

	if (x->xid_gss_proc != RPCSEC_GSS_DATA) {
		if (flags & F_SUM) {
			if (type == CALL) {
				(void) sprintf(get_sum_line(), "%s %c %u (%s)",
				    "RPC RPCSEC_GSS",
				    type == CALL ? 'C' : 'R',
				    x->xid_gss_proc,
				    rpcsec_gss_proc_to_string(x->xid_gss_proc));
			}
		} else if (flags & F_DTAIL) {
			if (x->xid_gss_proc == RPCSEC_GSS_INIT ||
			    x->xid_gss_proc == RPCSEC_GSS_CONTINUE_INIT) {
				if (type == CALL) {
					print_rpc_gss_init_arg(flags, x);
				} else {
					print_rpc_gss_init_res(flags);
				}
			}
		}
		return (1);
	}

	return (0);
}

/*
 *  Skip the header RPCSEC_GSS cred data and
 *  put service and control type in the xid cache.
 */
void
extract_rpcsec_gss_cred_info(int xid)
{
	unsigned int handle_len;
	unsigned int rpcsec_gss_ver;
	rpc_gss_service_t rpcsec_gss_service;
	unsigned int rpcsec_gss_proc;
	struct cache_struct *x;

	(void) getxdr_u_long();
	rpcsec_gss_ver = getxdr_u_long();
	/* see if we know this version or not */
	if (rpcsec_gss_ver != 1) {
		longjmp(xdr_err, 1);
	}
	rpcsec_gss_proc   = getxdr_u_long();
	(void) getxdr_u_long();
	rpcsec_gss_service    = getxdr_enum();
	/* skip the handle */
	xdr_skip(RNDUP(getxdr_u_long()));

	if (x = find_xid(xid)) {
		x->xid_gss_service = rpcsec_gss_service;
		x->xid_gss_proc = rpcsec_gss_proc;
	}

}

/*
 *  Print the argument data for the RPCSEC_GSS_INIT control procedure.
 */
static void
print_rpc_gss_init_arg(int flags, struct cache_struct *x)
{

	char  *line;
	unsigned int token_len;
	int pos = 0;

	/*
	 *  see if we need to print out the rpc_gss_init_arg structure
	 *  or not.
	 */

	if (x->xid_gss_proc != RPCSEC_GSS_INIT &&
	    x->xid_gss_proc != RPCSEC_GSS_CONTINUE_INIT) {
		return;
	}

	/* print it */

	(void) sprintf(get_line(pos, getxdr_pos()),
	    "RPCSEC_GSS_INIT args:");

	pos = getxdr_pos();
	token_len = getxdr_u_long();
	(void) getxdr_hex(token_len);
	line = get_line(pos, getxdr_pos());
	sprintf(line, "   gss token: length = %d, data = [%d bytes]",
	    token_len, token_len);

	show_trailer();
}

/*
 *  Print the results data for the RPCSEC_GSS_INIT control procedure.
 */
void
print_rpc_gss_init_res(int flags)
{

	char *handle, *line;
	unsigned int token_len, handle_len;
	unsigned int major, minor, seq_window;

	int pos = 0;
	struct cache_struct *x;

	/* print it */

	(void) sprintf(get_line(pos, getxdr_pos()), "RPCSEC_GSS_INIT result:");

	pos = getxdr_pos();
	handle_len = getxdr_u_long();
	handle = getxdr_hex(handle_len);
	line = get_line(pos, getxdr_pos());
	sprintf(line, "   handle: length = %d, data = [%s]",
	    handle_len, handle);
	pos = getxdr_pos();
	major = getxdr_u_long();
	minor = getxdr_u_long();
	seq_window = getxdr_u_long();

	(void) sprintf(get_line(pos, getxdr_pos()),
	    "   gss_major status = %u", major);

	(void) sprintf(get_line(pos, getxdr_pos()),
	    "   gss_minor status = %u", minor);

	(void) sprintf(get_line(pos, getxdr_pos()),
	    "   sequence window  = %u", seq_window);
	pos = getxdr_pos();
	token_len = getxdr_u_long();
	(void) getxdr_hex(token_len);
	line = get_line(pos, getxdr_pos());
	sprintf(line, "   gss token: length = %d, data = [%d bytes]",
	    token_len, token_len);
	show_trailer();
}
