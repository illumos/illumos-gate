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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <door.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/smb_winpipe.h>

#define	START_OUTDOOR_SIZE	65536

static int smb_winpipe_fd = -1;
static int smb_winpipe_cookie = 0x50495045;	/* PIPE */
static pthread_mutex_t smb_winpipe_mutex = PTHREAD_MUTEX_INITIALIZER;

static void smb_winpipe_request(void *, char *, size_t, door_desc_t *, uint_t);

/*
 * Create the winpipe door service.
 * Returns the door descriptor on success.  Otherwise returns -1.
 */
int
smb_winpipe_doorsvc_start(void)
{
	(void) pthread_mutex_lock(&smb_winpipe_mutex);

	if (smb_winpipe_fd != -1) {
		(void) pthread_mutex_unlock(&smb_winpipe_mutex);
		errno = EEXIST;
		return (-1);
	}

	errno = 0;
	if ((smb_winpipe_fd = door_create(smb_winpipe_request,
	    &smb_winpipe_cookie, (DOOR_UNREF | DOOR_REFUSE_DESC))) < 0) {
		smb_winpipe_fd = -1;
	}

	(void) pthread_mutex_unlock(&smb_winpipe_mutex);
	return (smb_winpipe_fd);
}

/*
 * Stop the winpipe door service.
 */
void
smb_winpipe_doorsvc_stop(void)
{
	(void) pthread_mutex_lock(&smb_winpipe_mutex);

	if (smb_winpipe_fd != -1) {
		(void) door_revoke(smb_winpipe_fd);
		smb_winpipe_fd = -1;
	}

	(void) pthread_mutex_unlock(&smb_winpipe_mutex);
}

static smb_dr_user_ctx_t *
smb_user_ctx_mkabsolute(uint8_t *buf, uint32_t len)
{
	smb_dr_user_ctx_t *obj;
	XDR xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);
	obj = (smb_dr_user_ctx_t *)malloc(sizeof (smb_dr_user_ctx_t));
	if (!obj) {
		xdr_destroy(&xdrs);
		syslog(LOG_ERR, "smb_user_ctx_mkabsolute: resource shortage");
		return (NULL);
	}

	bzero(obj, sizeof (smb_dr_user_ctx_t));
	if (!xdr_smb_dr_user_ctx_t(&xdrs, obj)) {
		syslog(LOG_ERR, "smb_user_ctx_mkabsolute: XDR decode error");
		free(obj);
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

static void
smb_user_ctx_free(smb_dr_user_ctx_t *user_ctx)
{
	if (user_ctx) {
		xdr_free(xdr_smb_dr_user_ctx_t, (char *)user_ctx);
		free(user_ctx);
	}
}

/*
 * Winpipe door service request handler.
 *
 * Door arg data is a previously marshalled in to flat buffer
 * that contains no pointers. This data is first unmarshalled into
 * common structures. The data from the door *argp contains a header structure,
 * mlsvc_door_hdr_t. Following are its members.
 *	thread_id - kernel thread id
 *	version number - possible use at a leter point
 *	call_type - rpc_transact, rpc_read or rpc_write
 *	length - max number of bytes that can be returned
 *	rpc_ctx - some rpc context info such as domain, user account, ...
 *	smb_pipe_t - pipeid, pipename, pipelen and data
 *
 * Convert the data and call mlrpc_process.  The returned outpipe contains
 * the relevant data to be returned to the client.
 *
 * Outgoing data must be marshalled again before returning.
 */

/*ARGSUSED*/
static void
smb_winpipe_request(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dd, uint_t n_desc)
{
	smb_pipe_t *inpipe = NULL;
	smb_pipe_t *outpipe = NULL;
	smb_pipe_t tmp_pipe;
	smb_dr_user_ctx_t *user_ctx = NULL;
	char *bufp;
	int bplen = 0;
	mlsvc_door_hdr_t mdhin, mdhout;
	int tbytes = 0;
	int bytes_off = 0;
	struct mlsvc_rpc_context *context;
	int current_out_len;
	uint32_t adj_len;
	char lfp[START_OUTDOOR_SIZE];
	boolean_t more_data = B_FALSE;

	if ((cookie != &smb_winpipe_cookie) || (argp == NULL) ||
	    (arg_size < SMB_WINPIPE_MIN_REQ_SIZE)) {
		(void) door_return(NULL, 0, NULL, 0);
	}

	bufp = argp;
	bcopy(bufp, &mdhin.md_tid, sizeof (uint64_t));
	bytes_off = sizeof (uint64_t);
	bcopy(bufp+bytes_off, &mdhin.md_version, sizeof (uint16_t));
	bytes_off += sizeof (uint16_t);
	bcopy(bufp+bytes_off, &mdhin.md_call_type, sizeof (uint16_t));
	bytes_off += sizeof (uint16_t);
	bcopy(bufp+bytes_off, &mdhin.md_length, sizeof (uint32_t));
	bytes_off += sizeof (uint32_t);
	bcopy(bufp+bytes_off, &mdhin.md_reserved, sizeof (uint64_t));
	bytes_off += sizeof (uint64_t);

	/*
	 * Flush is a special case, just release the RPC context.
	 */
	if (mdhin.md_call_type == SMB_RPC_FLUSH) {
		bcopy(bufp + bytes_off, &tmp_pipe.sp_pipeid, sizeof (uint32_t));
		mlrpc_release(tmp_pipe.sp_pipeid);
		goto zero_exit;
	}

	user_ctx = smb_user_ctx_mkabsolute((uchar_t *)bufp + bytes_off,
	    arg_size - bytes_off);
	if (!user_ctx) {
		syslog(LOG_ERR, "mds: user_ctx_mkabsolute failed");
		goto zero_exit;
	}

	tbytes += xdr_sizeof(xdr_smb_dr_user_ctx_t, user_ctx) + bytes_off;
	bufp += tbytes;

	bzero(&tmp_pipe, sizeof (smb_pipe_t));
	(void) strlcpy(tmp_pipe.sp_pipename, (char *)bufp, SMB_MAX_PIPENAMELEN);
	bufp += SMB_MAX_PIPENAMELEN;
	bcopy(bufp, &tmp_pipe.sp_pipeid, sizeof (uint32_t));
	bufp += sizeof (uint32_t);
	bcopy(bufp, &tmp_pipe.sp_datalen, sizeof (uint32_t));
	bufp += sizeof (uint32_t);

	if ((context = mlrpc_lookup(tmp_pipe.sp_pipeid)) == NULL)
		goto zero_exit;

	inpipe = context->inpipe;
	(void) strcpy(inpipe->sp_pipename, tmp_pipe.sp_pipename);

	outpipe = context->outpipe;
	(void) strcpy(outpipe->sp_pipename, "OUTPIPE");

	adj_len = mdhin.md_length;
	/*
	 * If RPC_TRANSACT, save len, set cookie to 0 and store
	 * outpipe pointer into rpc_context.  This will be used later
	 * by RPC_READ. See if we have pending writes.
	 * Clear the in context if we do.
	 */
	if ((mdhin.md_call_type == SMB_RPC_READ) && (context->inlen)) {
		context = mlrpc_process(inpipe->sp_pipeid, user_ctx);
		if (context == NULL)
			goto zero_exit;

		inpipe->sp_datalen = context->inlen;
		context->inlen = 0;
		context->outcookie = 0;
		context->outlen = outpipe->sp_datalen;
	}
	if (mdhin.md_call_type == SMB_RPC_TRANSACT) {
		/*
		 * Append trans data to the pipe
		 */
		if ((tmp_pipe.sp_datalen +
		    context->inlen) > SMB_CTXT_PIPE_SZ) {
			context->inlen = 0;
			goto zero_exit;
		}
		bcopy(bufp, inpipe->sp_data + context->inlen,
		    tmp_pipe.sp_datalen);
		inpipe->sp_datalen += tmp_pipe.sp_datalen;
		context = mlrpc_process(inpipe->sp_pipeid, user_ctx);
		if (context == NULL)
			goto zero_exit;

		context->outcookie = 0;
		context->outlen = outpipe->sp_datalen;
		context->inlen = 0;
		if (outpipe->sp_datalen < mdhin.md_length)
			adj_len = outpipe->sp_datalen;
		if (outpipe->sp_datalen > mdhin.md_length)
			more_data = B_TRUE;
	}
	outpipe->sp_more_data = (uint32_t)more_data;

	if (mdhin.md_call_type == SMB_RPC_WRITE) {
		/*
		 * Append write data to the pipe
		 */
		if ((tmp_pipe.sp_datalen +
		    context->inlen) > SMB_CTXT_PIPE_SZ) {
			context->inlen = 0;
			goto zero_exit;
		}
		bcopy(bufp, inpipe->sp_data + context->inlen,
		    tmp_pipe.sp_datalen);
		inpipe->sp_datalen += tmp_pipe.sp_datalen;
		context->inlen += tmp_pipe.sp_datalen;

		goto zero_exit;
	}

	/*
	 * check if this is the first transfer
	 * pipe and cookie management
	 */
	if (context->outcookie > 0) {
		if (context->outcookie >= context->outlen) {
			goto zero_exit;
		} else {
			bufp = outpipe->sp_data + context->outcookie;

			if (adj_len < (context->outlen - context->outcookie)) {
				context->outcookie += adj_len;
				current_out_len = adj_len;
			} else {
				current_out_len = context->outlen -
				    context->outcookie;
				context->outcookie = 0;
			}
		}
	} else {
		bufp = outpipe->sp_data;

		if (adj_len < context->outlen) {
			context->outcookie += adj_len;
			current_out_len = adj_len;
		} else {
			current_out_len = context->outlen;
			context->outcookie = 0;
		}
	}

	mdhout = mdhin;
	mdhout.md_tid = (uint64_t)getpid(); /* user process pid */
	bytes_off = 0;
	bcopy(&mdhout.md_tid, lfp, sizeof (uint64_t));
	bytes_off = sizeof (uint64_t);
	bcopy(&mdhout.md_version, lfp + bytes_off, sizeof (uint16_t));
	bytes_off += sizeof (uint16_t);
	bcopy(&mdhout.md_call_type, lfp + bytes_off, sizeof (uint16_t));
	bytes_off += sizeof (uint16_t);
	bcopy(&adj_len, lfp + bytes_off, sizeof (uint32_t));
	bytes_off += sizeof (uint32_t);
	bcopy(&mdhout.md_reserved, lfp + bytes_off, sizeof (uint64_t));
	bytes_off += sizeof (uint64_t);
	tbytes = bytes_off;
	bcopy(outpipe->sp_pipename, lfp + tbytes, SMB_MAX_PIPENAMELEN);
	bplen = SMB_MAX_PIPENAMELEN;
	bcopy(&(outpipe->sp_pipeid), lfp + tbytes + bplen, sizeof (uint32_t));
	bplen += sizeof (uint32_t);
	bcopy(&(current_out_len), lfp + tbytes + bplen, sizeof (uint32_t));
	bplen += sizeof (uint32_t);
	bcopy(&(outpipe->sp_more_data), lfp + tbytes + bplen,
	    sizeof (uint32_t));
	bplen += sizeof (uint32_t);

	bcopy(bufp, lfp + tbytes + bplen, current_out_len);

	tbytes += bplen + current_out_len;
	smb_user_ctx_free(user_ctx);
	(void) door_return((char *)lfp, tbytes, NULL, 0);
	/*NOTREACHED*/

zero_exit:
	smb_user_ctx_free(user_ctx);
	(void) door_return(NULL, 0, NULL, 0);
}
