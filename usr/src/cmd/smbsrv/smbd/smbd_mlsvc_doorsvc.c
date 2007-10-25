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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#include <smbsrv/ntsid.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/smb_winpipe.h>

static int smb_updoor_id = -1;
static pthread_mutex_t smb_winpipe_user_mutex;

#define	START_OUTDOOR_SIZE 65536
#define	MAX_INPIPE_LEN 65536

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
 * Function: smb_mlsvc_door_server
 *
 * This is the userland winpipe door entry point.
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
 * After converting the data, mlsvc_rpc_process is called
 * The returning outpipe contains the relevant data to be
 * returned to the windows client.
 *
 * Outgoing data must be marshalled again before returning.
 */

/*ARGSUSED*/
void
smb_mlsvc_door_server(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dd, uint_t n_desc)
{
	smb_pipe_t *inpipe = NULL;
	smb_pipe_t *outpipe = NULL;
	smb_pipe_t tmp_pipe;
	smb_dr_user_ctx_t *user_ctx = NULL;
	uchar_t *bufp;
	int bplen = 0;
	int total_pipelen;
	mlsvc_door_hdr_t mdhin, mdhout;
	int tbytes = 0;
	int bytes_off = 0;
	struct mlsvc_rpc_context *context;
	uchar_t *obuf = NULL;
	int current_out_len;
	uint32_t adj_len;
	char lfp[START_OUTDOOR_SIZE];

	bufp = (uchar_t *)argp;
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

	/* flush is a special case, just free the buffers and return */
	if (mdhin.md_call_type == SMB_RPC_FLUSH) {
		bcopy(bufp + bytes_off, &tmp_pipe.sp_pipeid, sizeof (uint32_t));
		context = mlsvc_lookup_context(tmp_pipe.sp_pipeid);
		if (!context) {
			syslog(LOG_ERR, "mds: Cannot lookup mlsvc context");
			goto zero_exit;
		}
		if (context->inpipe) {
			free(context->inpipe);
			context->inpipe = NULL;
		}
		if (context->outpipe) {
			free(context->outpipe);
			context->outpipe = NULL;
		}
		mlsvc_rpc_release(tmp_pipe.sp_pipeid);
		goto zero_exit;
	}

	user_ctx = smb_user_ctx_mkabsolute(bufp + bytes_off,
	    arg_size - bytes_off);
	if (!user_ctx) {
		syslog(LOG_ERR, "mds: user_ctx_mkabsolute failed");
		goto zero_exit;
	}

	tbytes += xdr_sizeof(xdr_smb_dr_user_ctx_t, user_ctx) + bytes_off;

	bzero(tmp_pipe.sp_pipename, SMB_MAX_PIPENAMELEN);
	bcopy(bufp + tbytes, tmp_pipe.sp_pipename, SMB_MAX_PIPENAMELEN);
	bplen = SMB_MAX_PIPENAMELEN;
	bcopy(bufp + tbytes + bplen, &tmp_pipe.sp_pipeid, sizeof (uint32_t));
	bplen += sizeof (uint32_t);
	bcopy(bufp + tbytes + bplen, &tmp_pipe.sp_datalen, sizeof (uint32_t));
	bplen += sizeof (uint32_t);

	total_pipelen = bplen + tmp_pipe.sp_datalen;
	inpipe = malloc(total_pipelen);
	if (! inpipe) {
		syslog(LOG_ERR, "mds: resource shortage");
		goto zero_exit;
	}
	(void) strlcpy(inpipe->sp_pipename, tmp_pipe.sp_pipename,
	    SMB_MAX_PIPENAMELEN);
	inpipe->sp_pipeid = tmp_pipe.sp_pipeid;
	inpipe->sp_datalen = tmp_pipe.sp_datalen;
	bcopy(bufp + tbytes + bplen, inpipe->sp_data, inpipe->sp_datalen);

	context = mlsvc_lookup_context(inpipe->sp_pipeid);
	if (!context) {
		syslog(LOG_ERR, "mds: Cannot lookup mlsvc context");
		goto zero_exit;
	}
	adj_len = mdhin.md_length;
	/*
	 * If RPC_TRANSACT, save len, set cookie to 0 and store
	 * outpipe pointer into rpc_context.  This will be used later
	 * by RPC_READ. See if we have pending writes.
	 * Clear the in context if we do.
	 */
	if ((mdhin.md_call_type == SMB_RPC_READ) && (context->inlen)) {
		context->inpipe->sp_datalen = context->inlen;
		if (context->inpipe->sp_pipeid != inpipe->sp_pipeid) {
			syslog(LOG_DEBUG, "mds: RPC_READ pipeid mismatch !!");
			goto zero_exit;
		}
		(void) mlsvc_rpc_process(context->inpipe, &outpipe, user_ctx);
		context->inlen = 0;
		free(context->inpipe);
		context->inpipe = NULL;
		/*
		 * if no outpipe yet, initialize it
		 */
		if (!context->outpipe) {
			context->outpipe = outpipe;
			context->outcookie = 0;
			context->outlen = outpipe->sp_datalen;
		}
	}
	if (mdhin.md_call_type == SMB_RPC_TRANSACT) {
		(void) mlsvc_rpc_process(inpipe, &outpipe, user_ctx);
		/*
		 * init pipe context for subsequent calls
		 */
		context->outpipe = outpipe;
		context->outcookie = 0;
		context->outlen = outpipe->sp_datalen;
		if (outpipe->sp_datalen < mdhin.md_length)
			adj_len = outpipe->sp_datalen;
	}
	if (mdhin.md_call_type == SMB_RPC_WRITE) {
		/*
		 * the first write we need to allocate
		 * the maximum inpipe len
		 */
		if (context->inlen == 0) {
			context->inpipe = malloc(MAX_INPIPE_LEN);
		}
		if (! context->inpipe) {
			syslog(LOG_ERR, "mds: ctx resource shortage");
			goto zero_exit;
		}
		bcopy(inpipe->sp_data, context->inpipe->sp_data +
		    context->inlen, inpipe->sp_datalen);
		/*
		 * if we get another RPC_WRITE then we need to append
		 */
		context->inlen += inpipe->sp_datalen;
		context->inpipe->sp_pipeid = inpipe->sp_pipeid;
		context->inpipe->sp_datalen = context->inlen;
		(void) strlcpy(context->inpipe->sp_pipename,
		    inpipe->sp_pipename, SMB_MAX_PIPENAMELEN);
		goto zero_exit;
	}
	obuf = malloc(START_OUTDOOR_SIZE);
	if (! obuf) {
		syslog(LOG_ERR, "mds: obuf resource shortage");
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
			if (adj_len < (context->outlen - context->outcookie)) {
				bcopy(context->outpipe->sp_data +
				    context->outcookie, obuf, adj_len);
				context->outcookie += adj_len;
				current_out_len = adj_len;
			} else {
				bcopy(context->outpipe->sp_data +
				    context->outcookie, obuf, (context->outlen -
				    context->outcookie));
				current_out_len = context->outlen -
				    context->outcookie;
				context->outcookie = 0;
				free(context->outpipe);
				context->outpipe = NULL;
			}
		}
		outpipe = malloc(START_OUTDOOR_SIZE);
		if (! outpipe) {
			syslog(LOG_ERR, "mds: outpipe resource shortage");
			goto zero_exit;
		}
	} else {
		if (adj_len < context->outlen) {
			bcopy(context->outpipe->sp_data, obuf, adj_len);
			context->outcookie += adj_len;
			current_out_len = adj_len;
		} else {
			bcopy(context->outpipe->sp_data, obuf, context->outlen);
			current_out_len = context->outlen;
			context->outcookie = 0;
			free(context->outpipe);
			context->outpipe = NULL;
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
	tbytes = 0;
	tbytes = bytes_off;
	bzero(outpipe->sp_pipename, SMB_MAX_PIPENAMELEN);
	(void) strcpy(outpipe->sp_pipename, "OUTPIPE");
	outpipe->sp_pipeid = inpipe->sp_pipeid;
	bcopy(outpipe->sp_pipename, lfp + tbytes, SMB_MAX_PIPENAMELEN);
	bplen = SMB_MAX_PIPENAMELEN;
	bcopy(&(outpipe->sp_pipeid), lfp + tbytes + bplen, sizeof (uint32_t));
	bplen += sizeof (uint32_t);

	bcopy(&(current_out_len), lfp + tbytes + bplen, sizeof (uint32_t));
	bplen += sizeof (uint32_t);

	bcopy(obuf, lfp + tbytes + bplen, current_out_len);
	tbytes += bplen + current_out_len;
	smb_user_ctx_free(user_ctx);
	free(obuf);
	free(inpipe);
	(void) door_return((char *)lfp, tbytes, NULL, 0);
	/*NOTREACHED*/

zero_exit:
	smb_user_ctx_free(user_ctx);

	if (obuf)
		free(obuf);
	if (inpipe)
		free(inpipe);

	(void) door_return(0, 0, NULL, 0);
}

/*
 * smb_mlsvc_srv_start
 *
 * Start the mlsvc door service.
 */
int
smb_mlsvc_srv_start()
{
	int newfd;

	(void) pthread_mutex_lock(&smb_winpipe_user_mutex);

	if (smb_updoor_id != -1) {
		(void) fprintf(stderr, "smb_mlsvc_srv_start: duplicate");
		(void) pthread_mutex_unlock(&smb_winpipe_user_mutex);
		return (-1);
	}

	errno = 0;
	if ((smb_updoor_id = door_create(smb_mlsvc_door_server, 0, 0)) < 0) {
		(void) fprintf(stderr, "smb_mlsvc_srv_start: door_create: %s",
		    strerror(errno));
		smb_updoor_id = -1;
		(void) pthread_mutex_unlock(&smb_winpipe_user_mutex);
		return (-1);
	}

	(void) unlink(SMB_WINPIPE_DOOR_UP_PATH);

	if ((newfd = creat(SMB_WINPIPE_DOOR_UP_PATH, 0644)) < 0) {
		(void) fprintf(stderr, "smb_mlsvc_srv_start: open: %s",
		    strerror(errno));
		(void) door_revoke(smb_updoor_id);
		smb_updoor_id = -1;
		(void) pthread_mutex_unlock(&smb_winpipe_user_mutex);
		return (-1);
	}

	(void) close(newfd);
	(void) fdetach(SMB_WINPIPE_DOOR_UP_PATH);

	if (fattach(smb_updoor_id, SMB_WINPIPE_DOOR_UP_PATH) < 0) {
		(void) fprintf(stderr, "smb_mlsvc_srv_start: fattach: %s",
		    strerror(errno));
		(void) door_revoke(smb_updoor_id);
		smb_updoor_id = -1;
		(void) pthread_mutex_unlock(&smb_winpipe_user_mutex);
		return (-1);
	}

	(void) pthread_mutex_unlock(&smb_winpipe_user_mutex);
	return (0);
}

/*
 * smb_mlsvc_srv_stop
 *
 * Stop the mlsvc door service.
 * We will eventually call this based on some signals
 * No one calls this just yet, if the process dies all this stuff happens
 * by default
 */
void
smb_mlsvc_srv_stop()
{
	(void) pthread_mutex_lock(&smb_winpipe_user_mutex);

	if (smb_updoor_id != -1) {
		(void) fdetach(SMB_WINPIPE_DOOR_UP_PATH);
		(void) door_revoke(smb_updoor_id);
		smb_updoor_id = -1;
	}

	(void) pthread_mutex_unlock(&smb_winpipe_user_mutex);
}
