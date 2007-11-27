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

/*
 * Winpipe door interface to MSRPC services.
 */

#define	START_UPDOOR_SIZE 16384
#define	START_INPIPE_SIZE 16384

#include <smbsrv/smb_incl.h>

#include <sys/stat.h>
#include <sys/door.h>
#include <sys/door_data.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/ndr.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/mlsvc_util.h>
#include <sys/uio.h>


static door_handle_t smb_winpipe_dh = NULL;
static int smb_winpipe_door_id = -1;
static uint64_t smb_winpipe_ncall = 0;
static kmutex_t smb_winpipe_mutex;
static kcondvar_t smb_winpipe_cv;

static int smb_winpipe_upcall(mlsvc_pipe_t *, smb_dr_user_ctx_t *,
    mlsvc_stream_t *, uint16_t, uint32_t, unsigned char *, smb_pipe_t *);

static smb_dr_user_ctx_t *smb_winpipe_ctx_alloc(struct smb_request *);
static void smb_winpipe_ctx_free(smb_dr_user_ctx_t *);
static uint8_t *smb_winpipe_ctx_mkselfrel(smb_dr_user_ctx_t *, uint32_t *);


void
smb_winpipe_init(void)
{
	mutex_init(&smb_winpipe_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&smb_winpipe_cv, NULL, CV_DEFAULT, NULL);
}

void
smb_winpipe_fini(void)
{
	smb_winpipe_close();
	cv_destroy(&smb_winpipe_cv);
	mutex_destroy(&smb_winpipe_mutex);
}

/*
 * Open the winpipe (user space) door.  If the door is already
 * open, close it because the door-id has probably changed.
 * Returns 0 on success.  Otherwise -1 to indicate a lookup failure.
 */
int
smb_winpipe_open(int door_id)
{
	smb_winpipe_close();

	mutex_enter(&smb_winpipe_mutex);
	smb_winpipe_ncall = 0;

	if (smb_winpipe_dh == NULL) {
		smb_winpipe_door_id = door_id;
		smb_winpipe_dh = door_ki_lookup(door_id);
	}

	mutex_exit(&smb_winpipe_mutex);
	return ((smb_winpipe_dh == NULL)  ? -1 : 0);
}

/*
 * Close the winpipe (user space) door.
 */
void
smb_winpipe_close(void)
{
	mutex_enter(&smb_winpipe_mutex);

	if (smb_winpipe_dh != NULL) {
		while (smb_winpipe_ncall > 0)
			cv_wait(&smb_winpipe_cv, &smb_winpipe_mutex);

		door_ki_rele(smb_winpipe_dh);
		smb_winpipe_dh = NULL;
	}

	mutex_exit(&smb_winpipe_mutex);
}

/*
 * Winpipe call interface: called by smb_rpc_transact and smb_rpc_read.
 * Serialization and call reference accounting handled here.
 *
 * The sr will be null on a flush operation, which will result in ctx
 * being null.  A null ctx must be handled by smb_winpipe_upcall.
 */
int
smb_winpipe_call(struct smb_request *sr,
	mlsvc_pipe_t *pi,
	mlsvc_stream_t *streamin,
	uint16_t call_type,
	uint32_t *nbytes)
{
	smb_dr_user_ctx_t *ctx;
	unsigned char *lbuf;
	smb_pipe_t *pp;
	int rc;

	mutex_enter(&smb_winpipe_mutex);

	if (smb_winpipe_dh == NULL) {
		mutex_exit(&smb_winpipe_mutex);

		if (smb_winpipe_open(smb_winpipe_door_id) != 0)
			return (-1);
	}

	++smb_winpipe_ncall;
	mutex_exit(&smb_winpipe_mutex);

	lbuf = kmem_zalloc(START_UPDOOR_SIZE, KM_SLEEP);
	pp = kmem_zalloc(START_INPIPE_SIZE, KM_SLEEP);
	ctx = smb_winpipe_ctx_alloc(sr);

	rc = smb_winpipe_upcall(pi, ctx, streamin, call_type, *nbytes,
	    lbuf, pp);

	if (rc == 0) {
		switch (call_type) {
		case SMB_RPC_TRANSACT:
		case SMB_RPC_READ:
		case SMB_RPC_FLUSH:
			*nbytes = pp->sp_datalen;
			break;

		default:
			/*
			 * A write just queues the data and returns.
			 */
			break;
		}
	}

	smb_winpipe_ctx_free(ctx);
	kmem_free(pp, START_INPIPE_SIZE);
	kmem_free(lbuf, START_UPDOOR_SIZE);

	mutex_enter(&smb_winpipe_mutex);
	--smb_winpipe_ncall;
	cv_signal(&smb_winpipe_cv);
	mutex_exit(&smb_winpipe_mutex);
	return (rc);
}

/*
 * Door upcall wrapper - handles data marshalling.
 * This function should only be called by smb_winpipe_call.
 */
static int
smb_winpipe_upcall(mlsvc_pipe_t *pipe_info,
	smb_dr_user_ctx_t *user_ctx,
	mlsvc_stream_t *streamin,
	uint16_t call_type,
	uint32_t req_cnt,
	unsigned char *lbuf,
	smb_pipe_t *pp)
{
	door_arg_t da;
	int user_ctx_bytes;
	mlsvc_door_hdr_t mdhin, mdhout;
	smb_pipe_t newpipe;
	int total_bytes = 0;
	int cnt;
	int bytes_off = 0;
	ulong_t save_resid;
	uint32_t tmp_resid;
	uint8_t *user_ctx_selfrel;

	/*
	 *	copy the pipe hdr into flat buf, this contains the thread id,
	 *	version and a couple of reserved fields for future expansion
	 */
	mdhin.md_tid = (uint64_t)curthread->t_did;
	mdhin.md_version = SMB_MLSVC_DOOR_VERSION;
	/*
	 * rpc_transact, rpc_read or rpc_write
	 */
	mdhin.md_call_type = call_type;
	mdhin.md_length = req_cnt;
	mdhin.md_reserved = 0;
	bcopy(&mdhin.md_tid, lbuf, sizeof (uint64_t));
	bytes_off += sizeof (uint64_t);
	bcopy(&mdhin.md_version, lbuf + bytes_off, sizeof (uint16_t));
	bytes_off += sizeof (uint16_t);
	bcopy(&mdhin.md_call_type, lbuf + bytes_off, sizeof (uint16_t));
	bytes_off += sizeof (uint16_t);
	bcopy(&mdhin.md_length, lbuf + bytes_off, sizeof (uint32_t));
	bytes_off += sizeof (uint32_t);
	bcopy(&mdhin.md_reserved, lbuf + bytes_off, sizeof (uint64_t));
	bytes_off += sizeof (uint64_t);
	total_bytes = bytes_off;

	/*
	 * Most of the marshalling isn't needed for flush.
	 * The pipe-id is needed to find the rpc_context and
	 * free the input and output pipes.
	 */
	if (call_type == SMB_RPC_FLUSH) {
		bcopy(&pipe_info->fid, lbuf + total_bytes, sizeof (uint32_t));
		total_bytes += sizeof (uint32_t);
	} else {
		user_ctx_selfrel = smb_winpipe_ctx_mkselfrel(user_ctx,
		    (uint32_t *)&cnt);

		if (user_ctx_selfrel == NULL) {
			return (-1);
		}

		bcopy(user_ctx_selfrel, lbuf + total_bytes, cnt);
		kmem_free(user_ctx_selfrel, cnt);
		total_bytes += cnt;
		/*
		 * based on uio stuff and smb_pipe_t size
		 * calculate size of buffer needed
		 */
		newpipe.sp_pipeid = pipe_info->fid;
		(void) strlcpy(newpipe.sp_pipename, pipe_info->pipe_name,
		    SMB_MAX_PIPENAMELEN);
		bcopy(newpipe.sp_pipename, lbuf + total_bytes,
		    SMB_MAX_PIPENAMELEN);
		bcopy(&newpipe.sp_pipeid, lbuf + total_bytes +
		    SMB_MAX_PIPENAMELEN, sizeof (uint32_t));
		total_bytes += sizeof (uint32_t) + SMB_MAX_PIPENAMELEN;
	}

	/* copy the pipe data len into flat buf */
	if ((mdhin.md_call_type == SMB_RPC_TRANSACT) ||
	    (mdhin.md_call_type == SMB_RPC_WRITE)) {
		/* we only want the least 4 significant bytes here */
		tmp_resid = (uint32_t)streamin->uio.uio_resid;
		bcopy(&tmp_resid, lbuf + total_bytes, sizeof (uint32_t));
		total_bytes += sizeof (uint32_t);
		save_resid = streamin->uio.uio_resid;
		(void) uiomove((caddr_t)(lbuf + total_bytes),
		    streamin->uio.uio_resid, UIO_WRITE, &streamin->uio);
		total_bytes += (save_resid - streamin->uio.uio_resid);
	} else if (mdhin.md_call_type == SMB_RPC_READ) {
		bzero(lbuf + total_bytes, sizeof (uint32_t));
		total_bytes += sizeof (uint32_t);
	}

	da.data_ptr = (char *)lbuf;
	da.data_size = total_bytes;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)lbuf;
	da.rsize = START_UPDOOR_SIZE;

	if (door_ki_upcall(smb_winpipe_dh, &da) != 0) {
		return (-1);
	}
	/* RPC_WRITE just queues the data and returns */
	if (mdhin.md_call_type == SMB_RPC_WRITE) {
		return (0);
	}
	bytes_off = 0;
	bcopy(da.data_ptr, &mdhout.md_tid, sizeof (uint64_t));
	bytes_off += sizeof (uint64_t);
	bcopy(da.data_ptr+bytes_off, &mdhout.md_version, sizeof (uint16_t));
	bytes_off += sizeof (uint16_t);
	bcopy(da.data_ptr+bytes_off, &mdhout.md_call_type, sizeof (uint16_t));
	bytes_off += sizeof (uint16_t);
	bcopy(da.data_ptr+bytes_off, &mdhout.md_length, sizeof (uint32_t));
	bytes_off += sizeof (uint32_t);
	bcopy(da.data_ptr+bytes_off, &mdhout.md_reserved, sizeof (uint64_t));
	bytes_off += sizeof (uint64_t);
	user_ctx_bytes = 0;
	total_bytes = user_ctx_bytes + bytes_off;

	bzero(pp, START_INPIPE_SIZE);
	bcopy(da.data_ptr+total_bytes, pp->sp_pipename, SMB_MAX_PIPENAMELEN);
	total_bytes += SMB_MAX_PIPENAMELEN;
	bcopy(da.data_ptr+total_bytes, &(pp->sp_pipeid), sizeof (uint32_t));
	total_bytes += sizeof (uint32_t);
	bcopy(da.data_ptr + total_bytes, &(pp->sp_datalen), sizeof (uint32_t));
	total_bytes += sizeof (uint32_t);

	if (pp->sp_datalen > 0) {
		pipe_info->outlen = pp->sp_datalen;
		pipe_info->output = kmem_alloc(pipe_info->outlen, KM_SLEEP);
		bcopy((char *)(da.data_ptr + total_bytes),
		    pipe_info->output, pipe_info->outlen);
	}

	return (0);
}


/*
 * Allocate a user context structure and initialize it based on the
 * specified SMB request data.  Resources allocated here must be
 * released using smb_winpipe_ctx_free.
 *
 * If sr is null, a null pointer is returned.
 */
static smb_dr_user_ctx_t *
smb_winpipe_ctx_alloc(struct smb_request *sr)
{
	smb_session_t *session;
	smb_user_t *user;
	smb_dr_user_ctx_t *ctx;

	if (sr == NULL)
		return (NULL);

	user = sr->uid_user;
	session = user->u_session;

	ASSERT(user);
	ASSERT(user->u_domain);
	ASSERT(user->u_name);
	ASSERT(session);
	ASSERT(session->workstation);

	ctx = kmem_zalloc(sizeof (smb_dr_user_ctx_t), KM_SLEEP);

	ctx->du_session_id = session->s_kid;
	ctx->du_native_os = session->native_os;
	ctx->du_ipaddr = session->ipaddr;
	ctx->du_uid = user->u_uid;
	ctx->du_logon_time = user->u_logon_time;
	ctx->du_flags = user->u_flags;

	ctx->du_domain_len = user->u_domain_len;
	ctx->du_domain = kmem_alloc(ctx->du_domain_len, KM_SLEEP);
	(void) strlcpy(ctx->du_domain, user->u_domain, ctx->du_domain_len);

	ctx->du_account_len = user->u_name_len;
	ctx->du_account = kmem_alloc(ctx->du_account_len, KM_SLEEP);
	(void) strlcpy(ctx->du_account, user->u_name, ctx->du_account_len);

	ctx->du_workstation_len = strlen(session->workstation) + 1;
	ctx->du_workstation = kmem_alloc(ctx->du_workstation_len,
	    KM_SLEEP);
	(void) strlcpy(ctx->du_workstation, session->workstation,
	    ctx->du_workstation_len);

	return (ctx);
}


/*
 * Free resources associated with a user context structure.
 */
static void
smb_winpipe_ctx_free(smb_dr_user_ctx_t *ctx)
{
	if (ctx == NULL)
		return;

	ASSERT(ctx->du_domain);
	ASSERT(ctx->du_account);
	ASSERT(ctx->du_workstation);

	kmem_free(ctx->du_domain, ctx->du_domain_len);
	kmem_free(ctx->du_account, ctx->du_account_len);
	kmem_free(ctx->du_workstation, ctx->du_workstation_len);
	kmem_free(ctx, sizeof (smb_dr_user_ctx_t));
}

/*
 * Convert a user context structure from absolute to self-relative format.
 *
 * On success, a pointer to an allocated XDR encoded buffer is returned,
 * with the buffer size in ret_len.  The caller is responsible for freeing
 * this buffer when it is no longer required.  If the return value is NULL,
 * it is not valid to interpret ret_len.
 */
static uint8_t *
smb_winpipe_ctx_mkselfrel(smb_dr_user_ctx_t *ctx, uint32_t *ret_len)
{
	XDR xdrs;
	uint8_t *buf;
	uint32_t len;

	if (ctx == NULL || ret_len == NULL) {
		return (NULL);
	}

	len = xdr_sizeof(xdr_smb_dr_user_ctx_t, ctx);
	buf = kmem_zalloc(len, KM_SLEEP);
	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_ENCODE);

	if (!xdr_smb_dr_user_ctx_t(&xdrs, ctx)) {
		kmem_free(buf, len);
		len = 0;
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	*ret_len = len;
	return (buf);
}
