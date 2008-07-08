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

/*
 * This module provides the interface to NDR RPC.
 */

#include <sys/stat.h>
#include <sys/door.h>
#include <sys/door_data.h>
#include <sys/uio.h>
#include <sys/ksynch.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_xdr.h>

#define	SMB_OPIPE_ISOPEN(OPIPE)	\
	(((OPIPE)->p_hdr.oh_magic == SMB_OPIPE_HDR_MAGIC) && \
	((OPIPE)->p_hdr.oh_fid))

extern volatile uint32_t smb_fids;

static int smb_opipe_do_open(smb_request_t *, smb_opipe_t *);
static char *smb_opipe_lookup(const char *path);
static uint32_t smb_opipe_fid(void);
static int smb_opipe_set_hdr(smb_opipe_t *opipe, uint32_t, uint32_t);
static void smb_opipe_enter(smb_opipe_t *);
static void smb_opipe_exit(smb_opipe_t *);

static door_handle_t smb_opipe_door_hd = NULL;
static int smb_opipe_door_id = -1;
static uint64_t smb_opipe_door_ncall = 0;
static kmutex_t smb_opipe_door_mutex;
static kcondvar_t smb_opipe_door_cv;

static int smb_opipe_door_call(smb_opipe_t *);
static int smb_opipe_door_upcall(smb_opipe_t *);
static void smb_user_context_fini(smb_opipe_context_t *);

/*
 * smb_opipe_open
 *
 * Open a well-known RPC named pipe. This routine should be called if
 * a file open is requested on a share of type STYPE_IPC.
 * If we recognize the pipe, we setup a new ofile.
 *
 * Returns 0 on success, Otherwise an NT status is returned to indicate
 * an error.
 */
int
smb_opipe_open(smb_request_t *sr)
{
	struct open_param *op = &sr->arg.open;
	smb_ofile_t *of;
	smb_opipe_t *opipe;
	smb_opipe_hdr_t hdr;
	smb_error_t err;
	char *pipe_name;

	if ((pipe_name = smb_opipe_lookup(op->fqi.path)) == NULL)
		return (NT_STATUS_OBJECT_NAME_NOT_FOUND);

	of = smb_ofile_open(sr->tid_tree, NULL, sr->smb_pid,
	    op->desired_access, 0, op->share_access,
	    SMB_FTYPE_MESG_PIPE, SMB_UNIQ_FID(), &err);
	if (of == NULL)
		return (err.status);

	op->dsize = 0x01000;
	op->dattr = FILE_ATTRIBUTE_NORMAL;
	op->ftype = SMB_FTYPE_MESG_PIPE;
	op->action_taken = SMB_OACT_LOCK | SMB_OACT_OPENED; /* 0x8001 */
	op->devstate = SMB_PIPE_READMODE_MESSAGE
	    | SMB_PIPE_TYPE_MESSAGE
	    | SMB_PIPE_UNLIMITED_INSTANCES; /* 0x05ff */
	op->fileid = of->f_fid;
	op->create_options = 0;

	sr->smb_fid = of->f_fid;
	sr->fid_ofile = of;

	opipe = of->f_pipe;
	mutex_init(&opipe->p_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&opipe->p_cv, NULL, CV_DEFAULT, NULL);
	smb_opipe_enter(opipe);

	opipe->p_name = pipe_name;
	opipe->p_doorbuf = kmem_zalloc(SMB_OPIPE_DOOR_BUFSIZE, KM_SLEEP);

	/*
	 * p_data points to the offset within p_doorbuf at which
	 * data will be written or read.
	 */
	opipe->p_data = opipe->p_doorbuf + xdr_sizeof(smb_opipe_hdr_xdr, &hdr);

	if (smb_opipe_do_open(sr, opipe) != 0) {
		/*
		 * On error, reset the header to clear the fid,
		 * which avoids confusion when smb_opipe_close() is
		 * called by smb_ofile_close().
		 */
		bzero(&opipe->p_hdr, sizeof (smb_opipe_hdr_t));
		kmem_free(opipe->p_doorbuf, SMB_OPIPE_DOOR_BUFSIZE);
		smb_opipe_exit(opipe);
		(void) smb_ofile_close(of, 0);
		return (NT_STATUS_NO_MEMORY);
	}

	smb_opipe_exit(opipe);
	return (NT_STATUS_SUCCESS);
}

/*
 * smb_opipe_lookup
 *
 * Lookup a path to see if it's a well-known RPC named pipe that we support.
 * The full pipe path will be in the form \\PIPE\\SERVICE.  The first part
 * can be assumed, so all we need here are the service names.
 *
 * Returns a pointer to the pipe name (without any leading \'s) on sucess.
 * Otherwise returns a null pointer.
 */
static char *
smb_opipe_lookup(const char *path)
{
	static char *named_pipes[] = {
		"LSARPC",
		"NETLOGON",
		"SAMR",
		"SPOOLSS",
		"SRVSVC",
		"SVCCTL",
		"WINREG",
		"WKSSVC",
		"EVENTLOG"
	};

	const char *name;
	int i;

	if (path == NULL)
		return (NULL);

	name = path;
	name += strspn(name, "\\");
	if (utf8_strncasecmp(name, "PIPE", 4) == 0) {
		path += 4;
		name += strspn(name, "\\");
	}

	for (i = 0; i < sizeof (named_pipes) / sizeof (named_pipes[0]); ++i) {
		if (utf8_strcasecmp(name, named_pipes[i]) == 0)
			return (named_pipes[i]);
	}

	return (NULL);
}

/*
 * Initialize the opipe header and context, and make the door call.
 */
static int
smb_opipe_do_open(smb_request_t *sr, smb_opipe_t *opipe)
{
	smb_opipe_context_t *ctx = &opipe->p_context;
	smb_user_t *user = sr->uid_user;
	uint8_t *buf = opipe->p_doorbuf;
	uint32_t buflen = SMB_OPIPE_DOOR_BUFSIZE;
	uint32_t len;

	smb_user_context_init(user, ctx);
	len = xdr_sizeof(smb_opipe_context_xdr, ctx);

	bzero(&opipe->p_hdr, sizeof (smb_opipe_hdr_t));
	opipe->p_hdr.oh_magic = SMB_OPIPE_HDR_MAGIC;
	opipe->p_hdr.oh_fid = smb_opipe_fid();

	if (smb_opipe_set_hdr(opipe, SMB_OPIPE_OPEN, len) == -1)
		return (-1);

	len = xdr_sizeof(smb_opipe_hdr_xdr, &opipe->p_hdr);
	buf += len;
	buflen -= len;

	if (smb_opipe_context_encode(ctx, buf, buflen) == -1)
		return (-1);

	return (smb_opipe_door_call(opipe));
}

/*
 * smb_opipe_fid
 *
 * The opipe_fid is an arbitrary id used to associate RPC requests
 * with a binding handle.  A new fid is returned on each call.
 * 0 or -1 are not assigned: 0 is used to indicate an invalid fid
 * and SMB sometimes uses -1 to indicate all open fid's.
 */
static uint32_t
smb_opipe_fid(void)
{
	static uint32_t opipe_fid;
	static kmutex_t smb_opipe_fid_mutex;

	mutex_enter(&smb_opipe_fid_mutex);

	if (opipe_fid == 0)
		opipe_fid = lbolt << 11;

	do {
		++opipe_fid;
	} while (opipe_fid == 0 || opipe_fid == (uint32_t)-1);

	mutex_exit(&smb_opipe_fid_mutex);

	return (opipe_fid);
}

/*
 * smb_opipe_close
 *
 * Called whenever an IPC file/pipe is closed.
 */
void
smb_opipe_close(smb_ofile_t *of)
{
	smb_opipe_t *opipe;

	ASSERT(of);
	ASSERT(of->f_ftype == SMB_FTYPE_MESG_PIPE);
	ASSERT(of->f_pipe != NULL);

	opipe = of->f_pipe;
	smb_opipe_enter(opipe);

	if (SMB_OPIPE_ISOPEN(opipe)) {
		(void) smb_opipe_set_hdr(opipe, SMB_OPIPE_CLOSE, 0);
		(void) smb_opipe_door_call(opipe);
		bzero(&opipe->p_hdr, sizeof (smb_opipe_hdr_t));
		kmem_free(opipe->p_doorbuf, SMB_OPIPE_DOOR_BUFSIZE);
	}

	smb_user_context_fini(&opipe->p_context);
	smb_opipe_exit(opipe);
	cv_destroy(&opipe->p_cv);
	mutex_destroy(&opipe->p_mutex);
}

static int
smb_opipe_set_hdr(smb_opipe_t *opipe, uint32_t cmd, uint32_t datalen)
{
	opipe->p_hdr.oh_op = cmd;
	opipe->p_hdr.oh_datalen = datalen;
	opipe->p_hdr.oh_resid = 0;
	opipe->p_hdr.oh_status = 0;

	return (smb_opipe_hdr_encode(&opipe->p_hdr, opipe->p_doorbuf,
	    SMB_OPIPE_DOOR_BUFSIZE));
}

/*
 * smb_opipe_transact
 *
 * This is the entry point for RPC bind and request transactions.
 * The fid is an arbitrary id used to associate RPC requests with a
 * particular binding handle.
 *
 * If the data to be returned is larger than the client expects, we
 * return as much as the client can handle and report a buffer overflow
 * warning, which informs the client that we have more data to return.
 * The residual data remains in the pipe until the client claims it or
 * closes the pipe.
 */
smb_sdrc_t
smb_opipe_transact(smb_request_t *sr, struct uio *uio)
{
	smb_xa_t *xa;
	smb_opipe_t *opipe;
	struct mbuf *mhead;
	int mdrcnt;
	int nbytes;
	int rc;

	if ((rc = smb_opipe_write(sr, uio)) != 0) {
		if (rc == EBADF)
			smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
			    ERRDOS, ERROR_INVALID_HANDLE);
		else
			smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
			    ERRDOS, ERROR_INTERNAL_ERROR);
		return (SDRC_ERROR);
	}

	xa = sr->r_xa;
	mdrcnt = xa->smb_mdrcnt;
	opipe = sr->fid_ofile->f_pipe;
	smb_opipe_enter(opipe);

	if (smb_opipe_set_hdr(opipe, SMB_OPIPE_READ, mdrcnt) == -1) {
		smb_opipe_exit(opipe);
		smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
		    ERRDOS, ERROR_INTERNAL_ERROR);
		return (SDRC_ERROR);
	}

	rc = smb_opipe_door_call(opipe);
	nbytes = opipe->p_hdr.oh_datalen;

	if (rc != 0) {
		smb_opipe_exit(opipe);
		smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
		    ERRDOS, ERROR_INTERNAL_ERROR);
		return (SDRC_ERROR);
	}

	if (nbytes) {
		mhead = smb_mbuf_get(opipe->p_data, nbytes);
		xa->rep_data_mb.max_bytes = nbytes;
		MBC_ATTACH_MBUF(&xa->rep_data_mb, mhead);
	}

	if (opipe->p_hdr.oh_resid) {
		/*
		 * The pipe contains more data than mdrcnt, warn the
		 * client that there is more data in the pipe.
		 * Typically, the client will call SmbReadX, which
		 * will call smb_opipe_read, to get the data.
		 */
		smbsr_warn(sr, NT_STATUS_BUFFER_OVERFLOW,
		    ERRDOS, ERROR_MORE_DATA);
	}

	smb_opipe_exit(opipe);
	return (SDRC_SUCCESS);
}

/*
 * smb_opipe_write
 *
 * Write RPC request data to the pipe.  The client should call smb_opipe_read
 * to complete the exchange and obtain the RPC response.
 *
 * Returns 0 on success or an errno on failure.
 */
int
smb_opipe_write(smb_request_t *sr, struct uio *uio)
{
	smb_opipe_t *opipe;
	uint32_t buflen;
	uint32_t len;
	int rc;

	ASSERT(sr->fid_ofile);
	ASSERT(sr->fid_ofile->f_ftype == SMB_FTYPE_MESG_PIPE);
	ASSERT(sr->fid_ofile->f_pipe != NULL);

	opipe = sr->fid_ofile->f_pipe;
	smb_opipe_enter(opipe);

	if (!SMB_OPIPE_ISOPEN(opipe)) {
		smb_opipe_exit(opipe);
		return (EBADF);
	}

	rc = smb_opipe_set_hdr(opipe, SMB_OPIPE_WRITE, uio->uio_resid);
	len = xdr_sizeof(smb_opipe_hdr_xdr, &opipe->p_hdr);
	if (rc == -1 || len == 0) {
		smb_opipe_exit(opipe);
		return (ENOMEM);
	}

	buflen = SMB_OPIPE_DOOR_BUFSIZE - len;
	(void) uiomove((caddr_t)opipe->p_data, buflen, UIO_WRITE, uio);

	rc = smb_opipe_door_call(opipe);

	smb_opipe_exit(opipe);
	return ((rc == 0) ? 0 : EIO);
}

/*
 * smb_opipe_read
 *
 * This interface may be called because smb_opipe_transact could not return
 * all of the data in the original transaction or to form the second half
 * of a transaction set up using smb_opipe_write.  Either way, we just need
 * to read data from the pipe and return it.
 *
 * The response data is encoded into raw_data as required by the smb_read
 * functions.  The uio_resid value indicates the number of bytes read.
 */
int
smb_opipe_read(smb_request_t *sr, struct uio *uio)
{
	smb_opipe_t *opipe;
	struct mbuf *mhead;
	uint32_t nbytes;
	int rc;

	ASSERT(sr->fid_ofile);
	ASSERT(sr->fid_ofile->f_ftype == SMB_FTYPE_MESG_PIPE);
	ASSERT(sr->fid_ofile->f_pipe != NULL);

	opipe = sr->fid_ofile->f_pipe;
	smb_opipe_enter(opipe);

	if (!SMB_OPIPE_ISOPEN(opipe)) {
		smb_opipe_exit(opipe);
		return (EBADF);
	}

	if (smb_opipe_set_hdr(opipe, SMB_OPIPE_READ, uio->uio_resid) == -1) {
		smb_opipe_exit(opipe);
		return (ENOMEM);
	}

	rc = smb_opipe_door_call(opipe);
	nbytes = opipe->p_hdr.oh_datalen;

	if (rc != 0 || nbytes > uio->uio_resid) {
		smb_opipe_exit(opipe);
		return (EIO);
	}

	if (nbytes) {
		mhead = smb_mbuf_get(opipe->p_data, nbytes);
		MBC_SETUP(&sr->raw_data, nbytes);
		MBC_ATTACH_MBUF(&sr->raw_data, mhead);
		uio->uio_resid -= nbytes;
	}

	smb_opipe_exit(opipe);
	return (rc);
}

/*
 * Named pipe I/O is serialized per fid to ensure that each request
 * has exclusive opipe access for the duration of the request.
 */
static void
smb_opipe_enter(smb_opipe_t *opipe)
{
	mutex_enter(&opipe->p_mutex);

	while (opipe->p_busy)
		cv_wait(&opipe->p_cv, &opipe->p_mutex);

	opipe->p_busy = 1;
	mutex_exit(&opipe->p_mutex);
}

static void
smb_opipe_exit(smb_opipe_t *opipe)
{
	mutex_enter(&opipe->p_mutex);
	opipe->p_busy = 0;
	cv_signal(&opipe->p_cv);
	mutex_exit(&opipe->p_mutex);
}

/*
 * opipe door client (to user space door server).
 */
void
smb_opipe_door_init(void)
{
	mutex_init(&smb_opipe_door_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&smb_opipe_door_cv, NULL, CV_DEFAULT, NULL);
}

void
smb_opipe_door_fini(void)
{
	smb_opipe_door_close();
	cv_destroy(&smb_opipe_door_cv);
	mutex_destroy(&smb_opipe_door_mutex);
}

/*
 * Open the (user space) door.  If the door is already open,
 * close it first because the door-id has probably changed.
 */
int
smb_opipe_door_open(int door_id)
{
	smb_opipe_door_close();

	mutex_enter(&smb_opipe_door_mutex);
	smb_opipe_door_ncall = 0;

	if (smb_opipe_door_hd == NULL) {
		smb_opipe_door_id = door_id;
		smb_opipe_door_hd = door_ki_lookup(door_id);
	}

	mutex_exit(&smb_opipe_door_mutex);
	return ((smb_opipe_door_hd == NULL)  ? -1 : 0);
}

/*
 * Close the (user space) door.
 */
void
smb_opipe_door_close(void)
{
	mutex_enter(&smb_opipe_door_mutex);

	if (smb_opipe_door_hd != NULL) {
		while (smb_opipe_door_ncall > 0)
			cv_wait(&smb_opipe_door_cv, &smb_opipe_door_mutex);

		door_ki_rele(smb_opipe_door_hd);
		smb_opipe_door_hd = NULL;
	}

	mutex_exit(&smb_opipe_door_mutex);
}

/*
 * opipe door call interface.
 * Door serialization and call reference accounting is handled here.
 */
static int
smb_opipe_door_call(smb_opipe_t *opipe)
{
	int rc;

	mutex_enter(&smb_opipe_door_mutex);

	if (smb_opipe_door_hd == NULL) {
		mutex_exit(&smb_opipe_door_mutex);

		if (smb_opipe_door_open(smb_opipe_door_id) != 0)
			return (-1);

		mutex_enter(&smb_opipe_door_mutex);
	}

	++smb_opipe_door_ncall;
	mutex_exit(&smb_opipe_door_mutex);

	rc = smb_opipe_door_upcall(opipe);

	mutex_enter(&smb_opipe_door_mutex);
	--smb_opipe_door_ncall;
	cv_signal(&smb_opipe_door_cv);
	mutex_exit(&smb_opipe_door_mutex);
	return (rc);
}

/*
 * Door upcall wrapper - handles data marshalling.
 * This function should only be called by smb_opipe_door_call.
 */
static int
smb_opipe_door_upcall(smb_opipe_t *opipe)
{
	door_arg_t da;
	smb_opipe_hdr_t hdr;
	int i;
	int rc;

	da.data_ptr = (char *)opipe->p_doorbuf;
	da.data_size = SMB_OPIPE_DOOR_BUFSIZE;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)opipe->p_doorbuf;
	da.rsize = SMB_OPIPE_DOOR_BUFSIZE;

	for (i = 0; i < 3; ++i) {
		if ((rc = door_ki_upcall_limited(smb_opipe_door_hd, &da,
		    NULL, SIZE_MAX, 0)) == 0)
			break;

		if (rc != EAGAIN && rc != EINTR)
			return (-1);
	}

	if (rc != 0)
		return (-1);

	if (smb_opipe_hdr_decode(&hdr, (uint8_t *)da.rbuf, da.rsize) == -1)
		return (-1);

	if ((hdr.oh_magic != SMB_OPIPE_HDR_MAGIC) ||
	    (hdr.oh_fid != opipe->p_hdr.oh_fid) ||
	    (hdr.oh_op != opipe->p_hdr.oh_op) ||
	    (hdr.oh_status != 0) ||
	    (hdr.oh_datalen > SMB_OPIPE_DOOR_BUFSIZE)) {
		return (-1);
	}

	opipe->p_hdr.oh_datalen = hdr.oh_datalen;
	opipe->p_hdr.oh_resid = hdr.oh_resid;
	return (0);
}

void
smb_user_context_init(smb_user_t *user, smb_opipe_context_t *ctx)
{
	smb_session_t *session;

	ASSERT(user);
	ASSERT(user->u_domain);
	ASSERT(user->u_name);

	session = user->u_session;
	ASSERT(session);
	ASSERT(session->workstation);

	ctx->oc_session_id = session->s_kid;
	ctx->oc_native_os = session->native_os;
	ctx->oc_ipaddr = session->ipaddr;
	ctx->oc_uid = user->u_uid;
	ctx->oc_logon_time = user->u_logon_time;
	ctx->oc_flags = user->u_flags;

	ctx->oc_domain_len = user->u_domain_len;
	ctx->oc_domain = smb_kstrdup(user->u_domain, ctx->oc_domain_len);

	ctx->oc_account_len = user->u_name_len;
	ctx->oc_account = smb_kstrdup(user->u_name, ctx->oc_account_len);

	ctx->oc_workstation_len = strlen(session->workstation) + 1;
	ctx->oc_workstation = smb_kstrdup(session->workstation,
	    ctx->oc_workstation_len);
}

static void
smb_user_context_fini(smb_opipe_context_t *ctx)
{
	if (ctx) {
		if (ctx->oc_domain)
			kmem_free(ctx->oc_domain, ctx->oc_domain_len);
		if (ctx->oc_account)
			kmem_free(ctx->oc_account, ctx->oc_account_len);
		if (ctx->oc_workstation)
			kmem_free(ctx->oc_workstation, ctx->oc_workstation_len);
		bzero(ctx, sizeof (smb_opipe_context_t));
	}
}

void
smb_user_list_free(smb_dr_ulist_t *userlist)
{
	int i;

	if (userlist) {
		for (i = 0; i < userlist->dul_cnt; i++)
			smb_user_context_fini(&userlist->dul_users[i]);
	}
}
