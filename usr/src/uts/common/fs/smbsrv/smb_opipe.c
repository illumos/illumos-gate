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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This module provides the interface to NDR RPC.
 */

#include <sys/stat.h>
#include <sys/door.h>
#include <sys/door_data.h>
#include <sys/uio.h>
#include <sys/ksynch.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_xdr.h>

#define	SMB_OPIPE_ISOPEN(OPIPE)	\
	(((OPIPE)->p_hdr.dh_magic == SMB_OPIPE_HDR_MAGIC) && \
	((OPIPE)->p_hdr.dh_fid))

extern volatile uint32_t smb_fids;

static int smb_opipe_do_open(smb_request_t *, smb_opipe_t *);
static char *smb_opipe_lookup(const char *);
static int smb_opipe_sethdr(smb_opipe_t *, uint32_t, uint32_t);
static int smb_opipe_exec(smb_opipe_t *);
static void smb_opipe_enter(smb_opipe_t *);
static void smb_opipe_exit(smb_opipe_t *);

static int smb_opipe_door_call(smb_opipe_t *);
static int smb_opipe_door_upcall(smb_opipe_t *);

smb_opipe_t *
smb_opipe_alloc(smb_server_t *sv)
{
	smb_opipe_t	*opipe;

	opipe = kmem_cache_alloc(smb_cache_opipe, KM_SLEEP);

	bzero(opipe, sizeof (smb_opipe_t));
	mutex_init(&opipe->p_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&opipe->p_cv, NULL, CV_DEFAULT, NULL);
	opipe->p_magic = SMB_OPIPE_MAGIC;
	opipe->p_server = sv;

	smb_llist_enter(&sv->sv_opipe_list, RW_WRITER);
	smb_llist_insert_tail(&sv->sv_opipe_list, opipe);
	smb_llist_exit(&sv->sv_opipe_list);

	return (opipe);
}

void
smb_opipe_dealloc(smb_opipe_t *opipe)
{
	smb_server_t *sv;

	SMB_OPIPE_VALID(opipe);
	sv = opipe->p_server;
	SMB_SERVER_VALID(sv);

	smb_llist_enter(&sv->sv_opipe_list, RW_WRITER);
	smb_llist_remove(&sv->sv_opipe_list, opipe);
	smb_llist_exit(&sv->sv_opipe_list);

	opipe->p_magic = (uint32_t)~SMB_OPIPE_MAGIC;
	smb_event_destroy(opipe->p_event);
	cv_destroy(&opipe->p_cv);
	mutex_destroy(&opipe->p_mutex);

	kmem_cache_free(smb_cache_opipe, opipe);
}

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
	smb_arg_open_t	*op = &sr->sr_open;
	smb_ofile_t *of;
	smb_opipe_t *opipe;
	smb_doorhdr_t hdr;
	smb_error_t err;
	char *pipe_name;

	if ((pipe_name = smb_opipe_lookup(op->fqi.fq_path.pn_path)) == NULL)
		return (NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/*
	 * If printing is disabled, pretend spoolss does not exist.
	 */
	if (sr->sr_server->sv_cfg.skc_print_enable == 0 &&
	    strcmp(pipe_name, "SPOOLSS") == 0)
		return (NT_STATUS_OBJECT_NAME_NOT_FOUND);

	op->create_options = 0;

	of = smb_ofile_open(sr, NULL, sr->smb_pid, op, SMB_FTYPE_MESG_PIPE,
	    SMB_UNIQ_FID(), &err);

	if (of == NULL)
		return (err.status);

	if (!smb_tree_is_connected(sr->tid_tree)) {
		smb_ofile_close(of, 0);
		smb_ofile_release(of);
		return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	op->dsize = 0x01000;
	op->dattr = FILE_ATTRIBUTE_NORMAL;
	op->ftype = SMB_FTYPE_MESG_PIPE;
	op->action_taken = SMB_OACT_LOCK | SMB_OACT_OPENED; /* 0x8001 */
	op->devstate = SMB_PIPE_READMODE_MESSAGE
	    | SMB_PIPE_TYPE_MESSAGE
	    | SMB_PIPE_UNLIMITED_INSTANCES; /* 0x05ff */
	op->fileid = of->f_fid;

	sr->smb_fid = of->f_fid;
	sr->fid_ofile = of;

	opipe = of->f_pipe;
	smb_opipe_enter(opipe);

	opipe->p_server = of->f_server;
	opipe->p_name = pipe_name;
	opipe->p_doorbuf = kmem_zalloc(SMB_OPIPE_DOOR_BUFSIZE, KM_SLEEP);

	/*
	 * p_data points to the offset within p_doorbuf at which
	 * data will be written or read.
	 */
	opipe->p_data = opipe->p_doorbuf + xdr_sizeof(smb_doorhdr_xdr, &hdr);

	if (smb_opipe_do_open(sr, opipe) != 0) {
		/*
		 * On error, reset the header to clear the fid,
		 * which avoids confusion when smb_opipe_close() is
		 * called by smb_ofile_close().
		 */
		bzero(&opipe->p_hdr, sizeof (smb_doorhdr_t));
		kmem_free(opipe->p_doorbuf, SMB_OPIPE_DOOR_BUFSIZE);
		smb_opipe_exit(opipe);
		smb_ofile_close(of, 0);
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
 * Returns a pointer to the pipe name (without any leading \'s) on success.
 * Otherwise returns a null pointer.
 */
static char *
smb_opipe_lookup(const char *path)
{
	static char *named_pipes[] = {
		"lsass",
		"LSARPC",
		"NETLOGON",
		"SAMR",
		"SPOOLSS",
		"SRVSVC",
		"SVCCTL",
		"WINREG",
		"WKSSVC",
		"EVENTLOG",
		"NETDFS"
	};

	const char *name;
	int i;

	if (path == NULL)
		return (NULL);

	name = path;
	name += strspn(name, "\\");
	if (smb_strcasecmp(name, "PIPE", 4) == 0) {
		path += 4;
		name += strspn(name, "\\");
	}

	for (i = 0; i < sizeof (named_pipes) / sizeof (named_pipes[0]); ++i) {
		if (smb_strcasecmp(name, named_pipes[i], 0) == 0)
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
	smb_netuserinfo_t *userinfo = &opipe->p_user;
	smb_user_t *user = sr->uid_user;
	smb_server_t *sv = sr->sr_server;
	uint8_t *buf = opipe->p_doorbuf;
	uint32_t buflen = SMB_OPIPE_DOOR_BUFSIZE;
	uint32_t len;

	if ((opipe->p_event = smb_event_create(sv, SMB_EVENT_TIMEOUT)) == NULL)
		return (-1);

	smb_user_netinfo_init(user, userinfo);
	len = xdr_sizeof(smb_netuserinfo_xdr, userinfo);

	bzero(&opipe->p_hdr, sizeof (smb_doorhdr_t));
	opipe->p_hdr.dh_magic = SMB_OPIPE_HDR_MAGIC;
	opipe->p_hdr.dh_flags = SMB_DF_SYSSPACE;
	opipe->p_hdr.dh_fid = smb_event_txid(opipe->p_event);

	if (smb_opipe_sethdr(opipe, SMB_OPIPE_OPEN, len) == -1)
		return (-1);

	len = xdr_sizeof(smb_doorhdr_xdr, &opipe->p_hdr);
	buf += len;
	buflen -= len;

	if (smb_netuserinfo_encode(userinfo, buf, buflen, NULL) == -1)
		return (-1);

	return (smb_opipe_door_call(opipe));
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

	opipe = of->f_pipe;
	SMB_OPIPE_VALID(opipe);

	(void) smb_server_cancel_event(of->f_server, opipe->p_hdr.dh_fid);
	smb_opipe_enter(opipe);

	if (SMB_OPIPE_ISOPEN(opipe)) {
		(void) smb_opipe_sethdr(opipe, SMB_OPIPE_CLOSE, 0);
		(void) smb_opipe_door_call(opipe);
		bzero(&opipe->p_hdr, sizeof (smb_doorhdr_t));
		kmem_free(opipe->p_doorbuf, SMB_OPIPE_DOOR_BUFSIZE);
	}

	smb_user_netinfo_fini(&opipe->p_user);
	smb_opipe_exit(opipe);
}

static int
smb_opipe_sethdr(smb_opipe_t *opipe, uint32_t cmd, uint32_t datalen)
{
	opipe->p_hdr.dh_op = cmd;
	opipe->p_hdr.dh_txid = opipe->p_hdr.dh_fid;
	opipe->p_hdr.dh_datalen = datalen;
	opipe->p_hdr.dh_resid = 0;
	opipe->p_hdr.dh_door_rc = EINVAL;

	return (smb_doorhdr_encode(&opipe->p_hdr, opipe->p_doorbuf,
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

	opipe = sr->fid_ofile->f_pipe;

	if ((rc = smb_opipe_exec(opipe)) != 0) {
		smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
		    ERRDOS, ERROR_INTERNAL_ERROR);
		return (SDRC_ERROR);
	}

	xa = sr->r_xa;
	mdrcnt = xa->smb_mdrcnt;
	smb_opipe_enter(opipe);

	if (smb_opipe_sethdr(opipe, SMB_OPIPE_READ, mdrcnt) == -1) {
		smb_opipe_exit(opipe);
		smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
		    ERRDOS, ERROR_INTERNAL_ERROR);
		return (SDRC_ERROR);
	}

	rc = smb_opipe_door_call(opipe);
	nbytes = opipe->p_hdr.dh_datalen;

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

	if (opipe->p_hdr.dh_resid) {
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

	opipe = sr->fid_ofile->f_pipe;
	SMB_OPIPE_VALID(opipe);
	smb_opipe_enter(opipe);

	if (!SMB_OPIPE_ISOPEN(opipe)) {
		smb_opipe_exit(opipe);
		return (EBADF);
	}

	rc = smb_opipe_sethdr(opipe, SMB_OPIPE_WRITE, uio->uio_resid);
	len = xdr_sizeof(smb_doorhdr_xdr, &opipe->p_hdr);
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

	opipe = sr->fid_ofile->f_pipe;
	SMB_OPIPE_VALID(opipe);

	if ((rc = smb_opipe_exec(opipe)) != 0)
		return (EIO);

	smb_opipe_enter(opipe);

	if (!SMB_OPIPE_ISOPEN(opipe)) {
		smb_opipe_exit(opipe);
		return (EBADF);
	}

	if (smb_opipe_sethdr(opipe, SMB_OPIPE_READ, uio->uio_resid) == -1) {
		smb_opipe_exit(opipe);
		return (ENOMEM);
	}

	rc = smb_opipe_door_call(opipe);
	nbytes = opipe->p_hdr.dh_datalen;

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

static int
smb_opipe_exec(smb_opipe_t *opipe)
{
	uint32_t	len;
	int		rc;

	smb_opipe_enter(opipe);

	rc = smb_opipe_sethdr(opipe, SMB_OPIPE_EXEC, 0);
	len = xdr_sizeof(smb_doorhdr_xdr, &opipe->p_hdr);
	if (rc == -1 || len == 0) {
		smb_opipe_exit(opipe);
		return (ENOMEM);
	}

	if ((rc = smb_opipe_door_call(opipe)) == 0)
		rc = smb_event_wait(opipe->p_event);

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

/*
 * Exit busy state.  If we have exec'd an RPC, we may have
 * to wait for notification that processing has completed.
 */
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
smb_opipe_door_init(smb_server_t *sv)
{
	sv->sv_opipe_door_id = -1;
	mutex_init(&sv->sv_opipe_door_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sv->sv_opipe_door_cv, NULL, CV_DEFAULT, NULL);
}

void
smb_opipe_door_fini(smb_server_t *sv)
{
	smb_opipe_door_close(sv);
	cv_destroy(&sv->sv_opipe_door_cv);
	mutex_destroy(&sv->sv_opipe_door_mutex);
}

/*
 * Open the (user space) door.  If the door is already open,
 * close it first because the door-id has probably changed.
 */
int
smb_opipe_door_open(smb_server_t *sv, int door_id)
{
	smb_opipe_door_close(sv);

	mutex_enter(&sv->sv_opipe_door_mutex);
	sv->sv_opipe_door_ncall = 0;

	if (sv->sv_opipe_door_hd == NULL) {
		sv->sv_opipe_door_id = door_id;
		sv->sv_opipe_door_hd = door_ki_lookup(door_id);
	}

	mutex_exit(&sv->sv_opipe_door_mutex);
	return ((sv->sv_opipe_door_hd == NULL)  ? -1 : 0);
}

/*
 * Close the (user space) door.
 */
void
smb_opipe_door_close(smb_server_t *sv)
{
	mutex_enter(&sv->sv_opipe_door_mutex);

	if (sv->sv_opipe_door_hd != NULL) {
		while (sv->sv_opipe_door_ncall > 0)
			cv_wait(&sv->sv_opipe_door_cv,
			    &sv->sv_opipe_door_mutex);

		door_ki_rele(sv->sv_opipe_door_hd);
		sv->sv_opipe_door_hd = NULL;
	}

	mutex_exit(&sv->sv_opipe_door_mutex);
}

/*
 * opipe door call interface.
 * Door serialization and call reference accounting is handled here.
 */
static int
smb_opipe_door_call(smb_opipe_t *opipe)
{
	int rc;
	smb_server_t *sv = opipe->p_server;

	mutex_enter(&sv->sv_opipe_door_mutex);

	if (sv->sv_opipe_door_hd == NULL) {
		mutex_exit(&sv->sv_opipe_door_mutex);

		if (smb_opipe_door_open(sv, sv->sv_opipe_door_id) != 0)
			return (-1);

		mutex_enter(&sv->sv_opipe_door_mutex);
	}

	sv->sv_opipe_door_ncall++;
	mutex_exit(&sv->sv_opipe_door_mutex);

	rc = smb_opipe_door_upcall(opipe);

	mutex_enter(&sv->sv_opipe_door_mutex);
	if ((--sv->sv_opipe_door_ncall) == 0)
		cv_signal(&sv->sv_opipe_door_cv);
	mutex_exit(&sv->sv_opipe_door_mutex);
	return (rc);
}

/*
 * Door upcall wrapper - handles data marshalling.
 * This function should only be called by smb_opipe_door_call.
 */
static int
smb_opipe_door_upcall(smb_opipe_t *opipe)
{
	smb_server_t *sv = opipe->p_server;
	door_arg_t da;
	smb_doorhdr_t hdr;
	int i;
	int rc;

	da.data_ptr = (char *)opipe->p_doorbuf;
	da.data_size = SMB_OPIPE_DOOR_BUFSIZE;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)opipe->p_doorbuf;
	da.rsize = SMB_OPIPE_DOOR_BUFSIZE;

	for (i = 0; i < 3; ++i) {
		if (smb_server_is_stopping(sv))
			return (-1);

		if ((rc = door_ki_upcall_limited(sv->sv_opipe_door_hd,
		    &da, NULL, SIZE_MAX, 0)) == 0)
			break;

		if (rc != EAGAIN && rc != EINTR)
			return (-1);
	}

	/* Check for door_return(NULL, 0, NULL, 0) */
	if (rc != 0 || da.data_size == 0 || da.rsize == 0)
		return (-1);

	if (smb_doorhdr_decode(&hdr, (uint8_t *)da.data_ptr, da.rsize) == -1)
		return (-1);

	if ((hdr.dh_magic != SMB_OPIPE_HDR_MAGIC) ||
	    (hdr.dh_fid != opipe->p_hdr.dh_fid) ||
	    (hdr.dh_op != opipe->p_hdr.dh_op) ||
	    (hdr.dh_door_rc != 0) ||
	    (hdr.dh_datalen > SMB_OPIPE_DOOR_BUFSIZE)) {
		return (-1);
	}

	opipe->p_hdr.dh_datalen = hdr.dh_datalen;
	opipe->p_hdr.dh_resid = hdr.dh_resid;
	return (0);
}
