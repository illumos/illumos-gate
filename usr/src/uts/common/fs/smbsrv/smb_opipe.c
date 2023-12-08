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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011-2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */

/*
 * This module provides the interface to NDR RPC.
 */

#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ksynch.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/filio.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_xdr.h>
#include <smb/winioctl.h>

static uint32_t smb_opipe_wait(smb_request_t *, smb_fsctl_t *);

/*
 * Allocate a new opipe and return it, or NULL, in which case
 * the caller will report "internal error".
 */
static smb_opipe_t *
smb_opipe_alloc(smb_request_t *sr)
{
	smb_server_t	*sv = sr->sr_server;
	smb_opipe_t	*opipe;
	ksocket_t	sock;

	if (ksocket_socket(&sock, AF_UNIX, SOCK_STREAM, 0,
	    KSOCKET_SLEEP, sr->user_cr) != 0)
		return (NULL);

	opipe = kmem_cache_alloc(smb_cache_opipe, KM_SLEEP);

	bzero(opipe, sizeof (smb_opipe_t));
	mutex_init(&opipe->p_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&opipe->p_cv, NULL, CV_DEFAULT, NULL);
	opipe->p_magic = SMB_OPIPE_MAGIC;
	opipe->p_server = sv;
	opipe->p_refcnt = 1;
	opipe->p_socket = sock;

	return (opipe);
}

/*
 * Destroy an opipe.  This is normally called from smb_ofile_delete
 * when the ofile has no more references and is about to be free'd.
 * This is also called here in error handling code paths, before
 * the opipe is installed under an ofile.
 */
void
smb_opipe_dealloc(smb_opipe_t *opipe)
{
	smb_server_t *sv;

	SMB_OPIPE_VALID(opipe);
	sv = opipe->p_server;
	SMB_SERVER_VALID(sv);

	/*
	 * This is called in the error path when opening,
	 * in which case we close the socket here.
	 */
	if (opipe->p_socket != NULL)
		(void) ksocket_close(opipe->p_socket, zone_kcred());

	opipe->p_magic = (uint32_t)~SMB_OPIPE_MAGIC;
	cv_destroy(&opipe->p_cv);
	mutex_destroy(&opipe->p_mutex);

	kmem_cache_free(smb_cache_opipe, opipe);
}

/*
 * Unblock a request that might be blocked reading some
 * pipe (AF_UNIX socket).  We don't have an easy way to
 * interrupt just the thread servicing this request, so
 * we shutdown(3socket) the socket, waking all readers.
 * That's a bit heavy-handed, making the socket unusable
 * after this, so we do this only when disconnecting a
 * session (i.e. stopping the SMB service), and not when
 * handling an SMB2_cancel or SMB_nt_cancel request.
 */
static void
smb_opipe_cancel(smb_request_t *sr)
{
	ksocket_t so;

	switch (sr->session->s_state) {
	case SMB_SESSION_STATE_DISCONNECTED:
	case SMB_SESSION_STATE_TERMINATED:
		if ((so = sr->cancel_arg2) != NULL)
			(void) ksocket_shutdown(so, SHUT_RDWR, sr->user_cr);
		break;
	}
}

/*
 * Helper for open: build pipe name and connect.
 */
static int
smb_opipe_connect(smb_request_t *sr, smb_opipe_t *opipe)
{
	struct sockaddr_un saddr;
	smb_arg_open_t	*op = &sr->sr_open;
	const char *name;
	int rc;

	name = op->fqi.fq_path.pn_path;
	name += strspn(name, "\\");
	if (smb_strcasecmp(name, "PIPE", 4) == 0) {
		name += 4;
		name += strspn(name, "\\");
	}
	(void) strlcpy(opipe->p_name, name, SMB_OPIPE_MAXNAME);
	(void) smb_strlwr(opipe->p_name);

	bzero(&saddr, sizeof (saddr));
	saddr.sun_family = AF_UNIX;
	(void) snprintf(saddr.sun_path, sizeof (saddr.sun_path),
	    "%s/%s", SMB_PIPE_DIR, opipe->p_name);
	rc = ksocket_connect(opipe->p_socket, (struct sockaddr *)&saddr,
	    sizeof (saddr), sr->user_cr);

	return (rc);
}

static int
smb_opipe_exists(char *name)
{
	struct sockaddr_un saddr;
	vnode_t		*vp;	/* Underlying filesystem vnode */
	int err;

	bzero(&saddr, sizeof (saddr));
	saddr.sun_family = AF_UNIX;
	(void) snprintf(saddr.sun_path, sizeof (saddr.sun_path),
	    "%s/%s", SMB_PIPE_DIR, name);

	err = lookupname(saddr.sun_path, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
	if (err == 0) {
		VN_RELE(vp);		/* release hold from lookup */
	}

	return (err);
}


/*
 * Helper for open: encode and send the user info.
 *
 * We send information about this client + user to the
 * pipe service so it can use it for access checks.
 * The service MAY deny the open based on this info,
 * (i.e. anonymous session trying to open a pipe that
 * requires authentication) in which case we will read
 * an error status from the service and return that.
 */
static void
smb_opipe_send_userinfo(smb_request_t *sr, smb_opipe_t *opipe,
    smb_error_t *errp)
{
	XDR xdrs;
	smb_netuserinfo_t nui;
	smb_pipehdr_t phdr;
	char *buf;
	uint32_t buflen;
	uint32_t status;
	size_t iocnt = 0;
	int rc;

	/*
	 * Any errors building the XDR message etc.
	 */
	errp->status = NT_STATUS_INTERNAL_ERROR;

	smb_user_netinfo_init(sr->uid_user, &nui);
	phdr.ph_magic = SMB_PIPE_HDR_MAGIC;
	phdr.ph_uilen = xdr_sizeof(smb_netuserinfo_xdr, &nui);

	buflen = sizeof (phdr) + phdr.ph_uilen;
	buf = kmem_alloc(buflen, KM_SLEEP);

	bcopy(&phdr, buf, sizeof (phdr));
	xdrmem_create(&xdrs, buf + sizeof (phdr),
	    buflen - (sizeof (phdr)), XDR_ENCODE);
	if (!smb_netuserinfo_xdr(&xdrs, &nui))
		goto out;

	/*
	 * Prepare for cancellable send/recv.
	 */
	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state != SMB_REQ_STATE_ACTIVE) {
		mutex_exit(&sr->sr_mutex);
		errp->status = NT_STATUS_CANCELLED;
		goto out;
	}
	sr->sr_state = SMB_REQ_STATE_WAITING_PIPE;
	sr->cancel_method = smb_opipe_cancel;
	sr->cancel_arg2 = opipe->p_socket;
	mutex_exit(&sr->sr_mutex);

	rc = ksocket_send(opipe->p_socket, buf, buflen, 0,
	    &iocnt, sr->user_cr);
	if (rc == 0 && iocnt != buflen)
		rc = EIO;
	if (rc == 0)
		rc = ksocket_recv(opipe->p_socket, &status, sizeof (status),
		    0, &iocnt, sr->user_cr);
	if (rc == 0 && iocnt != sizeof (status))
		rc = EIO;

	/*
	 * Did the send/recv. complete or was it cancelled?
	 */
	mutex_enter(&sr->sr_mutex);
switch_state:
	switch (sr->sr_state) {
	case SMB_REQ_STATE_WAITING_PIPE:
		/* Normal wakeup.  Keep rc from above. */
		sr->sr_state = SMB_REQ_STATE_ACTIVE;
		break;
	case SMB_REQ_STATE_CANCEL_PENDING:
		/* cancel_method running. wait. */
		cv_wait(&sr->sr_st_cv, &sr->sr_mutex);
		goto switch_state;
	case SMB_REQ_STATE_CANCELLED:
		rc = EINTR;
		break;
	default:
		/* keep rc from above */
		break;
	}
	sr->cancel_method = NULL;
	sr->cancel_arg2 = NULL;
	mutex_exit(&sr->sr_mutex);

	/*
	 * Return the status we read from the pipe service,
	 * normally NT_STATUS_SUCCESS, but could be something
	 * else like NT_STATUS_ACCESS_DENIED.
	 */
	switch (rc) {
	case 0:
		errp->status = status;
		break;
	case EINTR:
		errp->status = NT_STATUS_CANCELLED;
		break;
	/*
	 * If we fail sending the netuserinfo or recv'ing the
	 * status reponse, we have probably run into the limit
	 * on the number of open pipes.  That's this status:
	 */
	default:
		errp->status = NT_STATUS_PIPE_NOT_AVAILABLE;
		break;
	}

out:
	xdr_destroy(&xdrs);
	kmem_free(buf, buflen);
	smb_user_netinfo_fini(&nui);
}

/*
 * smb_opipe_open
 *
 * Open an RPC named pipe. This routine should be called if
 * a file open is requested on a share of type STYPE_IPC.
 * If we recognize the pipe, we setup a new ofile.
 *
 * Returns 0 on success, Otherwise an NT status code.
 */
int
smb_opipe_open(smb_request_t *sr, smb_ofile_t *ofile)
{
	smb_arg_open_t	*op = &sr->sr_open;
	smb_attr_t *ap = &op->fqi.fq_fattr;
	smb_opipe_t *opipe;
	smb_error_t err;

	opipe = smb_opipe_alloc(sr);
	if (opipe == NULL)
		return (NT_STATUS_INTERNAL_ERROR);

	if (smb_opipe_connect(sr, opipe) != 0) {
		smb_opipe_dealloc(opipe);
		return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	smb_opipe_send_userinfo(sr, opipe, &err);
	if (err.status != 0) {
		smb_opipe_dealloc(opipe);
		return (err.status);
	}

	/*
	 * We might have blocked in smb_opipe_connect long enough so
	 * a tree disconnect might have happened.  In that case, we
	 * would be adding an ofile to a tree that's disconnecting,
	 * which would interfere with tear-down.
	 */
	if (!smb_tree_is_connected(sr->tid_tree)) {
		smb_opipe_dealloc(opipe);
		return (NT_STATUS_NETWORK_NAME_DELETED);
	}

	/*
	 * Note: The new opipe is given to smb_ofile_open
	 * via op->pipe
	 */
	op->pipe = opipe;
	smb_ofile_open(sr, op, ofile);
	op->pipe = NULL;

	/* An "up" pointer, for debug. */
	opipe->p_ofile = ofile;

	/*
	 * Caller expects attributes in op->fqi
	 */
	(void) smb_opipe_getattr(ofile, &op->fqi.fq_fattr);

	op->dsize = 0;
	op->dattr = ap->sa_dosattr;
	op->fileid = ap->sa_vattr.va_nodeid;
	op->ftype = SMB_FTYPE_MESG_PIPE;
	op->action_taken = SMB_OACT_OPLOCK | SMB_OACT_OPENED;
	op->devstate = SMB_PIPE_READMODE_MESSAGE
	    | SMB_PIPE_TYPE_MESSAGE
	    | SMB_PIPE_UNLIMITED_INSTANCES; /* 0x05ff */

	sr->smb_fid = ofile->f_fid;
	sr->fid_ofile = ofile;

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_opipe_close
 *
 * Called by smb_ofile_close for pipes.
 *
 * Note: ksocket_close may block while waiting for
 * any I/O threads with a hold to get out.
 */
void
smb_opipe_close(smb_ofile_t *of)
{
	smb_opipe_t *opipe;
	ksocket_t sock;

	ASSERT(of->f_state == SMB_OFILE_STATE_CLOSING);
	ASSERT(of->f_ftype == SMB_FTYPE_MESG_PIPE);
	opipe = of->f_pipe;
	SMB_OPIPE_VALID(opipe);

	mutex_enter(&opipe->p_mutex);
	sock = opipe->p_socket;
	opipe->p_socket = NULL;
	mutex_exit(&opipe->p_mutex);

	(void) ksocket_shutdown(sock, SHUT_RDWR, of->f_cr);
	(void) ksocket_close(sock, of->f_cr);
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
	struct nmsghdr msghdr;
	smb_ofile_t *ofile;
	smb_opipe_t *opipe;
	ksocket_t sock;
	size_t sent = 0;
	int rc = 0;

	ofile = sr->fid_ofile;
	ASSERT(ofile->f_ftype == SMB_FTYPE_MESG_PIPE);
	opipe = ofile->f_pipe;
	SMB_OPIPE_VALID(opipe);

	mutex_enter(&opipe->p_mutex);
	sock = opipe->p_socket;
	if (sock != NULL)
		ksocket_hold(sock);
	mutex_exit(&opipe->p_mutex);
	if (sock == NULL)
		return (EBADF);

	bzero(&msghdr, sizeof (msghdr));
	msghdr.msg_iov = uio->uio_iov;
	msghdr.msg_iovlen = uio->uio_iovcnt;

	/*
	 * This should block until we've sent it all,
	 * or given up due to errors (pipe closed).
	 */
	while (uio->uio_resid > 0) {
		rc = ksocket_sendmsg(sock, &msghdr, 0, &sent, ofile->f_cr);
		if (rc != 0)
			break;
		uio->uio_resid -= sent;
	}

	ksocket_rele(sock);

	return (rc);
}

/*
 * smb_opipe_read
 *
 * This interface may be called from smb_opipe_transact (write, read)
 * or from smb_read / smb2_read to get the rest of an RPC response.
 * The response data (and length) are returned via the uio.
 */
int
smb_opipe_read(smb_request_t *sr, struct uio *uio)
{
	struct nmsghdr msghdr;
	smb_ofile_t *ofile;
	smb_opipe_t *opipe;
	ksocket_t sock;
	size_t recvcnt = 0;
	int rc;

	ofile = sr->fid_ofile;
	ASSERT(ofile->f_ftype == SMB_FTYPE_MESG_PIPE);
	opipe = ofile->f_pipe;
	SMB_OPIPE_VALID(opipe);

	mutex_enter(&opipe->p_mutex);
	sock = opipe->p_socket;
	if (sock != NULL)
		ksocket_hold(sock);
	mutex_exit(&opipe->p_mutex);
	if (sock == NULL)
		return (EBADF);

	/*
	 * Prepare for cancellable recvmsg.
	 */
	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state != SMB_REQ_STATE_ACTIVE) {
		mutex_exit(&sr->sr_mutex);
		rc = EINTR;
		goto out;
	}
	sr->sr_state = SMB_REQ_STATE_WAITING_PIPE;
	sr->cancel_method = smb_opipe_cancel;
	sr->cancel_arg2 = sock;
	mutex_exit(&sr->sr_mutex);

	/*
	 * This should block only if there's no data.
	 * A single call to recvmsg does just that.
	 * (Intentionaly no recv loop here.)
	 */
	bzero(&msghdr, sizeof (msghdr));
	msghdr.msg_iov = uio->uio_iov;
	msghdr.msg_iovlen = uio->uio_iovcnt;
	rc = ksocket_recvmsg(sock, &msghdr, 0,
	    &recvcnt, ofile->f_cr);

	/*
	 * Did the recvmsg complete or was it cancelled?
	 */
	mutex_enter(&sr->sr_mutex);
switch_state:
	switch (sr->sr_state) {
	case SMB_REQ_STATE_WAITING_PIPE:
		/* Normal wakeup.  Keep rc from above. */
		sr->sr_state = SMB_REQ_STATE_ACTIVE;
		break;
	case SMB_REQ_STATE_CANCEL_PENDING:
		/* cancel_method running. wait. */
		cv_wait(&sr->sr_st_cv, &sr->sr_mutex);
		goto switch_state;
	case SMB_REQ_STATE_CANCELLED:
		rc = EINTR;
		break;
	default:
		/* keep rc from above */
		break;
	}
	sr->cancel_method = NULL;
	sr->cancel_arg2 = NULL;
	mutex_exit(&sr->sr_mutex);

	if (rc != 0)
		goto out;

	if (recvcnt == 0) {
		/* Other side closed. */
		rc = EPIPE;
		goto out;
	}
	uio->uio_resid -= recvcnt;

out:
	ksocket_rele(sock);

	return (rc);
}

int
smb_opipe_ioctl(smb_request_t *sr, int cmd, void *arg, int *rvalp)
{
	smb_ofile_t *ofile;
	smb_opipe_t *opipe;
	ksocket_t sock;
	int rc;

	ofile = sr->fid_ofile;
	ASSERT(ofile->f_ftype == SMB_FTYPE_MESG_PIPE);
	opipe = ofile->f_pipe;
	SMB_OPIPE_VALID(opipe);

	mutex_enter(&opipe->p_mutex);
	sock = opipe->p_socket;
	if (sock != NULL)
		ksocket_hold(sock);
	mutex_exit(&opipe->p_mutex);
	if (sock == NULL)
		return (EBADF);

	rc = ksocket_ioctl(sock, cmd, (intptr_t)arg, rvalp, ofile->f_cr);

	ksocket_rele(sock);

	return (rc);
}

/*
 * Get the smb_attr_t for a named pipe.
 * Caller has already cleared to zero.
 */
int
smb_opipe_getattr(smb_ofile_t *of, smb_attr_t *ap)
{

	if (of->f_pipe == NULL)
		return (EINVAL);

	ap->sa_vattr.va_type = VFIFO;
	ap->sa_vattr.va_nlink = 1;
	ap->sa_vattr.va_nodeid = (uintptr_t)of->f_pipe;
	ap->sa_dosattr = FILE_ATTRIBUTE_NORMAL;
	ap->sa_allocsz = SMB_PIPE_MAX_MSGSIZE;

	return (0);
}

int
smb_opipe_getname(smb_ofile_t *of, char *buf, size_t buflen)
{
	smb_opipe_t *opipe;

	if ((opipe = of->f_pipe) == NULL)
		return (EINVAL);

	(void) snprintf(buf, buflen, "\\%s", opipe->p_name);
	return (0);
}

/*
 * Handle device type FILE_DEVICE_NAMED_PIPE
 * for smb2_ioctl
 */
/* ARGSUSED */
uint32_t
smb_opipe_fsctl(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	uint32_t status;

	if (!STYPE_ISIPC(sr->tid_tree->t_res_type))
		return (NT_STATUS_INVALID_DEVICE_REQUEST);

	switch (fsctl->CtlCode) {
	case FSCTL_PIPE_TRANSCEIVE:
		status = smb_opipe_transceive(sr, fsctl);
		break;

	case FSCTL_PIPE_PEEK:
		status = NT_STATUS_INVALID_DEVICE_REQUEST;
		break;

	case FSCTL_PIPE_WAIT:
		status = smb_opipe_wait(sr, fsctl);
		break;

	default:
		ASSERT(!"CtlCode");
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}

	return (status);
}

uint32_t
smb_opipe_transceive(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	smb_vdb_t	*vdb;
	smb_ofile_t	*ofile;
	struct mbuf	*mb;
	uint32_t	status;
	int		len, rc;

	/*
	 * Caller checked that this is the IPC$ share,
	 * and that this call has a valid open handle.
	 * Just check the type.
	 */
	ofile = sr->fid_ofile;
	if (ofile->f_ftype != SMB_FTYPE_MESG_PIPE)
		return (NT_STATUS_INVALID_HANDLE);

	/*
	 * The VDB is a bit large.  Allocate.
	 * This is automatically free'd with the SR
	 */
	vdb = smb_srm_zalloc(sr, sizeof (*vdb));
	rc = smb_mbc_decodef(fsctl->in_mbc, "#B",
	    fsctl->InputCount, vdb);
	if (rc != 0) {
		/* Not enough data sent. */
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rc = smb_opipe_write(sr, &vdb->vdb_uio);
	if (rc != 0)
		return (smb_errno2status(rc));

	vdb->vdb_tag = 0;
	vdb->vdb_uio.uio_iov = &vdb->vdb_iovec[0];
	vdb->vdb_uio.uio_iovcnt = MAX_IOVEC;
	vdb->vdb_uio.uio_segflg = UIO_SYSSPACE;
	vdb->vdb_uio.uio_extflg = UIO_COPY_DEFAULT;
	vdb->vdb_uio.uio_loffset = (offset_t)0;
	vdb->vdb_uio.uio_resid = fsctl->MaxOutputResp;
	mb = smb_mbuf_allocate(&vdb->vdb_uio);

	rc = smb_opipe_read(sr, &vdb->vdb_uio);
	if (rc != 0) {
		m_freem(mb);
		return (smb_errno2status(rc));
	}

	len = fsctl->MaxOutputResp - vdb->vdb_uio.uio_resid;
	smb_mbuf_trim(mb, len);
	MBC_ATTACH_MBUF(fsctl->out_mbc, mb);

	/*
	 * If the output buffer holds a partial pipe message,
	 * we're supposed to return NT_STATUS_BUFFER_OVERFLOW.
	 * As we don't have message boundary markers, the best
	 * we can do is return that status when we have ALL of:
	 *	Output buffer was < SMB_PIPE_MAX_MSGSIZE
	 *	We filled the output buffer (resid==0)
	 *	There's more data (ioctl FIONREAD)
	 */
	status = NT_STATUS_SUCCESS;
	if (fsctl->MaxOutputResp < SMB_PIPE_MAX_MSGSIZE &&
	    vdb->vdb_uio.uio_resid == 0) {
		int nread = 0, trval;
		rc = smb_opipe_ioctl(sr, FIONREAD, &nread, &trval);
		if (rc == 0 && nread != 0)
			status = NT_STATUS_BUFFER_OVERFLOW;
	}

	return (status);
}

static uint32_t
smb_opipe_wait(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	char		*name;
	uint64_t	timeout;
	uint32_t	namelen;
	int		rc;
	uint8_t		tflag;

	rc = smb_mbc_decodef(fsctl->in_mbc, "qlb.",
	    &timeout,	/* q */
	    &namelen,	/* l */
	    &tflag);	/* b */
	if (rc != 0)
		return (NT_STATUS_INVALID_PARAMETER);
	rc = smb_mbc_decodef(fsctl->in_mbc, "%#U",
	    sr,		/* % */
	    namelen,	/* # */
	    &name);	/* U */
	if (rc != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	rc = smb_opipe_exists(name);
	if (rc != 0)
		return (NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/*
	 * At this point we know the pipe exists.
	 *
	 * If the tflag is set, we're supposed to wait for up to
	 * timeout (100s of milliseconds) for a pipe "instance"
	 * to become "available" (so pipe open would work).
	 * However, this implementation has no need to wait,
	 * so just take a short delay instead.
	 */
	if (tflag != 0) {
		clock_t ticks = MSEC_TO_TICK(timeout * 100);
		if (ticks > MSEC_TO_TICK(100))
			ticks = MSEC_TO_TICK(100);
		delay(ticks);
	}

	return (0);
}
