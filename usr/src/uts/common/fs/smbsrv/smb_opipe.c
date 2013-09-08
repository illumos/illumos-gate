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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
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
	 * If we fail sending the netuserinfo or recv'ing the
	 * status reponse, we have probably run into the limit
	 * on the number of open pipes.  That's this status:
	 */
	errp->status = NT_STATUS_PIPE_NOT_AVAILABLE;

	rc = ksocket_send(opipe->p_socket, buf, buflen, 0,
	    &iocnt, sr->user_cr);
	if (rc == 0 && iocnt != buflen)
		rc = EIO;
	if (rc != 0)
		goto out;

	rc = ksocket_recv(opipe->p_socket, &status, sizeof (status), 0,
	    &iocnt, sr->user_cr);
	if (rc != 0 || iocnt != sizeof (status))
		goto out;

	/*
	 * Return the status we read from the pipe service,
	 * normally NT_STATUS_SUCCESS, but could be something
	 * else like NT_STATUS_ACCESS_DENIED.
	 */
	errp->status = status;

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
smb_opipe_open(smb_request_t *sr, uint32_t uniqid)
{
	smb_arg_open_t	*op = &sr->sr_open;
	smb_ofile_t *ofile;
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
	 * Note: If smb_ofile_open succeeds, the new ofile is
	 * in the FID lists can can be used by I/O requests.
	 */
	op->create_options = 0;
	op->pipe = opipe;
	ofile = smb_ofile_open(sr, NULL, op,
	    SMB_FTYPE_MESG_PIPE, uniqid, &err);
	op->pipe = NULL;
	if (ofile == NULL) {
		smb_opipe_dealloc(opipe);
		return (err.status);
	}

	/* An "up" pointer, for debug. */
	opipe->p_ofile = ofile;

	op->dsize = 0x01000;
	op->dattr = FILE_ATTRIBUTE_NORMAL;
	op->ftype = SMB_FTYPE_MESG_PIPE;
	op->action_taken = SMB_OACT_LOCK | SMB_OACT_OPENED; /* 0x8001 */
	op->devstate = SMB_PIPE_READMODE_MESSAGE
	    | SMB_PIPE_TYPE_MESSAGE
	    | SMB_PIPE_UNLIMITED_INSTANCES; /* 0x05ff */
	op->fileid = ofile->f_fid;

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

	bzero(&msghdr, sizeof (msghdr));
	msghdr.msg_iov = uio->uio_iov;
	msghdr.msg_iovlen = uio->uio_iovcnt;

	/*
	 * This should block only if there's no data.
	 * A single call to recvmsg does just that.
	 * (Intentionaly no recv loop here.)
	 */
	rc = ksocket_recvmsg(sock, &msghdr, 0,
	    &recvcnt, ofile->f_cr);
	if (rc != 0)
		goto out;

	if (recvcnt == 0) {
		/* Other side closed. */
		rc = EPIPE;
		goto out;
	}
	uio->uio_resid -= recvcnt;

	/*
	 * If we filled the user's buffer,
	 * find out if there's more data.
	 */
	if (uio->uio_resid == 0) {
		int rc2, nread, trval;
		rc2 = ksocket_ioctl(sock, FIONREAD, (intptr_t)&nread,
		    &trval, ofile->f_cr);
		if (rc2 == 0 && nread != 0)
			rc = E2BIG;	/* more data */
	}

out:
	ksocket_rele(sock);

	return (rc);
}
