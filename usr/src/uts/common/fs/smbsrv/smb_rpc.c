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
 * This module provides a set of wrapper functions to interface to the
 * RPC layer. Although this interface was originally implemented as a
 * single transaction using an input buffer and an output buffer, it
 * turns out that it really should have been a stream/pipe interface.
 * This was first discovered when we noticed that Windows2000 was using
 * smb_rpc_write and smb_rpc_read instead of smb_rpc_transact and then
 * later when we tried to return a larger number of shares than would
 * fit in a single transaction buffer.
 *
 * The interface is still limited by the buffers passed between this
 * module and the RPC module but now it will support a buffer overflow
 * and allow the client to read the remaining data on subsequent
 * requests. Also note that the smb_rpc_write and smb_rpc_read calls
 * are basically emulating the smb_rpc_transact function.
 */

#include <sys/ksynch.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/mlsvc.h>


extern volatile uint32_t smb_fids;

/*
 * This is the list of well-known RPC named pipes that we support.
 * The full pipe path will be in the form \\PIPE\\SERVICE. The first
 * part can be assumed, so all we need here are the service names.
 */
static char *rpc_named_pipes[] = {
	"\\LSARPC",
	"\\NETLOGON",
	"\\SAMR",
	"\\SPOOLSS",
	"\\SRVSVC",
	"\\SVCCTL",
	"\\WINREG",
	"\\WKSSVC",
	"\\EVENTLOG"
};


/*
 * This is a list of the port addresses for the named pipes above.
 * We need to check that these are correct but nothing appears to
 * rely on them so this is low priority.
 */
#if 0
static char *rpc_np_ports[] = {
	"\\PIPE\\",
	"\\PIPE\\lsass",
	"\\PIPE\\lsass",
	"\\PIPE\\spoolss",
	"\\PIPE\\ntsvcs",
	"\\PIPE\\ntsvcs",
	"\\PIPE\\winreg",
	"\\PIPE\\ntsvcs",
	"\\PIPE\\ntsvcs"
};
#endif


static int smb_rpc_initialize(struct smb_request *sr, char *pipe_name);
static uint32_t smb_rpc_fid(void);


/*
 * Named pipe I/O is serialized to ensure that each request has exclusive
 * access to the in and out pipe data for the duration of the request.
 */
static void
smb_rpc_enter(mlsvc_pipe_t *pi)
{
	mutex_enter(&pi->mutex);

	while (pi->busy)
		cv_wait(&pi->cv, &pi->mutex);

	pi->busy = 1;
	mutex_exit(&pi->mutex);
}

static void
smb_rpc_exit(mlsvc_pipe_t *pi)
{
	mutex_enter(&pi->mutex);
	pi->busy = 0;
	cv_signal(&pi->cv);
	mutex_exit(&pi->mutex);
}

/*
 * smb_rpc_lookup
 *
 * Lookup a path to see if it's a well-known RPC named pipe.
 *
 * Returns a pointer to the pipe name (without any leading \'s) if the path
 * refers to a well-known RPC named pipe. Otherwise returns a null pointer.
 */
char *
smb_rpc_lookup(char *path)
{
	int i;
	char *pipe_name;

	if (path == 0) {
		cmn_err(CE_WARN, "smb_rpc_lookup: invalid parameter");
		return (0);
	}

	/*
	 * Skip past the static part of the pipe
	 * name if it appears in the path.
	 */
	if (utf8_strncasecmp(path, "\\PIPE\\", 6) == 0)
		path += 5;

	for (i = 0;
	    i < sizeof (rpc_named_pipes) / sizeof (rpc_named_pipes[0]);
	    ++i) {
		if (utf8_strcasecmp(path, rpc_named_pipes[i]) == 0) {
			pipe_name = rpc_named_pipes[i];
			pipe_name += strspn(pipe_name, "\\");

			return (pipe_name);
		}
	}
	return (0);
}

/*
 * smb_rpc_open
 *
 * Open a well-known RPC named pipe. This routine should be called if
 * a file open is requested on a share of type STYPE_IPC. If we
 * recognize the pipe, we initialize the session data. This will setup
 * a new ofile and insert it into the session file list.
 *
 * Returns 0 on success, Otherwise an NT status is returned to indicate
 * an error.
 */
int
smb_rpc_open(struct smb_request *sr)
{
	struct open_param *op;
	char *pipe_name;
	int status;

	op = &sr->arg.open;

	if ((pipe_name = smb_rpc_lookup(op->fqi.path)) != 0) {
		if ((status = smb_rpc_initialize(sr, pipe_name)) != 0)
			return (status);

		return (NT_STATUS_SUCCESS);
	}

	return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
}


/*
 * smb_rpc_initialize
 *
 * Initialize various parts of the session data for a named pipe: open
 * parameters and the ofile. There are a number of magic numbers in
 * here that we need to identify but largely these values are ignored
 * by the rest of the code. Insert the ofile into the session file list.
 *
 * Returns 0 on success, Otherwise an NT status is returned to indicate
 * an error.
 */
static int
smb_rpc_initialize(struct smb_request *sr, char *pipe_name)
{
	struct open_param *op;
	struct smb_ofile *of;
	smb_error_t err;

	op = &sr->arg.open;
	of = smb_ofile_open(sr->tid_tree, NULL, sr->smb_pid,
	    op->desired_access, 0, op->share_access,
	    SMB_FTYPE_MESG_PIPE, pipe_name, smb_rpc_fid(),
	    SMB_UNIQ_FID(), &err);
	if (of == NULL)
		return (err.status);

	op->dsize = 0x01000;
	op->dattr = SMB_FA_NORMAL;
	op->ftype = SMB_FTYPE_MESG_PIPE;
	op->action_taken = SMB_OACT_LOCK | SMB_OACT_OPENED; /* 0x8001 */
	op->devstate = SMB_PIPE_READMODE_MESSAGE
	    | SMB_PIPE_TYPE_MESSAGE
	    | SMB_PIPE_UNLIMITED_INSTANCES; /* 0x05ff */
	op->fileid = of->f_fid;
	op->create_options = 0;

	sr->smb_fid = of->f_fid;
	sr->fid_ofile = of;
	return (0);
}

/*
 * smb_rpc_transact
 *
 * This is the entry point for RPC transactions to provide a wrapper for
 * the RPC layer. The SMB decoding and encoding is handled here so that
 * the RPC layer doesn't have to deal with it. Both bind operations and
 * RPC requests are handled here. The connection_fid is an arbitrary id
 * used to associate RPC requests with a particular binding handle.
 *
 * The RPC library expects the input stream to contain the request data.
 * It will build the output stream.
 *
 * If the data to be returned is larger than the client expects, we
 * return as much as the client can handle and report a buffer overflow
 * warning to inform the client that we have more data to return. The
 * residual data remains in the output stream until the client claims
 * it or closes the pipe.
 */
smb_sdrc_t
smb_rpc_transact(struct smb_request *sr, struct uio *uio)
{
	struct smb_xa *xa;
	mlsvc_pipe_t *pipe_info;
	mlsvc_stream_t *streamin;
	struct mbuf *mhead;
	int mdrcnt;
	int nbytes;
	int rc;
	boolean_t more_data;

	ASSERT(sr->fid_ofile);
	ASSERT(sr->fid_ofile->f_ftype == SMB_FTYPE_MESG_PIPE);
	ASSERT(sr->fid_ofile->f_pipe_info != NULL);

	xa = sr->r_xa;
	mdrcnt = xa->smb_mdrcnt;
	pipe_info = sr->fid_ofile->f_pipe_info;

	smb_rpc_enter(pipe_info);

	if (pipe_info->fid == 0) {
		smb_rpc_exit(pipe_info);
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERROR_INVALID_HANDLE);
		return (SDRC_ERROR);
	}

	streamin = &pipe_info->input;
	streamin->uio.uio_iov = uio->uio_iov;
	streamin->uio.uio_iovcnt = uio->uio_iovcnt;
	streamin->uio.uio_loffset = 0;
	streamin->uio.uio_resid = uio->uio_resid;
	streamin->uio.uio_segflg = UIO_SYSSPACE;

	nbytes = mdrcnt;

	rc = smb_winpipe_call(sr, pipe_info, streamin, SMB_RPC_TRANSACT,
	    (uint32_t *)&nbytes, &more_data);

	if (rc != 0) {
		smb_rpc_exit(pipe_info);
		smbsr_error(sr, NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID,
		    0, 0);
		return (SDRC_ERROR);
	}

	/*
	 * We need to zero the input stream so that we don't try to
	 * flush it on close: the mbuf chain belongs to the SMB XA.
	 * Then reassign the stream to refer to the output/response.
	 */
	if (more_data == B_TRUE) {
		/*
		 * We have more data to return than the client expects in the
		 * response to this request. So we send as much as the client
		 * can handle, mdrcnt, and store the rest in the output chain.
		 * The buffer overflow warning informs the client that we
		 * have more data to send. Typically, the client will call
		 * SmbRead&X, which will call smb_rpc_read, to get the data.
		 */

		mhead = smb_mbuf_get(pipe_info->output, mdrcnt);
		xa->rep_data_mb.max_bytes = mdrcnt;
		MBC_ATTACH_MBUF(&xa->rep_data_mb, mhead);

		smbsr_warn(sr, NT_STATUS_BUFFER_OVERFLOW,
		    ERRDOS, ERROR_MORE_DATA);
	} else {
		/*
		 * The client has provided enough buffer space, all
		 * we have to do is attach the output stream to the
		 * transaction response and zero out the stream.
		 */
		if (nbytes != 0) {
			mhead = smb_mbuf_get(pipe_info->output, nbytes);
			xa->rep_data_mb.max_bytes = nbytes;
			MBC_ATTACH_MBUF(&xa->rep_data_mb, mhead);
		}
	}

	if (pipe_info->output) {
		kmem_free(pipe_info->output, pipe_info->outlen);
		pipe_info->output = NULL;
		pipe_info->outlen = 0;
	}

	smb_rpc_exit(pipe_info);
	return (SDRC_SUCCESS);
}


/*
 * smb_rpc_fid
 *
 * The connection_fid is an arbitrary id used to associate RPC requests
 * with a particular binding handle. This routine provides a new fid on
 * each call.  It will not assign 0 or -1 so that those values can
 * remain available as sentinels.
 */
static uint32_t
smb_rpc_fid(void)
{
	static uint32_t connection_fid;
	static kmutex_t smb_rpc_fid_mutex;

	mutex_enter(&smb_rpc_fid_mutex);

	if (connection_fid == 0)
		connection_fid = lbolt << 11;

	do {
		++connection_fid;
	} while (connection_fid == 0 || connection_fid == (uint32_t)-1);

	mutex_exit(&smb_rpc_fid_mutex);

	return (connection_fid);
}


/*
 * smb_rpc_close
 *
 * This function should be called whenever an IPC file/pipe is closed.
 * All remaining I/O is flushed and the RPC layer is informed so that
 * it can release the resources being used for this connection.
 */
void
smb_rpc_close(struct smb_ofile *of)
{
	mlsvc_pipe_t *pipe_info;
	uint32_t nbytes = 0;
	boolean_t more_data;

	ASSERT(of);
	ASSERT(of->f_ftype == SMB_FTYPE_MESG_PIPE);
	ASSERT(of->f_pipe_info != NULL);

	pipe_info = of->f_pipe_info;
	smb_rpc_enter(pipe_info);

	if (pipe_info->fid != 0) {
		(void) smb_winpipe_call(0, pipe_info, 0, SMB_RPC_FLUSH,
		    &nbytes, &more_data);
		pipe_info->fid = 0;
	}

	if (pipe_info->output) {
		kmem_free(pipe_info->output, pipe_info->outlen);
		pipe_info->output = NULL;
		pipe_info->outlen = 0;
	}

	smb_rpc_exit(pipe_info);

	cv_destroy(&pipe_info->cv);
	mutex_destroy(&pipe_info->mutex);
}

/*
 * smb_rpc_write
 *
 * This interface is an alternative to smb_rpc_transact. We set up the
 * connection fid, as required, and copy the input data to the input
 * stream. The input stream is created by allocating enough mbufs to
 * hold the incoming data and doing a uio transfer. It is then up
 * to the client to call smb_rpc_read to actually make the transaction
 * happen.
 *
 * Returns 0 on success or an errno on failure.
 */
int
smb_rpc_write(struct smb_request *sr, struct uio *uio)
{
	mlsvc_pipe_t *pipe_info;
	mlsvc_stream_t *streamin;
	uint32_t mdrcnt;
	int rc;
	boolean_t more_data;

	ASSERT(sr->fid_ofile);
	ASSERT(sr->fid_ofile->f_ftype == SMB_FTYPE_MESG_PIPE);
	ASSERT(sr->fid_ofile->f_pipe_info != NULL);

	pipe_info = sr->fid_ofile->f_pipe_info;
	smb_rpc_enter(pipe_info);

	if (pipe_info->fid == 0) {
		smb_rpc_exit(pipe_info);
		return (EBADF);
	}

	streamin = &pipe_info->input;
	streamin->uio.uio_iov = uio->uio_iov;
	streamin->uio.uio_iovcnt = uio->uio_iovcnt;
	streamin->uio.uio_loffset = 0;
	streamin->uio.uio_resid = uio->uio_resid;
	streamin->uio.uio_segflg = UIO_SYSSPACE;
	mdrcnt = (uint32_t)uio->uio_resid;

	rc = smb_winpipe_call(sr, pipe_info, streamin, SMB_RPC_WRITE,
	    &mdrcnt, &more_data);

	smb_rpc_exit(pipe_info);

	return ((rc == 0) ? 0 : EIO);
}

/*
 * smb_rpc_read
 *
 * This interface may be called because smb_rpc_transact could not return
 * all of the data in the original transaction or to form the second half
 * of a transaction set up using smb_rpc_write. If there is data in the
 * output stream, we return it. Otherwise we assume that there is data
 * in the input stream that will provide the context to perform an RPC
 * transaction. The connection fid (pipe_info->fid) will provide the
 * context for mlsvc_rpc_process.
 *
 * The response data is encoded into raw_data as required by the smb_read
 * functions. The uio_resid value indicates the number of bytes read.
 */
/*ARGSUSED*/
int
smb_rpc_read(struct smb_request *sr, struct uio *uio)
{
	mlsvc_pipe_t *pinfo;
	mlsvc_stream_t *streamin;
	struct mbuf *mhead;
	int mdrcnt;
	int nbytes;
	int rc = 0;
	boolean_t more_data;

	ASSERT(sr->fid_ofile);
	ASSERT(sr->fid_ofile->f_ftype == SMB_FTYPE_MESG_PIPE);
	ASSERT(sr->fid_ofile->f_pipe_info != NULL);

	pinfo = sr->fid_ofile->f_pipe_info;
	smb_rpc_enter(pinfo);

	if (pinfo->fid == 0) {
		rc = EBADF;
		goto smb_rpc_read_exit;
	}

	/*
	 * if there is data left in the outpipe return it now
	 */
	streamin = 0;
	mdrcnt = uio->uio_resid;
	nbytes = mdrcnt;

	rc = smb_winpipe_call(sr, pinfo, streamin, SMB_RPC_READ,
	    (uint32_t *)&nbytes, &more_data);

	if (rc != 0 || nbytes == 0) {
		rc = EIO;
		goto smb_rpc_read_exit;
	}
	if (nbytes > mdrcnt) {
		nbytes = mdrcnt;
	}

	mhead = smb_mbuf_get(pinfo->output, nbytes);
	MBC_SETUP(&sr->raw_data, nbytes);
	MBC_ATTACH_MBUF(&sr->raw_data, mhead);

	uio->uio_resid -= nbytes;

smb_rpc_read_exit:
	if (pinfo->output) {
		kmem_free(pinfo->output, pinfo->outlen);
		pinfo->output = NULL;
		pinfo->outlen = 0;
	}

	smb_rpc_exit(pinfo);
	return (rc);
}
