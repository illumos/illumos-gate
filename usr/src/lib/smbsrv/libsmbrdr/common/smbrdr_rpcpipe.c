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
 * Functions to open and close named pipes. These functions are
 * described in the CIFS 1.0 Protocol Specification (December 19, 1997).
 */

#include <alloca.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <synch.h>

#include <smbsrv/libsmbrdr.h>
#include <smbsrv/ntstatus.h>
#include <smbrdr.h>

static int smbrdr_close(struct sdb_ofile *);
static DWORD smbrdr_ntcreatex(struct sdb_ofile *);
static struct sdb_ofile *smbrdr_ofile_alloc(struct sdb_netuse *, char *);

static void
smbrdr_ofile_clear(struct sdb_ofile *ofile)
{
	bzero(ofile, sizeof (struct sdb_ofile) - sizeof (mutex_t));
}

static void
smbrdr_ofile_free(struct sdb_ofile *ofile)
{
	smbrdr_ofile_clear(ofile);
	(void) mutex_unlock(&ofile->mtx);
}


/*
 * The ofile table.
 */
static struct sdb_ofile ofile_table[N_OFILE_TABLE];

static int mlsvc_pipe_recon_wait = 50;
static int mlsvc_pipe_recon_tries = 3;


/*
 * mlsvc_open_pipe
 *
 * Open an RPC pipe on hostname. On success, return the fid. Otherwise
 * returns a -ve error code.
 */
int
mlsvc_open_pipe(char *hostname, char *domain, char *username, char *pipename)
{
	struct sdb_netuse *netuse;
	struct sdb_ofile *ofile;
	unsigned short tid;
	DWORD status;
	int retry;
	struct timespec st;

	tid = smbrdr_tree_connect(hostname, username, "IPC$");
	if (tid == 0) {
		syslog(LOG_DEBUG, "smbrdr: (open) %s %s %s %s %s",
		    hostname, domain, username, pipename,
		    xlate_nt_status(NT_STATUS_UNEXPECTED_NETWORK_ERROR));
		return (-1);
	}

	netuse = smbrdr_netuse_get(tid);
	if (netuse == NULL) {
		syslog(LOG_DEBUG, "smbrdr: (open) %s %s %s %s %s",
		    hostname, domain, username, pipename,
		    xlate_nt_status(NT_STATUS_CONNECTION_INVALID));
		return (-1);
	}

	if ((ofile = smbrdr_ofile_alloc(netuse, pipename)) == 0) {
		syslog(LOG_DEBUG, "smbrdr: (open) %s %s %s %s %s",
		    hostname, domain, username, pipename,
		    xlate_nt_status(NT_STATUS_INSUFFICIENT_RESOURCES));
		smbrdr_netuse_put(netuse);
		return (-1);
	}

	status = NT_STATUS_OPEN_FAILED;

	for (retry = 0; retry < mlsvc_pipe_recon_tries; retry++) {
		status = smbrdr_ntcreatex(ofile);

		switch (status) {
		case NT_STATUS_SUCCESS:
			(void) mutex_unlock(&ofile->mtx);
			smbrdr_netuse_put(netuse);
			return (ofile->fid);

		case NT_STATUS_PIPE_NOT_AVAILABLE:
		case NT_STATUS_PIPE_BUSY:
			/*
			 * The server might return this error if it is
			 * temporarily busy or unable to create a pipe.
			 * We wait here before trying again to see if
			 * the pipe becomes available.
			 */
			st.tv_sec = 0;
			st.tv_nsec = mlsvc_pipe_recon_wait * 1000000;
			(void) nanosleep(&st, 0);
			break;

		default:
			/*
			 * Something else went wrong: no more retries.
			 */
			retry = mlsvc_pipe_recon_tries;
			break;
		}
	}

	syslog(LOG_DEBUG, "smbrdr: (open) %s %s %s %s %s",
	    hostname, domain, username, pipename,
	    xlate_nt_status(status));
	smbrdr_ofile_free(ofile);
	smbrdr_netuse_put(netuse);
	return (-1);
}

/*
 * mlsvc_close_pipe
 *
 * Close the named pipe represented by fid.
 */
int
mlsvc_close_pipe(int fid)
{
	struct sdb_ofile *ofile;
	unsigned short tid;
	int rc;

	if ((ofile = smbrdr_ofile_get(fid)) == NULL)
		return (-1);

	tid = ofile->tid;
	rc = smbrdr_close(ofile);
	smbrdr_ofile_put(ofile);

	if (rc == 0)
		(void) smbrdr_tree_disconnect(tid);

	return (rc);
}

/*
 * smbrdr_ofile_put
 *
 * Unlock given ofile structure.
 */
void
smbrdr_ofile_put(struct sdb_ofile *ofile)
{
	if (ofile)
		(void) mutex_unlock(&ofile->mtx);
}

/*
 * smbrdr_ofile_get
 *
 * Locate the ofile for the specified fid. Just to be safe, ensure that
 * the netuse pointer is valid. Return a pointer to the ofile structure.
 * Return a null pointer if a valid ofile cannot be found.
 */
struct sdb_ofile *
smbrdr_ofile_get(int fid)
{
	struct sdb_session *session;
	struct sdb_netuse *netuse;
	struct sdb_ofile *ofile;
	int i;

	for (i = 0; i < N_OFILE_TABLE; ++i) {
		ofile = &ofile_table[i];

		(void) mutex_lock(&ofile->mtx);

		if (ofile->fid == fid) {
			session = ofile->session;
			netuse = ofile->netuse;

			/*
			 * status check:
			 * make sure all the structures are in the right state
			 */
			if (session && netuse &&
			    (ofile->state == SDB_FSTATE_OPEN) &&
			    (netuse->state == SDB_NSTATE_CONNECTED) &&
			    (session->logon.state == SDB_LSTATE_SETUP) &&
			    (session->state == SDB_SSTATE_NEGOTIATED)) {
				/* sanity check */
				if ((ofile->sid == session->sid) &&
				    (ofile->uid == session->logon.uid) &&
				    (ofile->tid == netuse->tid)) {
					return (ofile);
				} else {
					/* invalid structure */
					smbrdr_ofile_clear(ofile);
				}
			}
		}

		(void) mutex_unlock(&ofile->mtx);
	}

	return (NULL);
}

/*
 * smbrdr_ofile_end_of_share
 *
 * This function can be used when closing a share to ensure that all
 * ofiles resources are released. Don't call mlsvc_close_pipe because
 * that will call mlsvc_smb_tdcon and we don't know what state
 * the share is in. The server will probably close all files anyway.
 * We are more interested in releasing the ofile resources.
 */
void
smbrdr_ofile_end_of_share(unsigned short tid)
{
	struct sdb_ofile *ofile;
	int i;

	for (i = 0; i < N_OFILE_TABLE; ++i) {
		ofile = &ofile_table[i];
		(void) mutex_lock(&ofile->mtx);
		if (ofile->tid == tid)
			(void) smbrdr_close(ofile);
		(void) mutex_unlock(&ofile->mtx);
	}
}

/*
 * smbrdr_dump_ofiles
 *
 * Dump the open files table.
 */
void
smbrdr_dump_ofiles()
{
	struct sdb_ofile *ofile;
	struct sdb_netuse *netuse;
	int i;

	for (i = 0; i < N_OFILE_TABLE; ++i) {
		ofile = &ofile_table[i];
		(void) mutex_lock(&ofile->mtx);
		netuse = ofile->netuse;

		if (netuse) {
			syslog(LOG_DEBUG, "file[%d]: %s (fid=%d)", i,
			    ofile->path, ofile->fid);
			syslog(LOG_DEBUG,
			    "file[%d]: session(%d), user(%d), tree(%d)",
			    i, netuse->session->sock, netuse->uid,
			    netuse->tid);
		}
		(void) mutex_unlock(&ofile->mtx);
	}
}

/*
 * Private Functions
 */

/*
 * smbrdr_close
 *
 * Send SMBClose request for the given open file.
 */
static int
smbrdr_close(struct sdb_ofile *ofile)
{
	struct sdb_session *session;
	struct sdb_netuse *netuse;
	struct sdb_logon *logon;
	smbrdr_handle_t srh;
	smb_hdr_t smb_hdr;
	DWORD status;
	int fid;
	int rc;

	if (ofile == NULL)
		return (0);

	ofile->state = SDB_FSTATE_CLOSING;

	if ((session = ofile->session) == NULL) {
		smbrdr_ofile_clear(ofile);
		return (0);
	}

	if ((session->state != SDB_SSTATE_NEGOTIATED) &&
	    (session->state != SDB_SSTATE_DISCONNECTING)) {
		smbrdr_ofile_clear(ofile);
		return (0);
	}

	fid = ofile->fid;

	netuse = ofile->netuse;
	logon = &session->logon;

	status = smbrdr_request_init(&srh, SMB_COM_CLOSE,
	    session, logon, netuse);

	if (status != NT_STATUS_SUCCESS) {
		smbrdr_ofile_clear(ofile);
		return (-1);
	}

	rc = smb_msgbuf_encode(&srh.srh_mbuf, "bwlw.", 3, fid, 0x00000000ul, 0);
	if (rc <= 0) {
		smbrdr_handle_free(&srh);
		smbrdr_ofile_clear(ofile);
		return (-1);
	}

	status = smbrdr_exchange(&srh, &smb_hdr, 0);
	if (status != NT_STATUS_SUCCESS)
		syslog(LOG_DEBUG, "smbrdr_close: %s", xlate_nt_status(status));

	smbrdr_handle_free(&srh);
	smbrdr_ofile_clear(ofile);
	return (0);
}

/*
 * smbrdr_ofile_alloc
 *
 * Allocate an ofile for the specified name. File info is associated
 * with a share so we need a valid share before calling this function.
 * If a slot is already allocated to the specified file, a pointer to
 * that slot is returned. Otherwise we allocate and initialize a new
 * slot in the table. If the table is full, a null pointer will be
 * returned.
 */
static struct sdb_ofile *
smbrdr_ofile_alloc(struct sdb_netuse *netuse, char *name)
{
	struct sdb_ofile *ofile;
	int i;

	for (i = 0; i < N_OFILE_TABLE; ++i) {
		ofile = &ofile_table[i];

		(void) mutex_lock(&ofile->mtx);
		if (ofile->netuse == 0) {

			ofile->session = netuse->session;
			ofile->netuse = netuse;
			ofile->sid = netuse->session->sid;
			ofile->uid = netuse->session->logon.uid;
			ofile->tid = netuse->tid;
			ofile->fid = 0;
			(void) strcpy(ofile->path, name);
			ofile->state = SDB_FSTATE_INIT;
			return (ofile);
		}

		(void) mutex_unlock(&ofile->mtx);
	}

	return (NULL);
}

/*
 * smbrdr_ntcreatex
 *
 * This will do an SMB_COM_NT_CREATE_ANDX with lots of default values.
 * All of the underlying session and share data should already be set
 * up before we get here. If everything works we'll get a valid fid.
 */
static DWORD
smbrdr_ntcreatex(struct sdb_ofile *ofile)
{
	struct sdb_logon *logon;
	struct sdb_netuse *netuse;
	struct sdb_session *sess;
	smbrdr_handle_t srh;
	smb_hdr_t smb_hdr;
	smb_msgbuf_t *mb;
	char *path;
	unsigned path_len;
	int data_bytes;
	int rc;
	unsigned short fid;
	int null_size;
	DWORD status;

	netuse = ofile->netuse;
	sess = netuse->session;
	logon = &sess->logon;

	/*
	 * If this was a general purpose interface, we should support
	 * full UNC semantics but we only use this for RPC over named
	 * pipes with well-known endpoints.
	 */
	path_len = strlen(ofile->path) + 2;
	path = alloca(path_len);

	if (ofile->path[0] != '\\')
		(void) snprintf(path, path_len, "\\%s", ofile->path);
	else
		(void) strcpy(path, ofile->path);

	if (sess->remote_caps & CAP_UNICODE) {
		path_len = mts_wcequiv_strlen(path);
		null_size = sizeof (mts_wchar_t);
	} else {
		path_len = strlen(path);
		null_size = sizeof (char);
	}

	syslog(LOG_DEBUG, "smbrdr_ntcreatex: %d %s", path_len, path);

	status = smbrdr_request_init(&srh, SMB_COM_NT_CREATE_ANDX,
	    sess, logon, netuse);

	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_ntcreatex: %s",
		    xlate_nt_status(status));
		return (NT_STATUS_INVALID_PARAMETER_1);
	}

	mb = &srh.srh_mbuf;

	data_bytes = path_len + null_size;

	rc = smb_msgbuf_encode(mb,
	    "(wct)b (andx)b1.w (resv). (nlen)w (flg)l"
	    "(rdf)l (dacc)l (allo)q (efa)l (shr)l (cdisp)l (copt)l (impl)l"
	    "(secf)b (bcc)w (name)u",
	    24,				/* smb_wct */
	    0xff,			/* AndXCommand (none) */
	    0x0000,			/* AndXOffset */
	    path_len,			/* Unicode NameLength */
	    0x00000006ul,		/* Flags (oplocks) */
	    0,				/* RootDirectoryFid */
	    0x0002019Ful,		/* DesiredAccess */
	    0x0ull,			/* AllocationSize */
	    0x00000000ul,		/* ExtFileAttributes */
	    0x00000003ul,		/* ShareAccess (RW) */
	    0x00000001ul,		/* CreateDisposition (OpenExisting) */
	    0x00000000ul,		/* CreateOptions */
	    0x00000002ul,		/* ImpersonationLevel */
	    0x01u,			/* SecurityFlags */
	    data_bytes,			/* smb_bcc */
	    path);			/* Name */

	if (rc <= 0) {
		smbrdr_handle_free(&srh);
		return (NT_STATUS_INVALID_PARAMETER_1);
	}

	status = smbrdr_exchange(&srh, &smb_hdr, 0);
	if (status != NT_STATUS_SUCCESS) {
		smbrdr_handle_free(&srh);
		return (NT_SC_VALUE(status));
	}

	rc = smb_msgbuf_decode(mb, "(wct). (andx)4. (opl)1. (fid)w", &fid);
	if (rc <= 0) {
		smbrdr_handle_free(&srh);
		return (NT_STATUS_INVALID_PARAMETER_2);
	}

	ofile->fid = fid;
	ofile->state = SDB_FSTATE_OPEN;
	syslog(LOG_DEBUG, "SmbRdrNtCreate: fid=%d", ofile->fid);
	smbrdr_handle_free(&srh);
	return (NT_STATUS_SUCCESS);
}
