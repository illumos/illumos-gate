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
 * Tree connect and disconnect functions to support SMB shares.
 * These functions are described in the CIFS draft 1.0 Protocol
 * Specification (December 19, 1997).
 */

#include <sys/errno.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <synch.h>
#include <pthread.h>

#include <smbsrv/libsmbrdr.h>
#include <smbrdr.h>
#include <smbsrv/ntstatus.h>


/*
 * The table of shares set up with the domain controller.
 */
static struct sdb_netuse netuse_table[N_NETUSE_TABLE];

static int smbrdr_tree_connectx(struct sdb_session *session,
    struct sdb_netuse *netuse, char *path, int path_len);

static struct sdb_netuse *smbrdr_netuse_alloc(struct sdb_session *session,
    char *sharename);
static int smbrdr_tdcon(struct sdb_netuse *netuse);

static void
smbrdr_netuse_clear(struct sdb_netuse *netuse)
{
	bzero(netuse, sizeof (struct sdb_netuse) - sizeof (mutex_t));
}

static void
smbrdr_netuse_free(struct sdb_netuse *netuse)
{
	smbrdr_netuse_clear(netuse);
	(void) mutex_unlock(&netuse->mtx);
}

/*
 * smbrdr_tree_connect
 *
 * Establish a share (tree connect). We need to retrieve the session
 * for the specified host and allocate a netuse structure. We set up
 * the path here (UNC encoded) to make handling the malloc/free easier
 * and pass everything on to smbrdr_tree_connectx where.  If everything
 * goes well, a valid tid will be stored in the netuse structure.
 *
 * On success, a pointer to the netuse is returned. Otherwise the
 * netuse is cleared and a null pointer is returned.
 */
unsigned short
smbrdr_tree_connect(char *hostname, char *username, char *sharename)
{
	struct sdb_session *session;
	struct sdb_netuse *netuse;
	char *path;
	int path_len;

	/*
	 * Make sure there is a session & logon for given info
	 */
	session = smbrdr_session_lock(hostname, username, SDB_SLCK_READ);
	if (session == NULL) {
		syslog(LOG_DEBUG, "smbrdr_tree_connect: no session for %s@%s",
		    username, hostname);
		return (0);
	}


	if ((netuse = smbrdr_netuse_alloc(session, sharename)) == 0) {
		syslog(LOG_DEBUG, "smbrdr_tree_connect: init failed");
		smbrdr_session_unlock(session);
		return (0);
	}

	/*
	 * Add some padding for the back-slash separators
	 * and the null-terminator.
	 */
	path_len = SMB_PI_MAX_HOST + MAX_SHARE_NAME + 5;

	if ((path = (char *)malloc(path_len)) == 0) {
		smbrdr_netuse_free(netuse);
		smbrdr_session_unlock(session);
		syslog(LOG_DEBUG, "smbrdr_tree_connect: %s", strerror(ENOMEM));
		return (0);
	}

	bzero(path, path_len);
	(void) snprintf(path, path_len, "\\\\%s\\%s", hostname, sharename);
	if (session->remote_caps & CAP_UNICODE)
		path_len = mts_wcequiv_strlen(path);
	else
		path_len = strlen(path);

	if (smbrdr_tree_connectx(session, netuse, path, path_len) < 0) {
		smbrdr_netuse_free(netuse);
		smbrdr_session_unlock(session);
		free(path);
		syslog(LOG_DEBUG, "smbrdr_tree_connect: %s failed", path);
		return (0);
	}

	free(path);
	(void) mutex_unlock(&netuse->mtx);
	smbrdr_session_unlock(session);
	return (netuse->tid);
}


/*
 * smbrdr_tree_connectx
 *
 * This message requests a share (tree connect) request to the server
 * associated with the session. The password is not relevant here if
 * the session was establishment using setup_andx. The outgoing tid
 * will be ignored - a valid one will be returned by the server.
 *
 * Returns 0 on success. Otherwise returns a -ve error code.
 */
static int
smbrdr_tree_connectx(struct sdb_session *session, struct sdb_netuse *netuse,
    char *path, int path_len)
{
	smb_hdr_t smb_hdr;
	smbrdr_handle_t srh;
	smb_msgbuf_t *mb;
	unsigned short flags;
	char *password;
	unsigned short password_len;
	char *service;
	unsigned service_len;
	unsigned short data_bytes;
	DWORD status;
	int rc;

	status = smbrdr_request_init(&srh, SMB_COM_TREE_CONNECT_ANDX,
	    session, &session->logon, 0);

	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_tree_connectx: %s",
		    xlate_nt_status(status));
		return (-1);
	}

	mb = &srh.srh_mbuf;

	flags = 0;			/* no flags */
	password = "";
	password_len = 1;		/* including nul */
	service = "?????";		/* does this work? */
	service_len = strlen(service);

	/*
	 * Calculate the BCC. The path is in UNICODE
	 * but the service is in ASCII.
	 */
	data_bytes  = password_len;
	data_bytes += path_len + 1;
	data_bytes += service_len + 1;

	rc = smb_msgbuf_encode(mb, "bb1.wwww#cus",
	    4,				/* smb_wct */
	    0xff,			/* AndXCommand (none) */
	    0xffff,			/* AndXOffset */
	    flags,			/* Flags */
	    password_len,		/* PasswordLength */
	    data_bytes+1,		/* smb_bcc */
	    password_len, password,	/* Password */
	    path,			/* Path */
	    service);			/* Service */

	if (rc <= 0) {
		syslog(LOG_DEBUG, "smbrdr_tree_connectx: encode failed");
		smbrdr_handle_free(&srh);
		return (-1);
	}

	status = smbrdr_exchange(&srh, &smb_hdr, 0);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_tree_connectx: %s",
		    xlate_nt_status(status));
		smbrdr_handle_free(&srh);
		return (-1);
	}

	netuse->tid = smb_hdr.tid;
	netuse->state = SDB_NSTATE_CONNECTED;
	smbrdr_handle_free(&srh);
	return (0);
}

/*
 * smbrdr_netuse_logoff
 *
 * This function can be used when closing a session to ensure that all
 * shares associated with the specified session are disconnected and
 * the resources released. We also notify the pipe interface to ensure
 * that any pipes associated with this share are also closed. This
 * function silently ignores errors because we have no idea what state
 * the session is in. We are more interested in releasing resources.
 */
void
smbrdr_netuse_logoff(unsigned short uid)
{
	struct sdb_netuse *netuse;
	int i;

	for (i = 0; i < N_NETUSE_TABLE; ++i) {
		netuse = &netuse_table[i];
		(void) mutex_lock(&netuse->mtx);
		if (netuse->uid == uid)
			(void) smbrdr_tdcon(netuse);
		(void) mutex_unlock(&netuse->mtx);
	}
}

int
smbrdr_tree_disconnect(unsigned short tid)
{
	struct sdb_netuse *netuse;
	int rc = -1;

	netuse = smbrdr_netuse_get(tid);
	if (netuse) {
		(void) smbrdr_tdcon(netuse);
		smbrdr_netuse_put(netuse);
		rc = 0;
	}

	return (rc);
}

/*
 * smbrdr_tdcon
 *
 * Disconnect a share. This message informs the server that we no longer
 * wish to access the resource specified by tid, obtained via a prior
 * smbrdr_tree_connect. The tid is passed in the SMB header so the setup
 * for this call is very straightforward.
 *
 * Returns 0 on success. Otherwise returns a -ve error code.
 */
static int
smbrdr_tdcon(struct sdb_netuse *netuse)
{
	struct sdb_session *session;
	smbrdr_handle_t srh;
	smb_hdr_t smb_hdr;
	DWORD status;
	int rc;

	netuse->state = SDB_NSTATE_DISCONNECTING;
	smbrdr_ofile_end_of_share(netuse->tid);

	if ((session = netuse->session) == NULL) {
		smbrdr_netuse_clear(netuse);
		return (0);
	}

	if ((session->state != SDB_SSTATE_NEGOTIATED) &&
	    (session->state != SDB_SSTATE_DISCONNECTING)) {
		smbrdr_netuse_clear(netuse);
		return (0);
	}

	status = smbrdr_request_init(&srh, SMB_COM_TREE_DISCONNECT,
	    session, &session->logon, netuse);

	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_tdcon: %s", xlate_nt_status(status));
		/* should we clear here? */
		smbrdr_netuse_clear(netuse);
		return (-1);
	}

	rc = smb_msgbuf_encode(&srh.srh_mbuf, "bw.", 0, 0);
	if (rc < 0) {
		syslog(LOG_DEBUG, "smbrdr_tdcon: encode failed");
		smbrdr_handle_free(&srh);
		/* should we clear here? */
		smbrdr_netuse_clear(netuse);
		return (rc);
	}

	status = smbrdr_exchange(&srh, &smb_hdr, 0);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_tdcon: %s", xlate_nt_status(status));
		rc = -1;
	} else {
		rc = 0;
	}

	smbrdr_handle_free(&srh);
	smbrdr_netuse_clear(netuse);
	return (rc);
}


/*
 * smbrdr_netuse_alloc
 *
 * Find a slot in the table for a share. Each share is associated with
 * a session and assigned a local drive letter name and a sharename.
 * If a slot is already allocated to the specified share, a pointer to
 * it is returned. Otherwise we allocate and initialize a new slot in
 * the table. If the table is full, a null pointer will be returned.
 *
 * IMPORTANT! the returned netuse will be locked caller has to unlock
 *            it after it's done with the pointer.
 */
static struct sdb_netuse *
smbrdr_netuse_alloc(struct sdb_session *session, char *sharename)
{
	struct sdb_netuse *netuse;
	int i;

	if (session == NULL || sharename == NULL)
		return (NULL);

	for (i = 0; i < N_NETUSE_TABLE; ++i) {
		netuse = &netuse_table[i];

		(void) mutex_lock(&netuse->mtx);
		if (netuse->state == SDB_NSTATE_START) {
			netuse->session = session;
			netuse->letter = i + '0';
			netuse->sid = session->sid;
			netuse->uid = session->logon.uid;
			netuse->tid = 0;
			(void) strcpy(netuse->share, sharename);
			netuse->state = SDB_NSTATE_INIT;
			return (netuse);
		}
		(void) mutex_unlock(&netuse->mtx);
	}

	syslog(LOG_DEBUG, "smbrdr_netuse_alloc: table full");
	return (0);
}

/*
 * smbrdr_netuse_put
 *
 * Unlock given netuse structure.
 */
void
smbrdr_netuse_put(struct sdb_netuse *netuse)
{
	(void) mutex_unlock(&netuse->mtx);
}

/*
 * smbrdr_netuse_get
 *
 * Find the netuse structure associated with the specified tid and
 * return a pointer to it. A null pointer is returned if no match
 * can be found.
 *
 * IMPORTANT! the returned netuse will be locked caller has to unlock
 *            it after it's done with the pointer.
 */
struct sdb_netuse *
smbrdr_netuse_get(int tid)
{
	struct sdb_session *session;
	struct sdb_netuse *netuse;
	int i;

	for (i = 0; i < N_NETUSE_TABLE; ++i) {
		netuse = &netuse_table[i];

		(void) mutex_lock(&netuse->mtx);

		if (netuse->tid == tid) {
			session = netuse->session;

			/*
			 * status check:
			 * make sure all the structures are in the right state
			 */
			if (session &&
			    (netuse->state == SDB_NSTATE_CONNECTED) &&
			    (session->logon.state == SDB_LSTATE_SETUP) &&
			    (session->state == SDB_SSTATE_NEGOTIATED)) {
				/* sanity check */
				if ((netuse->sid == session->sid) &&
				    (netuse->uid == session->logon.uid))
					return (netuse);
				else
					/* invalid structure */
					smbrdr_netuse_clear(netuse);
			}

		}

		(void) mutex_unlock(&netuse->mtx);
	}

	syslog(LOG_DEBUG, "smbrdr_netuse_get: %d: no such TID", tid);
	return (0);
}

/*
 * smbrdr_dump_netuse
 */
void
smbrdr_dump_netuse()
{
	struct sdb_netuse *netuse;
	int i;

	for (i = 0; i < N_NETUSE_TABLE; ++i) {
		netuse = &netuse_table[i];
		(void) mutex_lock(&netuse->mtx);
		if (netuse->session) {
			syslog(LOG_DEBUG, "tree[%d]: %s (tid=%d)", i,
			    netuse->share, netuse->tid);
			syslog(LOG_DEBUG, "tree[%d]: session(%d), user(%d)",
			    i, netuse->session->sock, netuse->uid);
		}
		(void) mutex_unlock(&netuse->mtx);
	}
}
