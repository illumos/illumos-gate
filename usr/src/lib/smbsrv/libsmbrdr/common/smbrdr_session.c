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
 * This module provides the netbios and SMB negotiation, connect and
 * disconnect interface.
 */

#include <unistd.h>
#include <syslog.h>
#include <synch.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <netdb.h>

#include <smbsrv/libsmbrdr.h>
#include <smbsrv/netbios.h>
#include <smbsrv/cifs.h>

#include <smbsrv/ntstatus.h>
#include <smbsrv/mlsvc.h>
#include <smbrdr.h>
#include <smbrdr_ipc_util.h>


static uint16_t smbrdr_ports[] = {
	SMB_SRVC_TCP_PORT,
	SSN_SRVC_TCP_PORT
};

static int smbrdr_nports = sizeof (smbrdr_ports) / sizeof (smbrdr_ports[0]);

/*
 * Pointer to the PDC location interface.
 * To be set up by SMB when it loads.
 */
static mlsvc_locate_pdc_t mlsvc_locate_pdc;

/*
 * This is a temporary hack to stop the DC from closing a session
 * due to inactivity.
 */
#define	MLSVC_SESSION_FORCE_KEEPALIVE	10

/*
 * This is the session data table.
 *
 * The rwlock synchronizes access to the session table
 *
 * The mutex is to make session lookup and create atomic
 * so we don't end up with two sessions with the same
 * system.
 */
static struct sdb_session session_table[MLSVC_DOMAIN_MAX];
static mutex_t smbrdr_screate_mtx;
static unsigned int session_id = 0;

static struct sdb_session *smbrdr_session_init(smb_ntdomain_t *di);
static int smbrdr_trnsprt_connect(struct sdb_session *, uint16_t);
static int smbrdr_session_connect(smb_ntdomain_t *di);
static int smbrdr_smb_negotiate(struct sdb_session *session);
static int smbrdr_smb_echo(struct sdb_session *session);
static void smbrdr_session_disconnect(struct sdb_session *session, int cleanup);
static int smbrdr_locate_dc(char *domain);

static void
smbrdr_session_clear(struct sdb_session *session)
{
	bzero(session, sizeof (struct sdb_session) - sizeof (rwlock_t));
}

/*
 * mlsvc_install_pdc_cb
 *
 * Function to be called by SMB initialization code to set up a
 * callback to the PDC location interface.
 */
void
mlsvc_install_pdc_cb(mlsvc_locate_pdc_t locate_pdc_cb)
{
	mlsvc_locate_pdc = locate_pdc_cb;
}

/*
 * mlsvc_locate_domain_controller
 *
 * Locate a domain controller. Note that this may close an existing
 * connection to the current domain controller.
 */
int
mlsvc_locate_domain_controller(char *domain)
{
	if (mlsvc_locate_pdc)
		return (mlsvc_locate_pdc(domain));

	return (0);
}

/*
 * Entry pointy for smbrdr initialization.
 */
void
smbrdr_init(void)
{
	smbrdr_ipc_init();
}

/*
 * mlsvc_disconnect
 *
 * Disconnects the session with given server.
 */
void
mlsvc_disconnect(char *server)
{
	struct sdb_session *session;

	session = smbrdr_session_lock(server, 0, SDB_SLCK_WRITE);
	if (session) {
		smbrdr_session_disconnect(session, 0);
		smbrdr_session_unlock(session);
	}
}

/*
 * smbrdr_negotiate
 *
 * Negotiate a session with a domain controller in the specified domain.
 * The domain must be one of values from the smbinfo that indicates the
 * resource domain or the account domain.
 *
 * If a session already exists, we can use that one. Otherwise we create
 * a new one. This sets up the session key and session security info that
 * we'll need later to authenticate the user. The session security info
 * is returned to support the SMB client pass-through authentication
 * interface.
 *
 * Returns 0 on success, otherwise -1.
 */
int
smbrdr_negotiate(char *domain_name)
{
	struct sdb_session *session = 0;
	smb_ntdomain_t *di;
	int retry = 1;
	int res = 0;

	if ((di = smb_getdomaininfo(0)) == 0) {
		/*
		 * Attempting to locate a domain controller
		 * will shutdown an existing PDC connection.
		 */
		(void) smbrdr_locate_dc(domain_name);
		di = smb_getdomaininfo(0);
	}

	if (di == 0) {
		syslog(LOG_ERR, "smbrdr: negotiate (cannot access domain)");
		return (-1);
	}

	/*
	 * The mutex is to make session lookup and create atomic
	 * so we don't end up with two sessions with the same
	 * server.
	 */
	(void) mutex_lock(&smbrdr_screate_mtx);
	while (retry > 0) {
		session = smbrdr_session_lock(di->server, 0, SDB_SLCK_WRITE);
		if (session  != 0) {
			if (nb_keep_alive(session->sock) == 0) {
				/* session is good, use it */
				smbrdr_session_unlock(session);
				break;
			} else {
				/* stale session */
				session->state = SDB_SSTATE_STALE;
				smbrdr_session_unlock(session);
			}
		}

		if (smbrdr_session_connect(di) != 0) {
			if (retry > 0) {
				/* Do we really need to do this here? */
				(void) smbrdr_locate_dc(domain_name);
				di = smb_getdomaininfo(0);
				if (di == 0) {
					syslog(LOG_ERR, "smbrdr: negotiate"
					    " (cannot access domain)");
					res = -1;
					break;
				}
				retry--;
			}
		} else {
			/* session is created */
			retry = 0;
		}
	}
	(void) mutex_unlock(&smbrdr_screate_mtx);

	return (res);
}

/*
 * smbrdr_session_connect
 *
 * This is the entry point for establishing an SMB connection to a
 * domain controller. A session structure is allocated, a netbios
 * session is set up and the SMB protocol is negotiated. If this is
 * successful, the returned session structure can be used to logon
 * to the the domain. A null pointer is returned if the connect fails.
 */
static int
smbrdr_session_connect(smb_ntdomain_t *di)
{
	struct sdb_session *session;
	uint16_t port;
	int rc = 0;

	/*
	 * smbrdr_session_init() will lock the session so that it wouldn't
	 * be accessible until it's established otherwise another thread
	 * might get access to a session which is not fully established.
	 */
	if ((session = smbrdr_session_init(di)) == 0) {
		syslog(LOG_ERR, "smbrdr: session init failed");
		return (-1);
	}

	for (port = 0; port < smbrdr_nports; ++port) {
		syslog(LOG_DEBUG, "smbrdr: trying port %d",
		    smbrdr_ports[port]);

		rc = smbrdr_trnsprt_connect(session, smbrdr_ports[port]);

		if (rc == 0) {
			syslog(LOG_DEBUG, "smbrdr: connected port %d",
			    smbrdr_ports[port]);
			break;
		}
	}

	if (rc < 0) {
		smbrdr_session_clear(session);
		smbrdr_session_unlock(session);
		syslog(LOG_ERR, "smbrdr: NBT/TCP connect failed");
		return (-1);
	}

	if (smbrdr_smb_negotiate(session) < 0) {
		(void) close(session->sock);
		smbrdr_session_clear(session);
		smbrdr_session_unlock(session);
		syslog(LOG_ERR, "smbrdr: SMB negotiate failed");
		return (-1);
	}

	smbrdr_session_unlock(session);
	return (0);
}


/*
 * smbrdr_trnsprt_connect
 *
 * Set up the TCP/IP and NETBIOS protocols for a session. This is just
 * standard socket sutff. The paranoia check for socket descriptor 0
 * is because we had a problem with this value and the console telnet
 * interface will lock up if we use and/or close stdin (0).
 *
 * Return 0 on success. Otherwise return (-1) to indicate a problem.
 */
static int
smbrdr_trnsprt_connect(struct sdb_session *sess, uint16_t port)
{
	char hostname[MAXHOSTNAMELEN];
	struct sockaddr_in sin;
	int sock, rc;
	mts_wchar_t unicode_server_name[SMB_PI_MAX_DOMAIN];
	char server_name[SMB_PI_MAX_DOMAIN];
	unsigned int cpid = oem_get_smb_cpid();

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
		/*
		 * We should never see descriptor 0 (stdin).
		 */
		syslog(LOG_ERR, "smbrdr: socket(%d) failed (%s)", sock,
		    strerror(errno));
		return (-1);
	}

	bzero(&sin, sizeof (struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = sess->di.ipaddr;
	sin.sin_port = htons(port);

	if ((rc = connect(sock, (struct sockaddr *)&sin, sizeof (sin))) < 0) {
		syslog(LOG_ERR, "smbrdr: connect failed (%s)", strerror(errno));
		if (sock != 0)
			(void) close(sock);
		return (-1);
	}

	(void) mts_mbstowcs(unicode_server_name, sess->di.server,
	    SMB_PI_MAX_DOMAIN);
	rc = unicodestooems(server_name, unicode_server_name,
	    SMB_PI_MAX_DOMAIN, cpid);
	if (rc == 0) {
		syslog(LOG_ERR, "smbrdr: unicode conversion failed");
		if (sock != 0)
			(void) close(sock);
		return (-1);
	}

	/*
	 * If we are using NetBIOS, we need to set up a NETBIOS session.
	 * This typically implies that we will be using port 139.
	 * Otherwise, we're doing NetBIOS-less SMB, i.e. SMB over TCP,
	 * which is typically on port 445.
	 */
	if (port == SSN_SRVC_TCP_PORT) {
		if (smb_getnetbiosname(hostname, MAXHOSTNAMELEN) != 0) {
			syslog(LOG_ERR, "smbrdr: no hostname");
			if (sock != 0)
				(void) close(sock);
			return (-1);
		}

		rc = nb_session_request(sock,
		    server_name, sess->scope, hostname, sess->scope);

		if (rc != 0) {
			syslog(LOG_ERR,
			    "smbrdr: NBT session request to %s failed %d",
			    server_name, rc);
			if (sock != 0)
				(void) close(sock);
			return (-1);
		}
	}

	sess->sock = sock;
	sess->port = port;
	syslog(LOG_DEBUG, "smbrdr: connected on port %d", port);
	sess->state = SDB_SSTATE_CONNECTED;
	return (0);
}

/*
 * smbrdr_smb_negotiate
 *
 * Negotiate the protocol we are going to use as described in CIFS
 * section 4.1.1. The only protocol we support is NT LM 0.12, so we
 * really expect to see dialect 0 in the response. The only other
 * data gathered is the session key.
 *
 * Negotiate using ASCII strings.
 *
 * Return 0 on success. Otherwise return a -ve error code.
 */
static int
smbrdr_smb_negotiate(struct sdb_session *sess)
{
	unsigned short dialect;
	smbrdr_handle_t srh;
	smb_hdr_t smb_hdr;
	smb_msgbuf_t *mb;
	DWORD status;
	int rc;
	uint8_t tmp_secmode;
	uint8_t tmp_clen;

	status = smbrdr_request_init(&srh, SMB_COM_NEGOTIATE, sess, 0, 0);

	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_ERR, "smbrdr: negotiate (%s)",
		    xlate_nt_status(status));
		return (-1);
	}

	mb = &srh.srh_mbuf;
	rc = smb_msgbuf_encode(mb, "(wct)b (bcc)w (dialect)bs",
	    0,			/* smb_wct */
	    12,			/* smb_bcc */
	    0x02,		/* dialect marker */
	    "NT LM 0.12");	/* only dialect we care about */

	if (rc <= 0) {
		syslog(LOG_ERR, "smbrdr: negotiate (encode failed)");
		smbrdr_handle_free(&srh);
		return (-1);
	}

	status = smbrdr_exchange(&srh, &smb_hdr, 0);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_ERR, "smbrdr: negotiate (%s)",
		    xlate_nt_status(status));
		smbrdr_handle_free(&srh);
		return (-1);
	}

	sess->secmode = 0;
	sess->sesskey = 0;
	sess->challenge_len = 0;

	rc = smb_msgbuf_decode(mb,
	    "(wordcnt)1.(dialect)w(secm)b12.(skey)l(cap)l10.(klen)b2.",
	    &dialect, &tmp_secmode, &sess->sesskey, &sess->remote_caps,
	    &tmp_clen);

	if (rc <= 0 || dialect != 0) {
		syslog(LOG_ERR, "smbrdr: negotiate (response error)");
		smbrdr_handle_free(&srh);
		return (-1);
	}
	sess->secmode = tmp_secmode;
	sess->challenge_len = tmp_clen;

	rc = smb_msgbuf_decode(mb, "#c",
	    sess->challenge_len, sess->challenge_key);
	if (rc <= 0) {
		syslog(LOG_ERR, "smbrdr: negotiate (decode error)");
		smbrdr_handle_free(&srh);
		return (-1);
	}

	smbrdr_handle_free(&srh);

	if ((sess->secmode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) &&
	    (sess->secmode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED)) {
		sess->sign_ctx.ssc_flags |= SMB_SCF_REQUIRED;
		syslog(LOG_DEBUG, "smbrdr: %s requires signing",
		    sess->di.server);
	}

	sess->state = SDB_SSTATE_NEGOTIATED;
	return (0);
}

/*
 * smbrdr_session_init
 *
 * Allocate an available slot in session table for the specified domain
 * information.
 *
 * IMPORTANT! the returned session will be locked caller has to unlock
 *            it by calling smbrdr_session_unlock() after it's done with
 *            the pointer.
 */
static struct sdb_session *
smbrdr_session_init(smb_ntdomain_t *di)
{
	struct sdb_session *session = 0;
	int i;
	char *p;

	if (di == 0)
		return (0);

	for (i = 0; i < MLSVC_DOMAIN_MAX; ++i) {
		session = &session_table[i];

		(void) rw_wrlock(&session->rwl);
		if (session->state == SDB_SSTATE_START) {
			smbrdr_session_clear(session);
			bcopy(di, &session->di, sizeof (smb_ntdomain_t));
			(void) utf8_strupr(session->di.domain);
			(void) utf8_strupr(session->di.server);

			smb_config_rdlock();
			p = smb_config_getstr(SMB_CI_NBSCOPE);
			(void) strlcpy(session->scope, p, SMB_PI_MAX_SCOPE);
			smb_config_unlock();

			(void) strlcpy(session->native_os,
			    "Solaris", SMB_PI_MAX_NATIVE_OS);
			(void) strlcpy(session->native_lanman,
			    "Windows NT 4.0", SMB_PI_MAX_LANMAN);
			session->sock = -1;
			session->port = smbrdr_ports[0];
			session->smb_flags = SMB_FLAGS_CANONICALIZED_PATHS
			    | SMB_FLAGS_CASE_INSENSITIVE;

			session->smb_flags2 = SMB_FLAGS2_KNOWS_LONG_NAMES
			    | SMB_FLAGS2_KNOWS_EAS;

			/*
			 * Note that by sending vc=0 server will shutdown all
			 * the other connections with NAS if there is any.
			 */
			session->vc = 0;
			session->sid = ++session_id;
			if (session->sid == 0)
				session->sid = 1;
			session->state = SDB_SSTATE_INIT;
			return (session);
		}
		(void) rw_unlock(&session->rwl);
	}

	syslog(LOG_WARNING, "smbrdr: no session available");
	return (0);
}

/*
 * smbrdr_session_disconnect
 *
 * This is the entry point for disconnecting an SMB connection. Ensure
 * that all logons and shares associated with this session are
 * terminated and then free the session.
 *
 * if 'cleanup' is 1 it means that only sessions that are not active
 * should be cleaned up. if 'cleanup' is 0 disconnect the session in any
 * states.
 */
static void
smbrdr_session_disconnect(struct sdb_session *session, int cleanup)
{
	int state;

	if (session == 0) {
		syslog(LOG_ERR, "smbrdr: (disconnect) null session");
		return;
	}

	state = session->state;
	if ((state != SDB_SSTATE_DISCONNECTING) &&
	    (state != SDB_SSTATE_CLEANING) &&
	    (state != SDB_SSTATE_START)) {
		if ((cleanup == 0) || (state == SDB_SSTATE_STALE)) {
			/*
			 * if session is in stale state it means the connection
			 * is lost so no logoff, tdcon, or close can actually
			 * be sent, thus only cleanup our side.
			 */
			session->state = (state == SDB_SSTATE_STALE)
			    ? SDB_SSTATE_CLEANING : SDB_SSTATE_DISCONNECTING;
			(void) smbrdr_smb_logoff(&session->logon);
			nb_close(session->sock);
			smbrdr_session_clear(session);
		}
	}
}

/*
 * smbrdr_session_unlock
 *
 * Unlock given session structure.
 */
void
smbrdr_session_unlock(struct sdb_session *session)
{
	if (session)
		(void) rw_unlock(&session->rwl);
}

/*
 * smbrdr_session_lock
 *
 * Lookup the session associated with the specified domain controller.
 * If a match is found, we return a pointer to the session, Otherwise
 * we return null. Only sessions in "negotiated" state are checked.
 * This mechanism is very simple and implies that we
 * should only ever have one session open to any domain controller.
 *
 * IMPORTANT! the returned session will be locked caller has to unlock
 *            it by calling smbrdr_session_unlock() after it's done with
 *            the pointer.
 */
struct sdb_session *
smbrdr_session_lock(char *server, char *username, int lmode)
{
	struct sdb_session *session;
	int i;

	if (server == 0) {
		syslog(LOG_ERR, "smbrdr: (lookup) no server specified");
		return (0);
	}

	for (i = 0; i < MLSVC_DOMAIN_MAX; ++i) {
		session = &session_table[i];

		(lmode == SDB_SLCK_READ) ? (void) rw_rdlock(&session->rwl) :
		    (void) rw_wrlock(&session->rwl);

		if ((session->state == SDB_SSTATE_NEGOTIATED) &&
		    (strcasecmp(session->di.server, server) == 0)) {
			if (username) {
				if (strcasecmp(username,
				    session->logon.username) == 0)
					return (session);

				(void) rw_unlock(&session->rwl);
				return (0);
			}
			return (session);
		}

		(void) rw_unlock(&session->rwl);
	}

	return (0);
}

/*
 * mlsvc_session_native_values
 *
 * Given a file id (i.e. a named pipe fid), return the remote native
 * OS and LM values for the associated session.
 */
int
mlsvc_session_native_values(int fid, int *remote_os,
    int *remote_lm, int *pdc_type)
{
	struct sdb_session *session;
	struct sdb_netuse *netuse;
	struct sdb_ofile *ofile;

	if (remote_os == 0 || remote_lm == 0) {
		syslog(LOG_ERR, "mlsvc_session_native_values: null");
		return (-1);
	}

	if ((ofile = smbrdr_ofile_get(fid)) == 0) {
		syslog(LOG_ERR,
		    "mlsvc_session_native_values: unknown file (%d)", fid);
		return (-1);
	}

	netuse = ofile->netuse;
	session = netuse->session;

	*remote_os = session->remote_os;
	*remote_lm = session->remote_lm;
	if (pdc_type)
		*pdc_type = session->pdc_type;
	smbrdr_ofile_put(ofile);
	return (0);
}

/*
 * smbrdr_disconnect_sessions
 *
 * Disconnects/cleanups all the sessions
 */
static void
smbrdr_disconnect_sessions(int cleanup)
{
	struct sdb_session *session;
	int i;

	for (i = 0; i < MLSVC_DOMAIN_MAX; ++i) {
		session = &session_table[i];
		(void) rw_wrlock(&session->rwl);
		smbrdr_session_disconnect(&session_table[i], cleanup);
		(void) rw_unlock(&session->rwl);
	}
}


/*
 * mlsvc_check_sessions
 *
 * This function should be run in an independent thread. At the time of
 * writing it is called periodically from an infinite loop in the start
 * up thread once initialization is complete. It sends a NetBIOS keep-
 * alive message on each active session and handles cleanup if a session
 * is closed from the remote end. Testing demonstrated that the domain
 * controller will close a session after 15 minutes of inactivity. Note
 * that neither NetBIOS keep-alive nor SMB echo is deemed as activity
 * in this case, however, RPC requests appear to reset the timeout and
 * keep the session open. Note that the NetBIOS request does stop the
 * remote NetBIOS layer from timing out the connection.
 */
void
mlsvc_check_sessions(void)
{
	static int session_keep_alive;
	struct sdb_session *session;
	smb_ntdomain_t di;
	int i;

	++session_keep_alive;

	for (i = 0; i < MLSVC_DOMAIN_MAX; ++i) {
		session = &session_table[i];

		(void) rw_wrlock(&session->rwl);

		if (session->state < SDB_SSTATE_CONNECTED) {
			(void) rw_unlock(&session->rwl);
			continue;
		}

		/*
		 * NetBIOS is only used on with port 139. The keep alive
		 * is not relevant over NetBIOS-less SMB over port 445.
		 * This is just to see if the socket is still alive.
		 */
		if (session->port == SSN_SRVC_TCP_PORT) {
			if (nb_keep_alive(session->sock) != 0) {
				session->state = SDB_SSTATE_STALE;
				(void) rw_unlock(&session->rwl);
				continue;
			}
		}

		if (session_keep_alive >= MLSVC_SESSION_FORCE_KEEPALIVE) {
			if (smbrdr_smb_echo(session) != 0) {
				syslog(LOG_WARNING,
				    "smbrdr: monitor[%s] cannot contact %s",
				    session->di.domain, session->di.server);
				(void) memcpy(&di, &session->di,
				    sizeof (smb_ntdomain_t));
				session->state = SDB_SSTATE_STALE;
				(void) rw_unlock(&session->rwl);
				if (smb_getdomaininfo(0) == 0)
					(void) smbrdr_locate_dc(di.domain);
			}
		} else
			(void) rw_unlock(&session->rwl);
	}

	if (session_keep_alive >= MLSVC_SESSION_FORCE_KEEPALIVE) {
		session_keep_alive = 0;
		/* cleanup */
		smbrdr_disconnect_sessions(1);
	}
}

/*
 * smbrdr_dump_sessions
 *
 * Debug function to dump the session table.
 */
void
smbrdr_dump_sessions(void)
{
	struct sdb_session *session;
	struct sdb_logon *logon;
	char ipstr[16];
	int i;

	for (i = 0; i < MLSVC_DOMAIN_MAX; ++i) {
		session = &session_table[i];

		(void) rw_rdlock(&session->rwl);
		if (session->state != SDB_SSTATE_START) {
			(void) inet_ntop(AF_INET,
			    (const void *)(&session->di.ipaddr),
			    ipstr, sizeof (ipstr));

			syslog(LOG_DEBUG, "session[%d]: state=%d",
			    i, session->state);
			syslog(LOG_DEBUG, "session[%d]: %s %s (%s)", i,
			    session->di.domain, session->di.server, ipstr);
			syslog(LOG_DEBUG, "session[%d]: %s %s (sock=%d)", i,
			    session->native_os, session->native_lanman,
			    session->sock);

			logon = &session->logon;
			if (logon->type != SDB_LOGON_NONE)
				syslog(LOG_DEBUG, "logon[%d]: %s (uid=%d)",
				    i, logon->username, logon->uid);
		}
		(void) rw_unlock(&session->rwl);
	}
}

/*
 * mlsvc_echo
 */
int
mlsvc_echo(char *server)
{
	struct sdb_session *session;
	int res = 0;

	if ((session = smbrdr_session_lock(server, 0, SDB_SLCK_WRITE)) == 0)
		return (1);

	if (smbrdr_smb_echo(session) != 0) {
		session->state = SDB_SSTATE_STALE;
		res = -1;
	}

	smbrdr_session_unlock(session);
	return (res);
}

/*
 * smbrdr_smb_echo
 *
 * This request can be used to test the connection to the server. The
 * server should echo the data sent. The server should ignore the tid
 * in the header, so this request when there are no tree connections.
 * See CIFS/1.0 section 4.1.7.
 *
 * Return 0 on success. Otherwise return a -ve error code.
 */
static int
smbrdr_smb_echo(struct sdb_session *session)
{
	static char *echo_str = "smbrdr";
	smbrdr_handle_t srh;
	smb_hdr_t smb_hdr;
	DWORD status;
	int rc;

	if ((session->state == SDB_SSTATE_DISCONNECTING) ||
	    (session->state == SDB_SSTATE_CLEANING) ||
	    (session->state == SDB_SSTATE_STALE)) {
		return (-1);
	}

	status = smbrdr_request_init(&srh, SMB_COM_ECHO, session, 0, 0);

	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_ERR, "SmbrdrEcho: %s", xlate_nt_status(status));
		return (-1);
	}

	rc = smb_msgbuf_encode(&srh.srh_mbuf, "bwws", 1, 1,
	    strlen(echo_str), echo_str);
	if (rc <= 0) {
		syslog(LOG_ERR, "SmbrdrEcho: encode failed");
		smbrdr_handle_free(&srh);
		return (-1);
	}

	status = smbrdr_exchange(&srh, &smb_hdr, 10);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_ERR, "SmbrdrEcho: %s", xlate_nt_status(status));
		rc = -1;
	} else {
		rc = 0;
	}

	smbrdr_handle_free(&srh);
	return (rc);
}

/*
 * smbrdr_locate_dc
 *
 * Locate a domain controller. Note that this may close an existing
 * connection to the current domain controller.
 */
static int
smbrdr_locate_dc(char *domain)
{
	if (mlsvc_locate_pdc)
		return (mlsvc_locate_pdc(domain));

	return (0);
}
