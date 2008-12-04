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

#include <sys/atomic.h>
#include <sys/strsubr.h>
#include <sys/synch.h>
#include <sys/types.h>
#include <sys/socketvar.h>
#include <sys/sdt.h>
#include <smbsrv/netbios.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_i18n.h>

static volatile uint64_t smb_kids;

uint32_t smb_keep_alive = SSN_KEEP_ALIVE_TIMEOUT;

static int smb_session_message(smb_session_t *);
static int smb_session_xprt_puthdr(smb_session_t *, smb_xprt_t *,
    uint8_t *, size_t);
static smb_user_t *smb_session_lookup_user(smb_session_t *, char *, char *);
static void smb_request_init_command_mbuf(smb_request_t *sr);


void
smb_session_timers(smb_session_list_t *se)
{
	smb_session_t	*session;

	rw_enter(&se->se_lock, RW_READER);
	session = list_head(&se->se_act.lst);
	while (session) {
		/*
		 * Walk through the table and decrement each keep_alive
		 * timer that has not timed out yet. (keepalive > 0)
		 */
		ASSERT(session->s_magic == SMB_SESSION_MAGIC);
		if (session->keep_alive &&
		    (session->keep_alive != (uint32_t)-1))
			session->keep_alive--;
		session = list_next(&se->se_act.lst, session);
	}
	rw_exit(&se->se_lock);
}

void
smb_session_correct_keep_alive_values(
    smb_session_list_t	*se,
    uint32_t		new_keep_alive)
{
	smb_session_t		*sn;

	if (new_keep_alive == smb_keep_alive)
		return;
	/*
	 * keep alive == 0 means do not drop connection if it's idle
	 */
	smb_keep_alive = (new_keep_alive) ? new_keep_alive : -1;

	/*
	 * Walk through the table and set each session to the new keep_alive
	 * value if they have not already timed out.  Block clock interrupts.
	 */
	rw_enter(&se->se_lock, RW_READER);
	sn = list_head(&se->se_rdy.lst);
	while (sn) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);
		sn->keep_alive = new_keep_alive;
		sn = list_next(&se->se_rdy.lst, sn);
	}
	sn = list_head(&se->se_act.lst);
	while (sn) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);
		if (sn->keep_alive)
			sn->keep_alive = new_keep_alive;
		sn = list_next(&se->se_act.lst, sn);
	}
	rw_exit(&se->se_lock);
}

/*
 * smb_reconnection_check
 *
 * This function is called when a client indicates its current connection
 * should be the only one it has with the server, as indicated by VC=0 in
 * a SessionSetupX request. We go through the session list and destroy any
 * stale connections for that client.
 *
 * Clients don't associate IP addresses and servers. So a client may make
 * independent connections (i.e. with VC=0) to a server with multiple
 * IP addresses. So, when checking for a reconnection, we need to include
 * the local IP address, to which the client is connecting, when checking
 * for stale sessions.
 *
 * Also check the server's NetBIOS name to support simultaneous access by
 * multiple clients behind a NAT server.  This will only work for SMB over
 * NetBIOS on TCP port 139, it will not work SMB over TCP port 445 because
 * there is no NetBIOS name.  See also Knowledge Base article Q301673.
 */
void
smb_session_reconnection_check(smb_session_list_t *se, smb_session_t *session)
{
	smb_session_t	*sn;

	rw_enter(&se->se_lock, RW_READER);
	sn = list_head(&se->se_act.lst);
	while (sn) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);
		if ((sn != session) &&
		    (sn->ipaddr == session->ipaddr) &&
		    (sn->local_ipaddr == session->local_ipaddr) &&
		    (strcasecmp(sn->workstation, session->workstation) == 0) &&
		    (sn->opentime <= session->opentime) &&
		    (sn->s_kid < session->s_kid)) {
			tsignal(sn->s_thread, SIGINT);
		}
		sn = list_next(&se->se_act.lst, sn);
	}
	rw_exit(&se->se_lock);
}

/*
 * Send a session message - supports SMB-over-NBT and SMB-over-TCP.
 *
 * The mbuf chain is copied into a contiguous buffer so that the whole
 * message is submitted to smb_sosend as a single request.  This should
 * help Ethereal/Wireshark delineate the packets correctly even though
 * TCP_NODELAY has been set on the socket.
 *
 * If an mbuf chain is provided, it will be freed and set to NULL here.
 */
int
smb_session_send(smb_session_t *session, uint8_t type, mbuf_chain_t *mbc)
{
	smb_txreq_t	*txr;
	smb_xprt_t	hdr;
	int		rc;

	switch (session->s_state) {
	case SMB_SESSION_STATE_DISCONNECTED:
	case SMB_SESSION_STATE_TERMINATED:
		if ((mbc != NULL) && (mbc->chain != NULL)) {
			m_freem(mbc->chain);
			mbc->chain = NULL;
			mbc->flags = 0;
		}
		return (ENOTCONN);
	default:
		break;
	}

	txr = smb_net_txr_alloc();

	if ((mbc != NULL) && (mbc->chain != NULL)) {
		rc = mbc_moveout(mbc, (caddr_t)&txr->tr_buf[NETBIOS_HDR_SZ],
		    sizeof (txr->tr_buf) - NETBIOS_HDR_SZ, &txr->tr_len);
		if (rc != 0) {
			smb_net_txr_free(txr);
			return (rc);
		}
	}

	hdr.xh_type = type;
	hdr.xh_length = (uint32_t)txr->tr_len;

	rc = smb_session_xprt_puthdr(session, &hdr, txr->tr_buf,
	    NETBIOS_HDR_SZ);

	if (rc != 0) {
		smb_net_txr_free(txr);
		return (rc);
	}
	txr->tr_len += NETBIOS_HDR_SZ;
	return (smb_net_txr_send(session->sock, &session->s_txlst, txr));
}

/*
 * Read, process and respond to a NetBIOS session request.
 *
 * A NetBIOS session must be established for SMB-over-NetBIOS.  Validate
 * the calling and called name format and save the client NetBIOS name,
 * which is used when a NetBIOS session is established to check for and
 * cleanup leftover state from a previous session.
 *
 * Session requests are not valid for SMB-over-TCP, which is unfortunate
 * because without the client name leftover state cannot be cleaned up
 * if the client is behind a NAT server.
 */
static int
smb_session_request(struct smb_session *session)
{
	int			rc;
	char			*calling_name;
	char			*called_name;
	char 			client_name[NETBIOS_NAME_SZ];
	struct mbuf_chain 	mbc;
	char 			*names = NULL;
	mts_wchar_t		*wbuf = NULL;
	smb_xprt_t		hdr;
	char *p;
	unsigned int cpid = oem_get_smb_cpid();
	int rc1, rc2;

	session->keep_alive = smb_keep_alive;

	if ((rc = smb_session_xprt_gethdr(session, &hdr)) != 0)
		return (rc);

	DTRACE_PROBE2(receive__session__req__xprthdr, struct session *, session,
	    smb_xprt_t *, &hdr);

	if ((hdr.xh_type != SESSION_REQUEST) ||
	    (hdr.xh_length != NETBIOS_SESSION_REQUEST_DATA_LENGTH)) {
		DTRACE_PROBE1(receive__session__req__failed,
		    struct session *, session);
		return (EINVAL);
	}

	names = kmem_alloc(hdr.xh_length, KM_SLEEP);

	if ((rc = smb_sorecv(session->sock, names, hdr.xh_length)) != 0) {
		kmem_free(names, hdr.xh_length);
		DTRACE_PROBE1(receive__session__req__failed,
		    struct session *, session);
		return (rc);
	}

	DTRACE_PROBE3(receive__session__req__data, struct session *, session,
	    char *, names, uint32_t, hdr.xh_length);

	called_name = &names[0];
	calling_name = &names[NETBIOS_ENCODED_NAME_SZ + 2];

	rc1 = netbios_name_isvalid(called_name, 0);
	rc2 = netbios_name_isvalid(calling_name, client_name);

	if (rc1 == 0 || rc2 == 0) {

		DTRACE_PROBE3(receive__invalid__session__req,
		    struct session *, session, char *, names,
		    uint32_t, hdr.xh_length);

		kmem_free(names, hdr.xh_length);
		MBC_INIT(&mbc, MAX_DATAGRAM_LENGTH);
		(void) smb_mbc_encodef(&mbc, "b",
		    DATAGRAM_INVALID_SOURCE_NAME_FORMAT);
		(void) smb_session_send(session, NEGATIVE_SESSION_RESPONSE,
		    &mbc);
		return (EINVAL);
	}

	DTRACE_PROBE3(receive__session__req__calling__decoded,
	    struct session *, session,
	    char *, calling_name, char *, client_name);

	/*
	 * The client NetBIOS name is in oem codepage format.
	 * We need to convert it to unicode and store it in
	 * multi-byte format.  We also need to strip off any
	 * spaces added as part of the NetBIOS name encoding.
	 */
	wbuf = kmem_alloc((SMB_PI_MAX_HOST * sizeof (mts_wchar_t)), KM_SLEEP);
	(void) oemstounicodes(wbuf, client_name, SMB_PI_MAX_HOST, cpid);
	(void) mts_wcstombs(session->workstation, wbuf, SMB_PI_MAX_HOST);
	kmem_free(wbuf, (SMB_PI_MAX_HOST * sizeof (mts_wchar_t)));

	if ((p = strchr(session->workstation, ' ')) != 0)
		*p = '\0';

	kmem_free(names, hdr.xh_length);
	return (smb_session_send(session, POSITIVE_SESSION_RESPONSE, NULL));
}

/*
 * Read 4-byte header from the session socket and build an in-memory
 * session transport header.  See smb_xprt_t definition for header
 * format information.
 *
 * Direct hosted NetBIOS-less SMB (SMB-over-TCP) uses port 445.  The
 * first byte of the four-byte header must be 0 and the next three
 * bytes contain the length of the remaining data.
 */
int
smb_session_xprt_gethdr(smb_session_t *session, smb_xprt_t *ret_hdr)
{
	int		rc;
	unsigned char	buf[NETBIOS_HDR_SZ];

	if ((rc = smb_sorecv(session->sock, buf, NETBIOS_HDR_SZ)) != 0)
		return (rc);

	switch (session->s_local_port) {
	case SSN_SRVC_TCP_PORT:
		ret_hdr->xh_type = buf[0];
		ret_hdr->xh_length = (((uint32_t)buf[1] & 1) << 16) |
		    ((uint32_t)buf[2] << 8) |
		    ((uint32_t)buf[3]);
		break;

	case SMB_SRVC_TCP_PORT:
		ret_hdr->xh_type = buf[0];

		if (ret_hdr->xh_type != 0) {
			cmn_err(CE_WARN, "0x%08x: invalid type (%u)",
			    session->ipaddr, ret_hdr->xh_type);
			return (EPROTO);
		}

		ret_hdr->xh_length = ((uint32_t)buf[1] << 16) |
		    ((uint32_t)buf[2] << 8) |
		    ((uint32_t)buf[3]);
		break;

	default:
		cmn_err(CE_WARN, "0x%08x: invalid port %u",
		    session->ipaddr, session->s_local_port);
		return (EPROTO);
	}

	return (0);
}

/*
 * Encode a transport session packet header into a 4-byte buffer.
 * See smb_xprt_t definition for header format information.
 */
static int
smb_session_xprt_puthdr(smb_session_t *session, smb_xprt_t *hdr,
    uint8_t *buf, size_t buflen)
{
	if (session == NULL || hdr == NULL ||
	    buf == NULL || buflen < NETBIOS_HDR_SZ) {
		return (-1);
	}

	switch (session->s_local_port) {
	case SSN_SRVC_TCP_PORT:
		buf[0] = hdr->xh_type;
		buf[1] = ((hdr->xh_length >> 16) & 1);
		buf[2] = (hdr->xh_length >> 8) & 0xff;
		buf[3] = hdr->xh_length & 0xff;
		break;

	case SMB_SRVC_TCP_PORT:
		buf[0] = hdr->xh_type;
		buf[1] = (hdr->xh_length >> 16) & 0xff;
		buf[2] = (hdr->xh_length >> 8) & 0xff;
		buf[3] = hdr->xh_length & 0xff;
		break;

	default:
		cmn_err(CE_WARN, "0x%08x: invalid port (%u)",
		    session->ipaddr, session->s_local_port);
		return (-1);
	}

	return (0);
}

static void
smb_request_init_command_mbuf(smb_request_t *sr)
{
	MGET(sr->command.chain, 0, MT_DATA);

	/*
	 * Setup mbuf, mimic MCLGET but use the complete packet buffer.
	 */
	sr->command.chain->m_ext.ext_buf = sr->sr_request_buf;
	sr->command.chain->m_data = sr->command.chain->m_ext.ext_buf;
	sr->command.chain->m_len = sr->sr_req_length;
	sr->command.chain->m_flags |= M_EXT;
	sr->command.chain->m_ext.ext_size = sr->sr_req_length;
	sr->command.chain->m_ext.ext_ref = &mclrefnoop;

	/*
	 * Initialize the rest of the mbuf_chain fields
	 */
	sr->command.flags = 0;
	sr->command.shadow_of = 0;
	sr->command.max_bytes = sr->sr_req_length;
	sr->command.chain_offset = 0;
}

/*
 * smb_request_cancel
 *
 * Handle a cancel for a request properly depending on the current request
 * state.
 */
void
smb_request_cancel(smb_request_t *sr)
{
	mutex_enter(&sr->sr_mutex);
	switch (sr->sr_state) {

	case SMB_REQ_STATE_SUBMITTED:
	case SMB_REQ_STATE_ACTIVE:
	case SMB_REQ_STATE_CLEANED_UP:
		sr->sr_state = SMB_REQ_STATE_CANCELED;
		break;

	case SMB_REQ_STATE_WAITING_LOCK:
		/*
		 * This request is waiting on a lock.  Wakeup everything
		 * waiting on the lock so that the relevant thread regains
		 * control and notices that is has been canceled.  The
		 * other lock request threads waiting on this lock will go
		 * back to sleep when they discover they are still blocked.
		 */
		sr->sr_state = SMB_REQ_STATE_CANCELED;

		ASSERT(sr->sr_awaiting != NULL);
		mutex_enter(&sr->sr_awaiting->l_mutex);
		cv_broadcast(&sr->sr_awaiting->l_cv);
		mutex_exit(&sr->sr_awaiting->l_mutex);

		break;

	case SMB_REQ_STATE_WAITING_EVENT:
	case SMB_REQ_STATE_EVENT_OCCURRED:
		/*
		 * Cancellations for these states are handled by the
		 * notify-change code
		 */
		break;

	case SMB_REQ_STATE_COMPLETED:
	case SMB_REQ_STATE_CANCELED:
		/*
		 * No action required for these states since the request
		 * is completing.
		 */
		break;
	/*
	 * Cases included:
	 *	SMB_REQ_STATE_FREE:
	 *	SMB_REQ_STATE_INITIALIZING:
	 */
	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&sr->sr_mutex);
}

/*
 * This is the entry point for processing SMB messages over NetBIOS or
 * SMB-over-TCP.
 *
 * NetBIOS connections require a session request to establish a session
 * on which to send session messages.
 *
 * Session requests are not valid on SMB-over-TCP.  We don't need to do
 * anything here as session requests will be treated as an error when
 * handling session messages.
 */
int
smb_session_daemon(smb_session_list_t *se)
{
	int		rc = 0;
	smb_session_t	*session;

	session = smb_session_list_activate_head(se);
	if (session == NULL)
		return (EINVAL);

	if (session->s_local_port == SSN_SRVC_TCP_PORT) {
		rc = smb_session_request(session);
		if (rc) {
			smb_rwx_rwenter(&session->s_lock, RW_WRITER);
			session->s_state = SMB_SESSION_STATE_DISCONNECTED;
			smb_rwx_rwexit(&session->s_lock);
			smb_session_list_terminate(se, session);
			return (rc);
		}
	}

	smb_rwx_rwenter(&session->s_lock, RW_WRITER);
	session->s_state = SMB_SESSION_STATE_ESTABLISHED;
	smb_rwx_rwexit(&session->s_lock);

	rc = smb_session_message(session);

	smb_rwx_rwenter(&session->s_lock, RW_WRITER);
	session->s_state = SMB_SESSION_STATE_DISCONNECTED;
	smb_rwx_rwexit(&session->s_lock);

	smb_soshutdown(session->sock);

	DTRACE_PROBE2(session__drop, struct session *, session, int, rc);

	smb_session_cancel(session);

	/*
	 * At this point everything related to the session should have been
	 * cleaned up and we expect that nothing will attempt to use the
	 * socket.
	 */
	smb_session_list_terminate(se, session);

	return (rc);
}

/*
 * Read and process SMB requests.
 *
 * Returns:
 *	0	Success
 *	1	Unable to read transport header
 *	2	Invalid transport header type
 *	3	Invalid SMB length (too small)
 *	4	Unable to read SMB header
 *	5	Invalid SMB header (bad magic number)
 *	6	Unable to read SMB data
 *	2x	Write raw failed
 */
static int
smb_session_message(smb_session_t *session)
{
	smb_request_t	*sr = NULL;
	smb_xprt_t	hdr;
	uint8_t		*req_buf;
	uint32_t	resid;
	int		rc;

	for (;;) {

		rc = smb_session_xprt_gethdr(session, &hdr);
		if (rc)
			return (rc);

		DTRACE_PROBE2(session__receive__xprthdr, session_t *, session,
		    smb_xprt_t *, &hdr);

		if (hdr.xh_type != SESSION_MESSAGE) {
			/*
			 * Anything other than SESSION_MESSAGE or
			 * SESSION_KEEP_ALIVE is an error.  A SESSION_REQUEST
			 * may indicate a new session request but we need to
			 * close this session and we can treat it as an error
			 * here.
			 */
			if (hdr.xh_type == SESSION_KEEP_ALIVE) {
				session->keep_alive = smb_keep_alive;
				continue;
			}
			return (EPROTO);
		}

		if (hdr.xh_length < SMB_HEADER_LEN)
			return (EPROTO);

		session->keep_alive = smb_keep_alive;

		/*
		 * Allocate a request context, read the SMB header and validate
		 * it. The sr includes a buffer large enough to hold the SMB
		 * request payload.  If the header looks valid, read any
		 * remaining data.
		 */
		sr = smb_request_alloc(session, hdr.xh_length);

		req_buf = (uint8_t *)sr->sr_request_buf;
		resid = hdr.xh_length;

		rc = smb_sorecv(session->sock, req_buf, SMB_HEADER_LEN);
		if (rc) {
			smb_request_free(sr);
			return (rc);
		}

		if (SMB_PROTOCOL_MAGIC_INVALID(sr)) {
			smb_request_free(sr);
			return (EPROTO);
		}

		if (resid > SMB_HEADER_LEN) {
			req_buf += SMB_HEADER_LEN;
			resid -= SMB_HEADER_LEN;

			rc = smb_sorecv(session->sock, req_buf, resid);
			if (rc) {
				smb_request_free(sr);
				return (rc);
			}
		}

		/*
		 * Initialize command MBC to represent the received data.
		 */
		smb_request_init_command_mbuf(sr);

		DTRACE_PROBE1(session__receive__smb, smb_request_t *, sr);

		/*
		 * If this is a raw write, hand off the request.  The handler
		 * will retrieve the remaining raw data and process the request.
		 */
		if (SMB_IS_WRITERAW(sr)) {
			rc = smb_handle_write_raw(session, sr);
			/* XXX smb_request_free(sr); ??? */
			return (rc);
		}

		sr->sr_state = SMB_REQ_STATE_SUBMITTED;
		(void) taskq_dispatch(session->s_server->sv_thread_pool,
		    smb_session_worker, sr, TQ_SLEEP);
	}
}

/*
 * Port will be SSN_SRVC_TCP_PORT or SMB_SRVC_TCP_PORT.
 */
smb_session_t *
smb_session_create(struct sonode *new_so, uint16_t port, smb_server_t *sv)
{
	uint32_t		ipaddr;
	uint32_t		local_ipaddr;
	struct sockaddr_in	sin;
	smb_session_t		*session;

	session = kmem_cache_alloc(sv->si_cache_session, KM_SLEEP);
	bzero(session, sizeof (smb_session_t));

	if (smb_idpool_constructor(&session->s_uid_pool)) {
		kmem_cache_free(sv->si_cache_session, session);
		return (NULL);
	}

	session->s_kid = SMB_NEW_KID();
	session->s_state = SMB_SESSION_STATE_INITIALIZED;
	session->native_os = NATIVE_OS_UNKNOWN;
	session->opentime = lbolt64;
	session->keep_alive = smb_keep_alive;
	session->activity_timestamp = lbolt64;

	smb_slist_constructor(&session->s_req_list, sizeof (smb_request_t),
	    offsetof(smb_request_t, sr_session_lnd));

	smb_llist_constructor(&session->s_user_list, sizeof (smb_user_t),
	    offsetof(smb_user_t, u_lnd));

	smb_llist_constructor(&session->s_xa_list, sizeof (smb_xa_t),
	    offsetof(smb_xa_t, xa_lnd));

	smb_net_txl_constructor(&session->s_txlst);

	smb_rwx_init(&session->s_lock);

	if (new_so) {
		bcopy(new_so->so_faddr_sa, &sin, new_so->so_faddr_len);
		ipaddr = sin.sin_addr.s_addr;
		bcopy(new_so->so_laddr_sa, &sin, new_so->so_faddr_len);
		local_ipaddr = sin.sin_addr.s_addr;
		session->s_local_port = port;
		session->ipaddr = ipaddr;
		session->local_ipaddr = local_ipaddr;
		session->sock = new_so;
	}

	session->s_server = sv;
	smb_server_get_cfg(sv, &session->s_cfg);
	session->s_cache_request = sv->si_cache_request;
	session->s_cache = sv->si_cache_session;
	session->s_magic = SMB_SESSION_MAGIC;
	return (session);
}

void
smb_session_delete(smb_session_t *session)
{
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);

	session->s_magic = (uint32_t)~SMB_SESSION_MAGIC;

	smb_rwx_destroy(&session->s_lock);
	smb_net_txl_destructor(&session->s_txlst);
	smb_slist_destructor(&session->s_req_list);
	smb_llist_destructor(&session->s_user_list);
	smb_llist_destructor(&session->s_xa_list);

	ASSERT(session->s_tree_cnt == 0);
	ASSERT(session->s_file_cnt == 0);
	ASSERT(session->s_dir_cnt == 0);

	smb_idpool_destructor(&session->s_uid_pool);
	kmem_cache_free(session->s_cache, session);
}

void
smb_session_cancel(smb_session_t *session)
{
	smb_xa_t	*xa, *nextxa;

	/* All the request currently being treated must be canceled. */
	smb_session_cancel_requests(session, NULL, NULL);

	/*
	 * We wait for the completion of all the requests associated with
	 * this session.
	 */
	smb_slist_wait_for_empty(&session->s_req_list);

	/*
	 * At this point the reference count of the users, trees, files,
	 * directories should be zero. It should be possible to destroy them
	 * without any problem.
	 */
	xa = smb_llist_head(&session->s_xa_list);
	while (xa) {
		nextxa = smb_llist_next(&session->s_xa_list, xa);
		smb_xa_close(xa);
		xa = nextxa;
	}
	smb_user_logoff_all(session);
}

/*
 * Cancel requests.  If a non-null tree is specified, only requests specific
 * to that tree will be cancelled.  If a non-null sr is specified, that sr
 * will be not be cancelled - this would typically be the caller's sr.
 */
void
smb_session_cancel_requests(
    smb_session_t	*session,
    smb_tree_t		*tree,
    smb_request_t	*exclude_sr)
{
	smb_request_t	*sr;

	smb_process_session_notify_change_queue(session, tree);

	smb_slist_enter(&session->s_req_list);
	sr = smb_slist_head(&session->s_req_list);

	while (sr) {
		ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
		if ((sr != exclude_sr) &&
		    (tree == NULL || sr->tid_tree == tree))
			smb_request_cancel(sr);

		sr = smb_slist_next(&session->s_req_list, sr);
	}

	smb_slist_exit(&session->s_req_list);
}

void
smb_session_worker(
    void	*arg)
{
	smb_request_t	*sr;

	sr = (smb_request_t *)arg;

	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);


	mutex_enter(&sr->sr_mutex);
	switch (sr->sr_state) {
	case SMB_REQ_STATE_SUBMITTED:
		mutex_exit(&sr->sr_mutex);
		if (smb_dispatch_request(sr)) {
			mutex_enter(&sr->sr_mutex);
			sr->sr_state = SMB_REQ_STATE_COMPLETED;
			mutex_exit(&sr->sr_mutex);
			smb_request_free(sr);
		}
		break;

	default:
		ASSERT(sr->sr_state == SMB_REQ_STATE_CANCELED);
		sr->sr_state = SMB_REQ_STATE_COMPLETED;
		mutex_exit(&sr->sr_mutex);
		smb_request_free(sr);
		break;
	}
}

/*
 * smb_session_disconnect_share
 *
 * Disconnects the specified share. This function should be called after the
 * share passed in has been made unavailable by the "share manager".
 */
void
smb_session_disconnect_share(smb_session_list_t *se, char *sharename)
{
	smb_session_t	*session;

	rw_enter(&se->se_lock, RW_READER);
	session = list_head(&se->se_act.lst);
	while (session) {
		ASSERT(session->s_magic == SMB_SESSION_MAGIC);
		smb_rwx_rwenter(&session->s_lock, RW_READER);
		switch (session->s_state) {
		case SMB_SESSION_STATE_NEGOTIATED:
		case SMB_SESSION_STATE_OPLOCK_BREAKING:
		case SMB_SESSION_STATE_WRITE_RAW_ACTIVE: {
			smb_user_t	*user;
			smb_user_t	*next;

			user = smb_user_lookup_by_state(session, NULL);
			while (user) {
				smb_user_disconnect_share(user, sharename);
				next = smb_user_lookup_by_state(session, user);
				smb_user_release(user);
				user = next;
			}
			break;

		}
		default:
			break;
		}
		smb_rwx_rwexit(&session->s_lock);
		session = list_next(&se->se_act.lst, session);
	}
	rw_exit(&se->se_lock);
}

void
smb_session_list_constructor(smb_session_list_t *se)
{
	bzero(se, sizeof (*se));
	rw_init(&se->se_lock, NULL, RW_DEFAULT, NULL);
	list_create(&se->se_rdy.lst, sizeof (smb_session_t),
	    offsetof(smb_session_t, s_lnd));
	list_create(&se->se_act.lst, sizeof (smb_session_t),
	    offsetof(smb_session_t, s_lnd));
}

void
smb_session_list_destructor(smb_session_list_t *se)
{
	list_destroy(&se->se_rdy.lst);
	list_destroy(&se->se_act.lst);
	rw_destroy(&se->se_lock);
}

void
smb_session_list_append(smb_session_list_t *se, smb_session_t *session)
{
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);
	ASSERT(session->s_state == SMB_SESSION_STATE_INITIALIZED);

	rw_enter(&se->se_lock, RW_WRITER);
	list_insert_tail(&se->se_rdy.lst, session);
	se->se_rdy.count++;
	se->se_wrop++;
	rw_exit(&se->se_lock);
}

void
smb_session_list_delete_tail(smb_session_list_t *se)
{
	smb_session_t	*session;

	rw_enter(&se->se_lock, RW_WRITER);
	session = list_tail(&se->se_rdy.lst);
	if (session) {
		ASSERT(session->s_magic == SMB_SESSION_MAGIC);
		ASSERT(session->s_state == SMB_SESSION_STATE_INITIALIZED);
		list_remove(&se->se_rdy.lst, session);
		ASSERT(se->se_rdy.count);
		se->se_rdy.count--;
		rw_exit(&se->se_lock);
		smb_session_delete(session);
		return;
	}
	rw_exit(&se->se_lock);
}

smb_session_t *
smb_session_list_activate_head(smb_session_list_t *se)
{
	smb_session_t	*session;

	rw_enter(&se->se_lock, RW_WRITER);
	session = list_head(&se->se_rdy.lst);
	if (session) {
		ASSERT(session->s_magic == SMB_SESSION_MAGIC);
		smb_rwx_rwenter(&session->s_lock, RW_WRITER);
		ASSERT(session->s_state == SMB_SESSION_STATE_INITIALIZED);
		session->s_thread = curthread;
		session->s_ktdid = session->s_thread->t_did;
		smb_rwx_rwexit(&session->s_lock);
		list_remove(&se->se_rdy.lst, session);
		se->se_rdy.count--;
		list_insert_tail(&se->se_act.lst, session);
		se->se_act.count++;
		se->se_wrop++;
	}
	rw_exit(&se->se_lock);
	return (session);
}

void
smb_session_list_terminate(smb_session_list_t *se, smb_session_t *session)
{
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);

	rw_enter(&se->se_lock, RW_WRITER);

	smb_rwx_rwenter(&session->s_lock, RW_WRITER);
	ASSERT(session->s_state == SMB_SESSION_STATE_DISCONNECTED);
	session->s_state = SMB_SESSION_STATE_TERMINATED;
	smb_sodestroy(session->sock);
	session->sock = NULL;
	smb_rwx_rwexit(&session->s_lock);

	list_remove(&se->se_act.lst, session);
	se->se_act.count--;
	se->se_wrop++;

	ASSERT(session->s_thread == curthread);

	rw_exit(&se->se_lock);

	smb_session_delete(session);
}

/*
 * smb_session_list_signal
 *
 * This function signals all the session threads. The intent is to terminate
 * them. The sessions still in the SMB_SESSION_STATE_INITIALIZED are delete
 * immediately.
 *
 * This function must only be called by the threads listening and accepting
 * connections. They must pass in their respective session list.
 */
void
smb_session_list_signal(smb_session_list_t *se)
{
	smb_session_t	*session;

	rw_enter(&se->se_lock, RW_WRITER);
	while (session = list_head(&se->se_rdy.lst)) {

		ASSERT(session->s_magic == SMB_SESSION_MAGIC);

		smb_rwx_rwenter(&session->s_lock, RW_WRITER);
		ASSERT(session->s_state == SMB_SESSION_STATE_INITIALIZED);
		session->s_state = SMB_SESSION_STATE_TERMINATED;
		smb_sodestroy(session->sock);
		session->sock = NULL;
		smb_rwx_rwexit(&session->s_lock);

		list_remove(&se->se_rdy.lst, session);
		se->se_rdy.count--;
		se->se_wrop++;

		rw_exit(&se->se_lock);
		smb_session_delete(session);
		rw_enter(&se->se_lock, RW_WRITER);
	}
	rw_downgrade(&se->se_lock);

	session = list_head(&se->se_act.lst);
	while (session) {

		ASSERT(session->s_magic == SMB_SESSION_MAGIC);
		tsignal(session->s_thread, SIGINT);
		session = list_next(&se->se_act.lst, session);
	}
	rw_exit(&se->se_lock);
}

/*
 * smb_session_lookup_user
 */
static smb_user_t *
smb_session_lookup_user(smb_session_t *session, char *domain, char *name)
{
	smb_user_t	*user;
	smb_llist_t	*ulist;

	ulist = &session->s_user_list;
	smb_llist_enter(ulist, RW_READER);
	user = smb_llist_head(ulist);
	while (user) {
		ASSERT(user->u_magic == SMB_USER_MAGIC);
		if (!utf8_strcasecmp(user->u_name, name) &&
		    !utf8_strcasecmp(user->u_domain, domain)) {
			mutex_enter(&user->u_mutex);
			if (user->u_state == SMB_USER_STATE_LOGGED_IN) {
				user->u_refcnt++;
				mutex_exit(&user->u_mutex);
				break;
			}
			mutex_exit(&user->u_mutex);
		}
		user = smb_llist_next(ulist, user);
	}
	smb_llist_exit(ulist);

	return (user);
}

/*
 * If a user attempts to log in subsequently from the specified session,
 * duplicates the existing SMB user instance such that all SMB user
 * instances that corresponds to the same user on the given session
 * reference the same user's cred.
 *
 * Returns NULL if the given user hasn't yet logged in from this
 * specified session.  Otherwise, returns a user instance that corresponds
 * to this subsequent login.
 */
smb_user_t *
smb_session_dup_user(smb_session_t *session, char *domain, char *account_name)
{
	smb_user_t *orig_user = NULL;
	smb_user_t *user = NULL;

	orig_user = smb_session_lookup_user(session, domain,
	    account_name);

	if (orig_user) {
		user = smb_user_dup(orig_user);
		smb_user_release(orig_user);
	}

	return (user);
}

/*
 * smb_request_alloc
 *
 * Allocate an smb_request_t structure from the kmem_cache.  Partially
 * initialize the found/new request.
 *
 * Returns pointer to a request
 */
smb_request_t *
smb_request_alloc(smb_session_t *session, int req_length)
{
	smb_request_t	*sr;

	ASSERT(session->s_magic == SMB_SESSION_MAGIC);

	sr = kmem_cache_alloc(session->s_cache_request, KM_SLEEP);

	/*
	 * Future:  Use constructor to pre-initialize some fields.  For now
	 * there are so many fields that it is easiest just to zero the
	 * whole thing and start over.
	 */
	bzero(sr, sizeof (smb_request_t));

	mutex_init(&sr->sr_mutex, NULL, MUTEX_DEFAULT, NULL);
	sr->session = session;
	sr->sr_server = session->s_server;
	sr->sr_gmtoff = session->s_server->si_gmtoff;
	sr->sr_cache = session->s_server->si_cache_request;
	sr->sr_cfg = &session->s_cfg;
	sr->request_storage.forw = &sr->request_storage;
	sr->request_storage.back = &sr->request_storage;
	sr->command.max_bytes = req_length;
	sr->reply.max_bytes = smb_maxbufsize;
	sr->sr_req_length = req_length;
	if (req_length)
		sr->sr_request_buf = kmem_alloc(req_length, KM_SLEEP);
	sr->sr_magic = SMB_REQ_MAGIC;
	sr->sr_state = SMB_REQ_STATE_INITIALIZING;
	smb_slist_insert_tail(&session->s_req_list, sr);
	return (sr);
}

/*
 * smb_request_free
 *
 * release the memories which have been allocated for a smb request.
 */
void
smb_request_free(smb_request_t *sr)
{
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(sr->session);
	ASSERT(sr->fid_ofile == NULL);
	ASSERT(sr->sid_odir == NULL);
	ASSERT(sr->r_xa == NULL);

	if (sr->tid_tree)
		smb_tree_release(sr->tid_tree);

	if (sr->uid_user)
		smb_user_release(sr->uid_user);

	smb_slist_remove(&sr->session->s_req_list, sr);

	sr->session = NULL;

	/* Release any temp storage */
	smbsr_free_malloc_list(&sr->request_storage);

	if (sr->sr_request_buf)
		kmem_free(sr->sr_request_buf, sr->sr_req_length);
	if (sr->command.chain)
		m_freem(sr->command.chain);
	if (sr->reply.chain)
		m_freem(sr->reply.chain);
	if (sr->raw_data.chain)
		m_freem(sr->raw_data.chain);

	sr->sr_magic = 0;
	mutex_destroy(&sr->sr_mutex);
	kmem_cache_free(sr->sr_cache, sr);
}
