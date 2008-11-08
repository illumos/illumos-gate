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
/*
 * SMB: session_setup_andx
 *
 * This SMB is used to further "Set up" the session normally just
 * established via the negotiate protocol.
 *
 * One primary function is to perform a "user logon" in the case where the
 * server is in user level security mode.  The Uid in the SMB header is set
 * by the client to be the userid desired for the AccountName and validated
 * by the AccountPassword.
 *
 * If the negotiated protocol is prior to NT LM 0.12, the format of
 * SMB_COM_SESSION_SETUP_ANDX is:
 *
 * Client Request                 Description
 * ============================== =====================================
 *
 * UCHAR WordCount;               Count of parameter words = 10
 * UCHAR AndXCommand;             Secondary (X) command; 0xFF = none
 * UCHAR AndXReserved;            Reserved (must be 0)
 * USHORT AndXOffset;             Offset to next command WordCount
 * USHORT MaxBufferSize;          Client maximum buffer size
 * USHORT MaxMpxCount;            Actual maximum multiplexed pending
 *                                 requests
 * USHORT VcNumber;               0 = first (only), nonzero=additional
 *                                 VC number
 * ULONG SessionKey;              Session key (valid iff VcNumber != 0)
 * USHORT PasswordLength;         Account password size
 * ULONG Reserved;                Must be 0
 * USHORT ByteCount;              Count of data bytes;    min = 0
 * UCHAR AccountPassword[];       Account Password
 * STRING AccountName[];          Account Name
 * STRING PrimaryDomain[];        Client's primary domain
 * STRING NativeOS[];             Client's native operating system
 * STRING NativeLanMan[];         Client's native LAN Manager type
 *
 * and the response is:
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 3
 * UCHAR AndXCommand;                 Secondary (X) command;  0xFF =
 *                                     none
 * UCHAR AndXReserved;                Reserved (must be 0)
 * USHORT AndXOffset;                 Offset to next command WordCount
 * USHORT Action;                     Request mode:
 *                                     bit0 = logged in as GUEST
 * USHORT ByteCount;                  Count of data bytes
 * STRING NativeOS[];                 Server's native operating system
 * STRING NativeLanMan[];             Server's native LAN Manager type
 * STRING PrimaryDomain[];            Server's primary domain
 *
 * If the server is in "share level security mode", the account name and
 * passwd should be ignored by the server.
 *
 * If challenge/response authentication is not being used, AccountPassword
 * should be a null terminated ASCII string with PasswordLength set to the
 * string size including the null; the password will case insensitive. If
 * challenge/response authentication is being used (see section 2.10), then
 * AccountPassword will be the response to the server's challenge, and
 * PasswordLength should be set to its length.
 *
 * The server validates the name and password supplied and if valid, it
 * registers the user identifier on this session as representing the
 * specified AccountName.  The Uid  field in the SMB header will then be
 * used to validate access on subsequent SMB requests.  The SMB requests
 * where permission checks are required are those which refer to a
 * symbolically named resource such as SMB_COM_OPEN, SMB_COM_RENAME,
 * SMB_COM_DELETE, etc..  The value of the Uid is relative to a specific
 * client/server session so it is possible to have the same Uid value
 * represent two different users on two different sessions at the server.
 *
 * Multiple session setup commands may be sent to register additional users
 * on this session.  If the server receives an additional
 * SMB_COM_SESSION_SETUP_ANDX, only the Uid, AccountName and
 * AccountPassword fields need contain valid values (the server MUST ignore
 * the other fields).
 *
 * The client writes the name of its domain in PrimaryDomain if it knows
 * what the domain name is.  If the domain name is unknown, the client
 * either encodes it as a NULL string, or as a question mark.
 *
 * If bit0 of Action is set, this informs the client that although the
 * server did not recognize the AccountName, it logged the user in as a
 * guest.  This is optional behavior by the server, and in any case one
 * would ordinarily expect guest privileges to limited.
 *
 * Another function of the Session Set Up protocol is to inform the server
 * of the maximum values which will be utilized by this client.  Here
 * MaxBufferSize is the maximum message size which the client can receive.
 * Thus although the server may support 16k buffers (as returned in the
 * SMB_COM_NEGOTIATE response), if the client only has 4k buffers, the
 * value of MaxBufferSize here would be 4096.  The minimum allowable value
 * for MaxBufferSize is 1024.  The SMB_COM_NEGOTIATE response includes the
 * server buffer size supported.  Thus this is the maximum SMB message size
 * which the client can send to the server.  This size may be larger than
 * the size returned to the server from the client via the
 * SMB_COM_SESSION_SETUP_AND X protocol which is the maximum SMB message
 * size which the server may send to the client.  Thus if the server's
 * buffer size were 4k and the client's buffer size were only 2K,  the
 * client could send up to 4k (standard) write requests but must only
 * request up to 2k for (standard) read requests.
 *
 * The field, MaxMpxCount informs the server of the maximum number of
 * requests which the client will have outstanding to the server
 * simultaneously (see sections 5.13 and 5.25).
 *
 * The VcNumber field specifies whether the client wants this to be the
 * first VC or an additional VC.  If the the SMB_COM_SESSION_SETUP_ANDX
 * request contains a VcNumber of 0 and other VCs are still connected to
 * that client, they should be aborted to free any resources held by the
 * server. This condition could occur if the client was rebooted and
 * reconnected to the server before the transport level had informed the
 * server of the previous VC termination. There is more information on
 * VCs in smb_negotiate.c.
 *
 * The values for MaxBufferSize, MaxMpxCount, and VcNumber must be less
 * than or equal to the maximum values supported by the server as returned
 * in the SMB_COM_NEGOTIATE response.
 *
 * If the negotiated SMB dialect is "NT LM 0.12" or later, the format of
 * the response SMB is unchanged, but the request is:
 *
 * Client Request                 Description
 * ============================== =====================================
 *
 * UCHAR WordCount;               Count of parameter words = 13
 * UCHAR AndXCommand;             Secondary (X) command;  0xFF = none
 * UCHAR AndXReserved;            Reserved (must be 0)
 * USHORT AndXOffset;             Offset to next command WordCount
 * USHORT MaxBufferSize;          Client's maximum buffer size
 * USHORT MaxMpxCount;            Actual maximum multiplexed pending
 *                                 requests
 * USHORT VcNumber;               0 = first (only), nonzero=additional
 *                                 VC number
 * ULONG SessionKey;              Session key (valid iff VcNumber != 0)
 * USHORT                         Account password size, ANSI
 * CaseInsensitivePasswordLength;
 * USHORT                         Account password size, Unicode
 * CaseSensitivePasswordLength;
 * ULONG Reserved;                must be 0
 * ULONG Capabilities;            Client capabilities
 * USHORT ByteCount;              Count of data bytes;    min = 0
 * UCHAR                          Account Password, ANSI
 * CaseInsensitivePassword[];
 * UCHAR CaseSensitivePassword[]; Account Password, Unicode
 * STRING AccountName[];          Account Name, Unicode
 * STRING PrimaryDomain[];        Client's primary domain, Unicode
 * STRING NativeOS[];             Client's native operating system,
 *                                 Unicode
 * STRING NativeLanMan[];         Client's native LAN Manager type,
 *                                 Unicode
 *
 * The client expresses its capabilities to the server encoded in the
 * Capabilities field:
 *
 * Capability Name           Encoding  Description
 * ========================  ========= ================================
 *
 * CAP_UNICODE               0x0004    The client can use UNICODE
 *                                      strings
 * CAP_LARGE_FILES           0x0008    The client can deal with files
 *                                      having 64 bit offsets
 * CAP_NT_SMBS               0x0010    The client understands the SMBs
 *                                      introduced with the NT LM 0.12
 *                                      dialect.  Implies CAP_NT_FIND.
 * CAP_NT_FIND               0x0200
 * CAP_STATUS32              0x0040    The client can receive 32 bit
 *                                      errors encoded in Status.Status
 * CAP_LEVEL_II_OPLOCKS      0x0080    The client understands Level II
 *                                      oplocks
 *
 * The entire message sent and received including the optional ANDX SMB
 * must fit in the negotiated maximum transfer size.  The following are the
 * only valid SMB commands for AndXCommand for SMB_COM_SESSION_SETUP_ANDX
 *
 * SMB_COM_TREE_CONNECT_ANDX     SMB_COM_OPEN
 * SMB_COM_OPEN_ANDX             SMB_COM_CREATE
 * SMB_COM_CREATE_NEW            SMB_COM_CREATE_DIRECTORY
 * SMB_COM_DELETE                SMB_COM_DELETE_DIRECTORY
 * SMB_COM_FIND                  SMB_COM_FIND_UNIQUE
 * SMB_COM_COPY                  SMB_COM_RENAME
 * SMB_COM_NT_RENAME             SMB_COM_CHECK_DIRECTORY
 * SMB_COM_QUERY_INFORMATION     SMB_COM_SET_INFORMATION
 * SMB_COM_NO_ANDX_COMMAND       SMB_COM_OPEN_PRINT_FILE
 * SMB_COM_GET_PRINT_QUEUE       SMB_COM_TRANSACTION
 *
 * 4.1.2.1   Errors
 *
 * ERRSRV/ERRerror     - no NEG_PROT issued
 * ERRSRV/ERRbadpw     - password not correct for given user name
 * ERRSRV/ERRtoomanyuids    - maximum number of users per session exceeded
 * ERRSRV/ERRnosupport - chaining of this request to the previous one is
 * not supported
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/smb_door_svc.h>

smb_sdrc_t
smb_pre_session_setup_andx(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SessionSetupX__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_session_setup_andx(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SessionSetupX__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_session_setup_andx(smb_request_t *sr)
{
	uint16_t maxbufsize, maxmpxcount, vcnumber = 0;
	uint32_t sesskey;
	uint32_t capabilities = 0;
	char *username = "";
	char *userdomain = "";
	char *native_os = "";
	char *native_lanman = "";
	char *hostname = sr->sr_cfg->skc_hostname;
	char *nbdomain = sr->sr_cfg->skc_nbdomain;
#ifdef FIX_6765156
	char *fqdn = sr->sr_cfg->skc_fqdn;
#endif
	smb_token_t *usr_token = NULL;
	smb_user_t *user = NULL;
	int security = sr->sr_cfg->skc_secmode;

	uint16_t ci_pwlen = 0;
	unsigned char *ci_password = NULL;
	uint16_t cs_pwlen = 0;
	unsigned char *cs_password = NULL;

	netr_client_t clnt_info;
	smb_session_key_t *session_key = NULL;
	int rc;
	char ipaddr_buf[INET6_ADDRSTRLEN];
	boolean_t known_domain;

	if (sr->session->dialect >= NT_LM_0_12) {
		rc = smbsr_decode_vwv(sr, "b.wwwwlww4.l", &sr->andx_com,
		    &sr->andx_off, &maxbufsize, &maxmpxcount, &vcnumber,
		    &sesskey, &ci_pwlen, &cs_pwlen, &capabilities);

		if (rc != 0)
			return (SDRC_ERROR);

		ci_password = kmem_alloc(ci_pwlen + 1, KM_SLEEP);
		cs_password = kmem_alloc(cs_pwlen + 1, KM_SLEEP);

		/*
		 * The padding between the Native OS and Native LM is a
		 * bit strange. On NT4.0, there is a 2 byte pad between
		 * the OS (Windows NT 1381) and LM (Windows NT 4.0).
		 * On Windows 2000, there is no padding between the OS
		 * (Windows 2000 2195) and LM (Windows 2000 5.0).
		 *
		 * If the padding is removed from this decode string
		 * the NT4.0 LM comes out as an empty string.
		 *
		 * So if the client's native OS is Win NT we consider
		 * the padding otherwise we don't.
		 */
		rc = smbsr_decode_data(sr, "%#c#cuuu",
		    sr,
		    ci_pwlen, ci_password,
		    cs_pwlen, cs_password,
		    &username,
		    &userdomain,
		    &native_os);

		if (rc != 0) {
			kmem_free(ci_password, ci_pwlen + 1);
			kmem_free(cs_password, cs_pwlen + 1);
			return (SDRC_ERROR);
		}

		ci_password[ci_pwlen] = 0;
		cs_password[cs_pwlen] = 0;

		sr->session->native_os = smbnative_os_value(native_os);

		if (sr->session->native_os == NATIVE_OS_WINNT)
			rc = smbsr_decode_data(sr, "%,u", sr, &native_lanman);
		else
			rc = smbsr_decode_data(sr, "%u", sr, &native_lanman);

		/*
		 * Native Lanman could be null so we really don't care
		 * if above decode fails, but to have a valid value for
		 * the field we set it to Win NT.
		 */
		if (rc != 0)
			native_lanman = "NT LAN Manager 4.0";

	} else {
		rc = smbsr_decode_vwv(sr, "b.wwwwlw4.", &sr->andx_com,
		    &sr->andx_off, &maxbufsize, &maxmpxcount,
		    &vcnumber, &sesskey, &ci_pwlen);

		if (rc != 0)
			return (SDRC_ERROR);

		ci_password = kmem_alloc(ci_pwlen + 1, KM_SLEEP);
		rc = smbsr_decode_data(sr, "%#c", sr, ci_pwlen, ci_password);
		if (rc != 0) {
			kmem_free(ci_password, ci_pwlen + 1);
			return (SDRC_ERROR);
		}

		ci_password[ci_pwlen] = 0;

		/*
		 * Despite the CIFS/1.0 spec, the rest of this message is
		 * not always present. We need to try to get the account
		 * name and the primary domain but we don't care about the
		 * the native OS or native LanMan fields.
		 */
		if (smbsr_decode_data(sr, "%u", sr, &username) != 0)
			username = "";

		if (smbsr_decode_data(sr, "%u", sr, &userdomain) != 0)
			userdomain = "";

		sr->session->native_os = NATIVE_OS_UNKNOWN;
	}

	/*
	 * If the vcnumber is zero, we can discard any
	 * other connections associated with this client.
	 */
	sr->session->vcnumber = vcnumber;
	if (vcnumber == 0)
		smb_server_reconnection_check(sr->sr_server, sr->session);

	sr->session->smb_msg_size = maxbufsize;

	bzero(&clnt_info, sizeof (netr_client_t));

	/*
	 * Both local and domain users can be authenticated in
	 * domain mode. Whether a user is local or not is determined
	 * by given domain name in the request. If client does not
	 * specify the domain name, both local and domain
	 * authentications should be tried. The preferred order is to
	 * try the local authentication first.
	 */
	known_domain = B_TRUE;
	if (*userdomain == 0) {
		userdomain = hostname;
		if (security == SMB_SECMODE_DOMAIN)
			known_domain = B_FALSE;
	}

	if ((cs_pwlen == 0) &&
	    (ci_pwlen == 0 || (ci_pwlen == 1 && *ci_password == 0))) {
		/* anonymous user */
		clnt_info.flags |= NETR_CFLG_ANON;
		username = "nobody";
	} else if (*username == '\0') {
		if (ci_password)
			kmem_free(ci_password, ci_pwlen + 1);
		if (cs_password)
			kmem_free(cs_password, cs_pwlen + 1);
		smbsr_error(sr, 0, ERRSRV, ERRaccess);
		return (SDRC_ERROR);
#ifndef FIX_6765156
	} else if (utf8_strcasecmp(userdomain, hostname) == 0) {
		/*
		 * When domain name is equal to hostname, it means
		 * the user is local even if system is running in
		 * domain mode, so perform a local logon.
		 */
		clnt_info.flags |= NETR_CFLG_LOCAL;
#endif
	} else if (security == SMB_SECMODE_DOMAIN) {
#ifdef FIX_6765156
		/*
		 * If the system is running in domain mode, domain
		 * authentication will be performed only when the client
		 * sends the domain that matches either the NetBIOS name
		 * or FQDN of the domain. Otherwise, local authentication
		 * will be performed.
		 */
		if (utf8_strcasecmp(userdomain, nbdomain) == 0 ||
		    utf8_strcasecmp(userdomain, fqdn) == 0)
			clnt_info.flags |= NETR_CFLG_DOMAIN;
		else
			clnt_info.flags |= NETR_CFLG_LOCAL;
#else
		clnt_info.flags |= NETR_CFLG_DOMAIN;
#endif
	} else if (security == SMB_SECMODE_WORKGRP) {
		clnt_info.flags |= NETR_CFLG_LOCAL;
	}

	/*
	 * If the domain is unknown, we are unable to determine
	 * whether the specified user is local or domain until
	 * the authentication has taken place; thus, the user
	 * lookup will be postponed until the user is successfully
	 * authenticated.
	 */
	if (known_domain)
		user = smb_session_dup_user(sr->session,
		    (clnt_info.flags & NETR_CFLG_LOCAL) ?
		    hostname : nbdomain, username);

	if (user == NULL) {
		cred_t		*cr;
		uint32_t	privileges;

		clnt_info.logon_level = NETR_NETWORK_LOGON;
		clnt_info.domain = userdomain;
		clnt_info.username = username;
		clnt_info.workstation = sr->session->workstation;
		clnt_info.ipaddr = sr->session->ipaddr;
		clnt_info.local_ipaddr = sr->session->local_ipaddr;
		clnt_info.challenge_key.challenge_key_val =
		    sr->session->challenge_key;
		clnt_info.challenge_key.challenge_key_len =
		    sr->session->challenge_len;
		clnt_info.nt_password.nt_password_val = cs_password;
		clnt_info.nt_password.nt_password_len = cs_pwlen;
		clnt_info.lm_password.lm_password_val = ci_password;
		clnt_info.lm_password.lm_password_len = ci_pwlen;
		clnt_info.native_os = sr->session->native_os;
		clnt_info.native_lm = smbnative_lm_value(native_lanman);
		clnt_info.local_port = sr->session->s_local_port;

		DTRACE_PROBE1(smb__sessionsetup__clntinfo, netr_client_t *,
		    &clnt_info);

		usr_token = smb_upcall_get_token(&clnt_info);

		/*
		 * If the domain is unknown and we fail to authenticate
		 * the user locally, pass-through authentication will be
		 * attempted.
		 */
		if (!known_domain) {
			if (usr_token == NULL) {
				clnt_info.domain = nbdomain;
				clnt_info.flags &= ~NETR_CFLG_LOCAL;
				clnt_info.flags |= NETR_CFLG_DOMAIN;
				usr_token = smb_upcall_get_token(&clnt_info);
			}

			/*
			 * Now that the user has successfully been
			 * authenticated, the clnt_info.domain is valid.
			 * Try to see if the user has already logged in from
			 * this session.
			 *
			 * If this is a subsequent login, a duplicate user
			 * instance will be returned. Otherwise, NULL is
			 * returned.
			 */
			if (usr_token != NULL)
				user = smb_session_dup_user(sr->session,
				    clnt_info.domain, username);
		}


		/* authentication fails */
		if (usr_token == NULL) {
			if (ci_password)
				kmem_free(ci_password, ci_pwlen + 1);
			if (cs_password)
				kmem_free(cs_password, cs_pwlen + 1);
			smbsr_error(sr, 0, ERRSRV, ERRbadpw);
			return (SDRC_ERROR);
		}

		if (usr_token->tkn_session_key) {
			session_key = kmem_alloc(sizeof (smb_session_key_t),
			    KM_SLEEP);
			(void) memcpy(session_key, usr_token->tkn_session_key,
			    sizeof (smb_session_key_t));
		}

		/* first login */
		if (user == NULL) {
			cr = smb_cred_create(usr_token, &privileges);
			if (cr != NULL) {
				user = smb_user_login(sr->session, cr,
				    usr_token->tkn_domain_name,
				    usr_token->tkn_account_name,
				    usr_token->tkn_flags,
				    privileges,
				    usr_token->tkn_audit_sid);
				smb_cred_rele(user->u_cred);

				if (user->u_privcred)
					smb_cred_rele(user->u_privcred);
			}
		}
		smb_token_free(usr_token);
	}

	if (ci_password)
		kmem_free(ci_password, ci_pwlen + 1);

	if (user == NULL) {
		if (session_key)
			kmem_free(session_key, sizeof (smb_session_key_t));
		if (cs_password)
			kmem_free(cs_password, cs_pwlen + 1);
		smbsr_error(sr, 0, ERRDOS, ERROR_INVALID_HANDLE);
		return (SDRC_ERROR);
	}

	sr->user_cr = user->u_cred;
	sr->smb_uid = user->u_uid;
	sr->uid_user = user;
	sr->session->capabilities = capabilities;

	/*
	 * Check to see if SMB signing is enable, but if it is already turned
	 * on leave it.
	 * The first authenticated logon provides the MAC key and sequence
	 * numbers for signing all further session on the
	 * same network connection.
	 */
	if (!(sr->session->signing.flags & SMB_SIGNING_ENABLED) &&
	    (sr->session->secmode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED) &&
	    (sr->smb_flg2 & SMB_FLAGS2_SMB_SECURITY_SIGNATURE) &&
	    session_key)
		smb_sign_init(sr, session_key, (char *)cs_password, cs_pwlen);

	if (cs_password)
		kmem_free(cs_password, cs_pwlen + 1);

	if (session_key)
		kmem_free(session_key, sizeof (smb_session_key_t));

	if (!(sr->smb_flg2 & SMB_FLAGS2_SMB_SECURITY_SIGNATURE) &&
	    (sr->sr_cfg->skc_signing_required)) {
		(void) inet_ntop(AF_INET, (char *)&sr->session->ipaddr,
		    ipaddr_buf, sizeof (ipaddr_buf));
		cmn_err(CE_NOTE,
		    "SmbSessonSetupX: client %s is not capable of signing",
		    ipaddr_buf);
		smbsr_error(sr, NT_STATUS_LOGON_FAILURE,
		    ERRDOS, ERROR_LOGON_FAILURE);
		return (SDRC_ERROR);
	}

	/*
	 * NT systems use different native OS and native LanMan values
	 * dependent on whether they are acting as a client or a server.
	 * As a server, NT 4.0 responds with the following values:
	 *
	 *	NativeOS:	Windows NT 4.0
	 *	NativeLM:	NT LAN Manager 4.0
	 *
	 * We should probably use the same values as NT but this code has
	 * been using the product name and "Windows NT 4.0" for a long time
	 * and I don't know if a change would cause any problems (see the
	 * conditional test below).
	 */
	rc = smbsr_encode_result(sr, 3, VAR_BCC, "bb.www%uuu",
	    3,
	    sr->andx_com,
	    -1,			/* andx_off */
	    ((user->u_flags & SMB_USER_FLAG_GUEST) ? 1 : 0),
	    VAR_BCC,
	    sr,
	    "Windows NT 4.0",
	    "NT LAN Manager 4.0",
	    nbdomain);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
