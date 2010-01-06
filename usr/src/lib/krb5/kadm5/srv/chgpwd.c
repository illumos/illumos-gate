/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/kadm5/srv/chgpwd.c
 *
 * Copyright 1998 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * chgpwd.c - Handles changepw requests issued from non-Solaris krb5 clients.
 */

#include <libintl.h>
#include <locale.h>
#include <kadm5/admin.h>
#include <syslog.h>
#include <krb5/adm_proto.h>

#define	MAXAPREQ 1500

static krb5_error_code
process_chpw_request(krb5_context context, void *server_handle,
			char *realm, int s, krb5_keytab keytab,
			struct sockaddr_in *sin, krb5_data *req,
			krb5_data *rep)
{
	krb5_error_code ret;
	char *ptr;
	int plen, vno;
	krb5_address local_kaddr, remote_kaddr;
	int allocated_mem = 0;
	krb5_data ap_req, ap_rep;
	krb5_auth_context auth_context;
	krb5_principal changepw;
	krb5_ticket *ticket;
	krb5_data cipher, clear;
	struct sockaddr local_addr, remote_addr;
	int addrlen;
	krb5_replay_data replay;
	krb5_error krberror;
	int numresult;
	char strresult[1024];
	char *clientstr;
	size_t clen;
	char *cdots;

	ret = 0;
	rep->length = 0;

	auth_context = NULL;
	changepw = NULL;
	ap_rep.length = 0;
	ap_rep.data = NULL;
	ticket = NULL;
	clear.length = 0;
	clear.data = NULL;
	cipher.length = 0;
	cipher.data = NULL;

	if (req->length < 4) {
		/*
		 * either this, or the server is printing bad messages,
		 * or the caller passed in garbage
		 */
		ret = KRB5KRB_AP_ERR_MODIFIED;
		numresult = KRB5_KPASSWD_MALFORMED;
		(void) strlcpy(strresult, "Request was truncated",
				sizeof (strresult));
		goto chpwfail;
	}

	ptr = req->data;

	/*
	 * Verify length
	 */
	plen = (*ptr++ & 0xff);
	plen = (plen<<8) | (*ptr++ & 0xff);

	if (plen != req->length)
		return (KRB5KRB_AP_ERR_MODIFIED);

	/*
	 * Verify version number
	 */
	vno = (*ptr++ & 0xff);
	vno = (vno<<8) | (*ptr++ & 0xff);

	if (vno != 1) {
		ret = KRB5KDC_ERR_BAD_PVNO;
		numresult = KRB5_KPASSWD_MALFORMED;
		(void) snprintf(strresult, sizeof (strresult),
		    "Request contained unknown protocol version number %d",
		    vno);
		goto chpwfail;
	}

	/*
	 * Read, check ap-req length
	 */
	ap_req.length = (*ptr++ & 0xff);
	ap_req.length = (ap_req.length<<8) | (*ptr++ & 0xff);

	if (ptr + ap_req.length >= req->data + req->length) {
		ret = KRB5KRB_AP_ERR_MODIFIED;
		numresult = KRB5_KPASSWD_MALFORMED;
		(void) strlcpy(strresult, "Request was truncated in AP-REQ",
					sizeof (strresult));
		goto chpwfail;
	}

	/*
	 * Verify ap_req
	 */
	ap_req.data = ptr;
	ptr += ap_req.length;

	if (ret = krb5_auth_con_init(context, &auth_context)) {
		krb5_klog_syslog(LOG_ERR,
				gettext("Change password request failed. "
					"Failed initializing auth context: %s"),
				error_message(ret));
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult, "Failed initializing auth context",
					sizeof (strresult));
		goto chpwfail;
	}

	if (ret = krb5_auth_con_setflags(context, auth_context,
					KRB5_AUTH_CONTEXT_DO_SEQUENCE)) {
		krb5_klog_syslog(LOG_ERR,
				gettext("Change password request failed. "
						"Failed setting auth "
					    "context flags: %s"),
				error_message(ret));
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult, "Failed initializing auth context",
					sizeof (strresult));
		goto chpwfail;
	}

	if (ret = krb5_build_principal(context, &changepw, strlen(realm), realm,
				    "kadmin", "changepw", NULL)) {
		krb5_klog_syslog(LOG_ERR,
			gettext("Change password request failed "
					"Failed to build kadmin/changepw "
					"principal: %s"),
			error_message(ret));
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult,
				"Failed building kadmin/changepw principal",
				sizeof (strresult));
		goto chpwfail;
	}

	ret = krb5_rd_req(context, &auth_context, &ap_req, changepw, keytab,
			NULL, &ticket);

	if (ret) {
		char kt_name[MAX_KEYTAB_NAME_LEN];
		if (krb5_kt_get_name(context, keytab,
				kt_name, sizeof (kt_name)))
			strncpy(kt_name, "default keytab", sizeof (kt_name));

		switch (ret) {
		case KRB5_KT_NOTFOUND:
		krb5_klog_syslog(LOG_ERR,
			gettext("Change password request failed because "
					"keytab entry \"kadmin/changepw\" "
					"is missing from \"%s\""),
			kt_name);
		break;
		case ENOENT:
		krb5_klog_syslog(LOG_ERR,
			gettext("Change password request failed because "
					"keytab file \"%s\" does not exist"),
			kt_name);
		break;
		default:
		krb5_klog_syslog(LOG_ERR,
			gettext("Change password request failed. "
				"Failed to parse Kerberos AP_REQ message: %s"),
			error_message(ret));
		}

		numresult = KRB5_KPASSWD_AUTHERROR;
		(void) strlcpy(strresult, "Failed reading application request",
					sizeof (strresult));
		goto chpwfail;
	}

	/*
	 * Set up address info
	 */
	addrlen = sizeof (local_addr);

	if (getsockname(s, &local_addr, &addrlen) < 0) {
		ret = errno;
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult,
				"Failed getting server internet address",
				sizeof (strresult));
		goto chpwfail;
	}

	/*
	 * Some brain-dead OS's don't return useful information from
	 * the getsockname call.  Namely, windows and solaris.
	 */
	if (((struct sockaddr_in *)&local_addr)->sin_addr.s_addr != 0) {
		local_kaddr.addrtype = ADDRTYPE_INET;
		local_kaddr.length = sizeof (((struct sockaddr_in *)
						&local_addr)->sin_addr);
		/* CSTYLED */
		local_kaddr.contents = (krb5_octet *) &(((struct sockaddr_in *)&local_addr)->sin_addr);
	} else {
		krb5_address **addrs;

		krb5_os_localaddr(context, &addrs);

		local_kaddr.magic = addrs[0]->magic;
		local_kaddr.addrtype = addrs[0]->addrtype;
		local_kaddr.length = addrs[0]->length;
		if ((local_kaddr.contents = malloc(addrs[0]->length)) == 0) {
			ret = errno;
			numresult = KRB5_KPASSWD_HARDERROR;
			(void) strlcpy(strresult,
				"Malloc failed for local_kaddr",
				sizeof (strresult));
			goto chpwfail;
		}

		(void) memcpy(local_kaddr.contents, addrs[0]->contents,
				addrs[0]->length);
		allocated_mem++;

		krb5_free_addresses(context, addrs);
	}

	addrlen = sizeof (remote_addr);

	if (getpeername(s, &remote_addr, &addrlen) < 0) {
		ret = errno;
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult,
				"Failed getting client internet address",
				sizeof (strresult));
		goto chpwfail;
	}

	remote_kaddr.addrtype = ADDRTYPE_INET;
	remote_kaddr.length = sizeof (((struct sockaddr_in *)
					&remote_addr)->sin_addr);
	/* CSTYLED */
	remote_kaddr.contents = (krb5_octet *) &(((struct sockaddr_in *)&remote_addr)->sin_addr);
	remote_kaddr.addrtype = ADDRTYPE_INET;
	remote_kaddr.length = sizeof (sin->sin_addr);
	remote_kaddr.contents = (krb5_octet *) &sin->sin_addr;

	/*
	 * mk_priv requires that the local address be set.
	 * getsockname is used for this.  rd_priv requires that the
	 * remote address be set.  recvfrom is used for this.  If
	 * rd_priv is given a local address, and the message has the
	 * recipient addr in it, this will be checked.  However, there
	 * is simply no way to know ahead of time what address the
	 * message will be delivered *to*.  Therefore, it is important
	 * that either no recipient address is in the messages when
	 * mk_priv is called, or that no local address is passed to
	 * rd_priv.  Both is a better idea, and I have done that.  In
	 * summary, when mk_priv is called, *only* a local address is
	 * specified.  when rd_priv is called, *only* a remote address
	 * is specified.  Are we having fun yet?
	 */
	if (ret = krb5_auth_con_setaddrs(context, auth_context, NULL,
					&remote_kaddr)) {
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult,
				"Failed storing client internet address",
				sizeof (strresult));
		goto chpwfail;
	}

	/*
	 * Verify that this is an AS_REQ ticket
	 */
	if (!(ticket->enc_part2->flags & TKT_FLG_INITIAL)) {
		numresult = KRB5_KPASSWD_AUTHERROR;
		(void) strlcpy(strresult,
				"Ticket must be derived from a password",
				sizeof (strresult));
		goto chpwfail;
	}

	/*
	 * Construct the ap-rep
	 */
	if (ret = krb5_mk_rep(context, auth_context, &ap_rep)) {
		numresult = KRB5_KPASSWD_AUTHERROR;
		(void) strlcpy(strresult,
				"Failed replying to application request",
				sizeof (strresult));
		goto chpwfail;
	}

	/*
	 * Decrypt the new password
	 */
	cipher.length = (req->data + req->length) - ptr;
	cipher.data = ptr;

	if (ret = krb5_rd_priv(context, auth_context, &cipher,
				&clear, &replay)) {
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult, "Failed decrypting request",
					sizeof (strresult));
		goto chpwfail;
	}

	ret = krb5_unparse_name(context, ticket->enc_part2->client, &clientstr);
	if (ret) {
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strcpy(strresult, "Failed decrypting request");
		goto chpwfail;
	}

	/*
	 * Change the password
	 */
	if ((ptr = (char *)malloc(clear.length + 1)) == NULL) {
		ret = errno;
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult, "Malloc failed for ptr",
			sizeof (strresult));
		krb5_free_unparsed_name(context, clientstr);
		goto chpwfail;
	}
	(void) memcpy(ptr, clear.data, clear.length);
	ptr[clear.length] = '\0';

	ret = (kadm5_ret_t)kadm5_chpass_principal_util(server_handle,
						ticket->enc_part2->client,
						ptr, NULL, strresult,
						sizeof (strresult));

	/*
	 * Zap the password
	 */
	(void) memset(clear.data, 0, clear.length);
	(void) memset(ptr, 0, clear.length);
	if (clear.data != NULL) {
		krb5_xfree(clear.data);
		clear.data = NULL;
	}
	free(ptr);
	clear.length = 0;

	clen = strlen(clientstr);
	trunc_name(&clen, &cdots);
	krb5_klog_syslog(LOG_NOTICE, "chpw request from %s for %.*s%s: %s",
		inet_ntoa(((struct sockaddr_in *)&remote_addr)->sin_addr),
		clen, clientstr, cdots, ret ? error_message(ret) : "success");
	krb5_free_unparsed_name(context, clientstr);

	if (ret) {
		if ((ret != KADM5_PASS_Q_TOOSHORT) &&
		    (ret != KADM5_PASS_REUSE) &&
		    (ret != KADM5_PASS_Q_CLASS) &&
		    (ret != KADM5_PASS_Q_DICT) &&
		    (ret != KADM5_PASS_TOOSOON))
			numresult = KRB5_KPASSWD_HARDERROR;
		else
			numresult = KRB5_KPASSWD_SOFTERROR;
		/*
		 * strresult set by kadb5_chpass_principal_util()
		 */
		goto chpwfail;
	}

	/*
	 * Success!
	 */
	numresult = KRB5_KPASSWD_SUCCESS;
	(void) strlcpy(strresult, "", sizeof (strresult));

chpwfail:

	clear.length = 2 + strlen(strresult);
	if (clear.data != NULL) {
		krb5_xfree(clear.data);
		clear.data = NULL;
	}
	if ((clear.data = (char *)malloc(clear.length)) == NULL) {
		ret = errno;
		numresult = KRB5_KPASSWD_HARDERROR;
		(void) strlcpy(strresult, "Malloc failed for clear.data",
			sizeof (strresult));
	}

	ptr = clear.data;

	*ptr++ = (numresult>>8) & 0xff;
	*ptr++ = numresult & 0xff;

	(void) memcpy(ptr, strresult, strlen(strresult));

	cipher.length = 0;

	if (ap_rep.length) {
		if (ret = krb5_auth_con_setaddrs(context, auth_context,
					&local_kaddr, NULL)) {
		    numresult = KRB5_KPASSWD_HARDERROR;
		    (void) strlcpy(strresult,
			"Failed storing client and server internet addresses",
			sizeof (strresult));
		} else {
			if (ret = krb5_mk_priv(context, auth_context, &clear,
						&cipher, &replay)) {
				numresult = KRB5_KPASSWD_HARDERROR;
				(void) strlcpy(strresult,
					"Failed encrypting reply",
					sizeof (strresult));
			}
		}
	}

	/*
	 * If no KRB-PRIV was constructed, then we need a KRB-ERROR.
	 * If this fails, just bail.  There's nothing else we can do.
	 */
	if (cipher.length == 0) {
		/*
		 * Clear out ap_rep now, so that it won't be inserted
		 * in the reply
		 */
		if (ap_rep.length) {
			if (ap_rep.data != NULL)
				krb5_xfree(ap_rep.data);
			ap_rep.data = NULL;
			ap_rep.length = 0;
		}

		krberror.ctime = 0;
		krberror.cusec = 0;
		krberror.susec = 0;
		if (ret = krb5_timeofday(context, &krberror.stime))
			goto bailout;

		/*
		 * This is really icky.  but it's what all the other callers
		 * to mk_error do.
		 */
		krberror.error = ret;
		krberror.error -= ERROR_TABLE_BASE_krb5;
		if (krberror.error < 0 || krberror.error > 128)
			krberror.error = KRB_ERR_GENERIC;

		krberror.client = NULL;
		if (ret = krb5_build_principal(context, &krberror.server,
					    strlen(realm), realm,
					    "kadmin", "changepw", NULL)) {
			goto bailout;
		}

		krberror.text.length = 0;
		krberror.e_data = clear;

		ret = krb5_mk_error(context, &krberror, &cipher);

		krb5_free_principal(context, krberror.server);

		if (ret)
			goto bailout;
	}

	/*
	 * Construct the reply
	 */
	rep->length = 6 + ap_rep.length + cipher.length;
	if ((rep->data = (char *)malloc(rep->length)) == NULL)  {
		ret = errno;
		goto bailout;
	}
	ptr = rep->data;

	/*
	 * Length
	 */
	*ptr++ = (rep->length>>8) & 0xff;
	*ptr++ = rep->length & 0xff;

	/*
	 * Version == 0x0001 big-endian
	 */
	*ptr++ = 0;
	*ptr++ = 1;

	/*
	 * ap_rep length, big-endian
	 */
	*ptr++ = (ap_rep.length>>8) & 0xff;
	*ptr++ = ap_rep.length & 0xff;

	/*
	 * ap-rep data
	 */
	if (ap_rep.length) {
		(void) memcpy(ptr, ap_rep.data, ap_rep.length);
		ptr += ap_rep.length;
	}

	/*
	 * krb-priv or krb-error
	 */
	(void) memcpy(ptr, cipher.data, cipher.length);

bailout:
	if (auth_context)
		krb5_auth_con_free(context, auth_context);
	if (changepw)
		krb5_free_principal(context, changepw);
	if (ap_rep.data != NULL)
		krb5_xfree(ap_rep.data);
	if (ticket)
		krb5_free_ticket(context, ticket);
	if (clear.data != NULL)
		krb5_xfree(clear.data);
	if (cipher.data != NULL)
		krb5_xfree(cipher.data);
	if (allocated_mem)
		krb5_xfree(local_kaddr.contents);

	return (ret);
}


/*
 * This routine is used to handle password-change requests received
 * on kpasswd-port 464 from MIT/M$ clients.
 */
void
handle_chpw(krb5_context context, int s1,
		void *serverhandle, kadm5_config_params *params)
{
	krb5_error_code ret;
	char req[MAXAPREQ];
	int len;
	struct sockaddr_in from;
	int fromlen;
	krb5_keytab kt;
	krb5_data reqdata, repdata;
	int s2 = -1;

	reqdata.length = 0;
	reqdata.data = NULL;
	repdata.length = 0;
	repdata.data = NULL;

	fromlen = sizeof (from);

	if ((len = recvfrom(s1, req, sizeof (req), 0, (struct sockaddr *)&from,
			    &fromlen)) < 0) {
		krb5_klog_syslog(LOG_ERR, gettext("chpw: Couldn't receive "
				"request: %s"), error_message(errno));
		return;
	}

	/*
	 * Solaris Kerberos:
	 * The only caller is kadmind, which is the master and therefore has the
	 * correct keys in the KDB, rather than obtaining them via the
	 * kadm5.keytab, by default.
	 */
	if ((ret = krb5_kt_resolve(context, "KDB:", &kt))) {
		krb5_klog_syslog(LOG_ERR, gettext("chpw: Couldn't open "
				"admin keytab %s"), error_message(ret));
		return;
	}

	reqdata.length = len;
	reqdata.data = req;

	/*
	 * This is really obscure.  s1 is used for all communications.  it
	 * is left unconnected in case the server is multihomed and routes
	 * are asymmetric.  s2 is connected to resolve routes and get
	 * addresses.  this is the *only* way to get proper addresses for
	 * multihomed hosts if routing is asymmetric.
	 *
	 * A related problem in the server, but not the client, is that
	 * many os's have no way to disconnect a connected udp socket, so
	 * the s2 socket needs to be closed and recreated for each
	 * request.  The s1 socket must not be closed, or else queued
	 * requests will be lost.
	 *
	 * A "naive" client implementation (one socket, no connect,
	 * hostname resolution to get the local ip addr) will work and
	 * interoperate if the client is single-homed.
	 */

	if ((s2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		krb5_klog_syslog(LOG_ERR, gettext("chpw: Cannot create "
				"connecting socket: %s"), error_message(errno));
		goto cleanup;
	}

	if (connect(s2, (struct sockaddr *)&from, sizeof (from)) < 0) {
		krb5_klog_syslog(LOG_ERR, gettext("chpw: Couldn't connect "
				"to client: %s"), error_message(errno));
		if (s2 > 0)
			(void) close(s2);
		goto cleanup;
	}

	if ((ret = process_chpw_request(context, serverhandle,
					params->realm, s2, kt, &from,
					&reqdata, &repdata))) {
		krb5_klog_syslog(LOG_ERR, gettext("chpw: Error processing "
				"request: %s"), error_message(ret));
	}

	if (s2 > 0)
		(void) close(s2);

	if (repdata.length == 0 || repdata.data == NULL) {
		/*
		 * Just return.  This means something really bad happened
		 */
		goto cleanup;
	}

	len = sendto(s1, repdata.data, repdata.length, 0,
		    (struct sockaddr *)&from, sizeof (from));

	if (len < repdata.length) {
		krb5_xfree(repdata.data);

		krb5_klog_syslog(LOG_ERR, gettext("chpw: Error sending reply:"
				" %s"), error_message(errno));
		goto cleanup;
	}

	if (repdata.data != NULL)
		krb5_xfree(repdata.data);
cleanup:
	krb5_kt_close(context, kt);
}
