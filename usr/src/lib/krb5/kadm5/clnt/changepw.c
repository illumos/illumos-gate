/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/os/changepw.c
 *
 * Copyright 1990,1999 by the Massachusetts Institute of Technology.
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

#define	NEED_SOCKETS
#include <k5-int.h>
#include <kadm5/admin.h>
#include <client_internal.h>
#include <gssapi/gssapi.h>
#include <gssapi_krb5.h>
#include <gssapiP_krb5.h>
#include <krb5.h>

/* #include "adm_err.h" */
#include <stdio.h>
#include <errno.h>

extern krb5_error_code krb5int_mk_chpw_req(krb5_context  context,
					krb5_auth_context auth_context,
					krb5_data *ap_req, char *passwd,
					krb5_data *packet);

extern krb5_error_code krb5int_rd_chpw_rep(krb5_context context,
					krb5_auth_context auth_context,
					krb5_data *packet, int *result_code,
					krb5_data *result_data);

/*
 * _kadm5_get_kpasswd_protocol
 *
 * returns the password change protocol value to the caller.
 * Since the 'handle' is an opaque value to higher up callers,
 * this method is needed to provide a way for them to get a peek
 * at the protocol being used without having to expose the entire
 * handle structure.
 */
krb5_chgpwd_prot
_kadm5_get_kpasswd_protocol(void *handle)
{
	kadm5_server_handle_t srvrhdl = (kadm5_server_handle_t)handle;

	return (srvrhdl->params.kpasswd_protocol);
}

/*
 * krb5_change_password
 *
 * Prepare and send a CHANGEPW request to a password server
 * using UDP datagrams.  This is only used for sending to
 * non-SEAM servers which support the Marc Horowitz defined
 * protocol (1998) for password changing.
 *
 * SUNW14resync - added _local as it conflicts with one in krb5.h
 */
static krb5_error_code
krb5_change_password_local(context, params, creds, newpw, srvr_rsp_code,
		    srvr_msg)
krb5_context context;
kadm5_config_params *params;
krb5_creds *creds;
char *newpw;
kadm5_ret_t *srvr_rsp_code;
krb5_data *srvr_msg;
{
	krb5_auth_context auth_context;
	krb5_data ap_req, chpw_req, chpw_rep;
	krb5_address local_kaddr, remote_kaddr;
	krb5_error_code code = 0;
	int i, addrlen;
	struct sockaddr *addr_p, local_addr, remote_addr, tmp_addr;
	struct sockaddr_in *sin_p;
	struct hostent *hp;
	int naddr_p;
	int cc, local_result_code, tmp_len;
	SOCKET s1 = INVALID_SOCKET;
	SOCKET s2 = INVALID_SOCKET;


	/* Initialize values so that cleanup call can safely check for NULL */
	auth_context = NULL;
	addr_p = NULL;
	memset(&chpw_req, 0, sizeof (krb5_data));
	memset(&chpw_rep, 0, sizeof (krb5_data));
	memset(&ap_req, 0, sizeof (krb5_data));

	/* initialize auth_context so that we know we have to free it */
	if ((code = krb5_auth_con_init(context, &auth_context)))
		goto cleanup;

	if (code = krb5_mk_req_extended(context, &auth_context,
					AP_OPTS_USE_SUBKEY,
					NULL, creds, &ap_req))
		goto cleanup;

	/*
	 * find the address of the kpasswd_server.
	 */
	addr_p = (struct sockaddr *)malloc(sizeof (struct sockaddr));
	if (!addr_p)
		goto cleanup;
	memset(addr_p, 0, sizeof (struct sockaddr));
	if ((hp = gethostbyname(params->kpasswd_server)) == NULL) {
		code = KRB5_REALM_CANT_RESOLVE;
		goto cleanup;
	}
	sin_p = (struct sockaddr_in *)addr_p;
	memset((char *)sin_p, 0, sizeof (struct sockaddr));
	sin_p->sin_family = hp->h_addrtype;
	sin_p->sin_port = htons(params->kpasswd_port);
	memcpy((char *)&sin_p->sin_addr, (char *)hp->h_addr, hp->h_length);
	naddr_p = 1;


	/*
	 * this is really obscure.  s1 is used for all communications.  it
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

	if ((s1 = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		code = errno;
		goto cleanup;
	}

	if ((s2 = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		code = errno;
		goto cleanup;
	}

	for (i = 0; i < naddr_p; i++)
	{
		fd_set fdset;
		struct timeval timeout;

		if (connect(s2, &addr_p[i], sizeof (addr_p[i])) ==
		    SOCKET_ERROR)
		{
			if ((errno == ECONNREFUSED) ||
			    (errno == EHOSTUNREACH))
				continue; /* try the next addr */

			code = errno;
			goto cleanup;
		}

		addrlen = sizeof (local_addr);

		if (getsockname(s2, &local_addr, &addrlen) < 0)
		{
			if ((errno == ECONNREFUSED) ||
			    (errno == EHOSTUNREACH))
				continue; /* try the next addr */

			code = errno;
			goto cleanup;
		}

		/*
		 * some brain-dead OS's don't return useful information from
		 * the getsockname call.  Namely, windows and solaris.
		 */
		if (((struct sockaddr_in *)&local_addr)->sin_addr.s_addr != 0)
		{
			local_kaddr.addrtype = ADDRTYPE_INET;
			local_kaddr.length = sizeof (((struct sockaddr_in *)
						    &local_addr)->sin_addr);
			local_kaddr.contents = (krb5_octet *)
				&(((struct sockaddr_in *)
				&local_addr)->sin_addr);
		}
		else
		{
			krb5_address **addrs;

			krb5_os_localaddr(context, &addrs);

			local_kaddr.magic = addrs[0]->magic;
			local_kaddr.addrtype = addrs[0]->addrtype;
			local_kaddr.length = addrs[0]->length;
			local_kaddr.contents = malloc(addrs[0]->length);
			memcpy(local_kaddr.contents, addrs[0]->contents,
			    addrs[0]->length);

			krb5_free_addresses(context, addrs);
		}

		addrlen = sizeof (remote_addr);
		if (getpeername(s2, &remote_addr, &addrlen) < 0)
		{
			if ((errno == ECONNREFUSED) ||
			    (errno == EHOSTUNREACH))
				continue; /* try the next addr */

			code = errno;
			goto cleanup;
		}

		remote_kaddr.addrtype = ADDRTYPE_INET;
		remote_kaddr.length = sizeof (((struct sockaddr_in *)
					    &remote_addr)->sin_addr);
		remote_kaddr.contents = (krb5_octet *)
			&(((struct sockaddr_in *)&remote_addr)->sin_addr);

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

		if (code = krb5_auth_con_setaddrs(context, auth_context,
						&local_kaddr, NULL))
		{
			code = errno;
			goto cleanup;
		}

		if (code = krb5int_mk_chpw_req(context, auth_context,
					    &ap_req, newpw, &chpw_req))
		{
			code = errno;
			goto cleanup;
		}

		if ((cc = sendto(s1, chpw_req.data, chpw_req.length, 0,
		    (struct sockaddr *)&addr_p[i],
		    sizeof (addr_p[i]))) != chpw_req.length)
		{
			if ((cc < 0) && ((errno == ECONNREFUSED) ||
					(errno == EHOSTUNREACH)))
				continue; /* try the next addr */

			code = (cc < 0) ? errno : ECONNABORTED;
			goto cleanup;
		}

		chpw_rep.length = 1500;
		chpw_rep.data = (char *)malloc(chpw_rep.length);

		/* XXX need a timeout/retry loop here */
		FD_ZERO(&fdset);
		FD_SET(s1, &fdset);
		timeout.tv_sec = 120;
		timeout.tv_usec = 0;
		switch (select(s1 + 1, &fdset, 0, 0, &timeout)) {
		case -1:
			code = errno;
			goto cleanup;
		case 0:
			code = ETIMEDOUT;
			goto cleanup;
		default:
			/* fall through */
			;
		}

		tmp_len = sizeof (tmp_addr);
		if ((cc = recvfrom(s1, chpw_rep.data, chpw_rep.length,
				0, &tmp_addr, &tmp_len)) < 0)
		{
			code = errno;
			goto cleanup;
		}

		closesocket(s1);
		s1 = INVALID_SOCKET;
		closesocket(s2);
		s2 = INVALID_SOCKET;

		chpw_rep.length = cc;

		if (code = krb5_auth_con_setaddrs(context, auth_context,
						NULL, &remote_kaddr))
			goto cleanup;

		if (code = krb5int_rd_chpw_rep(context, auth_context, &chpw_rep,
					&local_result_code, srvr_msg))
			goto cleanup;

		if (srvr_rsp_code)
			*srvr_rsp_code = local_result_code;

		code = 0;
		goto cleanup;
	}

	code = errno;

cleanup:
	if (auth_context != NULL)
		krb5_auth_con_free(context, auth_context);

	if (addr_p != NULL)
		krb5_xfree(addr_p);

	if (s1 != INVALID_SOCKET)
		closesocket(s1);

	if (s2 != INVALID_SOCKET)
		closesocket(s2);

	krb5_xfree(chpw_req.data);
	krb5_xfree(chpw_rep.data);
	krb5_xfree(ap_req.data);

	return (code);
}


/*
 * kadm5_chpass_principal_v2
 *
 * New function used to prepare to make the change password request to a
 * non-SEAM admin server.  The protocol used in this case is not based on
 * RPCSEC_GSS, it simply makes the request to port 464 (udp and tcp).
 * This is the same way that MIT KRB5 1.2.1 changes passwords.
 */
kadm5_ret_t
kadm5_chpass_principal_v2(void *server_handle,
			krb5_principal princ,
			char *newpw,
			kadm5_ret_t *srvr_rsp_code,
			krb5_data *srvr_msg)
{
	kadm5_ret_t code;
	kadm5_server_handle_t handle  = (kadm5_server_handle_t)server_handle;
	krb5_error_code result;
	krb5_creds mcreds;
	krb5_creds ncreds;
	krb5_ccache ccache;
	int cpwlen;
	char *cpw_service = NULL;

	/*
	 * The credentials have already been stored in the cache in the
	 * initialization step earlier, but we dont have direct access to it
	 * at this level. Derive the cache and fetch the credentials to use for
	 * sending the request.
	 */
	memset(&mcreds, 0, sizeof (krb5_creds));
	if ((code = krb5_cc_resolve(handle->context, handle->cache_name,
				    &ccache)))
		return (code);

	/* set the client principal in the credential match structure */
	mcreds.client = princ;

	/*
	 * set the server principal (kadmin/changepw@REALM) in the credential
	 * match struct
	 */
	cpwlen = strlen(KADM5_CHANGEPW_SERVICE) +
		strlen(handle->params.realm) + 2;
	cpw_service = malloc(cpwlen);
	if (cpw_service == NULL) {
		return (ENOMEM);
	}

	snprintf(cpw_service, cpwlen, "%s@%s",
		KADM5_CHANGEPW_SERVICE,	handle->params.realm);

	/* generate the server principal from the name string we generated */
	if ((code = krb5_parse_name(handle->context, cpw_service,
		&mcreds.server))) {
		free(cpw_service);
		return (code);
	}

	/* Find the credentials in the cache */
	if ((code = krb5_cc_retrieve_cred(handle->context, ccache, 0, &mcreds,
					&ncreds))) {
		free(cpw_service);
		return (code);
	}

	/* Now we have all we need to make the change request. */
	result = krb5_change_password_local(handle->context, &handle->params,
				    &ncreds, newpw,
				    srvr_rsp_code,
				    srvr_msg);

	free(cpw_service);
	return (result);
}
