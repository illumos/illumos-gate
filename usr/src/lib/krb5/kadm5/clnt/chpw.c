/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>

#include <k5-int.h>
#include <kadm5/admin.h>
#include <client_internal.h>
#include <auth_con.h>
#include <locale.h>

/*
 * krb5_mk_chpw_req
 *
 * Generate a CHANGEPW request packet to send to a
 * password server.
 * The format of the packet used here is defined in the
 * Marc Horowitz Password change protocol document (1998)
 * (expired).
 * It is also defined in the latest kerberos passwd set/change
 * protocol IETF draft document by UMich, Cisco, and MS.
 */
krb5_error_code KRB5_CALLCONV
krb5_mk_chpw_req(context, auth_context, ap_req, passwd, packet)
krb5_context context;
krb5_auth_context auth_context;
krb5_data *ap_req;
char *passwd;
krb5_data *packet;
{
	krb5_error_code ret = 0;
	krb5_data clearpw;
	krb5_data cipherpw;
	krb5_replay_data replay;
	char *ptr;

	cipherpw.data = NULL;

	if (ret = krb5_auth_con_setflags(context, auth_context,
					KRB5_AUTH_CONTEXT_DO_SEQUENCE))
		goto cleanup;

	clearpw.length = strlen(passwd);
	clearpw.data = passwd;

	if (ret = krb5_mk_priv(context, auth_context,
			    &clearpw, &cipherpw, &replay))
		goto cleanup;

	packet->length = 6 + ap_req->length + cipherpw.length;
	packet->data = (char *)malloc(packet->length);
	if (packet->data == NULL)
	{
		ret = ENOMEM;
		goto cleanup;
	}
	ptr = packet->data;

	/* length */
	*ptr++ = (packet->length>>8) & 0xff;
	*ptr++ = packet->length & 0xff;

	/*
	 * version == 0x0001 big-endian
	 * NOTE: when MS and MIT start supporting the latest
	 *	version of the passwd change protocol (v2),
	 *	this value will change to 2.
	 */
	*ptr++ = 0;
	*ptr++ = 1;

	/* ap_req length, big-endian */
	*ptr++ = (ap_req->length>>8) & 0xff;
	*ptr++ = ap_req->length & 0xff;

	/* ap-req data */
	memcpy(ptr, ap_req->data, ap_req->length);
	ptr += ap_req->length;

	/* krb-priv of password */
	memcpy(ptr, cipherpw.data, cipherpw.length);

cleanup:
	if (cipherpw.data != NULL)  /* allocated by krb5_mk_priv */
		free(cipherpw.data);

	return (ret);
}

/*
 * krb5_rd_chpw_rep
 *
 * Decode and parse the reply from the CHANGEPW request.
 */
krb5_error_code KRB5_CALLCONV
krb5_rd_chpw_rep(context, auth_context, packet, result_code, result_data)
krb5_context context;
krb5_auth_context auth_context;
krb5_data *packet;
int *result_code;
krb5_data *result_data;
{
	char *ptr;
	int plen, vno;
	krb5_data ap_rep;
	krb5_ap_rep_enc_part *ap_rep_enc;
	krb5_error_code ret;
	krb5_data cipherresult;
	krb5_data clearresult;
	krb5_error *krberror;
	krb5_replay_data replay;
	krb5_keyblock *tmp;
	int local_result_code;

	if (packet->length < 4)
		/*
		 * either this, or the server is printing bad messages,
		 * or the caller passed in garbage
		 */
		return (KRB5KRB_AP_ERR_MODIFIED);

	ptr = packet->data;

	/* verify length */
	plen = (*ptr++ & 0xff);
	plen = (plen<<8) | (*ptr++ & 0xff);

	if (plen != packet->length)
		return (KRB5KRB_AP_ERR_MODIFIED);

	/* verify version number */
	vno = (*ptr++ & 0xff);
	vno = (vno<<8) | (*ptr++ & 0xff);

	/*
	 * when the servers update to v2 of the protocol,
	 * "2" will be a valid version number here
	 */
	if (vno != 1 && vno != 2)
		return (KRB5KDC_ERR_BAD_PVNO);

	/* read, check ap-rep length */
	ap_rep.length = (*ptr++ & 0xff);
	ap_rep.length = (ap_rep.length<<8) | (*ptr++ & 0xff);

	if (ptr + ap_rep.length >= packet->data + packet->length)
		return (KRB5KRB_AP_ERR_MODIFIED);

	if (ap_rep.length) {
		/* verify ap_rep */
		ap_rep.data = ptr;
		ptr += ap_rep.length;

		/*
		 * Save send_subkey to later smash recv_subkey.
		 */
		ret = krb5_auth_con_getsendsubkey(context, auth_context, &tmp);
		if (ret)
			return (ret);

		if (ret = krb5_rd_rep(context, auth_context, &ap_rep,
				    &ap_rep_enc)) {
			krb5_free_keyblock(context, tmp);
			return (ret);
		}

		krb5_free_ap_rep_enc_part(context, ap_rep_enc);

		/* extract and decrypt the result */
		cipherresult.data = ptr;
		cipherresult.length = (packet->data + packet->length) - ptr;

		/*
		 * Smash recv_subkey to be send_subkey, per spec.
		 */
		ret = krb5_auth_con_setrecvsubkey(context, auth_context, tmp);
		krb5_free_keyblock(context, tmp);
		if (ret)
			return (ret);

		ret = krb5_rd_priv(context, auth_context, &cipherresult,
				&clearresult, &replay);

		if (ret)
			return (ret);
	} else {
		cipherresult.data = ptr;
		cipherresult.length = (packet->data + packet->length) - ptr;

		if (ret = krb5_rd_error(context, &cipherresult, &krberror))
			return (ret);

		clearresult = krberror->e_data;
	}

	if (clearresult.length < 2) {
		ret = KRB5KRB_AP_ERR_MODIFIED;
		goto cleanup;
	}

	ptr = clearresult.data;

	local_result_code = (*ptr++ & 0xff);
	local_result_code = (local_result_code<<8) | (*ptr++ & 0xff);

	if (result_code)
		*result_code = local_result_code;

	/*
	 * Make sure the result code is in range for this
	 * protocol.
	 */
	if ((local_result_code < KRB5_KPASSWD_SUCCESS) ||
	    (local_result_code > KRB5_KPASSWD_ETYPE_NOSUPP)) {
		ret = KRB5KRB_AP_ERR_MODIFIED;
		goto cleanup;
	}


	/* all success replies should be authenticated/encrypted */
	if ((ap_rep.length == 0) &&
	    (local_result_code == KRB5_KPASSWD_SUCCESS)) {
		ret = KRB5KRB_AP_ERR_MODIFIED;
		goto cleanup;
	}

	result_data->length = (clearresult.data + clearresult.length) - ptr;

	if (result_data->length) {
		result_data->data = (char *)malloc(result_data->length);
		if (result_data->data == NULL) {
			ret = ENOMEM;
			goto cleanup;
		}
		memcpy(result_data->data, ptr, result_data->length);
	} else {
		result_data->data = NULL;
	}

	ret = 0;

cleanup:
	if (ap_rep.length) {
		krb5_xfree(clearresult.data);
	} else {
		krb5_free_error(context, krberror);
	}

	return (ret);
}
