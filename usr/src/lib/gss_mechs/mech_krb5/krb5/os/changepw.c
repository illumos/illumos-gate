/*
 * lib/krb5/os/changepw.c
 *
 * Copyright 1990,1999,2001 by the Massachusetts Institute of Technology.
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
 * krb5_set_password - Implements set password per RFC 3244
 * Added by Paul W. Nelson, Thursby Software Systems, Inc.
 * Modified by Todd Stecher, Isilon Systems, to use krb1.4 socket infrastructure
 */

#include "fake-addrinfo.h"
#include "k5-int.h"
#include "os-proto.h"
#include "cm.h"

#include <stdio.h>
#include <errno.h>

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE int
#endif

struct sendto_callback_context {
    krb5_context 	context;
    krb5_auth_context 	auth_context;
    krb5_principal 	set_password_for;
    char 		*newpw;
    krb5_data 		ap_req;
};


/*
 * Wrapper function for the two backends
 */

static krb5_error_code
krb5_locate_kpasswd(krb5_context context, const krb5_data *realm,
		    struct addrlist *addrlist, krb5_boolean useTcp)
{
    krb5_error_code code;
    int sockType = (useTcp ? SOCK_STREAM : SOCK_DGRAM);

    code = krb5int_locate_server (context, realm, addrlist,
				  locate_service_kpasswd, sockType, 0);

    if (code == KRB5_REALM_CANT_RESOLVE || code == KRB5_REALM_UNKNOWN) {
	code = krb5int_locate_server (context, realm, addrlist,
				      locate_service_kadmin, SOCK_STREAM, 0);
	if (!code) {
	    /* Success with admin_server but now we need to change the
	       port number to use DEFAULT_KPASSWD_PORT and the socktype.  */
	    int i;
	    for (i=0; i<addrlist->naddrs; i++) {
		struct addrinfo *a = addrlist->addrs[i].ai;
		if (a->ai_family == AF_INET)
		    sa2sin (a->ai_addr)->sin_port = htons(DEFAULT_KPASSWD_PORT);
		if (sockType != SOCK_STREAM)
		    a->ai_socktype = sockType;
	    }
	}
    }
    return (code);
}


/**
 * This routine is used for a callback in sendto_kdc.c code. Simply
 * put, we need the client addr to build the krb_priv portion of the
 * password request.
 */


static void kpasswd_sendto_msg_cleanup (void* callback_context, krb5_data* message)
{
    struct sendto_callback_context *ctx = callback_context;
    krb5_free_data_contents(ctx->context, message);
}


static int kpasswd_sendto_msg_callback(struct conn_state *conn, void *callback_context, krb5_data* message)
{
    krb5_error_code 			code = 0;
    struct sockaddr_storage 		local_addr;
    krb5_address 			local_kaddr;
    struct sendto_callback_context	*ctx = callback_context;
    GETSOCKNAME_ARG3_TYPE 		addrlen;
    krb5_data				output;

    memset (message, 0, sizeof(krb5_data));

    /*
     * We need the local addr from the connection socket
     */
    addrlen = sizeof(local_addr);

    if (getsockname(conn->fd, ss2sa(&local_addr), &addrlen) < 0) {
	code = SOCKET_ERRNO;
	goto cleanup;
    }

    /* some brain-dead OS's don't return useful information from
     * the getsockname call.  Namely, windows and solaris.  */

    if (ss2sin(&local_addr)->sin_addr.s_addr != 0) {
	local_kaddr.addrtype = ADDRTYPE_INET;
	local_kaddr.length = sizeof(ss2sin(&local_addr)->sin_addr);
	local_kaddr.contents = (krb5_octet *) &ss2sin(&local_addr)->sin_addr;
    } else {
	krb5_address **addrs;

	code = krb5_os_localaddr(ctx->context, &addrs);
	if (code)
	    goto cleanup;

	local_kaddr.magic = addrs[0]->magic;
	local_kaddr.addrtype = addrs[0]->addrtype;
	local_kaddr.length = addrs[0]->length;
	local_kaddr.contents = malloc(addrs[0]->length);
	if (local_kaddr.contents == NULL && addrs[0]->length != 0) {
	    code = errno;
	    krb5_free_addresses(ctx->context, addrs);
	    goto cleanup;
	}
	memcpy(local_kaddr.contents, addrs[0]->contents, addrs[0]->length);

	krb5_free_addresses(ctx->context, addrs);
    }


    /*
     * TBD:  Does this tamper w/ the auth context in such a way
     * to break us?  Yes - provide 1 per conn-state / host...
     */


    if ((code = krb5_auth_con_setaddrs(ctx->context, ctx->auth_context,
				       &local_kaddr, NULL)))
	goto cleanup;

    if (ctx->set_password_for)
	code = krb5int_mk_setpw_req(ctx->context,
				    ctx->auth_context,
				    &ctx->ap_req,
				    ctx->set_password_for,
				    ctx->newpw,
				    &output);
    else
	code = krb5int_mk_chpw_req(ctx->context,
				   ctx->auth_context,
				   &ctx->ap_req,
				   ctx->newpw,
				   &output);
    if (code)
	goto cleanup;

    message->length = output.length;
    message->data = output.data;

cleanup:
    return code;
}


/*
** The logic for setting and changing a password is mostly the same
** krb5_change_set_password handles both cases
**	if set_password_for is NULL, then a password change is performed,
**  otherwise, the password is set for the principal indicated in set_password_for
*/
krb5_error_code KRB5_CALLCONV
krb5_change_set_password(krb5_context context, krb5_creds *creds, char *newpw,
			 krb5_principal set_password_for,
			 int *result_code, krb5_data *result_code_string,
			 krb5_data *result_string)
{
    krb5_data 			chpw_rep;
    krb5_address 		remote_kaddr;
    krb5_boolean		useTcp = 0;
    GETSOCKNAME_ARG3_TYPE 	addrlen;
    krb5_error_code 		code = 0;
    char 			*code_string;
    int				local_result_code;

    struct sendto_callback_context  callback_ctx;
    struct sendto_callback_info	callback_info;
    struct sockaddr_storage	remote_addr;
    struct addrlist 		al = ADDRLIST_INIT;

    memset( &callback_ctx, 0, sizeof(struct sendto_callback_context));
    callback_ctx.context = context;
    callback_ctx.newpw = newpw;
    callback_ctx.set_password_for = set_password_for;

    if ((code = krb5_auth_con_init(callback_ctx.context,
				   &callback_ctx.auth_context)))
	goto cleanup;

    if ((code = krb5_mk_req_extended(callback_ctx.context,
				     &callback_ctx.auth_context,
				     AP_OPTS_USE_SUBKEY,
				     NULL,
				     creds,
				     &callback_ctx.ap_req)))
	goto cleanup;

    do {
	if ((code = krb5_locate_kpasswd(callback_ctx.context,
					krb5_princ_realm(callback_ctx.context,
							 creds->server),
					&al, useTcp)))
	    break;

	addrlen = sizeof(remote_addr);

	callback_info.context = (void*) &callback_ctx;
	callback_info.pfn_callback = kpasswd_sendto_msg_callback;
	callback_info.pfn_cleanup = kpasswd_sendto_msg_cleanup;

	if ((code = krb5int_sendto(callback_ctx.context,
				   NULL,
				   &al,
				   &callback_info,
				   &chpw_rep,
				   NULL,
				   NULL,
				   ss2sa(&remote_addr),
                                   &addrlen,
				   NULL,
				   NULL,
				   NULL
		 ))) {

	    /*
	     * Here we may want to switch to TCP on some errors.
	     * right?
	     */
	    break;
	}

	remote_kaddr.addrtype = ADDRTYPE_INET;
	remote_kaddr.length = sizeof(ss2sin(&remote_addr)->sin_addr);
	remote_kaddr.contents = (krb5_octet *) &ss2sin(&remote_addr)->sin_addr;

	if ((code = krb5_auth_con_setaddrs(callback_ctx.context,
					   callback_ctx.auth_context,
					   NULL,
					   &remote_kaddr)))
	    break;

	if (set_password_for)
	    code = krb5int_rd_setpw_rep(callback_ctx.context,
					callback_ctx.auth_context,
					&chpw_rep,
					&local_result_code,
					result_string);
	else
	    code = krb5int_rd_chpw_rep(callback_ctx.context,
				       callback_ctx.auth_context,
				       &chpw_rep,
				       &local_result_code,
				       result_string);

	if (code) {
	    if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG && !useTcp ) {
		krb5int_free_addrlist (&al);
		useTcp = 1;
		continue;
	    }

	    break;
	}

	if (result_code)
	    *result_code = local_result_code;

	if (result_code_string) {
	    if (set_password_for)
		code = krb5int_setpw_result_code_string(callback_ctx.context,
							local_result_code,
							(const char **)&code_string);
	    else
		code = krb5_chpw_result_code_string(callback_ctx.context,
						    local_result_code,
						    &code_string);
	    if(code)
		goto cleanup;

	    result_code_string->length = strlen(code_string);
	    result_code_string->data = malloc(result_code_string->length);
	    if (result_code_string->data == NULL) {
		code = ENOMEM;
		goto cleanup;
	    }
	    strncpy(result_code_string->data, code_string, result_code_string->length);
	}

	if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG && !useTcp ) {
	    krb5int_free_addrlist (&al);
	    useTcp = 1;
        } else {
	    break;
	}
    } while (TRUE);

cleanup:
    if (callback_ctx.auth_context != NULL)
	krb5_auth_con_free(callback_ctx.context, callback_ctx.auth_context);

    krb5int_free_addrlist (&al);
    krb5_free_data_contents(callback_ctx.context, &callback_ctx.ap_req);

    return(code);
}

krb5_error_code KRB5_CALLCONV
krb5_change_password(krb5_context context, krb5_creds *creds, char *newpw, int *result_code, krb5_data *result_code_string, krb5_data *result_string)
{
	return krb5_change_set_password(
		context, creds, newpw, NULL, result_code, result_code_string, result_string );
}

/*
 * krb5_set_password - Implements set password per RFC 3244
 *
 */

krb5_error_code KRB5_CALLCONV
krb5_set_password(
	krb5_context context,
	krb5_creds *creds,
	char *newpw,
	krb5_principal change_password_for,
	int *result_code, krb5_data *result_code_string, krb5_data *result_string
	)
{
	return krb5_change_set_password(
		context, creds, newpw, change_password_for, result_code, result_code_string, result_string );
}

krb5_error_code KRB5_CALLCONV
krb5_set_password_using_ccache(
	krb5_context context,
	krb5_ccache ccache,
	char *newpw,
	krb5_principal change_password_for,
	int *result_code, krb5_data *result_code_string, krb5_data *result_string
	)
{
    krb5_creds		creds;
    krb5_creds		*credsp;
    krb5_error_code	code;

    /*
    ** get the proper creds for use with krb5_set_password -
    */
    memset (&creds, 0, sizeof(creds));
    /*
    ** first get the principal for the password service -
    */
    code = krb5_cc_get_principal (context, ccache, &creds.client);
    if (!code) {
	code = krb5_build_principal(context, &creds.server,
				    krb5_princ_realm(context, change_password_for)->length,
				    krb5_princ_realm(context, change_password_for)->data,
				    "kadmin", "changepw", NULL);
	if (!code) {
	    code = krb5_get_credentials(context, 0, ccache, &creds, &credsp);
	    if (!code) {
		code = krb5_set_password(context, credsp, newpw, change_password_for,
					 result_code, result_code_string,
					 result_string);
		krb5_free_creds(context, credsp);
	    }
	}
	krb5_free_cred_contents(context, &creds);
    }
    return code;
}
