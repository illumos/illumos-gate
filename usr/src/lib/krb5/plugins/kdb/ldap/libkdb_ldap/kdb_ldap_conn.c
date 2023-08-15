/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/kdb/kdb_ldap/kdb_ldap_conn.c
 *
 * Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "autoconf.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ldap_main.h"
#include "ldap_service_stash.h"
#include <kdb5.h>
#include <libintl.h>

static krb5_error_code
krb5_validate_ldap_context(krb5_context context, krb5_ldap_context *ldap_context)
{
    krb5_error_code             st=0;
    unsigned char               *password=NULL;

    if (ldap_context->bind_dn == NULL) {
	st = EINVAL;
	/* Solaris Kerberos: Keep error messages consistent */
	krb5_set_error_message(context, st, gettext("LDAP bind dn value missing"));
	goto err_out;
    }

    if (ldap_context->bind_pwd == NULL && ldap_context->service_password_file == NULL) {
	st = EINVAL;
	/* Solaris Kerberos: Keep error messages consistent */
	krb5_set_error_message(context, st, gettext("LDAP bind password value missing"));
	goto err_out;
    }

    if (ldap_context->bind_pwd == NULL && ldap_context->service_password_file !=
	NULL && ldap_context->service_cert_path == NULL) {
	if ((st=krb5_ldap_readpassword(context, ldap_context, &password)) != 0) {
	    prepend_err_str(context, gettext("Error reading password from stash: "), st, st);
	    goto err_out;
	}

	/* Check if the returned 'password' is actually the path of a certificate */
	if (!strncmp("{FILE}", (char *)password, 6)) {
	    /* 'password' format: <path>\0<password> */
	    ldap_context->service_cert_path = strdup((char *)password + strlen("{FILE}"));
	    if (ldap_context->service_cert_path == NULL) {
		st = ENOMEM;
		krb5_set_error_message(context, st, gettext("Error: memory allocation failed"));
		goto err_out;
	    }
	    if (password[strlen((char *)password) + 1] == '\0')
		ldap_context->service_cert_pass = NULL;
	    else {
		ldap_context->service_cert_pass = strdup((char *)password +
							 strlen((char *)password) + 1);
		if (ldap_context->service_cert_pass == NULL) {
		    st = ENOMEM;
		    krb5_set_error_message(context, st, gettext("Error: memory allocation failed"));
		    goto err_out;
		}
	    }
	    free(password);
	} else {
	    ldap_context->bind_pwd = (char *)password;
	    if (ldap_context->bind_pwd == NULL) {
		st = EINVAL;
		krb5_set_error_message(context, st, gettext("Error reading password from stash"));
		goto err_out;
	    }
	}
    }

    /* NULL password not allowed */
    if (ldap_context->bind_pwd != NULL && strlen(ldap_context->bind_pwd) == 0) {
	st = EINVAL;
	krb5_set_error_message(context, st, gettext("Service password length is zero"));
	goto err_out;
    }

err_out:
    return st;
}

/*
 * Internal Functions called by init functions.
 */

static krb5_error_code
krb5_ldap_bind(ldap_context, ldap_server_handle)
    krb5_ldap_context           *ldap_context;
    krb5_ldap_server_handle     *ldap_server_handle;
{
    krb5_error_code             st=0;
    struct berval               bv={0, NULL}, *servercreds=NULL;

    if (ldap_context->service_cert_path != NULL) {
	/* Certificate based bind (SASL EXTERNAL mechanism) */

	st = ldap_sasl_bind_s(ldap_server_handle->ldap_handle,
			      NULL,	   /* Authenticating dn */
			      LDAP_SASL_EXTERNAL,  /* Method used for authentication */
			      &bv,
			      NULL,
			      NULL,
			      &servercreds);

	while (st == LDAP_SASL_BIND_IN_PROGRESS) {
	    st = ldap_sasl_bind_s(ldap_server_handle->ldap_handle,
				  NULL,
				  LDAP_SASL_EXTERNAL,
				  servercreds,
				  NULL,
				  NULL,
				  &servercreds);
	}
    } else {
	/* password based simple bind */
        bv.bv_val = ldap_context->bind_pwd;
        bv.bv_len = strlen(ldap_context->bind_pwd);
        st = ldap_sasl_bind_s(ldap_server_handle->ldap_handle,
                                ldap_context->bind_dn,
                                LDAP_SASL_SIMPLE, &bv, NULL,
                                NULL, NULL);
    }
    return st;
}

static krb5_error_code
krb5_ldap_initialize(ldap_context, server_info)
    krb5_ldap_context *ldap_context;
    krb5_ldap_server_info *server_info;
{
    krb5_error_code             st=0;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    char			*errstr = NULL;


    ldap_server_handle = calloc(1, sizeof(krb5_ldap_server_handle));
    if (ldap_server_handle == NULL) {
	st = ENOMEM;
	goto err_out;
    }
    else {
	/*
	 * Solaris Kerbreros: need ldap_handle to be NULL so calls to
	 * ldap_initialize won't leak handles
	 */
	ldap_server_handle->ldap_handle = NULL;
    }

    if (strncasecmp(server_info->server_name, "ldapi:", 6) == 0) {
	/*
	 * Solaris Kerberos: ldapi is not supported on Solaris at this time.
	 * return an error.
	 */
	if (ldap_context->kcontext)
	    krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
		gettext("ldapi is not supported"));
	st = KRB5_KDB_ACCESS_ERROR;
	goto err_out;
    } else {
	/*
	 * Solaris Kerbreros: need to use SSL to protect LDAP simple and
	 * External binds.
	 */
	if (ldap_context->root_certificate_file == NULL) {
	    if (ldap_context->kcontext)
		krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
		    gettext("ldap_cert_path not set, can not create SSL connection"));
	    st = KRB5_KDB_ACCESS_ERROR;
	    goto err_out;
	}

	/* setup for SSL */
	if ((st = ldapssl_client_init(ldap_context->root_certificate_file, NULL)) < 0) {
	    if (ldap_context->kcontext)
		krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR, "%s",
		    ldapssl_err2string(st));
	    st = KRB5_KDB_ACCESS_ERROR;
	    goto err_out;
	}

	/* ldap init, use SSL */
	if ((st = ldap_initialize(&ldap_server_handle->ldap_handle,
				    server_info->server_name, SSL_ON, &errstr)) != LDAP_SUCCESS) {
	    if (ldap_context->kcontext) {
		krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR, "%s",
		    errstr);
	    }
	    st = KRB5_KDB_ACCESS_ERROR;
	    goto err_out;
	}

	if (ldap_context->service_cert_path != NULL) {
	    /*
	     * Solaris Kerbreros: for LDAP_SASL_EXTERNAL bind which requires the
	     * client offer its cert to the server.
	     */
	    if ((st = ldapssl_enable_clientauth(ldap_server_handle->ldap_handle,
					NULL, ldap_context->service_cert_pass,
					"XXX WAF need cert nickname/label")) < 0) {
		if (ldap_context->kcontext) {
		    krb5_set_error_message (ldap_context->kcontext,
					    KRB5_KDB_ACCESS_ERROR, "%s",
					    ldap_err2string(st));
		}
		st = KRB5_KDB_ACCESS_ERROR;
		goto err_out;
	    }
	}
    }

    if ((st=krb5_ldap_bind(ldap_context, ldap_server_handle)) == 0) {
	ldap_server_handle->server_info_update_pending = FALSE;
	server_info->server_status = ON;
	krb5_update_ldap_handle(ldap_server_handle, server_info);
    } else {
	if (ldap_context->kcontext)
	    /* Solaris Kerberos: Better error message */
	    krb5_set_error_message (ldap_context->kcontext,
				    KRB5_KDB_ACCESS_ERROR,
				    gettext("Failed to bind to ldap server \"%s\": %s"),
				    server_info->server_name, ldap_err2string(st));
	st = KRB5_KDB_ACCESS_ERROR;
	server_info->server_status = OFF;
	time(&server_info->downtime);
	(void)ldap_unbind_s(ldap_server_handle->ldap_handle);
	free(ldap_server_handle);
    }

err_out:
    return st;
}

/*
 * initialization for data base routines.
 */

krb5_error_code
krb5_ldap_db_init(krb5_context context, krb5_ldap_context *ldap_context)
{
    krb5_error_code             st=0;
    krb5_boolean                sasl_mech_supported=TRUE;
    int                         cnt=0, version=LDAP_VERSION3;
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    struct timeval              local_timelimit = {10,0};
#elif defined LDAP_X_OPT_CONNECT_TIMEOUT
    int              		local_timelimit = 1000; /* Solaris Kerberos: 1 second */
#endif

    if ((st=krb5_validate_ldap_context(context, ldap_context)) != 0)
	goto err_out;

    ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &version);
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, &local_timelimit);
#elif defined LDAP_X_OPT_CONNECT_TIMEOUT
    ldap_set_option(NULL, LDAP_X_OPT_CONNECT_TIMEOUT, &local_timelimit);
#endif

    HNDL_LOCK(ldap_context);
    while (ldap_context->server_info_list[cnt] != NULL) {
	krb5_ldap_server_info *server_info=NULL;

	server_info = ldap_context->server_info_list[cnt];

	if (server_info->server_status == NOTSET) {
	    int conns=0;

	    /*
	     * Check if the server has to perform certificate-based authentication
	     */
	    if (ldap_context->service_cert_path != NULL) {
		/* Find out if the server supports SASL EXTERNAL mechanism */
		if (has_sasl_external_mech(context, server_info->server_name) == 1) {
		    cnt++;
		    sasl_mech_supported = FALSE;
		    continue; /* Check the next LDAP server */
		}
		sasl_mech_supported = TRUE;
	    }

	    krb5_clear_error_message(context);

	    for (conns=0; conns < ldap_context->max_server_conns; ++conns) {
		if ((st=krb5_ldap_initialize(ldap_context, server_info)) != 0)
		    break;
	    } /* for (conn= ... */

	    if (server_info->server_status == ON)
		break;  /* server init successful, so break */
	}
	++cnt;
    }
    HNDL_UNLOCK(ldap_context);

err_out:
    if (sasl_mech_supported == FALSE) {
	st = KRB5_KDB_ACCESS_ERROR;
	krb5_set_error_message (context, st,
				gettext("Certificate based authentication requested but "
				"not supported by LDAP servers"));
    }
    return (st);
}


/*
 * get a single handle. Do not lock the mutex
 */

krb5_error_code
krb5_ldap_db_single_init(krb5_ldap_context *ldap_context)
{
    krb5_error_code             st=0;
    int                         cnt=0;
    krb5_ldap_server_info       *server_info=NULL;

    while (ldap_context->server_info_list[cnt] != NULL) {
	server_info = ldap_context->server_info_list[cnt];
	if ((server_info->server_status == NOTSET || server_info->server_status == ON)) {
	    if (server_info->num_conns < ldap_context->max_server_conns-1) {
		st = krb5_ldap_initialize(ldap_context, server_info);
		if (st == LDAP_SUCCESS)
		    goto cleanup;
	    }
	}
	++cnt;
    }

    /* If we are here, try to connect to all the servers */

    cnt = 0;
    while (ldap_context->server_info_list[cnt] != NULL) {
	server_info = ldap_context->server_info_list[cnt];
	st = krb5_ldap_initialize(ldap_context, server_info);
	if (st == LDAP_SUCCESS)
	    goto cleanup;
	++cnt;
    }
cleanup:
    return (st);
}

krb5_error_code
krb5_ldap_rebind(ldap_context, ldap_server_handle)
    krb5_ldap_context           *ldap_context;
    krb5_ldap_server_handle     **ldap_server_handle;
{
    krb5_ldap_server_handle     *handle = *ldap_server_handle;
    int				use_ssl;

    /*
     * Solaris Kerberos: use SSL unless ldapi (unix domain sockets is specified)
     */
    if (strncasecmp(handle->server_info->server_name, "ldapi:", 6) == 0)
	use_ssl = SSL_OFF;
    else
	use_ssl = SSL_ON;

    if ((ldap_initialize(&handle->ldap_handle, handle->server_info->server_name,
		use_ssl, NULL) != LDAP_SUCCESS)
	|| (krb5_ldap_bind(ldap_context, handle) != LDAP_SUCCESS))
	return krb5_ldap_request_next_handle_from_pool(ldap_context, ldap_server_handle);
    return LDAP_SUCCESS;
}

/*
 *     DAL API functions
 */
krb5_error_code krb5_ldap_lib_init()
{
    return 0;
}

krb5_error_code krb5_ldap_lib_cleanup()
{
    /* right now, no cleanup required */
    return 0;
}

krb5_error_code
krb5_ldap_free_ldap_context(krb5_ldap_context *ldap_context)
{
    if (ldap_context == NULL)
	return 0;

    krb5_ldap_free_krbcontainer_params(ldap_context->krbcontainer);
    ldap_context->krbcontainer = NULL;

    krb5_ldap_free_realm_params(ldap_context->lrparams);
    ldap_context->lrparams = NULL;

    krb5_ldap_free_server_params(ldap_context);

    return 0;
}

krb5_error_code
krb5_ldap_close(krb5_context context)
{
    kdb5_dal_handle  *dal_handle=NULL;
    krb5_ldap_context *ldap_context=NULL;

    if (context == NULL ||
	context->db_context == NULL ||
	((kdb5_dal_handle *)context->db_context)->db_context == NULL)
	return 0;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;
    dal_handle->db_context = NULL;

    krb5_ldap_free_ldap_context(ldap_context);

    return 0;
}
