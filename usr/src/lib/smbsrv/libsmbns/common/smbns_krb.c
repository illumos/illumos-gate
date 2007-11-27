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
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 *
 * Initialize a credentials cache.
 */
#include <kerberosv5/krb5.h>
#include <kerberosv5/com_err.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <netdb.h>
#include <syslog.h>
#include <locale.h>
#include <strings.h>
#include <sys/synch.h>
#include <gssapi/gssapi.h>

#include <smbsrv/libsmbns.h>

#include <smbns_krb.h>

static int krb5_acquire_cred_kinit_main();

typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

struct k_opts {
	/* in seconds */
	krb5_deltat starttime;
	krb5_deltat lifetime;
	krb5_deltat rlife;

	int forwardable;
	int proxiable;
	int addresses;

	int not_forwardable;
	int not_proxiable;
	int no_addresses;

	int verbose;

	char *principal_name;
	char *principal_passwd;
	char *service_name;
	char *keytab_name;
	char *k5_cache_name;
	char *k4_cache_name;

	action_type action;
};

struct k5_data {
	krb5_context ctx;
	krb5_ccache cc;
	krb5_principal me;
	char *name;
};

static int
k5_begin(struct k_opts *opts, struct k5_data *k5)
{
	int code;
	code = krb5_init_context(&k5->ctx);
	if (code) {
		return (code);
	}

	if ((code = krb5_cc_default(k5->ctx, &k5->cc))) {
		return (code);
	}

	/* Use specified name */
	if ((code = krb5_parse_name(k5->ctx, opts->principal_name, &k5->me))) {
		return (code);
	}

	code = krb5_unparse_name(k5->ctx, k5->me, &k5->name);
	if (code) {
		return (code);
	}
	opts->principal_name = k5->name;

	return (0);
}

static void
k5_end(struct k5_data *k5)
{
	if (k5->name)
		krb5_free_unparsed_name(k5->ctx, k5->name);
	if (k5->me)
		krb5_free_principal(k5->ctx, k5->me);
	if (k5->cc)
		krb5_cc_close(k5->ctx, k5->cc);
	if (k5->ctx)
		krb5_free_context(k5->ctx);
	(void) memset(k5, 0, sizeof (*k5));
}

static int
k5_kinit(struct k_opts *opts, struct k5_data *k5)
{
	int notix = 1;
	krb5_keytab keytab = 0;
	krb5_creds my_creds;
	krb5_error_code code = 0;
	krb5_get_init_creds_opt options;
	const char *errmsg;

	krb5_get_init_creds_opt_init(&options);
	(void) memset(&my_creds, 0, sizeof (my_creds));

	/*
	 * From this point on, we can goto cleanup because my_creds is
	 * initialized.
	 */
	if (opts->lifetime)
		krb5_get_init_creds_opt_set_tkt_life(&options, opts->lifetime);
	if (opts->rlife)
		krb5_get_init_creds_opt_set_renew_life(&options, opts->rlife);
	if (opts->forwardable)
		krb5_get_init_creds_opt_set_forwardable(&options, 1);
	if (opts->not_forwardable)
		krb5_get_init_creds_opt_set_forwardable(&options, 0);
	if (opts->proxiable)
		krb5_get_init_creds_opt_set_proxiable(&options, 1);
	if (opts->not_proxiable)
		krb5_get_init_creds_opt_set_proxiable(&options, 0);
	if (opts->addresses) {
		krb5_address **addresses = NULL;
		code = krb5_os_localaddr(k5->ctx, &addresses);
		if (code != 0) {
			errmsg = error_message(code);
			syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "k5_kinit: "
			    "getting local addresses (%s)"), errmsg);
			goto cleanup;
		}
		krb5_get_init_creds_opt_set_address_list(&options, addresses);
	}
	if (opts->no_addresses)
		krb5_get_init_creds_opt_set_address_list(&options, NULL);

	if ((opts->action == INIT_KT) && opts->keytab_name) {
		code = krb5_kt_resolve(k5->ctx, opts->keytab_name, &keytab);
		if (code != 0) {
			errmsg = error_message(code);
			syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "k5_kinit: "
			    "resolving keytab %s (%s)"), errmsg,
			    opts->keytab_name);
			goto cleanup;
		}
	}

	switch (opts->action) {
	case INIT_PW:
		code = krb5_get_init_creds_password(k5->ctx, &my_creds, k5->me,
		    opts->principal_passwd, NULL, 0, opts->starttime,
		    opts->service_name, &options);
		break;
	case INIT_KT:
		code = krb5_get_init_creds_keytab(k5->ctx, &my_creds, k5->me,
		    keytab, opts->starttime, opts->service_name, &options);
		break;
	case VALIDATE:
		code = krb5_get_validated_creds(k5->ctx, &my_creds, k5->me,
		    k5->cc, opts->service_name);
		break;
	case RENEW:
		code = krb5_get_renewed_creds(k5->ctx, &my_creds, k5->me,
		    k5->cc, opts->service_name);
		break;
	}

	if (code) {
		char *doing = 0;
		switch (opts->action) {
		case INIT_PW:
		case INIT_KT:
			doing = dgettext(TEXT_DOMAIN, "k5_kinit: "
			    "getting initial credentials");
			break;
		case VALIDATE:
			doing = dgettext(TEXT_DOMAIN, "k5_kinit: "
			    "validating credentials");
			break;
		case RENEW:
			doing = dgettext(TEXT_DOMAIN, "k5_kinit: "
			    "renewing credentials");
			break;
		}

		/*
		 * If got code == KRB5_AP_ERR_V4_REPLY && got_k4, we should
		 * let the user know that maybe he/she wants -4.
		 */
		if (code == KRB5KRB_AP_ERR_V4_REPLY) {
			syslog(LOG_ERR, "%s\n"
			    "The KDC doesn't support v5.  "
			    "You may want the -4 option in the future", doing);
			return (1);
		} else if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY) {
			syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "%s "
			    "(Password incorrect)"), doing);
		} else {
			errmsg = error_message(code);
			syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "%s (%s)"),
			    doing, errmsg);
		}
		goto cleanup;
	}

	if (!opts->lifetime) {
		/* We need to figure out what lifetime to use for Kerberos 4. */
		opts->lifetime = my_creds.times.endtime -
		    my_creds.times.authtime;
	}

	code = krb5_cc_initialize(k5->ctx, k5->cc, k5->me);
	if (code) {
		errmsg = error_message(code);
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "k5_kinit: "
		    "initializing cache %s (%s)"),
		    opts->k5_cache_name?opts->k5_cache_name:"", errmsg);
		goto cleanup;
	}

	code = krb5_cc_store_cred(k5->ctx, k5->cc, &my_creds);
	if (code) {
		errmsg = error_message(code);
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "k5_kinit: "
		    "storing credentials (%s)"), errmsg);
		goto cleanup;
	}

	notix = 0;

	cleanup:
		if (my_creds.client == k5->me) {
			my_creds.client = 0;
		}
		krb5_free_cred_contents(k5->ctx, &my_creds);
		if (keytab)
			krb5_kt_close(k5->ctx, keytab);
		return (notix?0:1);
}

int
smb_kinit(char *user, char *passwd)
{
	struct k_opts opts;
	struct k5_data k5;
	int authed_k5 = 0;

	assert(user);
	assert(passwd);

	(void) memset(&opts, 0, sizeof (opts));
	opts.action = INIT_PW;
	opts.principal_name = strdup(user);
	opts.principal_passwd = strdup(passwd);

	(void) memset(&k5, 0, sizeof (k5));

	if (k5_begin(&opts, &k5) != 0) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "smb_kinit: "
		    "NOT Authenticated to Kerberos v5  k5_begin failed\n"));
		return (0);
	}

	authed_k5 = k5_kinit(&opts, &k5);
	if (authed_k5) {
		syslog(LOG_DEBUG, dgettext(TEXT_DOMAIN, "smb_kinit: "
		    "Authenticated to Kerberos v5\n"));
	} else {
		syslog(LOG_DEBUG, dgettext(TEXT_DOMAIN, "smb_kinit: "
		    "NOT Authenticated to Kerberos v5\n"));
	}

	k5_end(&k5);

	return (authed_k5);
}

/*
 * krb5_display_stat
 * Display error message for GSS-API routines.
 * Parameters:
 *   maj       :  GSS major status
 *   min       :  GSS minor status
 *   caller_mod:  module name that calls this routine so that the module name
 *                can be displayed with the error messages
 * Returns:
 *   None
 */
static void
krb5_display_stat(OM_uint32 maj, OM_uint32 min, char *caller_mod)
{
	gss_buffer_desc msg;
	OM_uint32 msg_ctx = 0;
	OM_uint32 min2;
	(void) gss_display_status(&min2, maj, GSS_C_GSS_CODE, GSS_C_NULL_OID,
	    &msg_ctx, &msg);
	syslog(LOG_ERR, "%s: major status error: %s\n",
	    caller_mod, (char *)msg.value);
	(void) gss_display_status(&min2, min, GSS_C_MECH_CODE, GSS_C_NULL_OID,
	    &msg_ctx, &msg);
	syslog(LOG_ERR, "%s: minor status error: %s\n",
	    caller_mod, (char *)msg.value);
}

/*
 * krb5_acquire_cred_kinit
 *
 * Wrapper for krb5_acquire_cred_kinit_main with mutex to protect credential
 * cache file when calling krb5_acquire_cred or kinit.
 */

int
krb5_acquire_cred_kinit(char *user, char *pwd, gss_cred_id_t *cred_handle,
	gss_OID *oid, int *kinit_retry, char *caller_mod)
{
	int ret;

	ret = krb5_acquire_cred_kinit_main(user, pwd,
	    cred_handle, oid, kinit_retry, caller_mod);
	return (ret);
}

/*
 * krb5_acquire_cred_kinit_main
 *
 * This routine is called by ADS module to get a handle to administrative
 * user's credential stored locally on the system.  The credential is the TGT.
 * If the attempt at getting handle fails then a second attempt will be made
 * after getting a new TGT.
 *
 * If there's no username then we must be using host credentials and we don't
 * bother trying to acquire a credential for GSS_C_NO_NAME (which should be
 * equivalent to using GSS_C_NO_CREDENTIAL, but it isn't in a very subtle way
 * because mech_krb5 isn't so smart).  Specifically mech_krb5 will try hard
 * to get a non-expired TGT using the keytab if we're running as root (or fake
 * it, using the special app_krb5_user_uid() function), but only when we use
 * the default credential, as opposed to a credential for the default principal.
 *
 * Paramters:
 *   user       : username to retrieve a handle to its credential
 *   pwd        : password of username in case obtaining a new TGT is needed
 *   kinit_retry: if 0 then a second attempt will be made to get handle to the
 *                credential if the first attempt fails
 *   caller_mod : name of module that call this routine so that the module name
 *                can be included with error messages
 * Returns:
 *   cred_handle: handle to the administrative user's credential (TGT)
 *   oid        : contains Kerberos 5 object identifier
 *   kinit_retry: A 1 indicates that a second attempt has been made to get
 *                handle to the credential and no further attempts can be made
 *   -1         : error
 *    0         : success
 */
static int
krb5_acquire_cred_kinit_main(char *user, char *pwd, gss_cred_id_t *cred_handle,
	gss_OID *oid, int *kinit_retry, char *caller_mod)
{
	OM_uint32 maj, min;
	gss_name_t desired_name = GSS_C_NO_NAME;
	gss_OID_set desired_mechs;
	gss_buffer_desc oidstr, name_buf;
	char str[50], user_name[50];

	*cred_handle = GSS_C_NO_CREDENTIAL;
	*oid = GSS_C_NO_OID;
	if (user == NULL || *user == '\0')
		return (0);

	/* Object Identifier for Kerberos 5 */
	(void) strcpy(str, "{ 1 2 840 113554 1 2 2 }");
	oidstr.value = str;
	oidstr.length = strlen(str);
	if ((maj = gss_str_to_oid(&min, &oidstr, oid)) != GSS_S_COMPLETE) {
		krb5_display_stat(maj, min, caller_mod);
		return (-1);
	}
	if ((maj = gss_create_empty_oid_set(&min, &desired_mechs))
	    != GSS_S_COMPLETE) {
		krb5_display_stat(maj, min, caller_mod);
		(void) gss_release_oid(&min, oid);
		return (-1);
	}
	if ((maj = gss_add_oid_set_member(&min, *oid, &desired_mechs))
	    != GSS_S_COMPLETE) {
		krb5_display_stat(maj, min, caller_mod);
		(void) gss_release_oid(&min, oid);
		(void) gss_release_oid_set(&min, &desired_mechs);
		return (-1);
	}

	(void) strcpy(user_name, user);
	name_buf.value = user_name;
	name_buf.length = strlen(user_name)+1;
	if ((maj = gss_import_name(&min, &name_buf, GSS_C_NT_USER_NAME,
	    &desired_name)) != GSS_S_COMPLETE) {
		krb5_display_stat(maj, min, caller_mod);
		(void) gss_release_oid(&min, oid);
		(void) gss_release_oid_set(&min, &desired_mechs);
		return (-1);
	}

acquire_cred:
	if ((maj = gss_acquire_cred(&min, desired_name, 0, desired_mechs,
	    GSS_C_INITIATE, cred_handle, NULL, NULL)) != GSS_S_COMPLETE) {
		if (!*kinit_retry && pwd != NULL && *pwd != '\0') {
			syslog(LOG_ERR, "%s: Retry kinit to "
			    "acquire credential.\n", caller_mod);
			(void) smb_kinit(user, pwd);
			*kinit_retry = 1;
			goto acquire_cred;
		} else {
			krb5_display_stat(maj, min, caller_mod);
			(void) gss_release_oid(&min, oid);
			(void) gss_release_oid_set(&min, &desired_mechs);
			(void) gss_release_name(&min, &desired_name);
			if (pwd == NULL || *pwd == '\0') {
				/* See above */
				*cred_handle = GSS_C_NO_CREDENTIAL;
				return (0);
			}
			return (-1);
		}
	}

	(void) gss_release_oid_set(&min, &desired_mechs);
	(void) gss_release_name(&min, &desired_name);

	return (0);
}

/*
 * krb5_establish_sec_ctx_kinit
 *
 * This routine is called by the ADS module to establish a security
 * context before ADS updates are allowed.  If establishing a security context
 * fails for any reason, a second attempt will be made after a new TGT is
 * obtained.  This routine is called many time as needed until a security
 * context is established.
 *
 * The resources use for the security context must be released if security
 * context establishment process fails.
 * Parameters:
 *   user       : user used in establishing a security context for.  Is used for
 *                obtaining a new TGT for a second attempt at establishing
 *                security context
 *   pwd        : password of above user
 *   cred_handle: a handle to the user credential (TGT) stored locally
 *   gss_context: initially set to GSS_C_NO_CONTEXT but will contain a handle
 *                to a security context
 *   target_name: contains service name to establish a security context with,
 *                ie ldap or dns
 *   gss_flags  : flags used in establishing security context
 *   inputptr   : initially set to GSS_C_NO_BUFFER but will be token data
 *                received from service's server to be processed to generate
 *                further token to be sent back to service's server during
 *                security context establishment
 *   kinit_retry: if 0 then a second attempt will be made to get handle to the
 *                credential if the first attempt fails
 *   caller_mod : name of module that call this routine so that the module name
 *                can be included with error messages
 * Returns:
 *   gss_context    : a handle to a security context
 *   out_tok        : token data to be sent to service's server to establish
 *                    security context
 *   ret_flags      : return flags
 *   time_rec       : valid time for security context, not currently used
 *   kinit_retry    : A 1 indicates that a second attempt has been made to get
 *                    handle to the credential and no further attempts can be
 *                    made
 *   do_acquire_cred: A 1 indicates that a new handle to the local credential
 *                    is needed for second attempt at security context
 *                    establishment
 *   maj            : major status code used if determining is security context
 *                    establishment is successful
 */
int
krb5_establish_sec_ctx_kinit(char *user, char *pwd,
    gss_cred_id_t cred_handle, gss_ctx_id_t *gss_context,
    gss_name_t target_name, gss_OID oid, int gss_flags,
    gss_buffer_desc *inputptr, gss_buffer_desc* out_tok,
    OM_uint32 *ret_flags, OM_uint32 *time_rec,
    int *kinit_retry, int *do_acquire_cred,
    OM_uint32 *maj, char *caller_mod)
{
	OM_uint32 min;

	*maj = gss_init_sec_context(&min, cred_handle, gss_context,
	    target_name, oid, gss_flags, 0, NULL, inputptr, NULL,
	    out_tok, ret_flags, time_rec);
	if (*maj != GSS_S_COMPLETE && *maj != GSS_S_CONTINUE_NEEDED) {
		if (*gss_context != NULL)
			(void) gss_delete_sec_context(&min, gss_context, NULL);

		if ((user != NULL) && (pwd != NULL) && !*kinit_retry) {
			syslog(LOG_ERR, "%s: Retry kinit to establish "
			    "security context.\n", caller_mod);
			(void) smb_kinit(user, pwd);
			*kinit_retry = 1;
			*do_acquire_cred = 1;
			return (-1);
		} else {
			krb5_display_stat(*maj, min, caller_mod);
			return (-1);
		}
	}
	return (0);
}
