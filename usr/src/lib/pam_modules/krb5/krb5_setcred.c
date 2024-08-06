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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#include <libintl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>
#include <libintl.h>
#include <k5-int.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <com_err.h>

#include "utils.h"
#include "krb5_repository.h"

#define	PAMTXD			"SUNW_OST_SYSOSPAM"
#define	KRB5_DEFAULT_LIFE	60*60*10  /* 10 hours */

extern void krb5_cleanup(pam_handle_t *, void *, int);

static int attempt_refresh_cred(krb5_module_data_t *, const char *, int);
static int attempt_delete_initcred(krb5_module_data_t *);
static krb5_error_code krb5_renew_tgt(krb5_module_data_t *, krb5_principal,
		krb5_principal, int);

extern uint_t kwarn_add_warning(char *, int);
extern uint_t kwarn_del_warning(char *);

/*
 * pam_sm_setcred
 */
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i;
	int err = 0;
	int debug = 0;
	krb5_module_data_t *kmd = NULL;
	const char *user = NULL;
	krb5_repository_data_t *krb5_data = NULL;
	const pam_repository_t *rep_data = NULL;

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcasecmp(argv[i], "nowarn") == 0)
			flags = flags | PAM_SILENT;
	}

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (setcred): start: nowarn = %d, flags = 0x%x",
		    flags & PAM_SILENT ? 1 : 0, flags);

	/* make sure flags are valid */
	if (flags &&
	    !(flags & PAM_ESTABLISH_CRED) &&
	    !(flags & PAM_REINITIALIZE_CRED) &&
	    !(flags & PAM_REFRESH_CRED) &&
	    !(flags & PAM_DELETE_CRED) &&
	    !(flags & PAM_SILENT)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (setcred): illegal flag %d", flags);
		err = PAM_SYSTEM_ERR;
		goto out;
	}

	(void) pam_get_item(pamh, PAM_USER, (const void **)&user);

	if (user == NULL || *user == '\0')
		return (PAM_USER_UNKNOWN);

	if (pam_get_data(pamh, KRB5_DATA, (const void **)&kmd) != PAM_SUCCESS) {
		if (debug) {
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): kmd get failed, kmd=0x%p",
			    kmd);
		}

		/*
		 * User  doesn't need to authenticate for PAM_REFRESH_CRED
		 * or for PAM_DELETE_CRED
		 */
		if (flags & (PAM_REFRESH_CRED|PAM_DELETE_CRED)) {
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): inst kmd structure");

			kmd = calloc(1, sizeof (krb5_module_data_t));

			if (kmd == NULL)
				return (PAM_BUF_ERR);


			/*
			 * Need to initialize auth_status here to
			 * PAM_AUTHINFO_UNAVAIL else there is a false positive
			 * of PAM_SUCCESS.
			 */
			kmd->auth_status = PAM_AUTHINFO_UNAVAIL;

			if ((err = pam_set_data(pamh, KRB5_DATA,
			    kmd, &krb5_cleanup)) != PAM_SUCCESS) {
				free(kmd);
				return (PAM_SYSTEM_ERR);
			}
		} else {
			/*
			 * This could mean that we are not the account authority
			 * for the authenticated user.  Therefore we should
			 * return PAM_IGNORE in order to not affect the
			 * login process of said user.
			 */
			err = PAM_IGNORE;
			goto out;
		}

	} else {  /* pam_get_data success */
		if (kmd == NULL) {
			if (debug) {
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (setcred): kmd structure"
				    " gotten but is NULL for user %s", user);
			}
			err = PAM_SYSTEM_ERR;
			goto out;
		}

		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): kmd auth_status: %s",
			    pam_strerror(pamh, kmd->auth_status));

		/*
		 * pam_auth has set status to ignore, so we also return ignore
		 */
		if (kmd->auth_status == PAM_IGNORE) {
			err = PAM_IGNORE;
			goto out;
		}
	}

	kmd->debug = debug;

	/*
	 * User must have passed pam_authenticate()
	 * in order to use PAM_ESTABLISH_CRED or PAM_REINITIALIZE_CRED
	 */
	if ((flags & (PAM_ESTABLISH_CRED|PAM_REINITIALIZE_CRED)) &&
	    (kmd->auth_status != PAM_SUCCESS)) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): unable to "
			    "setcreds, not authenticated!");
		return (PAM_CRED_UNAVAIL);
	}

	/*
	 * We cannot assume that kmd->kcontext being non-NULL
	 * means it is valid.  Other pam_krb5 mods may have
	 * freed it but not reset it to NULL.
	 * Log a message when debugging to track down memory
	 * leaks.
	 */
	if (kmd->kcontext != NULL && kmd->debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (setcred): kcontext != NULL, "
		    "possible memory leak.");

	/*
	 * Use the authenticated and validated user, if applicable.
	 */
	if (kmd->user != NULL)
		user = kmd->user;

	/*
	 * If auth was short-circuited we will not have anything to
	 * renew, so just return here.
	 */
	(void) pam_get_item(pamh, PAM_REPOSITORY, (const void **)&rep_data);

	if (rep_data != NULL) {
		if (strcmp(rep_data->type, KRB5_REPOSITORY_NAME) != 0) {
			if (debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (setcred): wrong"
				    "repository found (%s), returning "
				    "PAM_IGNORE", rep_data->type);
			return (PAM_IGNORE);
		}
		if (rep_data->scope_len == sizeof (krb5_repository_data_t)) {
			krb5_data = (krb5_repository_data_t *)rep_data->scope;

			if (krb5_data->flags ==
			    SUNW_PAM_KRB5_ALREADY_AUTHENTICATED &&
			    krb5_data->principal != NULL &&
			    strlen(krb5_data->principal)) {
				if (debug)
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5 (setcred): "
					    "Principal %s already "
					    "authenticated, "
					    "cannot setcred",
					    krb5_data->principal);
				return (PAM_SUCCESS);
			}
		}
	}

	if (flags & PAM_REINITIALIZE_CRED)
		err = attempt_refresh_cred(kmd, user, PAM_REINITIALIZE_CRED);
	else if (flags & PAM_REFRESH_CRED)
		err = attempt_refresh_cred(kmd, user, PAM_REFRESH_CRED);
	else if (flags & PAM_DELETE_CRED)
		err = attempt_delete_initcred(kmd);
	else {
		/*
		 * Default case:  PAM_ESTABLISH_CRED
		 */
		err = attempt_refresh_cred(kmd, user, PAM_ESTABLISH_CRED);
	}

	if (err != PAM_SUCCESS)
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (setcred): pam_setcred failed "
		    "for %s (%s).", user, pam_strerror(pamh, err));

out:
	if (kmd && kmd->kcontext) {
		/*
		 * free 'kcontext' field if it is allocated,
		 * kcontext is local to the operation being performed
		 * not considered global to the entire pam module.
		 */
		krb5_free_context(kmd->kcontext);
		kmd->kcontext = NULL;
	}

	/*
	 * 'kmd' is not freed here, it is handled in krb5_cleanup
	 */
	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (setcred): end: %s",
		    pam_strerror(pamh, err));
	return (err);
}

static int
attempt_refresh_cred(
	krb5_module_data_t	*kmd,
	const char		*user,
	int	flag)
{
	krb5_principal	me;
	krb5_principal	server;
	krb5_error_code	code;
	char		kuser[2*MAXHOSTNAMELEN];
	krb5_data tgtname = {
		0,
		KRB5_TGS_NAME_SIZE,
		KRB5_TGS_NAME
	};

	/* Create a new context here. */
	if (krb5_init_secure_context(&kmd->kcontext) != 0) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): unable to "
			    "initialize krb5 context");
		return (PAM_SYSTEM_ERR);
	}

	if (krb5_cc_default(kmd->kcontext, &kmd->ccache) != 0) {
		return (PAM_SYSTEM_ERR);
	}

	if ((code = get_kmd_kuser(kmd->kcontext, user, kuser,
	    2 * MAXHOSTNAMELEN)) != 0) {
		return (code);
	}

	if (krb5_parse_name(kmd->kcontext, kuser, &me) != 0) {
		return (PAM_SYSTEM_ERR);
	}

	if (code = krb5_build_principal_ext(kmd->kcontext, &server,
	    krb5_princ_realm(kmd->kcontext, me)->length,
	    krb5_princ_realm(kmd->kcontext, me)->data,
	    tgtname.length, tgtname.data,
	    krb5_princ_realm(kmd->kcontext, me)->length,
	    krb5_princ_realm(kmd->kcontext, me)->data, 0)) {
		krb5_free_principal(kmd->kcontext, me);
		return (PAM_SYSTEM_ERR);
	}

	code = krb5_renew_tgt(kmd, me, server, flag);

	krb5_free_principal(kmd->kcontext, server);
	krb5_free_principal(kmd->kcontext, me);

	if (code) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5(setcred): krb5_renew_tgt() "
			    "failed: %s", error_message((errcode_t)code));
		return (PAM_CRED_ERR);
	} else {
		return (PAM_SUCCESS);
	}
}

/*
 * This code will update the credential matching "server" in the user's
 * credential cache.  The flag may be set to one of:
 * PAM_REINITIALIZE_CRED/PAM_ESTABLISH_CRED - If we have new credentials then
 *     create a new cred cache with these credentials else return failure.
 * PAM_REFRESH_CRED - If we have new credentials then create a new cred cache
 *  with these credentials else attempt to renew the credentials.
 *
 * Note for any of the flags that if a new credential does exist from the
 * previous auth pass then this will overwrite any existing credentials in the
 * credential cache.
 */
static krb5_error_code
krb5_renew_tgt(
	krb5_module_data_t *kmd,
	krb5_principal	me,
	krb5_principal	server,
	int	flag)
{
	krb5_error_code	retval;
	krb5_creds	creds;
	krb5_creds	*renewed_cred = NULL;
	char		*client_name = NULL;
	char		*username = NULL;

#define	my_creds	(kmd->initcreds)

	if ((flag != PAM_REFRESH_CRED) &&
	    (flag != PAM_REINITIALIZE_CRED) &&
	    (flag != PAM_ESTABLISH_CRED))
		return (KRB5KRB_ERR_GENERIC);

	/* this is needed only for the ktkt_warnd */
	if ((retval = krb5_unparse_name(kmd->kcontext, me, &client_name)) != 0)
		return (retval);

	(void) memset(&creds, 0, sizeof (krb5_creds));
	if ((retval = krb5_copy_principal(kmd->kcontext,
	    server, &creds.server))) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): krb5_copy_principal "
			    "failed: %s",
			    error_message((errcode_t)retval));
		goto cleanup_creds;
	}

	/* obtain ticket & session key */
	retval = krb5_cc_get_principal(kmd->kcontext,
	    kmd->ccache, &creds.client);
	if (retval && (kmd->debug))
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (setcred): User not in cred "
		    "cache (%s)", error_message((errcode_t)retval));

	/*
	 * We got here either with the ESTABLISH | REINIT | REFRESH flag and
	 * auth_status returns SUCCESS or REFRESH and auth_status failure.
	 *
	 * Rules:
	 * - If the prior auth pass was successful then store the new
	 * credentials in the cache, regardless of which flag.
	 *
	 * - Else if REFRESH flag is used and there are no new
	 * credentials then attempt to refresh the existing credentials.
	 *
	 * - Note, refresh will not work if "R" flag is not set in
	 * original credential.  We don't want to 2nd guess the
	 * intention of the person who created the existing credential.
	 */
	if (kmd->auth_status == PAM_SUCCESS) {
		/*
		 * Create a fresh ccache, and store the credentials
		 * we got from pam_authenticate()
		 */
		if ((retval = krb5_cc_initialize(kmd->kcontext,
		    kmd->ccache, me)) != 0) {
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): krb5_cc_initialize "
			    "failed: %s",
			    error_message((errcode_t)retval));
		} else if ((retval = krb5_cc_store_cred(kmd->kcontext,
		    kmd->ccache, &my_creds)) != 0) {
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): krb5_cc_store_cred "
			    "failed: %s",
			    error_message((errcode_t)retval));
		}
	} else if ((retval == 0) && (flag & PAM_REFRESH_CRED)) {
		/*
		 * If we only wanted to refresh the creds but failed
		 * due to expiration, lack of "R" flag, or other
		 * problems, return an error.
		 */
		if (retval = krb5_get_credentials_renew(kmd->kcontext,
		    0, kmd->ccache, &creds, &renewed_cred)) {
			if (kmd->debug) {
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (setcred): "
				    "krb5_get_credentials"
				    "_renew(update) failed: %s",
				    error_message((errcode_t)retval));
			}
		}
	} else {
		/*
		 * We failed to get the user's credentials.
		 * This might be due to permission error on the cache,
		 * or maybe we are looking in the wrong cache file!
		 */
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (setcred): Cannot find creds"
		    " for %s (%s)",
		    client_name ? client_name : "(unknown)",
		    error_message((errcode_t)retval));
	}

cleanup_creds:

	if ((retval == 0) && (client_name != NULL)) {
		/*
		 * Credential update was successful!
		 *
		 * We now chown the ccache to the appropriate uid/gid
		 * combination, if its a FILE based ccache.
		 */
		if (!kmd->env || strstr(kmd->env, "FILE:")) {
			uid_t uuid;
			gid_t ugid;
			char *tmpname = NULL;
			char *filepath = NULL;

			username = strdup(client_name);
			if (username == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "PAM-KRB5 (setcred): Out of memory");
				retval = KRB5KRB_ERR_GENERIC;
				goto error;
			}
			if ((tmpname = strchr(username, '@')))
				*tmpname = '\0';

			if (get_pw_uid(username, &uuid) == 0 ||
			    get_pw_gid(username, &ugid) == 0) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "PAM-KRB5 (setcred): Unable to "
				    "find matching uid/gid pair for user `%s'",
				    username);
				retval = KRB5KRB_ERR_GENERIC;
				goto error;
			}

			if (!kmd->env) {
				char buffer[512];

				if (snprintf(buffer, sizeof (buffer),
				    "%s=FILE:/tmp/krb5cc_%d", KRB5_ENV_CCNAME,
				    (int)uuid) >= sizeof (buffer)) {
					retval = KRB5KRB_ERR_GENERIC;
					goto error;
				}

				/*
				 * We MUST copy this to the heap for the putenv
				 * to work!
				 */
				kmd->env = strdup(buffer);
				if (!kmd->env) {
					retval = ENOMEM;
					goto error;
				} else {
					if (putenv(kmd->env)) {
						retval = ENOMEM;
						goto error;
					}
				}
			}

			/*
			 * We know at this point that kmd->env must start
			 * with the literal string "FILE:".  Set filepath
			 * character string to point to ":"
			 */

			filepath = strchr(kmd->env, ':');

			/*
			 * Now check if first char after ":" is null char
			 */
			if (filepath[1] == '\0') {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "PAM-KRB5 (setcred): Invalid pathname "
				    "for credential cache of user `%s'",
				    username);
				retval = KRB5KRB_ERR_GENERIC;
				goto error;
			}
			if (chown(filepath+1, uuid, ugid)) {
				if (kmd->debug)
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5 (setcred): chown to user "
					    "`%s' failed for FILE=%s",
					    username, filepath);
			}
		}
	}

error:
	if (retval == 0) {
		krb5_timestamp endtime;

		if (renewed_cred && renewed_cred->times.endtime != 0)
			endtime = renewed_cred->times.endtime;
		else
			endtime = my_creds.times.endtime;

		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): delete/add warning");

		if (kwarn_del_warning(client_name) != 0) {
			__pam_log(LOG_AUTH | LOG_NOTICE,
			    "PAM-KRB5 (setcred): kwarn_del_warning"
			    " failed: ktkt_warnd(8) down?");
		}

		if (kwarn_add_warning(client_name, endtime) != 0) {
			__pam_log(LOG_AUTH | LOG_NOTICE,
			    "PAM-KRB5 (setcred): kwarn_add_warning"
			    " failed: ktkt_warnd(8) down?");
		}
	}

	if (renewed_cred != NULL)
		krb5_free_creds(kmd->kcontext, renewed_cred);

	if (client_name != NULL)
		free(client_name);

	if (username)
		free(username);

	krb5_free_cred_contents(kmd->kcontext, &creds);

	return (retval);
}

/*
 * Delete the user's credentials for this session
 */
static int
attempt_delete_initcred(krb5_module_data_t *kmd)
{
	if (kmd == NULL)
		return (PAM_SUCCESS);

	if (kmd->debug) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (setcred): deleting user's "
		    "credentials (initcreds)");
	}
	krb5_free_cred_contents(kmd->kcontext, &kmd->initcreds);
	(void) memset((char *)&kmd->initcreds, 0, sizeof (krb5_creds));
	kmd->auth_status = PAM_AUTHINFO_UNAVAIL;
	return (PAM_SUCCESS);
}
