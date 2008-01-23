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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <krb5.h>
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

static int attempt_refresh_cred(krb5_module_data_t *, char *, int);
static int attempt_delete_initcred(krb5_module_data_t *);
static krb5_error_code krb5_renew_tgt(krb5_module_data_t *, krb5_principal,
		krb5_principal, int);
static krb5_boolean creds_match(krb5_context, const krb5_creds *,
	const krb5_creds *);

extern uint_t kwarn_add_warning(char *, int);
extern uint_t kwarn_del_warning(char *);

/*
 * pam_sm_setcred
 */
int
pam_sm_setcred(
	pam_handle_t *pamh,
	int	flags,
	int	argc,
	const char **argv)
{
	int	i;
	int	err = 0;
	int	debug = 0;
	krb5_module_data_t	*kmd = NULL;
	char			*user = NULL;
	int			result;
	krb5_repository_data_t	*krb5_data = NULL;
	pam_repository_t	*rep_data = NULL;

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

	(void) pam_get_item(pamh, PAM_USER, (void**) &user);

	if (user == NULL || *user == '\0')
		return (PAM_USER_UNKNOWN);

	if (pam_get_data(pamh, KRB5_DATA, (const void**)&kmd) != PAM_SUCCESS) {
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

			if (kmd == NULL) {
				result = PAM_BUF_ERR;
				return (result);
			}

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
			err = PAM_CRED_UNAVAIL;
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
	(void) pam_get_item(pamh, PAM_REPOSITORY, (void **)&rep_data);

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
	char		*user,
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

	/* User must have passed pam_authenticate() */
	if (kmd->auth_status != PAM_SUCCESS) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): unable to "
			    "setcreds, not authenticated!");
		return (PAM_CRED_UNAVAIL);
	}

	/* Create a new context here. */
	if (krb5_init_context(&kmd->kcontext) != 0) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): unable to "
			    "initialize krb5 context");
		return (PAM_SYSTEM_ERR);
	}

	if (krb5_cc_default(kmd->kcontext, &kmd->ccache) != 0) {
		return (PAM_SYSTEM_ERR);
	}

	if ((code = get_kmd_kuser(kmd->kcontext, (const char *)user, kuser,
	    2*MAXHOSTNAMELEN)) != 0) {
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
 * PAM_ESTABLISH_CRED -  Create a new cred cache if one doesnt exist,
 *                       else refresh the existing one.
 * PAM_REINITIALIZE_CRED  - destroy current cred cache and create a new one
 * PAM_REFRESH_CRED  - update the existing cred cache (default action)
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
	typedef struct _cred_node {
		krb5_creds		*creds;
		struct _cred_node	*next;
	} cred_node;
	cred_node *cred_list_head = NULL;
	cred_node *fetched = NULL;

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

	if ((retval == KRB5_FCC_NOFILE) &&
	    (flag & (PAM_ESTABLISH_CRED|PAM_REINITIALIZE_CRED))) {
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
			goto cleanup_creds;
		} else if ((retval = krb5_cc_store_cred(kmd->kcontext,
		    kmd->ccache, &my_creds)) != 0) {
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (setcred): krb5_cc_store_cred "
			    "failed: %s",
			    error_message((errcode_t)retval));
			goto cleanup_creds;
		}
	} else if (retval) {
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

	} else if (flag & PAM_REINITIALIZE_CRED) {
		/*
		 * This destroys the credential cache, and stores a new
		 * krbtgt with updated startime, endtime and renewable
		 * lifetime.
		 */
		creds.times.starttime = my_creds.times.starttime;
		creds.times.endtime = my_creds.times.endtime;
		creds.times.renew_till = my_creds.times.renew_till;
		if ((retval = krb5_get_credentials_renew(kmd->kcontext, 0,
		    kmd->ccache, &creds, &renewed_cred))) {
			if (kmd->debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (setcred): krb5_get_credentials",
				    "_renew(reinitialize) failed: %s",
				    error_message((errcode_t)retval));
			/* perhaps the tgt lifetime has expired */
			if ((retval = krb5_cc_initialize(kmd->kcontext,
			    kmd->ccache, me)) != 0) {
				goto cleanup_creds;
			} else if ((retval = krb5_cc_store_cred(kmd->kcontext,
			    kmd->ccache, &my_creds)) != 0) {
				goto cleanup_creds;
			}
		}
	} else {
		/*
		 * Creds already exist, update them if possible.
		 * We got here either with the ESTABLISH or REFRESH flag.
		 *
		 * The credential cache does exist, and we are going to
		 * read in each cred, looking for our own.  When we find
		 * a matching credential, we will update it, and store it.
		 * Any nonmatching credentials are stored as is.
		 *
		 * Rules:
		 *    TGT must exist in cache to get to this point.
		 *	if flag == ESTABLISH
		 *		refresh it if possible, else overwrite
		 *		with new TGT, other tickets in cache remain
		 *		unchanged.
		 *	else if flag == REFRESH
		 *		refresh it if possible, else return error.
		 *		- Will not work if "R" flag is not set in
		 *		original cred, we dont want to 2nd guess the
		 *		intention of the person who created the
		 *		existing TGT.
		 *
		 */
		krb5_cc_cursor	cursor;
		krb5_creds	nextcred;
		boolean_t	found = 0;

		if ((retval = krb5_cc_start_seq_get(kmd->kcontext,
		    kmd->ccache, &cursor)) != 0)
			goto cleanup_creds;

		while ((krb5_cc_next_cred(kmd->kcontext, kmd->ccache,
		    &cursor, &nextcred) == 0)) {
			/* if two creds match, we just update the first */
			if ((!found) && (creds_match(kmd->kcontext,
			    &nextcred, &creds))) {
				/*
				 * Mark it as found, don't store it
				 * in the list or else it will be
				 * stored twice later.
				 */
				found = 1;
			} else {
				/*
				 * Add a new node to the list
				 * of creds that must be replaced
				 * in the cache later.
				 */
				cred_node *newnode = (cred_node *)malloc(
				    sizeof (cred_node));
				if (newnode == NULL) {
					retval = ENOMEM;
					goto cleanup_creds;
				}
				newnode->creds = NULL;
				newnode->next = NULL;

				if (cred_list_head == NULL) {
					cred_list_head = newnode;
					fetched = cred_list_head;
				} else {
					fetched->next = newnode;
					fetched = fetched->next;
				}
				retval = krb5_copy_creds(kmd->kcontext,
				    &nextcred, &fetched->creds);
				if (retval)
					goto cleanup_creds;
			}
		}

		if ((retval = krb5_cc_end_seq_get(kmd->kcontext,
		    kmd->ccache, &cursor)) != 0)
			goto cleanup_creds;

		/*
		 * If we found a matching cred, renew it.
		 * This destroys the credential cache, if and only
		 * if it passes.
		 */
		if (found &&
		    (retval = krb5_get_credentials_renew(kmd->kcontext,
		    0, kmd->ccache, &creds, &renewed_cred))) {
			if (kmd->debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (setcred): krb5_get_credentials"
				    "_renew(update) failed: %s",
				    error_message((errcode_t)retval));
			/*
			 * If we only wanted to refresh the creds but failed
			 * due to expiration, lack of "R" flag, or other
			 * problems, return an error.  If we were trying to
			 * establish new creds, add them to the cache.
			 */
			if ((retval = krb5_cc_initialize(kmd->kcontext,
			    kmd->ccache, me)) != 0) {
				goto cleanup_creds;
			} else if ((retval = krb5_cc_store_cred(kmd->kcontext,
			    kmd->ccache, &my_creds)) != 0) {
				goto cleanup_creds;
			}
		}
		/*
		 * If no matching creds were found, we must
		 * initialize the cache before we can store stuff
		 * in it.
		 */
		if (!found) {
			if ((retval = krb5_cc_initialize(kmd->kcontext,
			    kmd->ccache, me)) != 0) {
				goto cleanup_creds;
			}
		}

		/* now store all the other tickets */
		fetched = cred_list_head;
		while (fetched != NULL) {
			retval = krb5_cc_store_cred(kmd->kcontext,
			    kmd->ccache, fetched->creds);
			fetched = fetched->next;
			if (retval) {
				if (kmd->debug)
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5(setcred): "
					    "krb5_cc_store_cred() "
					    "failed: %s",
					    error_message((errcode_t)retval));
				goto cleanup_creds;
			}
		}
	}

cleanup_creds:
	/* Cleanup the list of creds read from the cache if necessary */
	fetched = cred_list_head;
	while (fetched != NULL) {
		cred_node *old = fetched;
		/* Free the contents and the cred structure itself */
		krb5_free_creds(kmd->kcontext, fetched->creds);
		fetched = fetched->next;
		free(old);
	}

	if ((retval == 0) && (client_name != NULL)) {
		/*
		 * Credential update was successful!
		 *
		 * We now chown the ccache to the appropriate uid/gid
		 * combination, if its a FILE based ccache.
		 */
		if (strstr(kmd->env, "FILE:")) {
			uid_t uuid;
			gid_t ugid;
			char *username = NULL, *tmpname = NULL;
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
			if (!(filepath = strchr(kmd->env, ':')) ||
			    !(filepath+1)) {
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

			free(username);
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

		kwarn_del_warning(client_name);
		if (kwarn_add_warning(client_name, endtime) != 0) {
			__pam_log(LOG_AUTH | LOG_NOTICE,
			    "PAM-KRB5 (setcred): kwarn_add_warning"
			    " failed: ktkt_warnd(1M) down?");
		}
	}

	if (renewed_cred != NULL)
		krb5_free_creds(kmd->kcontext, renewed_cred);

	if (client_name != NULL)
		free(client_name);

	krb5_free_cred_contents(kmd->kcontext, &creds);

	return (retval);
}

static krb5_boolean
creds_match(krb5_context ctx, const krb5_creds *mcreds,
	const krb5_creds *creds)
{
	char *s1, *s2, *c1, *c2;
	krb5_unparse_name(ctx, mcreds->client, &c1);
	krb5_unparse_name(ctx, mcreds->server, &s1);
	krb5_unparse_name(ctx, creds->client, &c2);
	krb5_unparse_name(ctx, creds->server, &s2);

	return (krb5_principal_compare(ctx, mcreds->client, creds->client) &&
	    krb5_principal_compare(ctx, mcreds->server, creds->server));
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
