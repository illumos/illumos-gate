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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include <security/pam_appl.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>

#include "utils.h"

extern const char *error_message(long);

/* ******************************************************************** */
/*									*/
/* 		Utilities Functions					*/
/*									*/
/* ******************************************************************** */

/*
 * get_pw_uid():
 *	To get the uid from the passwd entry for specified user
 *	It returns 0 if the user can't be found, otherwise returns 1.
 */
int
get_pw_uid(const char *user, uid_t *uid)
{
	struct passwd sp;
	char buffer[1024];

	if (getpwnam_r(user, &sp, buffer, sizeof (buffer)) == NULL) {
		return (0);
	}

	*uid = sp.pw_uid;

	return (1);
}

/*
 * get_pw_gid():
 *	To get the gid from the passwd entry for specified user
 *	It returns 0 if the user can't be found, otherwise returns 1.
 */
int
get_pw_gid(char *user, gid_t *gid)
{
	struct passwd sp;
	char buffer[1024];

	if (getpwnam_r(user, &sp, buffer, sizeof (buffer)) == NULL) {
		return (0);
	}

	*gid = sp.pw_gid;

	return (1);
}


/*
 * get_kmd_kuser():
 *	To get the kerberos user name for the specified user.
 *	Assumes that the kuser string is allocated.  It will be
 *	overwritten.  This saves us having to deal will allocating
 *	and freeing the kuser string.
 *
 * RFC 1510 does not mention how to handle mixed case domainnames
 * while constructing client principals. So we will follow the same
 * procedure as for server principals and lowercase the domainname.
 *
 * Returns:
 *	PAM_BUF_ERR	- if there is an error from krb5_sname_to_principal(),
 *			  or krb5_unparse_name()
 *	0		- if there was no error
 */
int
get_kmd_kuser(krb5_context kcontext, const char *user, char *kuser, int length)
{
	if (strcmp(user, ROOT_UNAME) == 0) {
		krb5_principal princ;
		char *name, *princname, *lasts;

		if (krb5_sname_to_principal(kcontext, NULL, ROOT_UNAME,
			KRB5_NT_SRV_HST, &princ)) {
			return (PAM_BUF_ERR);
		}
		if (krb5_unparse_name(kcontext, princ, &princname)) {
			krb5_free_principal(kcontext, princ);
			return (PAM_BUF_ERR);
		}
		/* just interested in princ name before the @REALM part */
		if ((name = strtok_r(princname, "@", &lasts)) == NULL) {
			krb5_free_principal(kcontext, princ);
			free(princname);
			return (PAM_BUF_ERR);
		}
		if (strlcpy(kuser, name, length) >= length) {
			krb5_free_principal(kcontext, princ);
			free(princname);
			return (PAM_BUF_ERR);
		}
		krb5_free_principal(kcontext, princ);
		free(princname);
	} else {
		if (strlcpy(kuser, user, length) >= length) {
			return (PAM_BUF_ERR);
		}
	}
	return (0);
}

/*
 * return true (1) if the user's key is in the (default) keytab
 */
int
key_in_keytab(const char *user, int debug)
{
	krb5_keytab kt_handle;
	krb5_keytab_entry kt_ent;
	char *whoami = "key_in_keytab";
	krb5_error_code retval = 0;
	krb5_error_code code = 0;
	krb5_context kcontext = NULL;
	krb5_principal	princ = NULL;
	char		kuser[2*MAXHOSTNAMELEN];


	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (%s): start for user '%s'",
				    whoami, user ? user : "<null>");

	if (!user)
		return (retval);

	/* need to free context with krb5_free_context */
	if (code = krb5_init_secure_context(&kcontext)) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (%s): Error initializing "
			    "krb5: %s", whoami,
			    error_message(code));
		return (retval);
	}

	if ((code = get_kmd_kuser(kcontext, user, kuser,
		2 * MAXHOSTNAMELEN)) != 0) {
		goto out;
	}

	/* need to free princ with krb5_free_principal */
	if ((code = krb5_parse_name(kcontext, kuser, &princ)) != 0) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (%s): can't parse name (%s)",
				    whoami, error_message(code));
		goto out;
	}

	/* need to close keytab handle with krb5_kt_close */
	if ((code = krb5_kt_default(kcontext, &kt_handle))) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (%s): krb5_kt_default failed (%s)",
			    whoami, error_message(code));
		goto out;
	}

	code = krb5_kt_get_entry(kcontext, kt_handle, princ, 0, 0, &kt_ent);
	if (code != 0) {
		if (code == ENOENT) {
				if (debug)
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5 (%s): "
					    "Keytab does not exist",
					    whoami);
		} else if (code == KRB5_KT_NOTFOUND) {
				if (debug)
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5 (%s): "
					    "No entry for principal "
					    "'%s' exists in keytab",
					    whoami, kuser);
		} else {
				if (debug)
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5 (%s): "
					    "krb5_kt_get_entry failed (%s)",
					    whoami, error_message(code));
		}
	} else { /* Key found in keytab, return success */
			(void) krb5_kt_free_entry(kcontext, &kt_ent);
			if (debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (%s): "
				    "keytab entry for '%s' found",
				    whoami, user);
			retval = 1;
	}

	(void) krb5_kt_close(kcontext, kt_handle);
out:
	if (princ && kcontext)
		krb5_free_principal(kcontext, princ);

	if (kcontext)
		krb5_free_context(kcontext);

	return (retval);
}
