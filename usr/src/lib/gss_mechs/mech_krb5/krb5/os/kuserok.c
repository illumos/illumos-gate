/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */


/*
 * lib/krb5/os/kuserok.c
 *
 * Copyright 1990,1993 by the Massachusetts Institute of Technology.
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
 * krb5_kuserok()
 */

#include "k5-int.h"
#if !defined(_WIN32)		/* Not yet for Windows */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <libintl.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi_krb5.h>
#include <gssapiP_krb5.h>
#include <syslog.h>

#if defined(_AIX) && defined(_IBMR2)
#include <sys/access.h>
/* xlc has a bug with "const" */
#define getpwnam(user) getpwnam((char *)user)
#endif

#define MAX_USERNAME 65
#define	CACHE_FILENAME_LEN 35

#if defined(__APPLE__) && defined(__MACH__)
#include <hfs/hfs_mount.h>	/* XXX */
#define FILE_OWNER_OK(UID)  ((UID) == 0 || (UID) == UNKNOWNUID)
#else
#define FILE_OWNER_OK(UID)  ((UID) == 0)
#endif

/* Solaris Kerberos */
extern void
gsscred_set_options();

extern OM_uint32
gsscred_name_to_unix_cred_ext();

extern int
safechown(const char *src, uid_t uid, gid_t gid, int mode);

extern const char *error_message(long);


krb5_data tgtname = {
	0,
	KRB5_TGS_NAME_SIZE,
	KRB5_TGS_NAME
};

/* Solaris Kerberos */
static krb5_error_code
krb5_move_ccache(krb5_context kcontext, krb5_principal client,
		struct passwd *pwd)
{
	char *name = 0;
	static char ccache_name_buf[CACHE_FILENAME_LEN];
	krb5_ccache ccache = NULL;
	krb5_error_code retval;

	name = getenv(KRB5_ENV_CCNAME);
	if (name == 0)
		/*
		 * This means that there was no forwarding
		 * of creds
		 */
		return (0);
	else {
		/*
		 * creds have been forwarded and stored in
		 * KRB5_ENV_CCNAME and now we need to store it
		 * under uid
		 */

		krb5_creds mcreds, save_v5creds;

		memset(&mcreds, 0, sizeof (mcreds));
		memset(&save_v5creds, 0, sizeof (save_v5creds));

		mcreds.client =  client;
		retval = krb5_build_principal_ext(kcontext, &mcreds.server,
				krb5_princ_realm(kcontext,  client)->length,
				krb5_princ_realm(kcontext,  client)->data,
				tgtname.length, tgtname.data,
				krb5_princ_realm(kcontext,  client)->length,
				krb5_princ_realm(kcontext,  client)->data,
				0);
		if (retval) {
			syslog(LOG_ERR,
				gettext("KRB5: %s while creating"
					"V5 krbtgt principal "),
				error_message(retval));
			return (retval);
		}

		mcreds.ticket_flags = 0;
		retval = krb5_cc_default(kcontext, &ccache);
		if (retval) {
			syslog(LOG_ERR,
				gettext("KRB5: %s while getting "
					"default cache "),
				error_message(retval));
			return (retval);
		}

		retval = krb5_cc_retrieve_cred(kcontext, ccache,
						0,
						&mcreds, &save_v5creds);
		if (retval) {
			syslog(LOG_ERR,
				gettext("KRB5: %s while retrieving "
					"cerdentials "),
				error_message(retval));
			return (retval);
		}
		/*
		 * reset the env variable and recreate the
		 * cache using the default cache name
		 */
		retval = krb5_cc_destroy(kcontext, ccache);
		if (retval) {
			syslog(LOG_ERR,
				gettext("KRB5: %s while destroying cache "),
				error_message(retval));
			return (retval);
		}
		krb5_unsetenv(KRB5_ENV_CCNAME);
		snprintf(ccache_name_buf,
			CACHE_FILENAME_LEN,
			"FILE:/tmp/krb5cc_%d", pwd->pw_uid);
		krb5_setenv(KRB5_ENV_CCNAME, ccache_name_buf, 1);
		retval =  krb5_cc_resolve(kcontext, ccache_name_buf, &ccache);
		if (retval) {
			syslog(LOG_ERR,
				gettext("KRB5: %s while resolving cache "),
				error_message(retval));
			return (retval);
		}
		retval = krb5_cc_initialize(kcontext, ccache, client);
		if (retval) {
			syslog(LOG_ERR,
				gettext("KRB5: %s while initializing cache "),
				error_message(retval));
			return (retval);
		}
		retval =  krb5_cc_store_cred(kcontext, ccache, &save_v5creds);
		if (retval) {
			syslog(LOG_ERR,
				gettext("KRB5: %s while storing creds "),
				error_message(retval));
			return (retval);
		}
		snprintf(ccache_name_buf,
			CACHE_FILENAME_LEN,
			"/tmp/krb5cc_%d", pwd->pw_uid);
		if (safechown(ccache_name_buf, pwd->pw_uid,
			pwd->pw_gid, -1) == -1) {
			syslog(LOG_ERR,
				gettext("KRB5: Can not change "
					"ownership of cache file, "
					"possible security breach\n"));
		}
	}

	return (0);
}


/*
 * Solaris Kerberos:
 * krb5_gsscred: Given a kerberos principal try to find the corresponding
 * local uid via the gss cred table. Return TRUE if the uid was found in the
 * cred table, otherwise return FALSE.
 */
static krb5_boolean
krb5_gsscred(krb5_principal principal, uid_t *uid)
{
	OM_uint32 minor, major;
	gss_name_t name;
	gss_buffer_desc name_buf;

	name_buf.value = &principal;
	name_buf.length = sizeof (principal);

	/*
	 * Convert the kerb principal in to a gss name
	 */
	major = gss_import_name(&minor, &name_buf,
				(gss_OID)gss_nt_krb5_principal, &name);

	if (major != GSS_S_COMPLETE)
		return (FALSE);

	gsscred_set_options();

	/*
	 * Get the uid mapping from the gsscred table.
	 * (but set flag to not call back into this mech as we do krb5
	 * auth_to_local name mapping from this module).
	 */
	major = gsscred_name_to_unix_cred_ext(name, (gss_OID)gss_mech_krb5,
					  uid, 0, 0, 0, 0);

	(void) gss_release_name(&minor, &name);

	if (major != GSS_S_COMPLETE)
		return (FALSE);

	return (TRUE);
}

/*
 * Given a Kerberos principal "principal", and a local username "luser",
 * determine whether user is authorized to login according to the
 * authorization file ("~luser/.k5login" by default).  Returns TRUE
 * if authorized, FALSE if not authorized.
 *
 * If there is no account for "luser" on the local machine, returns
 * FALSE.  If there is no authorization file, and the given Kerberos
 * name "server" translates to the same name as "luser" (using
 * krb5_aname_to_lname()), returns TRUE.  Otherwise, if the authorization file
 * can't be accessed, returns FALSE.  Otherwise, the file is read for
 * a matching principal name, instance, and realm.  If one is found,
 * returns TRUE, if none is found, returns FALSE.
 *
 * The file entries are in the format produced by krb5_unparse_name(),
 * one entry per line.
 *
 */

krb5_boolean KRB5_CALLCONV
krb5_kuserok(krb5_context context, krb5_principal principal, const char *luser)
{
    struct stat sbuf;
    struct passwd *pwd;
    char pbuf[MAXPATHLEN];
    krb5_boolean isok = FALSE;
    FILE *fp;
    char kuser[MAX_USERNAME];
    char *princname;
    char linebuf[BUFSIZ];
    char *newline;
    /* Solaris Kerberos */
    uid_t uid;
    int gobble;

    /* no account => no access */
    char pwbuf[BUFSIZ];
    struct passwd pwx;
    if (k5_getpwnam_r(luser, &pwx, pwbuf, sizeof(pwbuf), &pwd) != 0)
	return(FALSE);
    (void) strncpy(pbuf, pwd->pw_dir, sizeof(pbuf) - 1);
    pbuf[sizeof(pbuf) - 1] = '\0';
    (void) strncat(pbuf, "/.k5login", sizeof(pbuf) - 1 - strlen(pbuf));

    if (access(pbuf, F_OK)) {	 /* not accessible */
	/*
	 * if they're trying to log in as themself, and there is no .k5login file,
	 * let them.  First, have krb5 check it's rules.  If no success,
	 * search the gsscred table (the sequence here should be consistent
	 * with the uid mappings done for gssd).
	 */
	if (!(krb5_aname_to_localname(context, principal,
				      sizeof(kuser), kuser))
	    && (strcmp(kuser, luser) == 0)) {
		/* Solaris Kerberos */
		if (krb5_move_ccache(context, principal, pwd))
			return (FALSE);
	    	return(TRUE);
	}

	if (krb5_gsscred(principal, &uid)) {
#ifdef DEBUG
	    char *princname;

	    (void)krb5_unparse_name(context, principal, &princname);
	    syslog(LOG_DEBUG, "gsscred mapped %s to %d expecting %d (%s)\n",
		   princname, uid, pwd->pw_uid, luser);
	    free(princname);
#endif
	    if (uid == pwd->pw_uid) {
		if (krb5_move_ccache(context, principal, pwd))
			return (FALSE);
		return (TRUE);
	    }
	}

    }
    if (krb5_unparse_name(context, principal, &princname))
	return(FALSE);			/* no hope of matching */

    /* open ~/.k5login */
    /* Solaris Kerberos */
    if ((fp = fopen(pbuf, "rF")) == NULL) {
	free(princname);
	return(FALSE);
    }
    /*
     * For security reasons, the .k5login file must be owned either by
     * the user himself, or by root.  Otherwise, don't grant access.
     */
    if (fstat(fileno(fp), &sbuf)) {
	fclose(fp);
	free(princname);
	return(FALSE);
    }
    if (sbuf.st_uid != pwd->pw_uid && !FILE_OWNER_OK(sbuf.st_uid)) {
	fclose(fp);
	free(princname);
	return(FALSE);
    }

    /* check each line */
    while (!isok && (fgets(linebuf, BUFSIZ, fp) != NULL)) {
	/* null-terminate the input string */
	linebuf[BUFSIZ-1] = '\0';
	newline = NULL;
	/* nuke the newline if it exists */
	if ((newline = strchr(linebuf, '\n')))
	    *newline = '\0';
	if (!strcmp(linebuf, princname)) {
	    isok = TRUE;
	    /* Solaris Kerberos */
	    if (krb5_move_ccache(context, principal, pwd))
		return (FALSE);
	    continue;
	}
	/* clean up the rest of the line if necessary */
	if (!newline)
	    while (((gobble = getc(fp)) != EOF) && gobble != '\n');
    }
    free(princname);
    fclose(fp);
    return(isok);
}

/* Solaris Kerberos */
OM_uint32
krb5_gss_userok(OM_uint32 *minor,
		const gss_name_t pname,
		const char *user,
		int *user_ok)
{
	krb5_context ctxt;
	OM_uint32 kret;

	if (pname == NULL || user == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (minor == NULL || user_ok == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*user_ok = 0;

	kret = krb5_gss_init_context(&ctxt);
	if (kret) {
		*minor = kret;
		return (GSS_S_FAILURE);
	}

	if (! kg_validate_name(pname)) {
		*minor = (OM_uint32) G_VALIDATE_FAILED;
		krb5_free_context(ctxt);
		return (GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
	}

	if (krb5_kuserok(ctxt, (krb5_principal) pname, user)) {
		*user_ok = 1;
	}

	krb5_free_context(ctxt);
	return (GSS_S_COMPLETE);
}

#else /* _WIN32 */

/*
 * If the given Kerberos name "server" translates to the same name as "luser"
 * (using * krb5_aname_to_lname()), returns TRUE.
 */
krb5_boolean KRB5_CALLCONV
krb5_kuserok(context, principal, luser)
    krb5_context context;
    krb5_principal principal;
    const char *luser;
{
    char kuser[50];

    if (krb5_aname_to_localname(context, principal, sizeof(kuser), kuser))
        return FALSE;

    if (strcmp(kuser, luser) == 0)
	    return TRUE;

    return FALSE;
}
#endif /* _WIN32 */
