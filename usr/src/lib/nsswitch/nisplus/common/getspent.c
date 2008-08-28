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

/*
 *  nisplus/getspent.c: implementations of getspnam(), getspent(), setspent(),
 *  endspent() for NIS+.  We keep the shadow information in a column
 *  ("shadow") of the same table that stores vanilla passwd information.
 */


#include <sys/types.h>
#include <shadow.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <thread.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

extern int key_secretkey_is_set_g();

/*
 * bugid 4301477:
 * We lock NIS+/getspnam() so there is only one at a time,
 * So applications which link with libthread can now call
 * getspnam() (or UNIX pam_authenticate() which calls getspnam)
 * in a Secure NIS+ environment (as per CERT Advisory 96.10).
 * This is usually not a problem as login/su/dtlogin are single
 * threaded, note dtlogin is now linked with libthread (bugid 4263325)
 * which is why this bug exists (Note thr_main() check was removed)
 */

static mutex_t  one_lane = DEFAULTMUTEX;


static nss_status_t
getbynam(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp	= (nss_XbyY_args_t *)a;
	struct spwd		*sp	= (struct spwd *)argp->buf.result;
	int			buflen	= argp->buf.buflen;
	nss_status_t		status;
	const char		*username;
	uid_t			orig_uid;
	uid_t			entry_uid;
	struct spwd		save_sp;
	char			*save_buf;

	/* part of fix for bugid 4301477 */
	(void) mutex_lock(&one_lane);

	/*
	 * There is a dirty little private protocol with the nis_object2str()
	 * routine below:  it gives us back a uid in the argp->key.uid
	 * field.  Since "key" is a union, and we're using key.name,
	 * we save/restore it in case anyone cares.
	 *
	 * NSS2: be->flag is used to indicate *NP* case since we
	 * may not have the shadow passwd available at this point
	 * if called by nscd's switch.
	 */
	username = argp->key.name;
	be->flag = 0;

	status = _nss_nisplus_lookup(be, argp, PW_TAG_NAME, username);

	/*
	 * passwd.org_dir may have its access rights set up so that
	 * the passwd field can only be read by the user whom
	 * the entry describes.  If we get an *NP* in the password
	 * field we should try to get it again as the user.  If not,
	 * we return now.
	 */

	/* fix for bugid 4301477 DELETED if (_thr_main() != -1) goto out; */

	if (status != NSS_SUCCESS || argp->returnval == 0 || be->flag == 0)
		goto out;

	/* Get our current euid and that of the entry */
	orig_uid = geteuid();
	entry_uid = argp->key.uid;
	be->flag = 0;

	/*
	 * If the entry uid differs from our own euid, set our euid to
	 * the entry uid and try the lookup again.
	 */

	if ((entry_uid != orig_uid) && (seteuid(entry_uid) != -1)) {
		/*
		 * Do the second lookup only if secretkey is set for
		 * this euid, otherwise it will be pointless.  Also,
		 * make sure we can allocate space to save the old
		 * results.
		 */
		if (key_secretkey_is_set_g(0, 0) &&
		    ((save_buf = (char *)malloc(buflen)) != 0)) {

			/* Save the old results in case the new lookup fails */
			(void) memcpy(save_buf, argp->buf.buffer, buflen);
			save_sp = *sp;

			/* Do the lookup (this time as the user). */
			status = _nss_nisplus_lookup(be, argp, PW_TAG_NAME,
						    username);

			/* If it failed, restore the old results */
			if (status != NSS_SUCCESS) {
				(void) memcpy(argp->buf.buffer, save_buf,
					buflen);
				*sp = save_sp;
				status = NSS_SUCCESS;
			}

			free(save_buf);
		}

		/* Set uid back */
		(void) seteuid(orig_uid);
	}

out:
	/* end of fix for bugid 4301477 unlock NIS+/getspnam() */
	(void) mutex_unlock(&one_lane);

	argp->key.name = username;
	return (status);
}

/*
 * place the results from the nis_object structure into argp->buf.result
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
/*ARGSUSED*/
static int
nis_object2str(nobj, obj, be, argp)
	int			nobj;
	nis_object		*obj;
	nisplus_backend_ptr_t	be;
	nss_XbyY_args_t		*argp;
{
	char			*buffer, *name, *passwd, *shadow;
	int			buflen, namelen, passwdlen, shadowlen;
	char			*endnum, *uidstr;
	uid_t			uid;
	int			uidlen;
	struct entry_col	*ecol;

	/*
	 * If we got more than one nis_object, we just ignore it.
	 * Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are
	 * null terminated.
	 */

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		obj->EN_data.en_cols.en_cols_len < PW_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/* name: user name */
	__NISPLUS_GETCOL_OR_RETURN(ecol, PW_NDX_NAME, namelen, name);

	/* passwd */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, PW_NDX_PASSWD, passwdlen, passwd);

	/* uid */
	__NISPLUS_GETCOL_OR_RETURN(ecol, PW_NDX_UID, uidlen, uidstr);
	uid = strtol(uidstr, &endnum, 10);
	if (*endnum != 0 || endnum == uidstr)
		return (NSS_STR_PARSE_PARSE);
	/*
	 * See discussion of private protocol in getbynam() above.
	 *   Note that we also end up doing this if we're called from
	 *   _nss_nisplus_getent(), but that's OK -- when we're doing
	 *   enumerations we don't care what's in the argp->key union.
	 */
	if (strncmp(passwd, NOPWDRTR, passwdlen) == 0) {
		be->flag = 1;
		argp->key.uid = uid;
	}

	/*
	 * shadow information
	 *
	 * We will be lenient to no shadow field or a shadow field
	 * with less than the desired number of ":" separated longs.
	 * XXX - should we be more strict ?
	 */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, PW_NDX_SHADOW, shadowlen, shadow);

	buflen = namelen + passwdlen + shadowlen + 3;
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL)
			return (NSS_STR_PARSE_PARSE);
		/* exclude trailing null from length */
		be->buflen = buflen - 1;
		buffer = be->buffer;
	} else {
		if (buflen > argp->buf.buflen)
			return (NSS_STR_PARSE_ERANGE);
		buflen = argp->buf.buflen;
		buffer = argp->buf.buffer;
		(void) memset(buffer, 0, buflen);
	}
	(void) snprintf(buffer, buflen, "%s:%s:%s",
		name, passwd, shadow);
#ifdef DEBUG
	(void) fprintf(stdout, "shadow [%s]\n", buffer);
	(void) fflush(stdout);
#endif  /* DEBUG */
	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t sp_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbynam
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_shadow_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(sp_ops,
				    sizeof (sp_ops) / sizeof (sp_ops[0]),
				    PW_TBLNAME, nis_object2str));
}
