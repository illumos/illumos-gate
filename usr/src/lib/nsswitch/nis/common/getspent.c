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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	nis/getspent.c -- "nis" backend for nsswitch "shadow" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <shadow.h>
#include <string.h>
#include "nis_common.h"

/*
 * Most of the information in a struct spwd simply isn't available from the
 * YP maps, we dummy out all the numeric fields and just get sp_namp and
 * sp_pwdp (name and password) from the YP passwd map.  Thus we don't
 * use the str2ent() routine that's passed to us, but instead have our
 * own dummy routine:
 *
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas. Let's not
 * fight over crumbs.
 */
static int
nis_str2spent(instr, lenstr, ent, buffer, buflen)
	const char		*instr;
	int			lenstr;
	void	*ent; /* it is really (struct spwd *) */
	char	*buffer;
	int	buflen;
{
	struct spwd		*spwd	= (struct spwd *)ent;
	char			*p, *q, *r;

	/*
	 * We know that instr != 0 because we're in 'nis', not 'files'
	 */
	if ((p = memchr(instr, ':', lenstr)) == 0) {
		return (NSS_STR_PARSE_PARSE);
	}
	if ((q = memchr(p + 1, ':', lenstr - (p + 1 - instr))) == 0) {
		return (NSS_STR_PARSE_PARSE);
	}
	/* Don't bother checking the rest of the YP passwd entry... */

	if (q + 1 - instr > buflen) {
		return (NSS_STR_PARSE_ERANGE);
	}
	/*
	 * "name:password" is copied
	 */
	(void) memcpy(buffer, instr, q - instr);
	if (spwd) {
		buffer[p - instr] = '\0';
		buffer[q - instr] = '\0';

		spwd->sp_namp	= buffer;
		spwd->sp_pwdp	= buffer + (p + 1 - instr);
		spwd->sp_lstchg	= -1;
		spwd->sp_min	= -1;
		spwd->sp_max	= -1;
		spwd->sp_warn	= -1;
		spwd->sp_inact	= -1;
		spwd->sp_expire	= -1;
		spwd->sp_flag	= 0;
	} else {
		/*
		 *  NSS2: nscd is running. Return files format.
		 *
		 *  name:password:::::::
		 */
		r = buffer + (q - instr);
		*r = '\0';
		if (strlcat(buffer, ":::::::", buflen) >= buflen)
			return (NSS_STR_PARSE_ERANGE);
	}
	return (NSS_STR_PARSE_SUCCESS);
}

typedef int	(*cstr2ent_t)(const char *, int, void *, char *, int);

static nss_status_t
getbyname(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	cstr2ent_t		save_c2e;
	nss_status_t		res;
	struct spwd 		*spwd;
	char			*p;

	save_c2e	= argp->str2ent;
	argp->str2ent	= nis_str2spent;
	res = _nss_nis_lookup(be, argp, 0, "passwd.byname", argp->key.name, 0);
	spwd = (struct spwd *)argp->buf.result;
	/*
	 * check for the C2 security flag "##" in the passwd field.
	 * If the first 2 chars in the passwd field is "##", get
	 * the user's passwd from passwd.adjunct.byname map.
	 * The lookup to this passwd.adjunct.byname map will only
	 * succeed if the caller's uid is 0 because only root user
	 * can use privilege port.
	 */
	if (res == NSS_SUCCESS) {
		if (spwd) {
			if ((spwd->sp_pwdp) && (*(spwd->sp_pwdp) == '#') &&
				(*(spwd->sp_pwdp + 1) == '#')) {
			/* get password from passwd.adjunct.byname */
				res = _nss_nis_lookup_rsvdport(be, argp, 0,
						"passwd.adjunct.byname",
						argp->key.name, 0);
			}
		} else {
			/*
			 * getent request from nscd
			 */
			if ((p = memchr(argp->buf.buffer, ':',
					argp->buf.buflen)) == NULL)
				return (NSS_STR_PARSE_PARSE);
			if (strncmp(p + 1, "##", 2) == 0)
				/* get password from passwd.adjunct.byname */
				res = _nss_nis_lookup_rsvdport(be, argp, 0,
						"passwd.adjunct.byname",
						argp->key.name, 0);
			if (res ==  NSS_SUCCESS) {
				argp->returnval = argp->buf.buffer;
				argp->returnlen = strlen(argp->buf.buffer);
			}
		}
	}

	argp->str2ent	= save_c2e;
	return (res);
}

#define	NIS_SP_GETENT

#ifdef	NIS_SP_GETENT

static nss_status_t
getent(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	cstr2ent_t		save_c2e;
	nss_status_t		res;
	struct spwd 		*spwd;
	char			*p;

	save_c2e	= argp->str2ent;
	argp->str2ent	= nis_str2spent;
	res = _nss_nis_getent_rigid(be, argp);
	spwd = (struct spwd *)argp->buf.result;
	/*
	 * check for the C2 security flag "##" in the passwd field.
	 * If the first 2 chars in the passwd field is "##", get
	 * the user's passwd from passwd.adjunct.byname map.
	 * The lookup to this passwd.adjunct.byname map will only
	 * succeed if the caller's uid is 0 because only root user
	 * can use privilege port.
	 */
	if (res == NSS_SUCCESS) {
		if (spwd) {
			if ((spwd->sp_pwdp) && (*(spwd->sp_pwdp) == '#') &&
				(*(spwd->sp_pwdp + 1) == '#')) {
				/* get password from passwd.adjunct.byname */
				res = _nss_nis_lookup_rsvdport(be, argp, 0,
					"passwd.adjunct.byname",
					spwd->sp_namp, 0);
			}
		} else {
			/*
			 * getent request from nscd
			 */
			if ((p = memchr(argp->buf.buffer, ':',
					argp->buf.buflen)) == NULL)
				return (NSS_STR_PARSE_PARSE);
			if (strncmp(p + 1, "##", 2) == 0) {
				/* need the name for the next search */
				*p = '\0';
				/* get password from passwd.adjunct.byname */
				res = _nss_nis_lookup_rsvdport(be, argp, 0,
					"passwd.adjunct.byname", p, 0);
			}
			if (res ==  NSS_SUCCESS) {
				argp->returnval = argp->buf.buffer;
				argp->returnlen = strlen(argp->buf.buffer);
			}
		}
	}

	argp->str2ent	= save_c2e;
	return (res);
}

#endif	/* NIS_SP_GETENT */

static nis_backend_op_t shadow_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
#ifdef	NIS_SP_GETENT
	getent,
#else
	0,
#endif	/* NIS_SP_GETENT */
	getbyname
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_shadow_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(shadow_ops,
				sizeof (shadow_ops) / sizeof (shadow_ops[0]),
				"passwd.byname"));
}
