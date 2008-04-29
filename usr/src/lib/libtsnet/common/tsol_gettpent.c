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
 *
 * From "tsol_gettpent.c	7.13	00/10/13 SMI; TSOL 2.x"
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <nss_dbdefs.h>
#include <libtsnet.h>
#include <secdb.h>
#include <nss.h>
#include <libintl.h>

extern void _nss_XbyY_fgets(FILE *, nss_XbyY_args_t *);	/* from lib.c */

static int tsol_tp_stayopen;	/* Unsynchronized, but it affects only	*/
				/*   efficiency, not correctness	*/
static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);


static void
_nss_initf_tsol_tp(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_TSOL_TP;
	p->default_config = NSS_DEFCONF_TSOL_TP;
}

tsol_tpent_t *
tsol_gettpbyname(const char *name)
{
	int		err = 0;
	char		*errstr = NULL;
	char		buf[NSS_BUFLEN_TSOL_TP];
	tsol_tpstr_t	result;
	tsol_tpstr_t	*tpstrp = NULL;
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, &result, buf, sizeof (buf), str_to_tpstr);

	arg.key.name	= name;
	arg.stayopen	= tsol_tp_stayopen;
	arg.h_errno	= TSOL_NOT_FOUND;
	arg.status = nss_search(&db_root, _nss_initf_tsol_tp,
	    NSS_DBOP_TSOL_TP_BYNAME, &arg);
	tpstrp = (tsol_tpstr_t *)NSS_XbyY_FINI(&arg);

#ifdef	DEBUG
	(void) fprintf(stdout, "tsol_gettpbyname %s: %s\n",
	    name, tpstrp ? tpstrp->template : "NULL");
#endif	/* DEBUG */

	if (tpstrp == NULL)
		return (NULL);

	return (tpstr_to_ent(tpstrp, &err, &errstr));
}

void
tsol_settpent(int stay)
{
	tsol_tp_stayopen |= stay;
	nss_setent(&db_root, _nss_initf_tsol_tp, &context);
}

void
tsol_endtpent(void)
{
	tsol_tp_stayopen = 0;
	nss_endent(&db_root, _nss_initf_tsol_tp, &context);
	nss_delete(&db_root);
}

tsol_tpent_t *
tsol_gettpent(void)
{
	int		err = 0;
	char		*errstr = NULL;
	char		buf[NSS_BUFLEN_TSOL_TP];
	tsol_tpstr_t	result;
	tsol_tpstr_t	*tpstrp = NULL;
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, &result, buf, sizeof (buf), str_to_tpstr);
	/* No key, no stayopen */
	arg.status = nss_getent(&db_root, _nss_initf_tsol_tp, &context, &arg);
	tpstrp = (tsol_tpstr_t *)NSS_XbyY_FINI(&arg);

#ifdef	DEBUG
	(void) fprintf(stdout, "tsol_gettpent: %s\n",
	    tpstrp ? tpstrp->template : "NULL");
#endif	/* DEBUG */

	if (tpstrp == NULL)
		return (NULL);

	return (tpstr_to_ent(tpstrp, &err, &errstr));
}

tsol_tpent_t *
tsol_fgettpent(FILE *f, boolean_t *error)
{
	int		err = 0;
	char		*errstr = NULL;
	char		buf[NSS_BUFLEN_TSOL_TP];
	tsol_tpstr_t	result;
	tsol_tpstr_t	*tpstrp = NULL;
	tsol_tpent_t	*tpentp = NULL;
	nss_XbyY_args_t	arg;

	NSS_XbyY_INIT(&arg, &result, buf, sizeof (buf), str_to_tpstr);
	_nss_XbyY_fgets(f, &arg);
	tpstrp = (tsol_tpstr_t *)NSS_XbyY_FINI(&arg);
	if (tpstrp == NULL)
		return (NULL);
	tpentp = tpstr_to_ent(tpstrp, &err, &errstr);
	while (tpentp == NULL) {
		/*
		 * Loop until we find a non-blank, non-comment line, or
		 * until EOF. No need to log blank lines, comments.
		 */
		if (err != LTSNET_EMPTY) {
			(void) fprintf(stderr, "%s: %.32s%s: %s\n",
			    gettext("Error parsing tnrhtp file"), errstr,
			    (strlen(errstr) > 32)? "...": "",
			    (char *)tsol_strerror(err, errno));
			*error = B_TRUE;
		}
		_nss_XbyY_fgets(f, &arg);
		tpstrp = (tsol_tpstr_t *)NSS_XbyY_FINI(&arg);
		if (tpstrp == NULL)	/* EOF */
			return (NULL);
		tpentp = tpstr_to_ent(tpstrp, &err, &errstr);
	}
	return (tpentp);
}

/*
 * This is the callback routine for nss.  It just wraps the tsol_sgettpent
 * parser.
 */
int
str_to_tpstr(const char *instr, int lenstr, void *entp, char *buffer,
    int buflen)
{
	int		len;
	char		*last = NULL;
	char		*sep = KV_TOKEN_DELIMIT;
	tsol_tpstr_t	*tpstrp = (tsol_tpstr_t *)entp;

	if ((instr >= buffer && (buffer + buflen) > instr) ||
	    (buffer >= instr && (instr + lenstr) > buffer))
		return (NSS_STR_PARSE_PARSE);
	if (lenstr >= buflen)
		return (NSS_STR_PARSE_ERANGE);
	(void) strncpy(buffer, instr, buflen);
	tpstrp->template = _strtok_escape(buffer, sep, &last);
	tpstrp->attrs = _strtok_escape(NULL, sep, &last);
	if (tpstrp->attrs != NULL) {
		len = strlen(tpstrp->attrs);
		if (tpstrp->attrs[len - 1] == '\n')
			tpstrp->attrs[len - 1] = '\0';
	}

#ifdef	DEBUG
	(void) fprintf(stdout,
	    "str_to_tpstr:\nstr - %s\n\ttemplate - %s\n\tattrs - %s\n",
	    instr, tpstrp->template ? tpstrp->template : "NULL",
	    tpstrp->attrs ? tpstrp->attrs : "NULL");
#endif	/* DEBUG */

	return (NSS_STR_PARSE_SUCCESS);
}
