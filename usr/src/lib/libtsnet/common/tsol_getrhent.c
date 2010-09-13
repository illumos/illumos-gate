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
 * From "tsol_getrhent.c	7.6	00/09/22 SMI; TSOL 2.x"
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <nss_dbdefs.h>
#include <libtsnet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <secdb.h>
#include <nss.h>
#include <libtsnet.h>
#include <libintl.h>

extern void _nss_XbyY_fgets(FILE *, nss_XbyY_args_t *);	/* from lib.c */

static int tsol_rh_stayopen;	/* Unsynchronized, but it affects only	*/
				/*   efficiency, not correctness	*/
static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

static void
_nss_initf_tsol_rh(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_TSOL_RH;
	p->default_config = NSS_DEFCONF_TSOL_RH;
}

tsol_rhent_t *
tsol_getrhbyaddr(const void *addrp, size_t len, int af)
{
	int		err = 0;
	char		*errstr = NULL;
	char		buf[NSS_BUFLEN_TSOL_RH];
	tsol_rhstr_t	result;
	tsol_rhstr_t	*rhstrp = NULL;
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, &result, buf, sizeof (buf), str_to_rhstr);

	arg.key.hostaddr.addr = (const char *)addrp;
	arg.key.hostaddr.len = len;
	arg.key.hostaddr.type = af;
	arg.stayopen = tsol_rh_stayopen;
	arg.h_errno = TSOL_NOT_FOUND;
	arg.status = nss_search(&db_root, _nss_initf_tsol_rh,
	    NSS_DBOP_TSOL_RH_BYADDR, &arg);
	rhstrp = (tsol_rhstr_t *)NSS_XbyY_FINI(&arg);

#ifdef	DEBUG
	(void) fprintf(stdout, "tsol_getrhbyaddr %s: %s\n",
	    (char *)addrp, rhstrp ? rhstrp->template : "NULL");
#endif	/* DEBUG */

	if (rhstrp == NULL)
		return (NULL);

	return (rhstr_to_ent(rhstrp, &err, &errstr));
}

void
tsol_setrhent(int stay)
{
	tsol_rh_stayopen |= stay;
	nss_setent(&db_root, _nss_initf_tsol_rh, &context);
}

void
tsol_endrhent(void)
{
	tsol_rh_stayopen = 0;
	nss_endent(&db_root, _nss_initf_tsol_rh, &context);
	nss_delete(&db_root);
}

tsol_rhent_t *
tsol_getrhent(void)
{
	int			err = 0;
	char			*errstr = NULL;
	char			buf[NSS_BUFLEN_TSOL_RH];
	tsol_rhstr_t		result;
	tsol_rhstr_t		*rhstrp = NULL;
	nss_XbyY_args_t		arg;

	NSS_XbyY_INIT(&arg, &result, buf, sizeof (buf), str_to_rhstr);
	/* No key, no stayopen */
	arg.status = nss_getent(&db_root, _nss_initf_tsol_rh, &context, &arg);
	rhstrp = (tsol_rhstr_t *)NSS_XbyY_FINI(&arg);

#ifdef	DEBUG
	(void) fprintf(stdout, "tsol_getrhent: %s\n",
	    rhstrp ? rhstrp->template : "NULL");
#endif	/* DEBUG */

	if (rhstrp == NULL)
		return (NULL);

	return (rhstr_to_ent(rhstrp, &err, &errstr));
}

tsol_rhent_t *
tsol_fgetrhent(FILE *f, boolean_t *error)
{
	int		err = 0;
	char		*errstr = NULL;
	char		buf[NSS_BUFLEN_TSOL_RH];
	tsol_rhstr_t	result;
	tsol_rhstr_t	*rhstrp = NULL;
	tsol_rhent_t	*rhentp = NULL;
	nss_XbyY_args_t	arg;

	NSS_XbyY_INIT(&arg, &result, buf, sizeof (buf), str_to_rhstr);
	_nss_XbyY_fgets(f, &arg);
	rhstrp = (tsol_rhstr_t *)NSS_XbyY_FINI(&arg);
	if (rhstrp == NULL)
		return (NULL);
	rhentp = rhstr_to_ent(rhstrp, &err, &errstr);
	while (rhentp == NULL) {
		/*
		 * Loop until we find a non-blank, non-comment line, or
		 * until EOF. No need to log blank lines, comments.
		 */
		if (err != LTSNET_EMPTY) {
			(void) fprintf(stderr, "%s: %.32s%s: %s\n",
			    gettext("Error parsing tnrhdb file"), errstr,
			    (strlen(errstr) > 32)? "...": "",
			    (char *)tsol_strerror(err, errno));
			*error = B_TRUE;
		}
		_nss_XbyY_fgets(f, &arg);
		rhstrp = (tsol_rhstr_t *)NSS_XbyY_FINI(&arg);
		if (rhstrp == NULL)	/* EOF */
			return (NULL);
		rhentp = rhstr_to_ent(rhstrp, &err, &errstr);
	}
	return (rhentp);
}

/*
 * This is the callback routine for nss.
 */
int
str_to_rhstr(const char *instr, int lenstr, void *entp, char *buffer,
    int buflen)
{
	int		len;
	char		*str = NULL;
	char		*last = NULL;
	char		*sep = KV_TOKEN_DELIMIT;
	tsol_rhstr_t	*rhstrp = (tsol_rhstr_t *)entp;

	if ((instr >= buffer && (buffer + buflen) > instr) ||
	    (buffer >= instr && (instr + lenstr) > buffer))
		return (NSS_STR_PARSE_PARSE);
	if (lenstr >= buflen)
		return (NSS_STR_PARSE_ERANGE);
	(void) strncpy(buffer, instr, buflen);
	str = _strtok_escape(buffer, sep, &last);
	rhstrp->address = _do_unescape(str);
	/*
	 * _do_unesape uses isspace() which removes "\n".
	 * we keep "\n" as we use it in checking for
	 * blank lines.
	 */
	if (strcmp(instr, "\n") == 0)
		rhstrp->address = "\n";
	rhstrp->template = _strtok_escape(NULL, sep, &last);
	if (rhstrp->template != NULL) {
		len = strlen(rhstrp->template);
		if (rhstrp->template[len - 1] == '\n')
			rhstrp->template[len - 1] = '\0';
	}
	if (rhstrp->address == NULL)
		rhstrp->family = 0;
	else if (strchr(rhstrp->address, ':') == NULL)
		rhstrp->family = AF_INET;
	else
		rhstrp->family = AF_INET6;

#ifdef	DEBUG
	(void) fprintf(stdout,
	    "str_to_rhstr:str - %s\taddress - %s\n\ttemplate - %s\n",
	    instr, rhstrp->address ? rhstrp->address : "NULL",
	    rhstrp->template ? rhstrp->template : "NULL");
#endif	/* DEBUG */

	return (NSS_STR_PARSE_SUCCESS);
}

tsol_host_type_t
tsol_getrhtype(char *rhost) {
	int herr;
	struct hostent *hp;
	in6_addr_t in6;
	char abuf[INET6_ADDRSTRLEN];
	tsol_rhent_t rhent;
	tsol_tpent_t tp;

	if ((hp = getipnodebyname(rhost, AF_INET6,
	    AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED, &herr)) == NULL) {
		return (UNLABELED);
	}

	(void) memset(&rhent, 0, sizeof (rhent));
	(void) memcpy(&in6, hp->h_addr, hp->h_length);

	if (IN6_IS_ADDR_V4MAPPED(&in6)) {
		rhent.rh_address.ta_family = AF_INET;
		IN6_V4MAPPED_TO_INADDR(&in6, &rhent.rh_address.ta_addr_v4);
		(void) inet_ntop(AF_INET, &rhent.rh_address.ta_addr_v4, abuf,
		    sizeof (abuf));
	} else {
		rhent.rh_address.ta_family = AF_INET6;
		rhent.rh_address.ta_addr_v6 = in6;
		(void) inet_ntop(AF_INET6, &in6, abuf, sizeof (abuf));
	}

	if (tnrh(TNDB_GET, &rhent) != 0)
		return (UNLABELED);

	if (rhent.rh_template[0] == '\0')
		return (UNLABELED);

	(void) strlcpy(tp.name, rhent.rh_template, sizeof (tp.name));

	if (tnrhtp(TNDB_GET, &tp) != 0)
		return (UNLABELED);

	return (tp.host_type);
}
