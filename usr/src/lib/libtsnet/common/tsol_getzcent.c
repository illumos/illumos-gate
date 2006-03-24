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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <nss_dbdefs.h>
#include <libtsnet.h>

static int tsol_zc_stayopen;	/* Unsynchronized, but it affects only	*/
				/*   efficiency, not correctness	*/
static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

struct zc_args {
	tsol_zcent_t *zc;
	int err;
	char *errstr;
	int errno_val;
};

static int str2tsol_zcent(const char *, int, void *, char *, int);

static void
_nss_initf_tsol_zc(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_TSOL_ZC;
	p->default_config = NSS_DEFCONF_TSOL_ZC;
}

/*
 * This is just a placeholder.  The system doesn't currently lookup tnzonecfg
 * entries via name services.
 */
/* ARGSUSED */
static void
switch_callback(void *res, const char *zonename, const char *label,
    const char *flags, const char *privmlp, const char *globalmlp)
{
}

tsol_zcent_t *
tsol_getzcbyname(const char *name)
{
	nss_XbyY_args_t arg;
	struct zc_args	zcargs;

	zcargs.zc = NULL;
	NSS_XbyY_INIT(&arg, &zcargs, (char *)switch_callback, 1,
	    str2tsol_zcent);
	arg.key.name	= name;
	arg.stayopen	= tsol_zc_stayopen;
	arg.h_errno	= TSOL_NOT_FOUND;
	arg.status = nss_search(&db_root, _nss_initf_tsol_zc,
	    NSS_DBOP_TSOL_ZC_BYNAME, &arg);
	(void) NSS_XbyY_FINI(&arg);
	if (arg.status != 0) {
		tsol_freezcent(zcargs.zc);
		zcargs.zc = NULL;
	}
	return (zcargs.zc);
}

void
tsol_setzcent(int stay)
{
	tsol_zc_stayopen |= stay;
	nss_setent(&db_root, _nss_initf_tsol_zc, &context);
}

void
tsol_endzcent(void)
{
	tsol_zc_stayopen = 0;
	nss_endent(&db_root, _nss_initf_tsol_zc, &context);
	nss_delete(&db_root);
}

struct tsol_zcent *
tsol_getzcent(void)
{
	nss_XbyY_args_t arg;
	struct zc_args zcargs;

	zcargs.zc = NULL;
	zcargs.errno_val = errno;
	NSS_XbyY_INIT(&arg, &zcargs, (char *)switch_callback, 1,
	    str2tsol_zcent);
	/* No key, no stayopen */
	arg.status = nss_getent(&db_root, _nss_initf_tsol_zc, &context, &arg);
	(void) NSS_XbyY_FINI(&arg);
	if (arg.status != 0) {
		tsol_freezcent(zcargs.zc);
		zcargs.zc = NULL;
	}
	if (zcargs.zc == NULL && zcargs.err == LTSNET_SYSERR)
		errno = zcargs.errno_val;
	return (zcargs.zc);
}

/*
 * This is the callback routine for nss.  It just wraps the tsol_sgetzcent
 * parser.
 */
/* ARGSUSED */
static int
str2tsol_zcent(const char *instr, int lenstr, void *entp, char *buffer,
    int buflen)
{
	struct zc_args *zcargs = entp;

	if (zcargs->zc != NULL)
		tsol_freezcent(zcargs->zc);
	zcargs->zc = tsol_sgetzcent(instr, &zcargs->err, &zcargs->errstr);
	zcargs->errno_val = errno;

	return (zcargs->zc == NULL ? NSS_STR_PARSE_PARSE :
	    NSS_STR_PARSE_SUCCESS);
}
