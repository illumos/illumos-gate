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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <locale.h>
#include <libintl.h>

/*
 * consolidation pkg command library includes
 */

#include <pkglib.h>

/*
 * local pkg command library includes
 */

#include "install.h"
#include "libinst.h"
#include "libadm.h"
#include "messages.h"

extern int	warnflag;

/*
 * forward declarations
 */

static int	finalck_warning(struct cfent *ept, int attrchg, int contchg);
static int	finalck_error(struct cfent *ept, int attrchg, int contchg);

int
finalck(struct cfent *ept, int attrchg, int contchg, boolean_t a_warning)
{
	int	errflg;

	/*
	 * invoke the correct finalck based on whether warnings or errors
	 * should be generated
	 */

	if (a_warning) {
		errflg = finalck_warning(ept, attrchg, contchg);
	} else {
		errflg = finalck_error(ept, attrchg, contchg);
	}

	/* exit debug output */

	echoDebug(DBG_FINALCK_EXIT, errflg, ept->ftype,
		ept->path ? ept->path : "");

	/* return results of the finalck_xxx call */

	return (errflg);
}

/*
 * this finalck generates errors on failure
 */

static int
finalck_error(struct cfent *ept, int attrchg, int contchg)
{
	int	errflg = 0;

	/* entry debug info */

	echoDebug(DBG_FINALCK_ERROR, attrchg, contchg, ept->ftype,
		ept->path ? ept->path : "");

	/* on attribute or content change, verify attributes */

	if (attrchg || contchg) {
		int	n;

		/* verify change, or fix if possible */
		n = averify(1, &ept->ftype, ept->path, &ept->ainfo);
		echoDebug(DBG_FINALCK_ERROR_AVERIFY, n);
		if (n != 0) {
			logerr(ERR_FINALCK_ATTR, ept->path);
			logerr(getErrbufAddr());
			errflg++;
			warnflag++;
			if (n == VE_EXIST)
				return (1); /* no need to check contents */
		}
	}

	/* on content change of "f/e/v" type, verify contents */

	if (contchg && strchr("fev", ept->ftype)) {
		int	n;

		/* verify change was executed properly */

		if (contchg < 0) {
			ept->cinfo.modtime = BADCONT;
			ept->cinfo.size = BADCONT;
			ept->cinfo.cksum = BADCONT;
		}

		n = cverify(1, &ept->ftype, ept->path, &ept->cinfo, 1);
		echoDebug(DBG_FINALCK_ERROR_CVERIFY, n);
		if (n != 0) {
			logerr(ERR_FINALCK_CONT, ept->path);
			logerr(getErrbufAddr());
			errflg++;
			warnflag++;
		}
	}

	return (errflg);
}

/*
 * this finalck generates warnings on failure
 */

static int
finalck_warning(struct cfent *ept, int attrchg, int contchg)
{
	int	errflg = 0;

	/* entry debug info */

	echoDebug(DBG_FINALCK_WARNING, attrchg, contchg, ept->ftype,
		ept->path ? ept->path : "");


	/* on attribute or content change, verify attributes */

	if (attrchg || contchg) {
		int	n;

		/* verify change, or fix if possible */

		n = averify(1, &ept->ftype, ept->path, &ept->ainfo);
		echoDebug(DBG_FINALCK_WARNING_AVERIFY, n);
		if (n != 0) {
			logerr(WRN_FINALCK_ATTR, ept->path);
			logerr(getErrbufAddr());
			errflg++;
			if (n == VE_EXIST) {
				return (1); /* no need to check contents */
			}
		}
	}

	/* on content change of "f/e/v" type, verify contents */

	if (contchg && strchr("fev", ept->ftype)) {
		int	n;

		/* verify change was executed properly */

		if (contchg < 0) {
			ept->cinfo.modtime = BADCONT;
			ept->cinfo.size = BADCONT;
			ept->cinfo.cksum = BADCONT;
		}

		n = cverify(1, &ept->ftype, ept->path, &ept->cinfo, 1);
		echoDebug(DBG_FINALCK_WARNING_CVERIFY, n);
		if (n != 0) {
			logerr(WRN_FINALCK_CONT, ept->path);
			logerr(getErrbufAddr());
		}
		errflg++;
	}

	return (errflg);
}
