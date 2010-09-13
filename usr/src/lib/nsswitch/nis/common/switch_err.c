/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	switch_err.c
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpcsvc/ypclnt.h>
#include <nsswitch.h>

/*
 * maps errors returned by libnsl/yp routines into switch errors
 */

int
switch_err(ypclnt_err)
	int ypclnt_err;
{
	int serr;

	switch (ypclnt_err) {
	case 0:
		serr = __NSW_SUCCESS;
		break;
	case YPERR_BADARGS:
	case YPERR_KEY:
	case YPERR_NOMORE:
		serr = __NSW_NOTFOUND;
		break;
	case YPERR_RPC:
	case YPERR_DOMAIN:
	case YPERR_MAP:
	case YPERR_YPERR:
	case YPERR_RESRC:
	case YPERR_PMAP:
	case YPERR_YPBIND:
	case YPERR_YPSERV:
	case YPERR_NODOM:
	case YPERR_BADDB:
	case YPERR_VERS:
	case YPERR_ACCESS:
		serr = __NSW_UNAVAIL;
		break;
	case YPERR_BUSY:
		serr = __NSW_TRYAGAIN; /* :-) */
	}

	return (serr);
}
