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
 *
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <sys/types.h>
#include <rpc/trace.h>

/*
 * Maps a yp protocol error code (as defined in
 * yp_prot.h) to a yp client interface error code (as defined in
 * ypclnt.h).
 */
int
ypprot_err(yp_protocol_error)
	int yp_protocol_error;
{
	int reason;
	trace2(TR_ypprot_err, 0, yp_protocol_error);
	switch (yp_protocol_error) {
	case YP_TRUE:
		reason = 0;
		break;
	case YP_NOMORE:
		reason = YPERR_NOMORE;
		break;
	case YP_NOMAP:
		reason = YPERR_MAP;
		break;
	case YP_NODOM:
		reason = YPERR_DOMAIN;
		break;
	case YP_NOKEY:
		reason = YPERR_KEY;
		break;
	case YP_BADARGS:
		reason = YPERR_BADARGS;
		break;
	case YP_BADDB:
		reason = YPERR_BADDB;
		break;
	case YP_VERS:
		reason = YPERR_VERS;
		break;
	default:
		reason = YPERR_YPERR;
		break;
	}
	trace1(TR_ypprot_err, 1);
	return (reason);
}
