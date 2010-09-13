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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

#include "mt.h"
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <sys/types.h>

/*
 * Maps a yp protocol error code (as defined in
 * yp_prot.h) to a yp client interface error code (as defined in
 * ypclnt.h).
 */
int
ypprot_err(int yp_protocol_error)
{
	switch (yp_protocol_error) {
	case YP_TRUE:
		return (0);
	case YP_NOMORE:
		return (YPERR_NOMORE);
	case YP_NOMAP:
		return (YPERR_MAP);
	case YP_NODOM:
		return (YPERR_DOMAIN);
	case YP_NOKEY:
		return (YPERR_KEY);
	case YP_BADARGS:
		return (YPERR_BADARGS);
	case YP_BADDB:
		return (YPERR_BADDB);
	case YP_VERS:
		return (YPERR_VERS);
	}
	return (YPERR_YPERR);
}
