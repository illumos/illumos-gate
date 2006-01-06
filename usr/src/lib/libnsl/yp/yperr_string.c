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
#include <rpcsvc/ypclnt.h>
#include <sys/types.h>

/*
 * This returns a pointer to an error message string appropriate to an input
 * yp error code.  An input value of zero will return a success message.
 * In all cases, the message string will start with a lower case chararacter,
 * and will be terminated neither by a period (".") nor a newline.
 */

char *
yperr_string(int code)
{
	switch (code) {
	case 0:
		return ("yp operation succeeded");
	case YPERR_BADARGS:
		return ("args to yp function are bad");
	case YPERR_RPC:
		return ("RPC failure on yp operation");
	case YPERR_DOMAIN:
		return ("can't bind to a server which serves domain");
	case YPERR_MAP:
		return ("no such map in server's domain");
	case YPERR_KEY:
		return ("no such key in map");
	case YPERR_YPERR:
		return ("internal yp server or client error");
	case YPERR_RESRC:
		return ("local resource allocation failure");
	case YPERR_NOMORE:
		return ("no more records in map database");
	case YPERR_PMAP:
		return ("can't communicate with rpcbind");
	case YPERR_YPBIND:
		return ("can't communicate with ypbind");
	case YPERR_YPSERV:
		return ("can't communicate with ypserv");
	case YPERR_NODOM:
		return ("local domain name not set");
	case YPERR_BADDB:
		return ("yp map data base is bad");
	case YPERR_VERS:
		return ("yp client/server version mismatch");
	case YPERR_ACCESS:
		return ("permission denied");
	case YPERR_BUSY:
		return ("database is busy");
	}
	return ("unknown yp client error code");
}
