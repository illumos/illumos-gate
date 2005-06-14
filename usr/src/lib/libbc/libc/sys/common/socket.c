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
 * Copyright (c) 1990-1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>

extern int	errno;

int
socket(family, type, protocol)
register int	family;
register int	type;
register int	protocol;
{
	int	a;
	static int map[]={0,2,1,4,5,6};
	if ((a = _socket_bsd(family, map[type], protocol)) == -1) {
		maperror(errno);
		switch (errno) {
		case EAFNOSUPPORT:
		case EPROTOTYPE:
			errno = EPROTONOSUPPORT;
			break;
		}
	}
	return(a);
}


