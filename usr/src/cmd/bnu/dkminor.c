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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"

#ifndef DIAL
	static char	SCCSID[] = "@(#)dkminor.c	2.3+BNU DKHOST 86/12/02";
#endif
/*
 *	COMMKIT(TM) Software - Datakit(R) VCS Interface Release 2.0 V1
 */
/*
   Return minor device number for a given Datakit device.
   The channel number is used since using the minor device returned
   by fstat gives wrong results for duplex systems.
*/

#include "dk.h"
GLOBAL
dkminor(fd)
{
	struct diocreq iocb;


	if (ioctl(fd, DIOCINFO, &iocb) < 0)
		return(-1);
	return(iocb.req_chmin); /* req_chmin contains channel number */
}
