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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* 	Portions Copyright(c) 1988, Sun Microsystems Inc.	*/
/*	All Rights Reserved					*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <sys/uadmin.h>
#include <unistd.h>
#include <errno.h>

/*
 * Not all BSD's semantics are supported
 * including RB_SINGLE, RB_RB_DUMP, RB_STRING
 */

/*
 * BSD reboot.h
 */
#define	RB_AUTOBOOT	0	/* flags for system auto-booting itself */

#define	RB_ASKNAME	0x001   /* ask for file name to reboot from */
#define	RB_SINGLE	0x002   /* reboot to single user only */
#define	RB_NOSYNC	0x004   /* dont sync before reboot */
#define	RB_HALT		0x008   /* don't reboot, just halt */
#define	RB_INITNAME	0x010   /* name given for /etc/init */
#define	RB_NOBOOTRC	0x020   /* don't run /etc/rc.boot */
#define	RB_DEBUG	0x040   /* being run under debugger */
#define	RB_DUMP		0x080   /* dump system core */
#define	RB_WRITABLE	0x100   /* mount root read/write */
#define	RB_STRING	0x200   /* pass boot args to prom monitor */

/*ARGSUSED*/
int
reboot(int howto, char *bootargs)
{
	int	cmd;
	int	fcn;
	int	mdep = 0;

	if (getuid() != 0) {
		errno = EPERM;
		return (-1);
	}

	if (howto & RB_HALT) {
		cmd = A_SHUTDOWN;
		fcn = AD_HALT;
	} else if (howto & RB_ASKNAME) {
		cmd = A_SHUTDOWN;
		fcn = AD_IBOOT;
	} else {		/* assume RB_AUTOBOOT */
		cmd = A_SHUTDOWN;
		fcn = AD_BOOT;
	}

	/* return something to be consistent with the original prototype */
	return (uadmin(cmd, fcn, mdep));
		/* most cases, we are gone and code does not reach here */
}
