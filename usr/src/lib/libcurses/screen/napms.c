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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	"curses_inc.h"
#include	<stdio.h>
#include	<sys/types.h>
#include	<poll.h>

/*
 * napms.  Sleep for ms milliseconds.  We don't expect a particularly good
 * resolution - 60ths of a second is normal, 10ths might even be good enough,
 * but the rest of the program thinks in ms because the unit of resolution
 * varies from system to system.  (In some countries, it's 50ths, for example.)
 * Vaxen running 4.2BSD and 3B's use 100ths.
 *
 * Here are some reasonable ways to get a good nap.
 *
 * (1) Use the poll() or select() system calls in SVr3 or Berkeley 4.2BSD.
 *
 * (2) Use the 1/10th second resolution wait in the System V tty driver.
 *     It turns out this is hard to do - you need a tty line that is
 *     always unused that you have read permission on to sleep on.
 *
 * (3) Install the ft (fast timer) device in your kernel.
 *     This is a psuedo-device to which an ioctl will wait n ticks
 *     and then send you an alarm.
 *
 * (4) Install the nap system call in your kernel.
 *     This system call does a timeout for the requested number of ticks.
 *
 * (5) Write a routine that busy waits checking the time with ftime.
 *     Ftime is not present on SYSV systems, and since this busy waits,
 *     it will drag down response on your system.  But it works.
 */

int
napms(int ms)
{
	struct pollfd pollfd;

	if (poll(&pollfd, 0L, ms) == -1)
		perror("poll");
	return (OK);
}
