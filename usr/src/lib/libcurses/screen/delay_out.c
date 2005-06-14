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

/*
 * Code for various kinds of delays.  Most of this is nonportable and
 * requires various enhancements to the operating system, so it won't
 * work on all systems.  It is included in curses to provide a portable
 * interface, and so curses itself can use it for function keys.
 */

#include	<sys/types.h>
#include	"curses_inc.h"

/*
 * Delay the output for ms milliseconds.
 * Note that this is NOT the same as a high resolution sleep.  It will
 * cause a delay in the output but will not necessarily suspend the
 * processor.  For applications needing to sleep for 1/10th second,
 * this is not a usable substitute.  It causes a pause in the displayed
 * output, for example, for the eye wink in snake.  It is disrecommended
 * for "delay" to be much more than 1/2 second, especially at high
 * baud rates, because of all the characters it will output.  Note
 * that due to system delays, the actual pause could be even more.
 * You can't get a decent pac-man game with this routine.
 */

int
delay_output(int ms)
{
	extern	int	_outchar(char);

	return (_delay(ms * 10, _outchar));
}
