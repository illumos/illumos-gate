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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/
/*
 *
 * Conditional compilation definitions needed in ifdef.c and postio.c.
 *
 */


#ifdef SYSV
#include <termio.h>
#endif


#ifdef V9
#include <sys/filio.h>
#include <sys/ttyio.h>

extern int	tty_ld;
#endif


#ifdef BSD4_2
#include <sgtty.h>
#include <sys/time.h>
#include <errno.h>

#define FD_ZERO(s) (s) = 0
#define FD_SET(n,s) (s) |= 1 << (n)

extern int	errno;
#endif


#ifdef DKHOST
#include <dk.h>
#include <sysexits.h>

extern char	*dtnamer();
extern int	dkminor();
#endif


/*
 *
 * External variable declarations - most (if not all) are defined in postio.c and
 * needed by the routines in ifdef.c.
 *
 */


extern char	*line;			/* printer is on this line */
extern int	ttyi;			/* input */
extern int	ttyo;			/* and output file descriptors */
extern FILE	*fp_log;		/* just for DKHOST stuff */

extern char	mesg[];			/* exactly what came back on ttyi */
extern char	*endmesg;		/* one in front of last free slot in mesg */
extern int	next;			/* next character goes in mesg[next] */

extern short	baudrate;		/* printer is running at this speed */
extern int	stopbits;		/* and expects this many stop bits */
extern int	interactive;		/* TRUE for interactive mode */

extern int	canread;		/* allows reads */
extern int	canwrite;		/* and writes if TRUE */

