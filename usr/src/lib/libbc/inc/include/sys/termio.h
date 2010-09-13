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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#ifndef _sys_termio_h
#define	_sys_termio_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/ioccom.h>
#include	<sys/termios.h>

#define	NCC	8

#define	SSPEED	7	/* default speed: 300 baud */

/*
 * Ioctl control packet
 */
struct termio {
	unsigned short	c_iflag;	/* input modes */
	unsigned short	c_oflag;	/* output modes */
	unsigned short	c_cflag;	/* control modes */
	unsigned short	c_lflag;	/* line discipline modes */
	char	c_line;			/* line discipline */
	unsigned char	c_cc[NCC];	/* control chars */
};

#define	TCGETA	_IOR('T', 1, struct termio)
#define	TCSETA	_IOW('T', 2, struct termio)
#define	TCSETAW	_IOW('T', 3, struct termio)
#define	TCSETAF	_IOW('T', 4, struct termio)
#define	TCSBRK	_IO('T', 5)

#endif /* !_sys_termio_h */
