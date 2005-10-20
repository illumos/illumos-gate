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

#ifndef	__sys_ttycom_h
#define	__sys_ttycom_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_POSIX_SOURCE

/*
 * Window/terminal size structure.
 * This information is stored by the kernel
 * in order to provide a consistent interface,
 * but is not used by the kernel.
 *
 * Type must be "unsigned short" so that types.h not required.
 */
struct winsize {
	unsigned short	ws_row;		/* rows, in characters */
	unsigned short	ws_col;		/* columns, in characters */
	unsigned short	ws_xpixel;	/* horizontal size, pixels - not used */
	unsigned short	ws_ypixel;	/* vertical size, pixels - not used */
};

#define	TIOCGWINSZ	_IOR('t', 104, struct winsize)	/* get window size */
#define	TIOCSWINSZ	_IOW('t', 103, struct winsize)	/* set window size */

/*
 * Sun version of same.
 */
struct ttysize {
	int	ts_lines;	/* number of lines on terminal */
	int	ts_cols;	/* number of columns on terminal */
};

#define	TIOCSSIZE	_IOW('t',37,struct ttysize)/* set tty size */
#define	TIOCGSIZE	_IOR('t',38,struct ttysize)/* get tty size */

/*
 * 4.3BSD and SunOS terminal "ioctl"s with no "termios" equivalents.
 * This file is included by <sys/termios.h> and indirectly by <sys/ioctl.h>
 * so that programs that include either one have these "ioctl"s defined.
 */
#define	TIOCSCTTY	_IO('t', 132)		/* get a ctty */
#define	TIOCGPGRP	_IOR('t', 119, int)	/* get pgrp of tty */
#define	TIOCGETPGRP	_IOR('t', 131, int)	/* get pgrp of tty (posix) */
#define	TIOCSPGRP	_IOW('t', 118, int)	/* set pgrp of tty */
#define	TIOCSETPGRP	_IOW('t', 130, int)	/* set pgrp of tty (posix) */
#define	TIOCOUTQ	_IOR('t', 115, int)	/* output queue size */
#define	TIOCSTI		_IOW('t', 114, char)	/* simulate terminal input */
#define	TIOCNOTTY	_IO('t', 113)		/* void tty association */
#define	TIOCPKT		_IOW('t', 112, int)	/* pty: set/clear packet mode */
#define		TIOCPKT_DATA		0x00	/* data packet */
#define		TIOCPKT_FLUSHREAD	0x01	/* flush data not yet written to controller */
#define		TIOCPKT_FLUSHWRITE	0x02	/* flush data read from controller but not yet processed */
#define		TIOCPKT_STOP		0x04	/* stop output */
#define		TIOCPKT_START		0x08	/* start output */
#define		TIOCPKT_NOSTOP		0x10	/* no more ^S, ^Q */
#define		TIOCPKT_DOSTOP		0x20	/* now do ^S, ^Q */
#define		TIOCPKT_IOCTL		0x40	/* "ioctl" packet */
#define	TIOCMSET	_IOW('t', 109, int)	/* set all modem bits */
#define	TIOCMBIS	_IOW('t', 108, int)	/* bis modem bits */
#define	TIOCMBIC	_IOW('t', 107, int)	/* bic modem bits */
#define	TIOCMGET	_IOR('t', 106, int)	/* get all modem bits */
#define		TIOCM_LE	0001		/* line enable */
#define		TIOCM_DTR	0002		/* data terminal ready */
#define		TIOCM_RTS	0004		/* request to send */
#define		TIOCM_ST	0010		/* secondary transmit */
#define		TIOCM_SR	0020		/* secondary receive */
#define		TIOCM_CTS	0040		/* clear to send */
#define		TIOCM_CAR	0100		/* carrier detect */
#define		TIOCM_CD	TIOCM_CAR
#define		TIOCM_RNG	0200		/* ring */
#define		TIOCM_RI	TIOCM_RNG
#define		TIOCM_DSR	0400		/* data set ready */

#define	TIOCREMOTE	_IOW('t', 105, int)	/* remote input editing */
#define	TIOCUCNTL	_IOW('t', 102, int)	/* pty: set/clr usr cntl mode */

/*
 * Sun-specific ioctls with no "termios" equivalents.
 */
#define	TIOCTCNTL	_IOW('t', 32, int)	/* pty: set/clr intercept ioctl mode */
#define	TIOCSIGNAL	_IOW('t', 33, int)	/* pty: send signal to slave */
#define	TIOCCONS	_IO('t', 36)		/* get console I/O */
#define	TIOCSSOFTCAR	_IOW('t', 101, int)	/* set soft carrier flag */
#define	TIOCGSOFTCAR	_IOR('t', 100, int)	/* get soft carrier flag */
#define	TIOCISPACE	_IOR('t', 128, int)	/* space left in input queue */
#define	TIOCISIZE	_IOR('t', 129, int)	/* size of input queue */

#endif	/* !_POSIX_SOURCE */
#endif	/* !__sys_ttycom_h */
