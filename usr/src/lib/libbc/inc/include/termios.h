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

#ifndef	__SYS_TERMIOS_H
#define	__SYS_TERMIOS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stdtypes.h>
#include <sys/ioccom.h>
#include <sys/ttydev.h>
#include <sys/ttycom.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NCCS	17

/*
 * control characters
 * the following are not (yet) posix
 * VEOL2, VSWTCH, VDSUSP, VREPRINT, VDISCARD, VWERASE, VLNEXT, VSTATUS
 */
#define	VINTR		0
#define	VQUIT		1
#define	VERASE		2
#define	VKILL		3
#define	VEOF		4
#define	VEOL		5
#ifndef _POSIX_SOURCE
#define	VEOL2		6
#define	VSWTCH		7
#endif
#define	VSTART		8
#define	VSTOP		9
#define	VSUSP		10
#ifndef _POSIX_SOURCE
#define	VDSUSP		11
#define	VREPRINT	12
#define	VDISCARD	13
#define	VWERASE		14
#define	VLNEXT		15
#define	VSTATUS		16
#endif

#define	VMIN		VEOF
#define	VTIME		VEOL

#ifndef	_POSIX_SOURCE
#define	_CTRL(c)	('c'&037)

/*
 * default control chars.
 * guarded for ttychars.h.
 */
#ifndef	CINTR
#define	CINTR	_CTRL(c)
#define	CQUIT	034		/* FS, ^\ */
#define	CERASE	0177		/* DEL, ^? */
#define	CKILL	_CTRL(u)
#define	CEOF	_CTRL(d)
#define	CEOT	CEOF
#define	CEOL	0
#define	CEOL2	0
#define	CSWTCH	0
#define	CNSWTCH	0
#define	CSTART	_CTRL(q)
#define	CSTOP	_CTRL(s)
#define	CSUSP	_CTRL(z)
#define	CDSUSP	_CTRL(y)
#define	CRPRNT	_CTRL(r)
#define	CFLUSH	_CTRL(o)
#define	CWERASE	_CTRL(w)
#define	CLNEXT	_CTRL(v)
#endif	/* !CINTR */

#define	CESC	'\\'
#define	CNUL	0
#define	CDEL	0377
#endif	/* !_POSIX_SOURCE */

/* input modes */
#define	IGNBRK	0x00000001
#define	BRKINT	0x00000002
#define	IGNPAR	0x00000004
#define	PARMRK	0x00000008
#define	INPCK	0x00000010
#define	ISTRIP	0x00000020
#define	INLCR	0x00000040
#define	IGNCR	0x00000080
#define	ICRNL	0x00000100
/*	IUCLC	0x00000200	not posix, defined below */
#define	IXON	0x00000400
/*	IXANY	0x00000800	not posix, defined below */
#define	IXOFF	0x00001000
/*	IMAXBEL	0x00002000	not posix, defined below */

#ifndef	_POSIX_SOURCE
#define	IUCLC	0x00000200
#define	IXANY	0x00000800
#define	IMAXBEL	0x00002000
#endif	/* !_POSIX_SOURCE */

/* output modes */
#define	OPOST	0x00000001
#ifndef	_POSIX_SOURCE
#define	OLCUC	0x00000002
#define	ONLCR	0x00000004
#define	OCRNL	0x00000008
#define	ONOCR	0x00000010
#define	ONLRET	0x00000020
#define	OFILL	0x00000040
#define	OFDEL	0x00000080
#define	NLDLY	0x00000100
#define	NL0	0
#define	NL1	0x00000100
#define	CRDLY	0x00000600
#define	CR0	0
#define	CR1	0x00000200
#define	CR2	0x00000400
#define	CR3	0x00000600
#define	TABDLY	0x00001800
#define	TAB0	0
#define	TAB1	0x00000800
#define	TAB2	0x00001000
#define	XTABS	0x00001800
#define	TAB3	XTABS
#define	BSDLY	0x00002000
#define	BS0	0
#define	BS1	0x00002000
#define	VTDLY	0x00004000
#define	VT0	0
#define	VT1	0x00004000
#define	FFDLY	0x00008000
#define	FF0	0
#define	FF1	0x00008000
#define	PAGEOUT	0x00010000
#define	WRAP	0x00020000
#endif	/* !_POSIX_SOURCE */

/* control modes */
#ifndef	_POSIX_SOURCE
#define	CBAUD	0x0000000f
#endif
#define	CSIZE	0x00000030
#define	CS5	0
#define	CS6	0x00000010
#define	CS7	0x00000020
#define	CS8	0x00000030
#define	CSTOPB	0x00000040
#define	CREAD	0x00000080
#define	PARENB	0x00000100
#define	PARODD	0x00000200
#define	HUPCL	0x00000400
#define	CLOCAL	0x00000800
#ifndef	_POSIX_SOURCE
#define	LOBLK	0x00001000
#define	CIBAUD	0x000f0000
#define	CRTSXOFF 0x40000000
#define	CRTSCTS	0x80000000
#define	CBAUDEXT 0x200000
#define	CIBAUDEXT 0x400000

/*
 * 4.4BSD flags for hardware flow control
 */
#define	CRTS_IFLOW 0x40000000
#define	CCTS_OFLOW 0x80000000

#define	IBSHIFT	16
#endif	/* !_POSIX_SOURCE */

/* line discipline 0 modes */
#define	ISIG	0x00000001
#define	ICANON	0x00000002
/*	XCASE	0x00000004		not posix, defined below */
#define	ECHO	0x00000008
#define	ECHOE	0x00000010
#define	ECHOK	0x00000020
#define	ECHONL	0x00000040
#define	NOFLSH	0x00000080
#define	TOSTOP	0x00000100
/*	ECHOCTL	0x00000200		not posix, defined below */
/*	ECHOPRT	0x00000400		not posix, defined below */
/*	ECHOKE	0x00000800		not posix, defined below */
/*	DEFECHO	0x00001000		not posix, defined below */
/*	FLUSHO	0x00002000		not posix, defined below */
/*	PENDIN	0x00004000		not posix, defined below */
#define	IEXTEN	0x00008000

#ifndef	_POSIX_SOURCE
#define	XCASE	0x00000004
#define	ECHOCTL	0x00000200
#define	ECHOPRT	0x00000400
#define	ECHOKE	0x00000800
#define	DEFECHO	0x00001000
#define	FLUSHO	0x00002000
#define	PENDIN	0x00004000
#endif	/* !_POSIX_SOURCE */

#ifndef	_POSIX_SOURCE
/*
 * codes 1 through 5, not shown here, are old "termio" calls
 */
#define	TCXONC		_IO('T', 6)
#define	TCFLSH		_IO('T', 7)
#define	TCGETS		_IOR('T', 8, struct termios)
#define	TCSETS		_IOW('T', 9, struct termios)
#define	TCSETSW		_IOW('T', 10, struct termios)
#define	TCSETSF		_IOW('T', 11, struct termios)
#endif	/* !_POSIX_SOURCE */

#define	TCOOFF		0		/* arg to TCXONC & tcflow() */
#define	TCOON		1		/* arg to TCXONC & tcflow() */
#define	TCIOFF		2		/* arg to TCXONC & tcflow() */
#define	TCION		3		/* arg to TCXONC & tcflow() */
#define	TCIFLUSH	0		/* arg to TCFLSH & tcflush() */
#define	TCOFLUSH	1		/* arg to TCFLSH & tcflush() */
#define	TCIOFLUSH	2		/* arg to TCFLSH & tcflush() */
#define	TCSANOW		0		/* arg to tcsetattr() */
#define	TCSADRAIN	1		/* arg to tcsetattr() */
#define	TCSAFLUSH	2		/* arg to tcsetattr() */

/*
 * Ioctl control packet
 */
struct	termios {
	tcflag_t	c_iflag;	/* input modes */
	tcflag_t	c_oflag;	/* output modes */
	tcflag_t	c_cflag;	/* control modes */
	tcflag_t	c_lflag;	/* line discipline modes */
	char		c_line;		/* line discipline XXX */
	cc_t		c_cc[NCCS];	/* control chars */
};


#ifndef	KERNEL
speed_t	cfgetispeed(/* struct termios *termios_p */);
speed_t	cfgetospeed(/* struct termios *termios_p */);
int	cfsetispeed(/* struct termios *termios_p, speed_t speed */);
int	cfsetospeed(/* struct termios *termios_p, speed_t speed */);
int	tcdrain(/* int fildes */);
int	tcflow(/* int fildes, int action */);
int	tcflush(/* int fildes, int queue_selector */);
int	tcgetattr(/* int fildes, struct termios *termios_p */);
int	tcsendbreak(/* int fildes, int duration */);
int	tcsetattr(/* int fildes, int optional_actions, struct *termios_p */);
#endif	/* !KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* __SYS_TERMIOS_H */
