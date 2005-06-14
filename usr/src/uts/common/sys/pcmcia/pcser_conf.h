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
 * Copyright (c) 1995,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _PCSER_CONF_H
#define	_PCSER_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * pcserconf.h - misc stuff
 */

#ifdef	ZIP
/*
 * default setting for the serial lines
 */
static struct pcser_defaults_t pcser_initmodes = {
	/* flags */
	SDFLAGS,
	/* drain_size */
	PCSER_DRAIN_BSIZE,
	/* pcser_hiwater */
	PCSER_HIWATER,
	/* pcser_lowwater */
	PCSER_LOWWATER,
	/* rtpr */
	PCSER_RTPR,
	/* rx_fifo_thld */
	RX_FIFO_SIZE,
	/* struct termios */
	{
		BRKINT|ICRNL|IXON|ISTRIP,		/* iflag */
		OPOST|ONLCR|XTABS,			/* oflag */
		CFLAGS|TX_BAUD,				/* cflag */
		ISIG|ICANON|ECHO,			/* lflag */
		{ /* cc[NCCS] */
			CINTR, CQUIT, CERASE, CKILL,
			CEOF, CEOL, CEOL2, CSWTCH,
			CSTART, CSTOP, CSUSP, CDSUSP,
			CRPRNT, CFLUSH, CWERASE, CLNEXT,
		},
	},
};
#endif	/* ZIP */

/*
 * baud rate conversion table - note that for speeds that we don't
 *	support, the table entry is 0
 */
unsigned short pcser_baud_table[PCSER_MAX_SPEEDS] = {
	0x00000,	/* B0 (hangup line, not really a speed) */
	0x00900,	/* B50 */
	0x00600,	/* B75 */
	0x00417,	/* B110 */
	0x00359,	/* B134 */
	0x00300,	/* B150 */
	0x00240,	/* B200 */
	0x00180,	/* B300 */
	0x000c0,	/* B600 */
	0x00060,	/* B1200 */
	0x00040,	/* B1800 */
	0x00030,	/* B2400 */
	0x00018,	/* B4800 */
	0x0000c,	/* B9600 */
	0x00006,	/* B19200 */
	0x00003,	/* B38400 */
	0x00002,	/* B57600 */
	0x00000,	/* B76800 */
	0x00001,	/* B115200 */
	0x00000,	/* B153600 */
	0x00000,	/* B230400 */
	0x00000,	/* B307200 */
	0x00000,	/* B460800 */
};

/*
 * ioctl debugging stuff
 */
#ifdef	DEBUG_PCSERIOCTL

struct ioc_txt_t {
	char	*name;
	int	ioc_cmd;
};

struct ioc_txt_t ioc_txt[] = {
	{ "TCSBRK",		TCSBRK },
	{ "TCSETSW",		TCSETSW },
	{ "TCSETSF",		TCSETSF },
	{ "TCSETAW",		TCSETAW },
	{ "TCSETAF",		TCSETAF },
	{ "TIOCSBRK",		TIOCSBRK },
	{ "TIOCCBRK",		TIOCCBRK },
	{ "TCGETA",		TCGETA },
	{ "TCSETA",		TCSETA },
	{ "TCSETAW",		TCSETAW },
	{ "TCSETAF",		TCSETAF },
	{ "TCXONC",		TCXONC },
	{ "TCFLSH",		TCFLSH },
	{ "TIOCKBON",		TIOCKBON },
	{ "TIOCKBOF",		TIOCKBOF },
	{ "KBENABLED",		KBENABLED },
	{ "TCDSET",		TCDSET },
	{ "RTS_TOG",		RTS_TOG },
	{ "TIOCGWINSZ",		TIOCGWINSZ },
	{ "TIOCSWINSZ",		TIOCSWINSZ },
	{ "TIOCGSOFTCAR",	TIOCGSOFTCAR },
	{ "TIOCSSOFTCAR",	TIOCSSOFTCAR },
	{ "TCGETS",		TCGETS },
	{ "TCSETS",		TCSETS },
	{ "TCSANOW",		TCSANOW },
	{ "TCSADRAIN",		TCSADRAIN },
	{ "TCSAFLUSH",		TCSAFLUSH },
	{ "STGET",		STGET },
	{ "STSET",		STSET },
	{ "STTHROW",		STTHROW },
	{ "STWLINE",		STWLINE },
	{ "STTSV",		STTSV },
	{ "TCGETX",		TCGETX },
	{ "TCSETX",		TCSETX },
	{ "TCSETXW",		TCSETXW },
	{ "TCSETXF",		TCSETXF },
	{ "TIOCMSET",		TIOCMSET },
	{ "TIOCMBIS",		TIOCMBIS },
	{ "TIOCMBIC",		TIOCMBIC },
	{ "TIOCMGET",		TIOCMGET },
	{ "TIOCFLUSH",		TIOCFLUSH },
	{ "TIOCCDTR",		TIOCCDTR },
	{ "TIOCSDTR",		TIOCSDTR },
	{ (char *)NULL,		0 }
};
#endif	/* DEBUG_PCSERIOCTL */

#ifdef	__cplusplus
}
#endif

#endif	/* _PCSER_CONF_H */
