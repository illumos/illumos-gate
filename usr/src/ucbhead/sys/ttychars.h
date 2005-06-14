/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 */

/*
 * User visible structures and constants
 * related to terminal handling.
 */

#ifndef _SYS_TTYCHARS_H
#define	_SYS_TTYCHARS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct ttychars {
	char	tc_erase;	/* erase last character */
	char	tc_kill;	/* erase entire line */
	char	tc_intrc;	/* interrupt */
	char	tc_quitc;	/* quit */
	char	tc_startc;	/* start output */
	char	tc_stopc;	/* stop output */
	char	tc_eofc;	/* end-of-file */
	char	tc_brkc;	/* input delimiter (like nl) */
	char	tc_suspc;	/* stop process signal */
	char	tc_dsuspc;	/* delayed stop process signal */
	char	tc_rprntc;	/* reprint line */
	char	tc_flushc;	/* flush output (toggles) */
	char	tc_werasc;	/* word erase */
	char	tc_lnextc;	/* literal next character */
};

#ifndef _SYS_TERMIOS_H

#ifndef CTRL
#define	CTRL(c)	((c) & 037)
#endif

/* default special characters */
#define	CERASE	0177
#define	CKILL	CTRL('u')
#define	CINTR	CTRL('c')
#define	CQUIT	034		/* FS, ^\ */
#define	CSTART	CTRL('q')
#define	CSTOP	CTRL('s')
#define	CEOF	CTRL('d')
#define	CEOT	CEOF
#define	CBRK	0377
#define	CSUSP	CTRL('z')
#define	CDSUSP	CTRL('y')
#define	CRPRNT	CTRL('r')
#define	CFLUSH	CTRL('o')
#define	CWERASE	CTRL('w')
#define	CLNEXT	CTRL('v')

#endif	/* _SYS_TERMIOS_H */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_TTYCHARS_H */
