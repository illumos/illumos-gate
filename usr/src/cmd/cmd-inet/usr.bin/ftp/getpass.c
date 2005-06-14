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
 *	Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

/*
 *	University Copyright- Copyright (c) 1982, 1986, 1988
 *	The Regents of the University of California
 *	All Rights Reserved
 *
 *	University Acknowledgment- Portions of this document are derived from
 *	software developed by the University of California, Berkeley, and its
 *	contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ftp_var.h"

static	struct termios termios_b;
static	tcflag_t flags;
static	FILE *fi;

/* ARGSUSED */
static void
intfix(int sig)
{
	termios_b.c_lflag = flags;
	(void) tcsetattr(fileno(fi), TCSADRAIN, &termios_b);
	exit(EXIT_FAILURE);
}

char *
mygetpass(char *prompt)
{
	register char *p;
	register int c;
	static char pbuf[50+1];
	void (*sig)();

	stop_timer();
	if ((fi = fopen("/dev/tty", "r")) == NULL)
		fi = stdin;
	else
		setbuf(fi, (char *)NULL);

	if (tcgetattr(fileno(fi), &termios_b) < 0)
		perror("ftp: tcgetattr");	/* go ahead, anyway */
	flags = termios_b.c_lflag;

	sig = signal(SIGINT, intfix);

	termios_b.c_lflag &= ~ECHO;
	(void) tcsetattr(fileno(fi), TCSADRAIN, &termios_b);
	(void) fprintf(stderr, "%s", prompt);
	(void) fflush(stderr);
	p = pbuf;
	while ((c = getc(fi)) != '\n' && c != EOF) {
		if (p < &pbuf[sizeof (pbuf)-1])
			*p++ = c;
	}
	*p = '\0';
	(void) fprintf(stderr, "\n");
	(void) fflush(stderr);
	termios_b.c_lflag = flags;
	(void) tcsetattr(fileno(fi), TCSADRAIN, &termios_b);
	(void) signal(SIGINT, sig);
	if (fi != stdin)
		(void) fclose(fi);
	reset_timer();
	return (pbuf);
}
