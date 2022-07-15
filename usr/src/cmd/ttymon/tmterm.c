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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <termio.h>
#include <sys/stermio.h>
#include <sys/termiox.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include "sys/stropts.h"
#include "sys/signal.h"
#include "ttymon.h"
#include "tmstruct.h"
#include "tmextern.h"

/*
 *	set_termio	- set termio on device
 *		fd	- fd for the device
 *		options - stty termio options
 *		aspeed  - autobaud speed
 *		clear	- if TRUE, current flags will be set to some defaults
 *			  before applying the options
 *			- if FALSE, current flags will not be cleared
 *		mode	- terminal mode, CANON, RAW
 */



int
set_termio(int fd, char *options, char *aspeed, int clear, long mode)
{
	struct	 termio termio;
	struct	 termios termios;
	struct	 stio stermio;
	struct	 termiox termiox;
	struct	 winsize winsize;
	struct	 winsize owinsize;
	int	 term;
	int	 cnt = 1;
	char	 *uarg;
	char	 *argvp[MAXARGS];	/* stty args */
	static   char	 *binstty = "/usr/bin/stty";
	static	 char	buf[BUFSIZ];

#ifdef	DEBUG
	debug("in set_termio");
#endif

	if ((term = get_ttymode(fd, &termio, &termios, &stermio,
	    &termiox, &winsize)) < 0) {
		log("set_termio: get_ttymode failed: %s", strerror(errno));
		return (-1);
	}
	owinsize = winsize;
	if (clear) {
		if (mode & CANON) {
			/* could have removed these too - rely on defaults */
			termios.c_cc[VEOF] = CEOF;
			termios.c_cc[VEOL] = CNUL;
		} else {
			termios.c_lflag &= ECHO;
			termios.c_cc[VMIN] = 1;
			termios.c_cc[VTIME] = 0;
		}

	}

	if (options != NULL && *options != '\0') {
		/* just a place holder to make it look like invoking stty */
		argvp[0] = binstty;
		(void) strcpy(buf, options);
		mkargv(buf, &argvp[1], &cnt, MAXARGS - 1);
		if (aspeed != NULL && *aspeed != '\0') {
			argvp[cnt++] = aspeed;
		}
		argvp[cnt] = (char *)0;
		if ((uarg = sttyparse(cnt, argvp, term, &termio, &termios,
		    &termiox, &winsize)) != NULL) {
			log("sttyparse unknown mode: %s", uarg);
			return (-1);
		}
	}


	if (set_ttymode(fd, term, &termio, &termios, &stermio,
	    &termiox, &winsize, &owinsize) != 0) {
		log("set_termio: set_ttymode failed", strerror(errno));
		return (-1);
	}

	return (0);
}

#ifdef	NOT_USE
/*
 *	turnon_canon	- turn on canonical processing
 *			- return 0 if succeeds, -1 if fails
 */
turnon_canon(int fd)
{
	struct termio termio;

#ifdef	DEBUG
	debug("in turnon_canon");
#endif
	if (ioctl(fd, TCGETA, &termio) != 0) {
		log("turnon_canon: TCGETA failed, fd = %d: %s", fd,
		    strerror(errno));
		return (-1);
	}
	termio.c_lflag |= (ISIG|ICANON|ECHO|ECHOE|ECHOK);
	termio.c_cc[VEOF] = CEOF;
	termio.c_cc[VEOL] = CNUL;
	if (ioctl(fd, TCSETA, &termio) != 0) {
		log("turnon_canon: TCSETA failed, fd = %d: %s", fd,
		    strerror(errno));
		return (-1);
	}
	return (0);
}
#endif

/*
 *	flush_input	- flush the input queue
 */
void
flush_input(int fd)
{
	if (ioctl(fd, I_FLUSH, FLUSHR) == -1)
		log("flush_input failed, fd = %d: %s", fd, strerror(errno));

	if (ioctl(fd, TCSBRK, 1) == -1)
		log("drain of ouput failed, fd = %d: %s", fd, strerror(errno));
}

/*
 * push_linedisc	- if modules is not NULL, pop everything
 *			- then push modules specified by "modules"
 */
int
push_linedisc(
	int	fd,	/* fd to push modules on */
	char	*modules, /* ptr to a list of comma separated module names */
	char	*device) /* device name for printing msg */
{
	char	*p, *tp;
	char	buf[BUFSIZ];

#ifdef	DEBUG
	debug("in push_linedisc");
#endif
	/*
	 * copy modules into buf so we won't mess up the original buffer
	 * because strtok will chop the string
	 */
	p = strcpy(buf, modules);

	while (ioctl(fd, I_POP, 0) >= 0)  /* pop everything */
		;
	for (p = strtok(p, ","); p != NULL; p = strtok(NULL, ",")) {
		for (tp = p + strlen(p) - 1; tp >= p && isspace(*tp); --tp)
			*tp = '\0';
		if (ioctl(fd, I_PUSH, p) == -1) {
			log("push (%s) on %s failed: %s", p, device,
			    strerror(errno));
			return (-1);
		}
	}
	return (0);
}

/*
 *	hang_up_line	- set speed to B0. This will drop DTR
 */
int
hang_up_line(int fd)
{
	struct termio termio;
	struct termios termios;

#ifdef	DEBUG
	debug("in hang_up_line");
#endif
	if (ioctl(fd, TCGETS, &termios) < 0) {
		if (ioctl(fd, TCGETA, &termio) < 0) {
			log("hang_up_line: TCGETA failed: %s", strerror(errno));
			return (-1);
		}
		termio.c_cflag &= ~CBAUD;
		termio.c_cflag |= B0;

		if (ioctl(fd, TCSETA, &termio) < 0) {
			log("hang_up_line: TCSETA failed: %s", strerror(errno));
			return (-1);
		}
	} else {
		(void) cfsetospeed(&termios, B0);

		if (ioctl(fd, TCSETS, &termios) < 0) {
			log("hang_up_line: TCSETS failed: %s", strerror(errno));
			return (-1);
		}
	}
	return (0);
}

/*
 * initial_termio	- set initial termios
 *			- return 0 if successful, -1 if failed.
 */
int
initial_termio(int fd, struct pmtab *pmptr)
{
	int	ret;
	struct	Gdef *speedef;

	speedef = get_speed(pmptr);
	if (speedef->g_autobaud & A_FLAG) {
		pmptr->p_ttyflags |= A_FLAG;
		if (auto_termio(fd) == -1) {
			(void) close(fd);
			return (-1);
		}
	} else {
		if (pmptr->p_ttyflags & R_FLAG)
			ret = set_termio(fd, speedef->g_iflags,
			    NULL, TRUE, (long)RAW);
		else
			ret = set_termio(fd, speedef->g_iflags,
			    NULL, TRUE, (long)CANON);
		if (ret == -1) {
			log("initial termio on (%s) failed", pmptr->p_device);
			(void) close(fd);
			return (-1);
		}
	}
	return (0);
}
