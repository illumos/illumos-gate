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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stropts.h>

#include "tmextern.h"

#define	NTRY	5

/*
 * At this time, we only recognize certain speeds.
 * This table can be expanded if new patterns are found
 */
static struct	autobaud {
	char	*a_speed;
	char	*a_pattern;	/* first byte is length */
} autob2400[] = {
#ifdef i386
	/*
	 * These are the bit patterns returned on x86 boxes
	 */
	"110",		"\1\000",
#else
	"110",		"\3\000\000\000",
#endif
	"1200",		"\2\346\200",
	"2400",		"\1\15",
	"4800",		"\1\371",
	"4800",		"\1\362",
	"9600",		"\1\377",
	0,		0
};

/*
 *	auto_termio - set termio to allow autobaud
 *		    - the line is set to raw mode, with VMIN = 5, VTIME = 1
 *		    - baud rate is set to 2400
 */
int
auto_termio(int fd)
{
	struct termio termio;
	struct termios termios;

	if (ioctl(fd, TCGETS, &termios) == -1) {
		if (ioctl(fd, TCGETA, &termio) == -1) {
			log("auto_termio: ioctl TCGETA failed, fd = %d: %s", fd,
			    strerror(errno));
			return (-1);
		}
		termio.c_iflag = 0;
		termio.c_cflag &= ~(CBAUD|CSIZE|PARENB);
		termio.c_cflag |= CREAD|HUPCL|(CS8&CSIZE)|(B2400&CBAUD);
		termio.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK);
		termio.c_oflag = 0;

		termio.c_cc[VMIN] = 5;
		termio.c_cc[VTIME] = 1;

		if (ioctl(fd, TCSETAF, &termio) == -1) {
			log("auto_termio: ioctl TCSETAF failed, fd = %d: %s",
			    fd, strerror(errno));
			return (-1);
		}
	} else {
		termios.c_iflag &= 0xffff0000;
		termios.c_cflag &= ~(CSIZE|PARENB);
		termios.c_cflag |= CREAD|HUPCL|(CS8&CSIZE);
		termios.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK);
		termios.c_oflag &= 0xffff0000;

		termios.c_cc[VMIN] = 5;
		termios.c_cc[VTIME] = 1;
		(void) cfsetospeed(&termios, B2400);

		if (ioctl(fd, TCSETSF, &termios) == -1) {
			log("auto_termio: ioctl TCSETSF failed, fd = %d: %s",
			    fd, strerror(errno));
			return (-1);
		}
	}
	return (0);
}

/*
 *	autobaud - determine the baudrate by reading data at 2400 baud rate
 *		 - the program is anticipating <CR>
 *		 - the bit pattern is matched again an autobaud table
 *		 - if a match is found, the matched speed is returned
 *		 - otherwise, NULL is returned
 */

char *
autobaud(int fd, int timeout)
{
	int i, k, count;
	static char	buf[5];
	char *cp = buf;
	struct	autobaud *tp;
	struct	sigaction sigact;

#ifdef	DEBUG
	debug("in autobaud");
#endif
	(void) auto_termio(fd);
	sigact.sa_flags = 0;
	sigact.sa_handler = SIG_IGN;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaction(SIGINT, &sigact, NULL);
	count = NTRY;
	while (count--) {
		if (timeout) {
			sigact.sa_flags = 0;
			sigact.sa_handler = timedout;
			(void) sigemptyset(&sigact.sa_mask);
			(void) sigaction(SIGALRM, &sigact, NULL);
			(void) alarm((unsigned)timeout);
		}
		cp = &buf[1];
		if (peek_ptr != NULL) {
			k = peek_ptr->len;
			(void) strncpy(cp, peek_ptr->buf, k);
			peek_ptr = NULL;
		} else if ((k = read(fd, cp, 5)) < 0) {
			fatal("autobaud: read failed: %s", strerror(errno));
		}
		if (timeout)
			(void) alarm((unsigned)0);
		buf[0] = (char)k;
		for (tp = autob2400; tp->a_speed; tp++) {
			for (i = 0; ; i++) {
				if (buf[i] != tp->a_pattern[i])
					break;
				if (i == buf[0]) {
					return (tp->a_speed);
				}
			}
		}
		flush_input(fd);
	} /* end while */
	return (NULL);		/* autobaud failed */
}
