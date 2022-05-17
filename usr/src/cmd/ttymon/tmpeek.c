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
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stropts.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include "ttymon.h"
#include "tmstruct.h"
#include "tmextern.h"

#define	BRK	1
#define	DEL	2

struct	strbuf *do_peek(int, int);
static	int	process(int, struct strbuf *);

static	int	interrupt;

/*
 *	poll_data	- it polls the device, waiting for data
 *			- return BADSPEED it <brk> is received
 *			- return the result of process if data is received
 *			- write a newline if <del> is received
 *			- exit if hangup is received
 */
int
poll_data(void)
{
	int j;
	struct strbuf *ptr;
	struct pollfd fds[1];
	struct sigaction sigact;

#ifdef	DEBUG
	debug("in poll_data");
#endif
	if (peek_ptr != NULL) {
		for (j = 0; j < peek_ptr->len; j++)
			peek_ptr->buf[j] &= 0x7F;
		return (process(0, peek_ptr));
	}
	fds[0].fd = 0;
	fds[0].events = POLLIN;
	sigact.sa_flags = 0;
	sigact.sa_handler = sigint;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGINT);
	(void) sigaction(SIGINT, &sigact, NULL);
	for (;;) {
		interrupt = 0;
		if ((j = poll(fds, 1, -1)) == -1) {
			if (interrupt == BRK) {
				return (BADSPEED);
			}
			if (interrupt == DEL) { /* XXX revisit kmd */
				return (BADSPEED);
			}
		} else if (j > 0) {
			if (fds[0].revents & POLLHUP) {
				log("POLLHUP received, about to exit");
				exit(1);
			}
			if (fds[0].revents & POLLIN) {
				ptr = do_peek(fds[0].fd, 255);
				if (ptr != NULL) {
					return (process(fds[0].fd, ptr));
				}
			}
		}
	}
}

/*
 *	process	- process the data
 *		- return GOODNAME if it is a non-empty line
 *		- return NONAME if a <CR> is received
 *		- return BADNAME if zero byte is detected
 *		- except the case of GOODNAME, data will be pulled out
 *		  of the stream
 */
static int
process(
	int	fd,		/* fd to read data from if necessary	*/
	struct strbuf *ptr)	/* ptr that holds data in ptr->buf	*/
{
	unsigned i;
	char	junk[BUFSIZ];

	for (i = 0; i < ptr->len; i++) {
		if (ptr->buf[i] == '\0') {
			(void) read(fd, junk, i+1);
			return (BADSPEED);
		} else if ((ptr->buf[i] == '\n') || (ptr->buf[i] == '\r')) {
			if (i == 0) {
				(void) read(fd, junk, ptr->len);
				return (NONAME);
			} else
				return (GOODNAME);
		}
	}	/* end for loop */
	/* end of input is encountered */
#ifdef	DEBUG
	debug("in process: EOF encountered");
#endif
	exit(1);
	/*NOTREACHED*/
}

/*
 *	do_peek	- peek at the stream to get the data
 *	int	fd;	fd to do the ioctl on
 *	int	n;	maxlen of data to peek at
 *		- this only called when POLLIN is detected,
 *		- so there should always be something there
 *		- return a ptr to the buf that contains the data
 *		- return NULL if nothing to peek at
 */
struct	strbuf	*
do_peek(int fd, int n)
{
	int	 ret;
	static	 struct strpeek peek;
	struct strpeek *peekp;
	static	 char	buf[BUFSIZ];

#ifdef	DEBUG
	debug("in do_peek");
#endif

	peekp = &peek;
	peekp->flags = 0;
	/* need to ask for ctl info to avoid bug in I_PEEK code */
	peekp->ctlbuf.maxlen = 1;
	peekp->ctlbuf.buf = buf;
	peekp->databuf.maxlen = n;
	peekp->databuf.buf = buf;
	ret = ioctl(fd, I_PEEK, &peek);
	if (ret == -1) {
		log("do_peek: I_PEEK failed: %s", errno);
		exit(1);
	}
	if (ret == 0) {
		return (NULL);
	}
	return (&(peekp->databuf));
}

/*
 *	sigint	- this is called when SIGINT is caught
 */
void
sigint(int s __unused)
{
	struct strbuf *ptr;
	char   junk[2];

#ifdef	DEBUG
	debug("in sigint");
#endif
	ptr = do_peek(0, 1);
	if (ptr == NULL) {	/* somebody type <del> */
		interrupt = DEL;
	} else {
		if (ptr->buf[0] == '\0') {
			/* somebody type <brk> or frame error */
			(void) read(0, junk, 1);
			interrupt = BRK;
		}
	}
}
