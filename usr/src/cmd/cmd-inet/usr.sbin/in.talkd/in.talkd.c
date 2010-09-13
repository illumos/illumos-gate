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
 *
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California.
 * All Rights Reserved.
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Invoked by the Internet daemon to handle talk requests
 * Processes talk requests until MAX_LIFE seconds go by with
 * no action, then dies.
 */

#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/systeminfo.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "talkd_impl.h"

static CTL_MSG request;
static CTL_RESPONSE response;

char hostname[HOST_NAME_LENGTH];
int debug = 0;

static CTL_MSG swapmsg(CTL_MSG req);

int
main()
{
	struct sockaddr_in from;
	socklen_t from_size = (socklen_t)sizeof (from);
	int cc;
	int name_length = sizeof (hostname);
	fd_set rfds;
	struct timeval tv;

	(void) sysinfo(SI_HOSTNAME, hostname, name_length);

	for (;;) {
		tv.tv_sec = MAX_LIFE;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		if (select(1, &rfds, 0, 0, &tv) <= 0)
			return (0);
		cc = recvfrom(0, (char *)&request, sizeof (request), 0,
		    (struct sockaddr *)&from, &from_size);

		if (cc != sizeof (request)) {
			if (cc < 0 && errno != EINTR) {
				print_error("receive");
			}
		} else {

			if (debug) {
				(void) printf("Request received : \n");
				(void) print_request(&request);
			}

			request = swapmsg(request);
			process_request(&request, &response);

			if (debug) {
				(void) printf("Response sent : \n");
				print_response(&response);
			}

			/*
			 * Can block here, is this what I want?
			 */
			cc = sendto(0, (char *)&response, sizeof (response), 0,
			    (struct sockaddr *)&request.ctl_addr,
			    (socklen_t)sizeof (request.ctl_addr));

			if (cc != sizeof (response)) {
				print_error("Send");
			}
		}
	}
}

void
print_error(char *string)
{
	FILE *cons;
	char *err_dev = "/dev/console";
	char *sys;
	pid_t val, pid;

	if (debug)
		err_dev = "/dev/tty";

	if ((sys = strerror(errno)) == (char *)NULL)
	    sys = "Unknown error";

	/* don't ever open tty's directly, let a child do it */
	if ((pid = fork()) == 0) {
		cons = fopen(err_dev, "a");
		if (cons != NULL) {
			(void) fprintf(cons, "Talkd : %s : %s(%d)\n\r", string,
			    sys, errno);
			(void) fclose(cons);
		}
		exit(0);
	} else {
		/* wait for the child process to return */
		do {
			val = wait(0);
			if (val == (pid_t)-1) {
				if (errno == EINTR) {
					continue;
				} else if (errno == ECHILD) {
					break;
				}
			}
		} while (val != pid);
	}
}

#define	swapshort(a) (((a << 8) | ((unsigned short) a >> 8)) & 0xffff)
#define	swaplong(a) ((swapshort(a) << 16) | (swapshort(((unsigned)a >> 16))))

/*
 * Heuristic to detect if need to swap bytes.
 */

static CTL_MSG
swapmsg(CTL_MSG req)
{
	CTL_MSG swapreq;

	if (req.ctl_addr.sin_family == swapshort(AF_INET)) {
		swapreq = req;
		swapreq.id_num = swaplong(req.id_num);
		swapreq.pid = swaplong(req.pid);
		swapreq.addr.sin_family = swapshort(req.addr.sin_family);
		swapreq.ctl_addr.sin_family =
			swapshort(req.ctl_addr.sin_family);
		return (swapreq);
	} else {
		return (req);
	}
}
