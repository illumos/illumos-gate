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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file handles haggling with the various talk daemons to
 * get a socket to talk to. sockt is opened and connected in
 * the progress
 */

#include "talk_ctl.h"
#include <libintl.h>

struct sockaddr_in daemon_addr = { AF_INET };
struct sockaddr_in ctl_addr = { AF_INET };
struct sockaddr_in my_addr = { AF_INET };

/* inet addresses of the two machines */
struct in_addr my_machine_addr;
struct in_addr rem_machine_addr;

u_short daemon_port;	/* port number of the talk daemon */

int ctl_sockt;
int sockt;
int invitation_waiting = 0;

CTL_MSG msg;

void
open_sockt()
{
	socklen_t length;

	my_addr.sin_addr = my_machine_addr;
	my_addr.sin_port = 0;

	sockt = socket(AF_INET, SOCK_STREAM, 0);

	if (sockt <= 0) {
		p_error(gettext("Bad socket"));
	}

	if (bind(sockt, (struct sockaddr *)&my_addr, sizeof (my_addr)) != 0) {
		p_error(gettext("Binding local socket"));
	}

	length = (socklen_t) sizeof (my_addr);

	if (getsockname(sockt, (struct sockaddr *)&my_addr, &length) == -1) {
		p_error(gettext("Bad address for socket"));
	}
}

	/* open the ctl socket */

void
open_ctl()
{
	socklen_t length;

	ctl_addr.sin_port = 0;
	ctl_addr.sin_addr = my_machine_addr;

	ctl_sockt = socket(AF_INET, SOCK_DGRAM, 0);

	if (ctl_sockt <= 0) {
		p_error(gettext("Bad socket"));
	}

	if (bind(ctl_sockt, (struct sockaddr *)&ctl_addr, sizeof (ctl_addr))
		!= 0) {
		p_error(gettext("Couldn't bind to control socket"));
	}

	length = (socklen_t) sizeof (ctl_addr);
	if (getsockname(ctl_sockt, (struct sockaddr *)&ctl_addr, &length)
		== -1) {
		p_error(gettext("Bad address for ctl socket"));
	}
}

/* print_addr is a debug print routine */

void
print_addr(addr)
struct sockaddr_in addr;
{
	int i;

	printf("addr = %x, port = %o, family = %o zero = ",
		addr.sin_addr, (int)addr.sin_port, addr.sin_family);

	for (i = 0; i < 8; i++) {
		printf("%o ", (int)addr.sin_zero[i]);
	}
	putchar('\n');
}
