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

#include "talk_ctl.h"
#include <locale.h>

#ifdef SYSV
#define	bcmp(a, b, c)	memcmp((a), (b), (c))
#define	bcopy(a, b, c)	memcpy((b), (a), (c))
#endif /* SYSV */

struct hostent *gethostbyname();
struct servent *getservbyname();

void
get_addrs(my_machine_name, rem_machine_name)
char *my_machine_name;
char *rem_machine_name;
{
	struct hostent *hp;
	struct servent *sp;

	msg.pid = getpid();

	/* look up the address of the local host */

	hp = gethostbyname(my_machine_name);

	if (hp == (struct hostent *) 0) {
		fprintf(stderr,
		gettext("This machine doesn't exist. Boy, am I confused!\n"));
		exit(1);
	}

	if (hp->h_addrtype != AF_INET) {
		fprintf(stderr,
		gettext("Protocol mix up with local machine address\n"));
		exit(1);
	}

	bcopy(hp->h_addr, (char *)&my_machine_addr, hp->h_length);

	/* if on the same machine, then simply copy */

	if (bcmp((char *)&rem_machine_name, (char *)&my_machine_name,
		sizeof (rem_machine_name)) == 0) {
	bcopy((char *)&my_machine_addr, (char *)&rem_machine_addr,
		sizeof (rem_machine_name));
	} else {

		if ((rem_machine_addr.s_addr =
			(unsigned long)inet_addr(rem_machine_name)) == -1) {

		/* look up the address of the recipient's machine */

		hp = gethostbyname(rem_machine_name);

		if (hp == (struct hostent *) 0) {
			fprintf(stderr,
			gettext("%s is an unknown host\n"), rem_machine_name);
			exit(1);
		}

		if (hp->h_addrtype != AF_INET) {
			fprintf(stderr,
		gettext("Protocol mix up with remote machine address\n"));
			exit(1);
		}

		bcopy(hp->h_addr, (char *) &rem_machine_addr, hp->h_length);
	}
	}


	/* find the daemon portal */

#ifdef NTALK
	sp = getservbyname("ntalk", "udp");
#else
	sp = getservbyname("talk", "udp");
#endif

	if (strcmp(sp->s_proto, "udp") != 0) {
	fprintf(stderr, gettext("Protocol mix up with talk daemon\n"));
	exit(1);
	}

	if (sp == 0) {
		p_error(
		gettext("This machine doesn't support a tcp talk daemon"));
		exit(1);
	}

	daemon_port = sp->s_port;
}
