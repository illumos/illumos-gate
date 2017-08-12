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
 * Copyright 2017 Gary Mills
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

#include "talk.h"
#include "ctl.h"
#include <locale.h>
#include <pwd.h>
#include <sys/systeminfo.h>

char *getlogin(), *ttyname(int);

extern CTL_MSG msg;

/*
 * Determine the local and remote user, tty, and machines
 */

struct hostent *gethostbyname();

void
get_names(argc, argv)
int argc;
char *argv[];
{
	char hostname[HOST_NAME_LENGTH + 1];
	char *rem_name;
	char *my_name;
	char *my_machine_name;
	char *rem_machine_name;
	char *rem_tty;
	char *ptr;
	int name_length;

	if (argc < 2) {
		fprintf(stderr,
		    "Usage: talk %s\n", gettext("address [terminal]"));
		exit(1);
	}
	if (!isatty(0)) {
		fprintf(stderr,
	gettext("Standard input must be a tty, not a pipe or a file\n"));
		exit(1);
	}

	if (!isatty(1)) {
		fprintf(stderr,
	gettext("Standard output must be a tty, not a pipe or a file\n"));
		exit(1);
	}

	if ((my_name = getlogin()) == NULL) {
	struct passwd *pass = getpwuid(getuid());
	if (pass != NULL)
		my_name = pass->pw_name;
	}
	if (my_name == NULL) {
		fprintf(stderr,
	gettext("Who are you?  You have no entry in /etc/utmp!  Aborting..\n"));
		exit(1);
	}

	name_length = HOST_NAME_LENGTH;
	(void) sysinfo(SI_HOSTNAME, hostname, name_length);
	my_machine_name = hostname;

	/*
	 * check for, and strip out, the machine name of the target
	 */

	for (ptr = argv[1]; *ptr != '\0' &&
			 *ptr != '@' &&
			 *ptr != ':' &&
			 *ptr != '!' &&
			 *ptr != '.'; ptr++) {
	}

	if (*ptr == '\0') {

		/* this is a local to local talk */

	rem_name = argv[1];
	rem_machine_name = my_machine_name;

	} else {

	if (*ptr == '@') {
		/* user@host */
		rem_name = argv[1];
		rem_machine_name = ptr + 1;
	} else {
		/* host.user or host!user or host:user */
		rem_name = ptr + 1;
		rem_machine_name = argv[1];
	}
	*ptr = '\0';
	}


	if (argc > 2) {
	rem_tty = argv[2];	/* tty name is arg 2 */
	} else {
	rem_tty = "";
	}

	get_addrs(my_machine_name, rem_machine_name);

	/* Load these useful values into the standard message header */

	msg.id_num = 0;

	strncpy(msg.l_name, my_name, NAME_SIZE);
	msg.l_name[NAME_SIZE - 1] = '\0';

	strncpy(msg.r_name, rem_name, NAME_SIZE);
	msg.r_name[NAME_SIZE - 1] = '\0';

	strncpy(msg.r_tty, rem_tty, TTY_SIZE);
	msg.r_tty[TTY_SIZE - 1] = '\0';
}
