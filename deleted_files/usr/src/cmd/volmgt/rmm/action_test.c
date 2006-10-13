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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>

extern char		*prog_name;		/* in rmmount */

int
main(int argc, char **argv)
{
	int		c;
	int		i;
	char		*action;
	char		*path;
	char		*usertty;
	char		*device;
	char		*name;
	char		*user;
	int		yes = 0;
	int		no = 0;
	int		pau = 0;


	/* change our prog's idea of it's name */
	prog_name = argv[0];

	(void) printf("pid = %ld\n", getpid());

	/*
	 * print all the args out
	 */
	for (i = 0; i < argc; i++) {
		(void) printf("argv[%d] = '%s'\n", i, argv[i]);
	}

	/* process arguments */
	while ((c = getopt(argc, argv, "nyp")) != EOF) {
		switch (c) {
		case 'n':
			no++;
			break;
		case 'y':
			yes++;
			break;
		case 'p':
			pau++;
			break;
		default:
			return (-1);
		}
	}

	action = getenv("VOLUME_ACTION");
	path = getenv("VOLUME_PATH");
	usertty = getenv("VOLUME_USERTTY");
	device = getenv("VOLUME_DEVICE");
	name = getenv("VOLUME_NAME");
	user = getenv("VOLUME_USER");

	if (action != NULL) {
		(void) printf("VOLUME_ACTION = %s\n", action);
	} else {
		(void) printf("VOLUME_ACTION undefined\n");
	}

	if (path != NULL) {
		(void) printf("VOLUME_PATH = %s\n", path);
	} else {
		(void) printf("VOLUME_PATH undefined\n");
	}

	if (usertty != NULL) {
		(void) printf("VOLUME_USERTTY = %s\n", usertty);
	} else {
		(void) printf("VOLUME_USERTTY undefined\n");
	}

	if (device != NULL) {
		(void) printf("VOLUME_DEVICE = %s\n", device);
	} else {
		(void) printf("VOLUME_DEVICE undefined\n");
	}

	if (name != NULL) {
		(void) printf("VOLUME_NAME = %s\n", name);
	} else {
		(void) printf("VOLUME_NAME undefined\n");
	}

	if (user != NULL) {
		(void) printf("VOLUME_USER = %s\n", user);
	} else {
		(void) printf("VOLUME_USER undefined\n");
	}

	if (pau) {
		(int) pause();
	}
	if (no) {
		return (1);
	}

	if (yes) {
		return (0);
	}

	return (128);
}
