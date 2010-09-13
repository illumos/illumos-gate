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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <userdefs.h>
#include "messages.h"

/*
 *  groupdel group
 *
 *	This command deletes groups from the system.  Arguments are:
 *
 *	group - a character string group name
 */

char *cmdname = "groupdel";

extern void errmsg(), exit();
extern int del_group();

int
main(int argc, char **argv)
{
	char *group;		/* group name from command line */
	int retval = 0;

	if (argc != 2) {
		errmsg(M_DUSAGE);
		exit(EX_SYNTAX);
	}

	group = argv[1];

	switch (retval = del_group(group)) {
	case EX_UPDATE:
		errmsg(M_UPDATE, "deleted");
		break;
	case EX_NAME_NOT_EXIST:
		errmsg(M_NO_GROUP, group);
		break;
	}

	return (retval);
}
