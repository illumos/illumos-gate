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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * wracct - write system accounting records
 */

#include <sys/types.h>
#include <sys/procset.h>
#include <exacct.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <strings.h>
#include <errno.h>

#define	CMDNAME "wracct"
#define	USAGE \
    gettext("Usage: wracct -i id_list [-t partial | interval ] " \
	"{process | task}\n")
#define	OPTIONS_STRING "i:t:"

static void
usage(void)
{
	(void) fprintf(stderr, USAGE);
	exit(2);
}

static long
Atol(char *p)
{
	long l;
	char *q;
	errno = 0;
	l = strtol(p, &q, 10);
	if (errno != 0 || q == p || l < 0 || *q != '\0') {
		(void) fprintf(stderr, gettext("%s: illegal argument -- %s\n"),
		    CMDNAME, p);
		exit(2);
		/*NOTREACHED*/
	} else {
		return (l);
	}
}

int
main(int argc, char *argv[])
{
	idtype_t ent_flag = -1;
	int rec_flag = EW_PARTIAL;
	id_t id = -1;
	char *id_sequence = NULL;
	char *idlp = NULL;
	int c, r;

	while ((c = getopt(argc, argv, OPTIONS_STRING)) != EOF) {
		switch (c) {
			case 't':
				if (strcmp(optarg, "partial") == 0) {
					rec_flag = EW_PARTIAL;
				} else if (strcmp(optarg, "interval") == 0) {
					rec_flag = EW_INTERVAL;
				} else {
					(void) fprintf(stderr,
					    gettext("%s: wrong record type\n"),
					    CMDNAME);
					usage();
				}
				break;
			case 'i':
				id_sequence = strdup(optarg);
				break;
			case '?':
			default:
				usage();
				break;
		}
	}

	if (optind >= argc) {
		usage();
	}

	if (strcmp(argv[optind], "task") == 0) {
		ent_flag = P_TASKID;
	} else if (strcmp(argv[optind], "process") == 0 ||
	    strcmp(argv[optind], "proc") == 0) {
		ent_flag = P_PID;
	} else {
		usage();
	}

	if (ent_flag == P_PID && rec_flag == EW_INTERVAL) {
		(void) fprintf(stderr,
		    gettext("%s: interval process records not supported\n"),
		    CMDNAME);
		exit(2);
	}

	if (id_sequence == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: please use -i option to specify ids\n"),
		    CMDNAME);
		exit(2);
	}

	for (idlp = strtok(id_sequence, ", \t\n"); idlp != NULL;
	    idlp = strtok(NULL, ", \t\n")) {
		id = Atol(idlp);
		if (wracct(ent_flag, id, rec_flag) < 0) {
			r = errno;
			(void) fprintf(stderr,
			    "%s: operation failed on %s %d: %s\n",
			    CMDNAME, (ent_flag == P_TASKID) ? "taskid" : "pid",
			    (int)id, strerror(r));
			exit(1);
		}
	}

	return (0);
}
