/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <project.h>
#include <nl_types.h>
#include <locale.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <zone.h>
#include <libzonecfg.h>

static void usage(void);
static int donice(int which, id_t who, int prio, int increment, char *who_s);
static int parse_obsolete_options(int argc, char **argv);
static int name2id(char *);

#define	PRIO_MAX		19
#define	PRIO_MIN		-20
#define	RENICE_DEFAULT_PRIORITY	10
#define	RENICE_PRIO_INCREMENT	1
#define	RENICE_PRIO_ABSOLUTE	0

typedef struct {
	int	id;
	char	*name;
} type_t;

static type_t types[] = {
	{ PRIO_PROCESS,		"pid"		},
	{ PRIO_PGRP,		"pgid"		},
	{ PRIO_USER,		"uid"		},
	{ PRIO_USER,		"user"		},
	{ PRIO_TASK,		"taskid"	},
	{ PRIO_PROJECT,		"projid"	},
	{ PRIO_PROJECT,		"project"	},
	{ PRIO_GROUP,		"gid"		},
	{ PRIO_GROUP,		"group"		},
	{ PRIO_SESSION,		"sid"		},
	{ PRIO_ZONE,		"zone"		},
	{ PRIO_ZONE,		"zoneid"	},
	{ PRIO_CONTRACT,	"ctid"		},
	{ 0,			NULL		}
};

/*
 * Change the priority (nice) of processes
 * or groups of processes which are already
 * running.
 */

int
main(int argc, char *argv[])
{
	int c;
	int optflag = 0;
	int which = PRIO_PROCESS;
	id_t who = 0;
	int errs = 0;
	char *end_ptr;
	int incr = RENICE_DEFAULT_PRIORITY;
	int prio_type = RENICE_PRIO_INCREMENT;
	struct passwd *pwd;
	struct group *grp;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2)
		(void) usage();

	/*
	 * There is ambiguity in the renice options spec.
	 * If argv[1] is in the valid range of priority values then
	 * treat it as a priority.  Otherwise, treat it as a pid.
	 */

	if (isdigit(argv[1][0])) {
		if (strtol(argv[1], (char **)NULL, 10) > (PRIO_MAX+1)) {
			argc--;			/* renice pid ... */
			argv++;
			prio_type = RENICE_PRIO_INCREMENT;
		} else {			/* renice priority ... */
			exit(parse_obsolete_options(argc, argv));
		}
	} else if ((argv[1][0] == '-' || argv[1][0] == '+') &&
			isdigit(argv[1][1])) {	/* renice priority ... */

		exit(parse_obsolete_options(argc, argv));

	} else {	/* renice [-n increment] [-g|-p|-u] ID ... */

		while ((c = getopt(argc, argv, "n:gpui:")) != -1) {
			switch (c) {
			case 'n':
				incr = strtol(optarg, &end_ptr, 10);
				prio_type = RENICE_PRIO_INCREMENT;
				if (*end_ptr != '\0')
					usage();
				break;
			case 'g':
				which = PRIO_PGRP;
				optflag++;
				break;
			case 'p':
				which = PRIO_PROCESS;
				optflag++;
				break;
			case 'u':
				which = PRIO_USER;
				optflag++;
				break;
			case 'i':
				which = name2id(optarg);
				optflag++;
				break;
			default:
				usage();
			}
		}

		argc -= optind;
		argv += optind;

		if (argc == 0 || (optflag > 1))
			usage();
	}

	for (; argc > 0; argc--, argv++) {

		if (isdigit(argv[0][0])) {
			who = strtol(*argv, &end_ptr, 10);

			/* if a zone id, make sure it is valid */
			if (who >= 0 && end_ptr != *argv &&
			    *end_ptr == '\0' && (which != PRIO_ZONE ||
			    getzonenamebyid(who, NULL, 0) != -1) &&
			    (which != PRIO_CONTRACT || who != 0)) {
				errs += donice(which, who, incr, prio_type,
				    *argv);
				continue;
			}
		}

		switch (which) {
		case PRIO_USER:
			if ((pwd = getpwnam(*argv)) != NULL) {
				who = pwd->pw_uid;
				errs += donice(which, who, incr, prio_type,
				    *argv);
			} else {
				(void) fprintf(stderr,
				    gettext("renice: unknown user: %s\n"),
				    *argv);
				errs++;
			}
			break;
		case PRIO_GROUP:
			if ((grp = getgrnam(*argv)) != NULL) {
				who = grp->gr_gid;
				errs += donice(which, who, incr, prio_type,
				    *argv);
			} else {
				(void) fprintf(stderr,
				    gettext("renice: unknown group: %s\n"),
				    *argv);
				errs++;
			}
			break;
		case PRIO_PROJECT:
			if ((who = getprojidbyname(*argv)) != (id_t)-1) {
				errs += donice(which, who, incr, prio_type,
				    *argv);
			} else {
				(void) fprintf(stderr,
				    gettext("renice: unknown project: %s\n"),
				    *argv);
				errs++;
			}
			break;
		case PRIO_ZONE:
			if (zone_get_id(*argv, &who) != 0) {
				(void) fprintf(stderr,
				    gettext("renice: unknown zone: %s\n"),
				    *argv);
				errs++;
				break;
			}
			errs += donice(which, who, incr, prio_type, *argv);
			break;
		default:
			/*
			 * In all other cases it is invalid id or name
			 */
			(void) fprintf(stderr,
			    gettext("renice: bad value: %s\n"), *argv);
			errs++;
		}
	}

	return (errs != 0);
}

static int
parse_obsolete_options(int argc, char *argv[])
{
	int which = PRIO_PROCESS;
	id_t who = 0;
	int prio;
	int errs = 0;
	char *end_ptr;

	argc--;
	argv++;

	if (argc < 2) {
		usage();
	}

	prio = strtol(*argv, &end_ptr, 10);
	if (*end_ptr != '\0') {
		usage();
	}

	if (prio == 20) {
		(void) fprintf(stderr,
			gettext("renice: nice value 20 rounded down to 19\n"));
	}

	argc--;
	argv++;

	for (; argc > 0; argc--, argv++) {
		if (strcmp(*argv, "-g") == 0) {
			which = PRIO_PGRP;
			continue;
		}
		if (strcmp(*argv, "-u") == 0) {
			which = PRIO_USER;
			continue;
		}
		if (strcmp(*argv, "-p") == 0) {
			which = PRIO_PROCESS;
			continue;
		}
		if (which == PRIO_USER && !isdigit(argv[0][0])) {
			struct passwd *pwd = getpwnam(*argv);

			if (pwd == NULL) {
				(void) fprintf(stderr,
				    gettext("renice: unknown user: %s\n"),
				    *argv);
				errs++;
				continue;
			}
			who = pwd->pw_uid;
		} else {
			who = strtol(*argv, &end_ptr, 10);
			if ((who < 0) || (*end_ptr != '\0')) {
				(void) fprintf(stderr,
				    gettext("renice: bad value: %s\n"), *argv);
				errs++;
				continue;
			}
		}
		errs += donice(which, who, prio, RENICE_PRIO_ABSOLUTE, *argv);
	}
	return (errs != 0);
}



static int
donice(int which, id_t who, int prio, int increment, char *who_s)
{
	int oldprio;

	oldprio = getpriority(which, who);

	if (oldprio == -1 && errno) {
		(void) fprintf(stderr, gettext("renice: %d:"), who);
		perror("getpriority");
		return (1);
	}

	if (increment)
		prio = oldprio + prio;

	if (setpriority(which, who, prio) < 0) {
		(void) fprintf(stderr, gettext("renice: %s:"), who_s);
		if (errno == EACCES && prio < oldprio)
			(void) fprintf(stderr, gettext(
			    " Cannot lower nice value.\n"));
		else
			perror("setpriority");
		return (1);
	}

	return (0);
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: renice [-n increment] [-i idtype] ID ...\n"));
	(void) fprintf(stderr,
	    gettext("       renice [-n increment] [-g | -p | -u] ID ...\n"));
	(void) fprintf(stderr,
	    gettext("       renice priority "
	    "[-p] pid ... [-g pgrp ...] [-p pid ...] [-u user ...]\n"));
	(void) fprintf(stderr,
	    gettext("       renice priority "
	    " -g pgrp ... [-g pgrp ...] [-p pid ...] [-u user ...]\n"));
	(void) fprintf(stderr,
	    gettext("       renice priority "
	    " -u user ... [-g pgrp ...] [-p pid ...] [-u user ...]\n"));
	(void) fprintf(stderr,
	    gettext("  where %d <= priority <= %d\n"), PRIO_MIN, PRIO_MAX);
	exit(2);
}

static int
name2id(char *name)
{
	type_t *type = types;

	while (type->name != NULL) {
		if (strcmp(type->name, name) == 0)
			return (type->id);
		type++;
	}
	(void) fprintf(stderr, gettext("renice: unknown id type: %s\n"), name);
	exit(1);
	/*NOTREACHED*/
}
