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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <libproc.h>

extern int _getgroupsbymember(const char *, gid_t[], int, int);

static int look(char *);
static int perr(char *);

static void usage(void);
static void initcred(void);

static char *command;
static char *procname;

static char *user;
static char *group;
static char *grplst;
static char *login;

static boolean_t all = B_FALSE;
static boolean_t doset = B_FALSE;
static int ngrp = -1;
static gid_t *groups;
static long ngroups_max;

static uid_t uid = (uid_t)-1;
static gid_t gid = (gid_t)-1;

int
main(int argc, char **argv)
{
	int rc = 0;
	int c;
	struct rlimit rlim;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	if ((ngroups_max = sysconf(_SC_NGROUPS_MAX)) < 0)
		return (perr("sysconf(_SC_NGROUPS_MAX)"));

	opterr = 0;

	while ((c = getopt(argc, argv, "au:g:l:G:")) != EOF) {
		switch (c) {
		case 'a':
			all = B_TRUE;
			break;
		case 'u':
			user = optarg;
			doset = B_TRUE;
			break;
		case 'g':
			group = optarg;
			doset = B_TRUE;
			break;
		case 'G':
			grplst = optarg;
			doset = B_TRUE;
			break;
		case 'l':
			login = optarg;
			doset = B_TRUE;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}
	if (login != NULL && (user != NULL || group != NULL || grplst != NULL))
		usage();

	if (all && doset)
		usage();

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	if (doset)
		initcred();

	/*
	 * Make sure we'll have enough file descriptors to handle a target
	 * that has many many mappings.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	while (argc-- > 0)
		rc += look(*argv++);

	return (rc > 255 ? 255 : rc);
}

static void
credupdate(prcred_t *pcr)
{
	if (uid != (uid_t)-1)
		pcr->pr_euid = pcr->pr_ruid = pcr->pr_suid = uid;
	if (gid != (gid_t)-1)
		pcr->pr_egid = pcr->pr_rgid = pcr->pr_sgid = gid;
	if (ngrp >= 0) {

		pcr->pr_ngroups = ngrp;

		(void) memcpy(pcr->pr_groups, groups, ngrp * sizeof (gid_t));
	}
}

static int
look(char *arg)
{
	struct ps_prochandle *Pr;
	static prcred_t *prcred = NULL;
	int gcode;

	procname = arg;		/* for perr() */

	if (prcred == NULL) {
		prcred = malloc(sizeof (prcred_t) +
			(ngroups_max - 1) * sizeof (gid_t));
		if (prcred == NULL) {
			(void) perr("malloc");
			exit(1);
		}
	}

	if ((Pr = proc_arg_grab(arg, doset ? PR_ARG_PIDS : PR_ARG_ANY,
	    PGRAB_RETAIN | PGRAB_FORCE | (doset ? 0 : PGRAB_RDONLY) |
	    PGRAB_NOSTOP, &gcode)) == NULL) {
		(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
		    command, arg, Pgrab_error(gcode));
		return (1);
	}

	if (Pcred(Pr, prcred, ngroups_max) == -1) {
		(void) perr("getcred");
		Prelease(Pr, 0);
		return (1);
	}

	if (doset) {
		credupdate(prcred);
		if (Psetcred(Pr, prcred) != 0) {
			(void) perr("setcred");
			Prelease(Pr, 0);
			return (1);
		}
		Prelease(Pr, 0);
		return (0);
	}

	if (Pstate(Pr) == PS_DEAD)
		(void) printf("core of %d:\t", (int)Pstatus(Pr)->pr_pid);
	else
		(void) printf("%d:\t", (int)Pstatus(Pr)->pr_pid);

	if (!all &&
	    prcred->pr_euid == prcred->pr_ruid &&
	    prcred->pr_ruid == prcred->pr_suid)
		(void) printf("e/r/suid=%u  ", prcred->pr_euid);
	else
		(void) printf("euid=%u ruid=%u suid=%u  ",
			prcred->pr_euid, prcred->pr_ruid, prcred->pr_suid);

	if (!all &&
	    prcred->pr_egid == prcred->pr_rgid &&
	    prcred->pr_rgid == prcred->pr_sgid)
		(void) printf("e/r/sgid=%u\n", prcred->pr_egid);
	else
		(void) printf("egid=%u rgid=%u sgid=%u\n",
			prcred->pr_egid, prcred->pr_rgid, prcred->pr_sgid);

	if (prcred->pr_ngroups != 0 &&
	    (all || prcred->pr_ngroups != 1 ||
	    prcred->pr_groups[0] != prcred->pr_rgid)) {
		int i;

		(void) printf("\tgroups:");
		for (i = 0; i < prcred->pr_ngroups; i++)
			(void) printf(" %u", prcred->pr_groups[i]);
		(void) printf("\n");
	}

	Prelease(Pr, 0);
	return (0);
}

static int
perr(char *s)
{
	if (s)
		(void) fprintf(stderr, "%s: ", procname);
	else
		s = procname;
	perror(s);
	return (1);
}

static void
usage(void)
{
	(void) fprintf(stderr, "usage:\t%s [-a] { pid | core } ...\n"
	    "\t%s [-u user] [-g group] [-G groups] pid ...\n"
	    "\t%s -l login pid ...\n"
	    "  (report or modify process credentials)\n",
	    command, command, command);
	exit(2);
}


static uint32_t
str2id(const char *str)
{
	unsigned long res;
	char *p;

	errno = 0;
	res = strtoul(str, &p, 0);
	if (p == str || *p != '\0' || errno != 0)
		return ((uint32_t)-1);
	else
		return ((uint32_t)res);
}

static gid_t
str2gid(const char *grnam)
{
	struct group *grp = getgrnam(grnam);
	gid_t res;

	if (grp == NULL) {
		res = (gid_t)str2id(grnam);
		if (res == (gid_t)-1) {
			(void) fprintf(stderr, "%s: %s: unknown group"
			    " or bad gid\n",
			    command, grnam);
			exit(1);
		}
	} else {
		res = grp->gr_gid;
	}
	return (res);
}

static void
initcred(void)
{
	struct passwd *pwd;

	if ((groups = malloc(ngroups_max * sizeof (gid_t))) == NULL) {
		(void) perr("malloc");
		exit(1);
	}

	if (login != NULL) {
		pwd = getpwnam(login);

		if (pwd == NULL) {
			(void) fprintf(stderr, "%s: %s: unknown user\n",
			    command, login);
			exit(1);
		}
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;

		groups[0] = gid;

		ngrp = _getgroupsbymember(login, groups, (int)ngroups_max, 1);
	}

	if (user != NULL) {
		pwd = getpwnam(user);
		if (pwd == NULL) {
			uid = (uid_t)str2id(user);
			if (uid == (uid_t)-1) {
				(void) fprintf(stderr, "%s: %s: unknown user"
				    " or bad uid\n",
				    command, user);
				exit(1);
			}
		} else {
			uid = pwd->pw_uid;
		}
	}

	if (group != NULL)
		gid = str2gid(group);

	if (grplst != NULL) {
		char *cgrp;

		ngrp = 0;

		while ((cgrp = strtok(grplst, ",")) != NULL) {

			if (ngrp >= ngroups_max) {
				(void) fprintf(stderr, "%s: Too many groups\n",
				    command);
				exit(1);
			}
			groups[ngrp++] = str2gid(cgrp);

			/* For iterations of strtok */
			grplst = NULL;
		}
	}
}
