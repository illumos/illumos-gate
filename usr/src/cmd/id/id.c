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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <locale.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/param.h>
#include <unistd.h>
#include <string.h>
#include <project.h>
#include <stdlib.h>
#include <alloca.h>

#define	PWNULL  ((struct passwd *)0)
#define	GRNULL  ((struct group *)0)

typedef enum TYPE {
	UID, EUID, GID, EGID, SGID
}	TYPE;

typedef enum PRINT {
	CURR,		/* Print uid/gid only */
	ALLGROUPS,	/* Print all groups */
	GROUP,		/* Print only group */
	USER		/* Print only uid */
}	PRINT;
static PRINT mode = CURR;

static int usage(void);
static void puid(uid_t);
static void pgid(gid_t);
static void prid(TYPE, uid_t);
static int getusergroups(int, gid_t *, char *, gid_t);

static int nflag = 0;		/* Output names, not numbers */
static int rflag = 0;		/* Output real, not effective IDs */
static char stdbuf[BUFSIZ];

int
main(int argc, char *argv[])
{
	gid_t *idp;
	uid_t uid, euid;
	gid_t gid, egid, prgid;
	int c, aflag = 0, project_flag = 0;
	struct passwd *pwp;
	int i, j;
	int groupmax = sysconf(_SC_NGROUPS_MAX);
	gid_t *groupids = alloca(groupmax * sizeof (gid_t));
	struct group *gr;
	char *user = NULL;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	while ((c = getopt(argc, argv, "Ggunarp")) != EOF) {
		switch (c) {
			case 'G':
				if (mode != CURR)
					return (usage());
				mode = ALLGROUPS;
				break;

			case 'g':
				if (mode != CURR)
					return (usage());
				mode = GROUP;
				break;

			case 'a':
				aflag++;
				break;

			case 'n':
				nflag++;
				break;

			case 'r':
				rflag++;
				break;

			case 'u':
				if (mode != CURR)
					return (usage());
				mode = USER;
				break;

			case 'p':
				if (mode != CURR)
					return (usage());
				project_flag++;
				break;

			case '?':
				return (usage());
		}
	}
	setbuf(stdout, stdbuf);
	argc -= optind-1;
	argv += optind-1;

	/* -n and -r must be combined with one of -[Ggu] */
	/* -r cannot be combined with -G */
	/* -a and -p cannot be combined with -[Ggu] */

	if ((mode == CURR && (nflag || rflag)) ||
		(mode == ALLGROUPS && rflag) ||
		(argc != 1 && argc != 2) ||
		(mode != CURR && (project_flag || aflag)))
		return (usage());
	if (argc == 2) {
		if ((pwp = getpwnam(argv[1])) == PWNULL) {
			(void) fprintf(stderr,
				gettext("id: invalid user name: \"%s\"\n"),
					argv[1]);
			return (1);
		}
		user = argv[1];
		uid = euid = pwp->pw_uid;
		prgid = gid = egid = pwp->pw_gid;
	} else {
		uid = getuid();
		gid = getgid();
		euid = geteuid();
		egid = getegid();
	}

	if (mode != CURR) {
		if (!rflag) {
			uid = euid;
			gid = egid;
		}
		if (mode == USER)
			puid(uid);
		else if (mode == GROUP)
			pgid(gid);
		else if (mode == ALLGROUPS) {
			pgid(gid);
			if (user)
				i = getusergroups(groupmax, groupids, user,
				    prgid);
			else
				i = getgroups(groupmax, groupids);
			if (i == -1)
				perror("getgroups");
			else if (i > 0) {
				for (j = 0; j < i; ++j) {
					if ((gid = groupids[j]) == egid)
						continue;
					(void) putchar(' ');
					pgid(gid);
				}
			}
		}
		(void) putchar('\n');
	} else {
		prid(UID, uid);
		prid(GID, gid);
		if (uid != euid)
			prid(EUID, euid);
		if (gid != egid)
			prid(EGID, egid);

		if (aflag) {
			if (user)
				i = getusergroups(groupmax, groupids, user,
				    prgid);
			else
				i = getgroups(groupmax, groupids);
			if (i == -1)
				perror("getgroups");
			else if (i > 0) {
				(void) printf(" groups=");
				for (idp = groupids; i--; idp++) {
					(void) printf("%u", *idp);
					if (gr = getgrgid(*idp))
						(void) printf("(%s)",
							gr->gr_name);
					if (i)
						(void) putchar(',');
				}
			}
		}
#ifdef XPG4
		/*
		 * POSIX requires us to show all supplementary groups
		 * groups other than the effective group already listed.
		 *
		 * This differs from -a above, because -a always shows
		 * all groups including the effective group in the group=
		 * line.
		 *
		 * It would be simpler if SunOS could just adopt this
		 * POSIX behavior, as it is so incredibly close to the
		 * the norm already.
		 *
		 * Then the magic -a flag could just indicate whether or
		 * not we are suppressing the effective group id.
		 */
		else {
			if (user)
				i = getusergroups(groupmax, groupids, user,
				    prgid);
			else
				i = getgroups(groupmax, groupids);
			if (i == -1)
				perror("getgroups");
			else if (i > 1) {
				(void) printf(" groups=");
				for (idp = groupids; i--; idp++) {
					if (*idp == egid)
						continue;
					(void) printf("%u", *idp);
					if (gr = getgrgid(*idp))
						(void) printf("(%s)",
							gr->gr_name);
					if (i)
						(void) putchar(',');
				}
			}
		}
#endif
		if (project_flag) {
			struct project proj;
			void *projbuf;
			projid_t curprojid = getprojid();

			if ((projbuf = malloc(PROJECT_BUFSZ)) == NULL) {
				(void) fprintf(stderr, "unable to allocate "
				    "memory\n");
				return (2);
			}

			if (user) {
				if (getdefaultproj(user, &proj, projbuf,
				    PROJECT_BUFSZ) != NULL)
					(void) printf(" projid=%d(%s)",
					    (int)proj.pj_projid, proj.pj_name);
				else
					/*
					 * This can only happen if project
					 * "default" has been removed from
					 * /etc/project file or the whole
					 * project database file was removed.
					 */
					(void) printf(" projid=(NONE)");
			} else {
				if (getprojbyid(curprojid, &proj, projbuf,
				    PROJECT_BUFSZ) == NULL)
					(void) printf(" projid=%d",
					    (int)curprojid);
				else
					(void) printf(" projid=%d(%s)",
					    (int)curprojid, proj.pj_name);
			}
			free(projbuf);
		}
		(void) putchar('\n');
	}
	return (0);
}

static int
usage()
{
	(void) fprintf(stderr, gettext(
	    "Usage: id [-ap] [user]\n"
	    "       id -G [-n] [user]\n"
	    "       id -g [-nr] [user]\n"
	    "       id -u [-nr] [user]\n"));
	return (2);
}

static void
puid(uid_t uid)
{
	struct passwd *pw;

	if (nflag && (pw = getpwuid(uid)) != PWNULL)
		(void) printf("%s", pw->pw_name);
	else
		(void) printf("%u", uid);
}

static void
pgid(gid_t gid)
{
	struct group *gr;

	if (nflag && (gr = getgrgid(gid)) != GRNULL)
		(void) printf("%s", gr->gr_name);
	else
		(void) printf("%u", gid);
}

static void
prid(TYPE how, uid_t id)
{
	char *s;

	switch ((int)how) {
		case UID:
			s = "uid";
			break;

		case EUID:
			s = " euid";
			break;

		case GID:
			s = " gid";
			break;

		case EGID:
			s = " egid";
			break;

	}
	if (s != NULL)
		(void) printf("%s=", s);
	(void) printf("%u", id);
	switch ((int)how) {
	case UID:
	case EUID:
		{
			struct passwd *pwp;

			if ((pwp = getpwuid(id)) != PWNULL)
				(void) printf("(%s)", pwp->pw_name);

		}
		break;
	case GID:
	case EGID:
		{
			struct group *grp;

			if ((grp = getgrgid(id)) != GRNULL)
				(void) printf("(%s)", grp->gr_name);
		}
		break;
	}
}

/*
 * Get the supplementary group affiliation for the user
 */
static int getusergroups(gidsetsize, grouplist, user, prgid)
int	gidsetsize;
gid_t	*grouplist;
char	*user;
gid_t	prgid;
{
	struct group *group;
	char **gr_mem;
	int ngroups = 0;

	setgrent();
	while ((ngroups < gidsetsize) && ((group = getgrent()) != NULL))
		for (gr_mem = group->gr_mem; *gr_mem; gr_mem++)
			if (strcmp(user, *gr_mem) == 0) {
				if (gidsetsize)
					grouplist[ngroups] = group->gr_gid;
				ngroups++;
			}
	endgrent();
	if (gidsetsize && !ngroups)
		grouplist[ngroups++] = prgid;
	return (ngroups);
}
