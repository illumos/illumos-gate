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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * chown [-fR] uid[.gid] file ...
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dirent.h>
#include <grp.h>
#include <errno.h>
#include <unistd.h>

struct	passwd *pwd;
struct	passwd *getpwnam();
struct	stat stbuf;
uid_t	uid;
int	status;
int	fflag;
int	rflag;

void fatal(int, char *, char *);

int
main(int argc, char *argv[])
{
	int c;
	gid_t gid;
	char *cp, *group;
	char optchar[2];
	struct group *grp;
	extern char *strchr();

	argc--, argv++;
	while (argc > 0 && argv[0][0] == '-') {
		for (cp = &argv[0][1]; *cp; cp++)

		switch (*cp) {

		case 'f':
			fflag++;
			break;

		case 'R':
			rflag++;
			break;

		default:
			optchar[0] = *cp;
			optchar[1] = '\0';
			fatal(255, "unknown option: %s", optchar);
		}
		argv++, argc--;
	}
	if (argc < 2) {
		fprintf(stderr, "usage: chown [-fR] owner[.group] file ...\n");
		exit(-1);
	}
	gid = -1;
	group = strchr(argv[0], '.');
	if (group != NULL) {
		*group++ = '\0';
		if (!isnumber(group)) {
			if ((grp = getgrnam(group)) == NULL)
				fatal(255, "unknown group: %s", group);
			gid = grp -> gr_gid;
			(void) endgrent();
		} else if (*group != '\0') {
			errno = 0;
			gid = (gid_t)strtol(group, NULL, 10);
			if (errno != 0) {
				if (errno == ERANGE) {
					fatal(2,
					    "group id too large: %s", group);
				} else {
					fatal(2, "group id invalid: %s", group);
				}
			}
		}
	}
	if (!isnumber(argv[0])) {
		if ((pwd = getpwnam(argv[0])) == NULL)
			fatal(255, "unknown user id: %s", argv[0]);
		uid = pwd->pw_uid;
	} else {
		errno = 0;
		uid = (uid_t)strtol(argv[0], NULL, 10);
		if (errno != 0) {
			if (errno == ERANGE) {
				fatal(2, "user id too large: %s", argv[0]);
			} else {
				fatal(2, "user id invalid: %s", argv[0]);
			}
		}
	}
	for (c = 1; c < argc; c++) {
		/* do stat for directory arguments */
		if (lstat(argv[c], &stbuf) < 0) {
			status += Perror(argv[c]);
			continue;
		}
		if (rflag && ((stbuf.st_mode&S_IFMT) == S_IFDIR)) {
			status += chownr(argv[c], uid, gid);
			continue;
		}
		if (lchown(argv[c], uid, gid)) {
			status += Perror(argv[c]);
			continue;
		}
	}
	return (status);
}

int
isnumber(char *s)
{
	int c;

	while (c = *s++)
		if (!isdigit(c))
			return (0);
	return (1);
}

int
chownr(char *dir, uid_t uid, gid_t gid)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat st;
	char savedir[1024];
	int ecode;

	if (getcwd(savedir, 1024) == NULL)
		fatal(255, "%s", savedir);
	/*
	 * Change what we are given before doing it's contents.
	 */
	if (chown(dir, uid, gid) < 0 && Perror(dir))
		return (1);
	if (chdir(dir) < 0) {
		Perror(dir);
		return (1);
	}
	if ((dirp = opendir(".")) == NULL) {
		Perror(dir);
		return (1);
	}
	dp = readdir(dirp);
	dp = readdir(dirp); /* read "." and ".." */
	ecode = 0;
	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
		if (lstat(dp->d_name, &st) < 0) {
			ecode = Perror(dp->d_name);
			if (ecode)
				break;
			continue;
		}
		if ((st.st_mode&S_IFMT) == S_IFDIR) {
			ecode = chownr(dp->d_name, uid, gid);
			if (ecode)
				break;
			continue;
		}
		if (lchown(dp->d_name, uid, gid) < 0 &&
		    (ecode = Perror(dp->d_name)))
			break;
	}
	closedir(dirp);
	if (chdir(savedir) < 0)
		fatal(255, "can't change back to %s", savedir);
	return (ecode);
}

int
error(char *fmt, char *a)
{

	if (!fflag) {
		fprintf(stderr, "chown: ");
		fprintf(stderr, fmt, a);
		putc('\n', stderr);
	}
	return (!fflag);
}

void
fatal(int status, char *fmt, char *a)
{

	fflag = 0;
	(void) error(fmt, a);
	exit(status);
}

int
Perror(char *s)
{

	if (!fflag) {
		fprintf(stderr, "chown: ");
		perror(s);
	}
	return (!fflag);
}
