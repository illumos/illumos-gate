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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * newgrp [-l | -] [group]
 *
 * rules
 *	if no arg, group id in password file is used
 *	else if group id == id in password file
 *	else if login name is in member list
 *	else if password is present and user knows it
 *	else too bad
 */
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <crypt.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>

#define	SHELL	"/usr/bin/sh"

#define	PATH	"PATH=:/usr/bin:"
#define	SUPATH	"PATH=:/usr/sbin:/usr/bin"
#define	ELIM	128

char	PW[] = "newgrp: Password: ";
char	NG[] = "newgrp: Sorry";
char	PD[] = "newgrp: Permission denied";
char	UG[] = "newgrp: Unknown group";
char	NS[] = "newgrp: You have no shell";

char *homedir;
char *logname;

char *envinit[ELIM];
extern char **environ;
char *path = PATH;
char *supath = SUPATH;

extern void audit_newgrp_login(char *, int);

main(argc, argv)
char *argv[];
{
	register char *s;
	register struct passwd *p;
	char *rname();
	gid_t chkgrp();
	int eflag = 0;
	int flag;
	uid_t uid;
	char *shell, *dir, *name;
	size_t len;

#ifdef	DEBUG
	chroot(".");
#endif

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((p = getpwuid(getuid())) == NULL)
		error(NG);
	endpwent();

	while ((flag = getopt(argc, argv, "l")) != EOF) {
		switch (flag) {
		case 'l':
			eflag++;
			break;

		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv = &argv[optind];

	if (argc > 0 && *argv[0] == '-') {
		if (eflag)
			usage();
		eflag++;
		argv++;
		--argc;
	}

	if (argc > 0)
		p->pw_gid = chkgrp(argv[0], p);

	uid = p->pw_uid;

	len = strlen(p->pw_dir) + 1;
	if ((dir = (char *)malloc(len)) == NULL)
		error("newgrp: Memory request failed");
	(void) strncpy(dir, p->pw_dir, len);
	len = strlen(p->pw_name) + 1;
	if ((name = (char *)malloc(len)) == NULL)
		error("newgrp: Memory request failed");
	(void) strncpy(name, p->pw_name, len);

	if (setgid(p->pw_gid) < 0 || setuid(getuid()) < 0)
		error(NG);

	if (!*p->pw_shell) {
		if ((shell = getenv("SHELL")) != NULL) {
			p->pw_shell = shell;
		} else {
			p->pw_shell = SHELL;
		}
	}

	if (eflag) {
		char *simple;

		len = strlen(dir) + 6;
		if ((homedir = (char *)malloc(len)) == NULL)
			error("newgrp: Memory request failed");
		(void) snprintf(homedir, len, "HOME=%s", dir);
		len = strlen(name) + 9;
		if ((logname = (char *)malloc(len)) == NULL)
			error("newgrp: Memory request failed");
		(void) snprintf(logname, len, "LOGNAME=%s", name);


		envinit[2] = logname;
		chdir(dir);
		envinit[0] = homedir;
		if (uid == 0)
			envinit[1] = supath;
		else
			envinit[1] = path;
		envinit[3] = NULL;
		environ = envinit;

		len = strlen(p->pw_shell) + 2;
		if ((shell = (char *)malloc(len)) == NULL)
			error("newgrp: Memory request failed");
		(void) snprintf(shell, len, "-%s", p->pw_shell);
		simple = strrchr(shell, '/');
		if (simple) {
			*(shell+1) = '\0';
			shell = strcat(shell, ++simple);
		}
	}
	else
		shell = p->pw_shell;

	execl(p->pw_shell, shell, NULL);
	error(NS);
}

warn(s)
char *s;
{
	fprintf(stderr, "%s\n", gettext(s));
}

error(s)
char *s;
{
	warn(s);
	exit(1);
}

gid_t
chkgrp(gname, p)
char	*gname;
struct	passwd *p;
{
	register char **t;
	register struct group *g;

	g = getgrnam(gname);
	endgrent();
	if (g == NULL) {
		warn(UG);
		return (getgid());
	}
	if (p->pw_gid == g->gr_gid || getuid() == 0)
		return (g->gr_gid);
	for (t = g->gr_mem; *t; ++t) {
		if (strcmp(p->pw_name, *t) == 0)
			return (g->gr_gid);
	}
	if (*g->gr_passwd) {
		if (!isatty(fileno(stdin))) {
			error(PD);
		}
		if (strcmp(g->gr_passwd,
		    crypt(getpass(PW), g->gr_passwd)) == 0) {
			audit_newgrp_login(gname, 0);
			return (g->gr_gid);
		}
		audit_newgrp_login(gname, 1);
	}
	warn(NG);
	return (getgid());
}

/*
 * return pointer to rightmost component of pathname
 */
char *
rname(pn)
char *pn;
{
	register char *q;

	q = pn;
	while (*pn)
		if (*pn++ == '/')
			q = pn;
	return (q);
}

usage()
{
	fprintf(stderr, gettext(
		"usage: newgrp [-l | -] [group]\n"));
	exit(2);
}
