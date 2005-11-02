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

#include	<stdio.h>
#include 	<limits.h>
#include	<errno.h>
#include	<stdarg.h>
#include	<sys/vfstab.h>

#include	<locale.h>

static int perr(const char *fmt, ...);

#define	ARGV_MAX	1024
#define	FSTYPE_MAX	8

#define	VFS_PATH	"/usr/lib/fs"

#define	EQ(X, Y, Z)	!strncmp(X, Y, Z)
#define	NEWARG()\
	(nargv[nargc++] = &argv[1][0],\
		nargc == ARGV_MAX ? perr("volcopy:  too many arguments.\n") : 1)

extern char	*default_fstype();

char	*nargv[ARGV_MAX];
int	nargc = 2;

char	vfstab[] = VFSTAB;

static void doexec(char *fstype, char *nargv[]);

int
main(int argc, char **argv)
{
	char	cc;
	int	ii, Vflg = 0, Fflg = 0;
	char	*fstype = NULL;
	FILE	*fd;
	struct vfstab	vget, vref;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while (argc > 1 && argv[1][0] == '-') {
		if (EQ(argv[1], "-a", 2)) {
			NEWARG();
		} else if (EQ(argv[1], "-e", 2)) {
			NEWARG();
		} else if (EQ(argv[1], "-s", 2)) {
			NEWARG();
		} else if (EQ(argv[1], "-y", 2)) {
			NEWARG();
		} else if (EQ(argv[1], "-buf", 4)) {
			NEWARG();
		} else if (EQ(argv[1], "-bpi", 4)) {
			NEWARG();
			if ((cc = argv[1][4]) < '0' || cc > '9') {
				++argv;
				--argc;
				NEWARG();
			}
		} else if (EQ(argv[1], "-feet", 5)) {
			NEWARG();
			if ((cc = argv[1][5]) < '0' || cc > '9') {
				++argv;
				--argc;
				NEWARG();
			}
		} else if (EQ(argv[1], "-reel", 5)) {
			NEWARG();
			if ((cc = argv[1][5]) < '0' || cc > '9') {
				++argv;
				--argc;
				NEWARG();
			}
		} else if (EQ(argv[1], "-r", 2)) { /* 3b15 only */
			NEWARG();
			if ((cc = argv[1][2]) < '0' || cc > '9') {
				++argv;
				--argc;
				NEWARG();
			}
		} else if (EQ(argv[1], "-block", 6)) { /* 3b15 only */
			NEWARG();
			if ((cc = argv[1][6]) < '0' || cc > '9') {
				++argv;
				--argc;
				NEWARG();
			}
		} else if (EQ(argv[1], "-V", 2)) {
			Vflg++;
		} else if (EQ(argv[1], "-F", 2)) {
			if (Fflg)
				perr("volcopy: More than one"
					"FSType specified.\n"
					"Usage:\nvolcopy [-F FSType] [-V]"
					" [current_options] [-o "
					"specific_options] operands\n");
			Fflg++;
			if (argv[1][2] == '\0') {
				++argv;
				--argc;
				if (argc == 1)
					perr("Usage:\nvolcopy [-F FSType] [-V]"
						" [current_options] [-o "
						"specific_options] operands\n");
				fstype = &argv[1][0];
			} else
				fstype = &argv[1][2];
			if (strlen(fstype) > FSTYPE_MAX)
				perr("volcopy: FSType %s exceeds %d"
					" characters\n", fstype, FSTYPE_MAX);
		} else if (EQ(argv[1], "-o", 2)) {
			NEWARG();
			if (argv[1][2] == '\0') {
				++argv;
				--argc;
				NEWARG();
			}
			if (Fflg && strlen(fstype) > FSTYPE_MAX)
				perr("volcopy: FSType %s exceeds %d "
					"characters.\nUsage:\nvolcopy "
					"[-F FSType] [-V] [current_options] "
					"[-o specific_options] "
					"operands\n", fstype, FSTYPE_MAX);
		} else if (EQ(argv[1], "-nosh", 5)) { /* 3b15 only */
			NEWARG();
		} else if (EQ(argv[1], "-?", 2)) {
			if (Fflg) {
				nargv[2] = "-?";
				doexec(fstype, nargv);
			} else {
				perr("Usage:\nvolcopy [-F FSType] [-V] "
					"[current_options] [-o "
					"specific_options] operands\n");
		}
		} else
			perr("<%s> invalid option\nUsage:\n"
				"volcopy [-F FSType] [-V] "
				"[current_options] [-o "
				"specific_options] operands\n", argv[1]);
		++argv;
		--argc;
	} /* argv[1][0] == '-' */

	if (argc != 6) /* if mandatory fields not present */
		perr("Usage:\nvolcopy [-F FSType] [-V] "
			"[current_options] [-o "
			"specific_options] operands\n");

	if (nargc + 5 >= ARGV_MAX)
		perr("volcopy: too many arguments.\n");

	for (ii = 0; ii < 5; ii++)
		nargv[nargc++] = argv[ii+1];

	if (fstype == NULL) {
		if ((fd = fopen(vfstab, "r")) == NULL)
			perr("volcopy: cannot open %s.\n", vfstab);

		vfsnull(&vref);
		vref.vfs_special = argv[2];
		ii = getvfsany(fd, &vget, &vref);
		if (ii == -1) {
			rewind(fd);
			vfsnull(&vref);
			vref.vfs_fsckdev = argv[2];
			ii = getvfsany(fd, &vget, &vref);
		}

		fclose(fd);

		switch (ii) {
		case -1:
			fstype = default_fstype(argv[2]);
			break;
		case 0:
			fstype = vget.vfs_fstype;
			break;
		case VFS_TOOLONG:
			perr("volcopy: line in vfstab exceeds "
				"%d characters\n", VFS_LINE_MAX-2);
			break;
		case VFS_TOOFEW:
			perr("volcopy: line in vfstab has too few entries\n");
			break;
		case VFS_TOOMANY:
			perr("volcopy: line in vfstab has too many entries\n");
			break;
		default:
			break;
		}
	}

	if (Vflg) {
		printf("volcopy -F %s", fstype);
		for (ii = 2; nargv[ii]; ii++)
			printf(" %s", nargv[ii]);
		printf("\n");
		exit(0);
	}

	doexec(fstype, nargv);
	return (0);
}

static void
doexec(char *fstype, char *nargv[])
{
	char	full_path[PATH_MAX];
	char	*vfs_path = VFS_PATH;

	/* build the full pathname of the fstype dependent command. */
	sprintf(full_path, "%s/%s/volcopy", vfs_path, fstype);

	/* set the new argv[0] to the filename */
	nargv[1] = "volcopy";

	/* Try to exec the fstype dependent portion of the mount. */
	execv(full_path, &nargv[1]);
	if (errno == EACCES) {
		perr("volcopy: cannot execute %s"
			" - permission denied\n", full_path);
		exit(1);
	}
	if (errno == ENOEXEC) {
		nargv[0] = "sh";
		nargv[1] = full_path;
		execv("/sbin/sh", &nargv[0]);
	}
	perr("volcopy: Operation not applicable for FSType %s\n", fstype);
	exit(1);
}

/*
 * perr:  Print error messages.
 */

static int
perr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, gettext(fmt), ap);
	va_end(ap);
	exit(1);
	return (0);
}
