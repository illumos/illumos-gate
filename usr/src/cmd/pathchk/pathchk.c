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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Copyright 1991, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * Standards Conformance :
 *      P1003.2/D11.2
 *
 */
/*
 * Original ident string for reference
 * ident	"$Id: pathchk.c,v 1.29 1994/05/24 15:51:19 mark Exp $"
 */

#include <locale.h>
#include <libintl.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>		/* for creat() prototype */
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * These are the characters in the portable filename character set defined
 * in POSIX P1003.2.
 */
static	char	portfsset[] = \
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";


#ifndef M_FSDELIM
#define	M_FSDELIM(c)	((c) == '/')
#endif

static char *nametoolong = "%s: component too long.\n";
static char *pathtoolong = "%s: pathname too long.\n";
static char *notsrch = "%s: Not searchable.\n";
static char *badchar = "%s: Nonportable character '%c' (%#02X) found.\n";
static char *badbyte = "%s: Nonportable byte %#02X found.\n";

static char *pathconfprob = "pathchk: warning: \
			    pathconf(\"%s\", %s) returns '%s'. Using %s = %d\n";


static int printWarnings = 1;

static int checkpathname(char *, int);
static void usage(void);

/*
 * mainline for pathchk
 */
int
main(int argc, char **argv)
{
	int c;
	int errors;
	int pflag = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);


	while ((c = getopt(argc, argv, "pw")) != EOF) {
		switch (c) {
		case 'p':
			pflag = 1;
			break;

		case 'w':
			/* turn off warning messages */
			printWarnings = 0;
			break;

		default:
			usage();
		}
	}

	argv += optind;

	if (*argv == 0) {
		usage();
		/* NOTREACHED */
	}

	errors = 0;
	while (*argv) {
		errors += checkpathname(*argv, pflag);
		argv += 1;
	}

	return (errors);
}

/*
 * checkPathConf(const char *, int, long *)
 *
 * Calls pathconf(), and returns 1 if pathconf failed, zero
 * otherwise.  If pathconf() succeeded, then *valp contains the
 * value returned
 */
static int
checkPathConf(const char *path, int type, long *valp)
{
	errno = 0;
	*valp = pathconf(path, type);
	if ((*valp == -1) && (errno != 0) && (errno != EACCES)) {
		/*
		 * pathconf() is not supported on some mounted filesystems
		 * (e.g NFS mounts) and pathconf() is known to fail.
		 * So, we print a warning and use the POSIX default values.
		 */
		if (type == _PC_PATH_MAX)
			*valp = _POSIX_PATH_MAX;
		else
			*valp = _POSIX_NAME_MAX;

		if (printWarnings) {
			(void) fprintf(stderr, gettext(pathconfprob), path,
				type == _PC_PATH_MAX?"_PC_PATH_MAX" :
				    "_PC_NAME_MAX", strerror(errno),
				type == _PC_PATH_MAX ? "PATH_MAX" : "NAME_MAX",
				    *valp);
		}
	}
	return ((*valp == -1) && (errno != 0));
}


#define	UPDATE_LIMITS(buf)\
{\
	if (pflag) {\
		nameMax = _POSIX_NAME_MAX;\
		pathMax = _POSIX_PATH_MAX;\
	} else if (checkPathConf((buf), _PC_PATH_MAX, &pathMax) || \
	    checkPathConf((buf), _PC_NAME_MAX, &nameMax)) {\
		(void) fprintf(stderr, gettext(notsrch), buf);\
		return (1);\
	}\
}

/*
 * checkpathname(char *pname)
 * pathchk a single pathname.
 */
int
checkpathname(char *path, int pflag)
{
	int		checkStat;
	long		nameMax;
	long		pathMax;
	char		*scomp;
	char		*ecomp;
	register char	*p;

	p = path;
	checkStat = 1;

	/*
	 * Get the initial NAME_MAX and PATH_MAX values
	 */
	if (M_FSDELIM(*p)) {
		char buf[2];

		buf[0] = *p;
		buf[1] = '\0';

		UPDATE_LIMITS(buf);
	} else {
		/*
		 * This is a relative pathname, initial values
		 * are relative to the current directory
		 */
		UPDATE_LIMITS(".");
	}

	/*
	 * Check to make sure that the pathname doesn't exceed the
	 * current PATH_MAX
	 */
	if (pathMax != -1 && strlen(p) > (size_t)pathMax) {
		(void) fprintf(stderr, gettext(pathtoolong), path);
		return (1);
	}


	/*
	 * Now spin around checking all the prefixes of
	 * the pathname, until we hit the end of the
	 * argument
	 */
	while (*p != '\0') {
		/*
		 * Find the beginning of the next
		 * component.  Assume that
		 * M_FSDELIM('\0') == 0
		 */
		while (M_FSDELIM(*p))
			p += 1;

		if (*p == '\0') {
			/*
			 * There were trailing fsdelim chars on
			 * the path provided, so we were
			 * finished, we just didn't know it.
			 */
			return (0);
		}

		scomp = p;

		/*
		 * Find the end of the current component
		 * and check for valid characters in the component
		 */
		while (*p != '\0' && !M_FSDELIM(*p)) {
			/*
			 * for pflag: check for PFCS characters
			 * otherwise assume all characters are valid
			 */
			if (pflag && (strchr(portfsset, *p) == 0)) {
				if (isprint(*p)) {
					(void) fprintf(stderr,
					    gettext(badchar), path, *p, *p);
				} else {
					(void) fprintf(stderr,
					    gettext(badbyte), path, *p);
				}
				return (1);
			}
			p += 1;
		 }

		ecomp = p;

		/*
		 * Make sure that this component does not exceed
		 * NAME_MAX in the current prefix directory
		 */
		if ((nameMax != -1) && (ecomp - scomp > nameMax)) {
			(void) fprintf(stderr, gettext(nametoolong), scomp);
			return (1);
		} else if (!pflag && checkStat) {
			/*
			 * Perform the extra checks that
			 * are required when not just
			 * checking for portability.
			 */
			struct stat sb;
			char fsdelim;

			fsdelim = *ecomp;
			*ecomp = '\0';

			if (stat(path, &sb) == -1) {
				/*
				 * We error out if an
				 * intermediate component
				 * is a file, when we
				 * were expecting a
				 * directory, or it is an
				 * unsearchable directory.
				 */
				if ((errno == ENOTDIR && fsdelim != '\0') ||
				    (errno == EACCES)) {
					(void) fprintf(stderr, gettext(notsrch),
						path);
					return (1);
				} else if (errno == ENOENT) {
					checkStat = 0;
				}
			} else if (S_ISDIR(sb.st_mode)) {
				/*
				 * If the current prefix is a
				 * directory, then we need to
				 * update the limits for NAME_MAX
				 * for the next component and the suffix.
				 */
				if (checkPathConf(path, _PC_NAME_MAX,
				    &nameMax)) {
					(void) fprintf(stderr,
					    gettext(notsrch), path);
					return (1);
				}
			}

			/*
			 * restore the fsdelim char that we
			 * stomped to produce a prefix.
			 */
			*ecomp = fsdelim;
		} /* if (we need to stat the path) */
	} /* while (more of this path to check) */

	/*
	 * We successfully traversed the whole pathname
	 */
	return (0);
}

void
usage()
{
	(void) fprintf(stderr, gettext("usage: pathchk [-p] pathname ..."));
	(void) fprintf(stderr, "\n");
	exit(2);
}
