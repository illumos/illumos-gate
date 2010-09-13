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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Rmdir(1) removes directory.
 * If -p option is used, rmdir(1) tries to remove the directory
 * and it's parent directories.  It exits with code 0 if the WHOLE
 * given path is removed and 2 if part of path remains.
 * Results are printed except when -s is used.
 */

#include <stdio.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>


int
main(int argc, char **argv)
{

	char	*prog;
	int c, pflag, sflag, errflg, rc;
	char *ptr, *remain, *msg, *path;
	unsigned int pathlen;

	prog = argv[0];
	pflag = sflag = 0;
	errflg = 0;
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "ps")) != EOF)
		switch (c) {
			case 'p':
				pflag++;
				break;
			case 's':
				sflag++;
				break;
			case '?':
				errflg++;
				break;
		}
	if (argc < 2 || errflg) {
		(void) fprintf(stderr, gettext("Usage: %s [-ps] dirname ...\n"),
		    prog);
		exit(2);
	}
	errno = 0;
	argc -= optind;
	argv = &argv[optind];
	while (argc--) {
		ptr = *argv++;
		/*
		 * -p option. Remove directory and parents.
		 * Prints results of removing
		 */
		if (pflag) {
			pathlen = (unsigned)strlen(ptr);
			if ((path = (char *)malloc(pathlen + 4)) == NULL ||
			    (remain = (char *)malloc(pathlen + 4)) == NULL) {
				perror(prog);
				exit(2);
			}
			(void) strcpy(path, ptr);

			/*
			 * rmdirp removes directory and parents
			 * rc != 0 implies only part of path removed
			 */

			if (((rc = rmdirp(path, remain)) != 0) && !sflag) {
				switch (rc) {
				case -1:
					if (errno == EEXIST)
						msg = gettext(
						    "Directory not empty");
					else
						msg = strerror(errno);
					break;
				case -2:
					errno = EINVAL;
					msg = gettext("Can not remove . or ..");
					break;
				case -3:
					errno = EINVAL;
					msg = gettext(
					    "Can not remove current directory");
					break;
				}
				(void) fprintf(stderr, gettext("%s: directory"
				    " \"%s\": %s not removed; %s\n"),
				    prog, ptr, remain, msg);
			}
			free(path);
			free(remain);
			continue;
		}

		/* No -p option. Remove only one directory */

		if (rmdir(ptr) == -1) {
			switch (errno) {
			case EEXIST:
				msg = gettext("Directory not empty");
				break;
			case ENOTDIR:
				msg = gettext("Path component not a directory");
				break;
			case ENOENT:
				msg = gettext("Directory does not exist");
				break;
			case EACCES:
				msg = gettext(
				    "Search or write permission needed");
				break;
			case EBUSY:
				msg = gettext(
				    "Directory is a mount point or in use");
				break;
			case EROFS:
				msg = gettext("Read-only file system");
				break;
			case EIO:
				msg = gettext(
				    "I/O error accessing file system");
				break;
			case EINVAL:
				msg = gettext(
				    "Can't remove current directory or ..");
				break;
			case EFAULT:
			default:
				msg = strerror(errno);
				break;
			}
			(void) fprintf(stderr,
			    gettext("%s: directory \"%s\": %s\n"),
			    prog, ptr, msg);
			continue;
		}
	}
	return (errno ? 2 : 0);
}
