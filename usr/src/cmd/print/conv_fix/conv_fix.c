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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>

extern char *optarg;

/*
 * FUNCTION:
 *	static char *_file_getline(FILE *fp)
 * INPUT:
 *	FILE *fp - file pointer to read from
 * OUTPUT:
 *	char *(return) - an entry from the stream
 * DESCRIPTION:
 *	This routine will read in a line at a time.  If the line ends in a
 *	newline, it returns.  If the line ends in a backslash newline, it
 *	continues reading more.  It will ignore lines that start in # or
 *	blank lines.
 */
static char *
_file_getline(FILE *fp)
{
	char entry[BUFSIZ], *tmp;
	int size;

	size = sizeof (entry);
	tmp  = entry;

	/* find an entry */
	while (fgets(tmp, size, fp)) {
		if ((tmp == entry) && ((*tmp == '#') || (*tmp == '\n'))) {
			continue;
		} else {
			if ((*tmp == '#') || (*tmp == '\n')) {
				*tmp = '\0';
				break;
			}

			size -= strlen(tmp);
			tmp += strlen(tmp);

			if (*(tmp-2) != '\\')
				break;

			size -= 2;
			tmp -= 2;
		}
	}

	if (tmp == entry)
		return (NULL);
	else
		return (strdup(entry));
}

int
main(int ac, char *av[])
{
	int   c;
	char  file[80], ofile[80];
	char *cp;
	FILE *fp, *fp2;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(ac, av, "f:o:")) != EOF)

		switch (c) {
		case 'f':
			(void) strlcpy(file, optarg, sizeof (file));
			break;
		case 'o':
			(void) strlcpy(ofile, optarg, sizeof (ofile));
			break;
		default:
			(void) fprintf(stderr, gettext(
				"Usage: %s [-f file] [-o output file]\n"),
				av[0]);
			return (1);
		}

	if ((fp = fopen(file, "r")) != NULL) {
		int fd;

		fd = open(ofile, O_RDWR|O_APPEND);
		if ((fd < 0) && (errno == ENOENT))
			fd = open(ofile, O_RDWR|O_CREAT|O_EXCL, 0644);

		if (fd < 0) {
			(void) fprintf(stderr,
			    gettext("Error trying to open file.\n"));
			return (1);
		}

		lseek(fd, 0, SEEK_END);

		if ((fp2 = fdopen(fd, "a")) != NULL) {
			while ((cp = _file_getline(fp)) != NULL) {
				(void) fprintf(fp2, "%s", cp);
			}
			return (0);
		} else {
			(void) fprintf(stderr,
			    gettext("Error trying to open file.\n"));
			return (1);
		}
	} else {
		(void) fprintf(stderr,
		    gettext("Error trying to open file.\n"));
		return (1);
	}
}
