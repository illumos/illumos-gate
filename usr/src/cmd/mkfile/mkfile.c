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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <errno.h>

#define	WRITEBUF_SIZE	8192

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

#define	BLOCK_SIZE	512		/* bytes */
#define	KILOBYTE	1024
#define	MEGABYTE	(KILOBYTE * KILOBYTE)
#define	GIGABYTE	(KILOBYTE * MEGABYTE)

#define	FILE_MODE	(S_ISVTX + S_IRUSR + S_IWUSR)

static void usage(void);

char buf[WRITEBUF_SIZE];

int
main(int argc, char **argv)
{
	char	*opts;
	off_t	size;
	size_t	len;
	size_t	mult = 1;
	int	errors = 0;
	int	i;
	int	verbose = 0;	/* option variable */
	int	nobytes = 0;	/* option variable */
	int	saverr;

	if (argc == 1)
		usage();

	while (argv[1] && argv[1][0] == '-') {
		opts = &argv[1][0];
		while (*(++opts)) {
			switch (*opts) {
			case 'v':
				verbose++;
				break;
			case 'n':
				nobytes++;
				break;
			default:
				usage();
			}
		}
		argc--;
		argv++;
	}
	if (argc < 3)
		usage();

	len = strlen(argv[1]);
	if (len && isalpha(argv[1][len-1])) {
		switch (argv[1][len-1]) {
		case 'k':
		case 'K':
			mult = KILOBYTE;
			break;
		case 'b':
		case 'B':
			mult = BLOCK_SIZE;
			break;
		case 'm':
		case 'M':
			mult = MEGABYTE;
			break;
		case 'g':
		case 'G':
			mult = GIGABYTE;
			break;
		default:
			(void) fprintf(stderr, "unknown size %s\n", argv[1]);
			usage();
		}

		for (i = 0; i <= (len-2); i++) {
			if (!isdigit(argv[1][i])) {
				(void) fprintf(stderr, "unknown size "
					"%s\n", argv[1]);
				usage();
			}
		}
		argv[1][len-1] = '\0';
	}
	size = ((off_t)atoll(argv[1]) * (off_t)mult);

	argv++;
	argc--;

	while (argc > 1) {
		int fd;

		if (verbose)
			(void) fprintf(stdout, "%s %lld bytes\n", argv[1],
			    (offset_t)size);
		fd = open(argv[1], O_CREAT|O_TRUNC|O_RDWR, FILE_MODE);
		if (fd < 0) {
			saverr = errno;
			(void) fprintf(stderr,
			    gettext("Could not open %s: %s\n"),
			    argv[1], strerror(saverr));
			errors++;
			argv++;
			argc--;
			continue;
		}
		if (lseek(fd, (off_t)size-1, SEEK_SET) < 0) {
			saverr = errno;
			(void) fprintf(stderr, gettext(
			    "Could not seek to offset %ld in %s: %s\n"),
			    (ulong_t)size-1, argv[1], strerror(saverr));
			(void) close(fd);
			errors++;
			argv++;
			argc--;
			continue;
		} else if (write(fd, "", 1) != 1) {
			saverr = errno;
			(void) fprintf(stderr, gettext(
			    "Could not set length of %s: %s\n"),
			    argv[1], strerror(saverr));
			(void) close(fd);
			errors++;
			argv++;
			argc--;
			continue;
		}

		if (!nobytes) {
			off_t written = 0;

			if (lseek(fd, (off_t)0, SEEK_SET) < 0) {
				saverr = errno;
				(void) fprintf(stderr, gettext(
				    "Could not seek to beginning of %s: %s\n"),
				    argv[1], strerror(saverr));
				(void) close(fd);
				errors++;
				argv++;
				argc--;
				continue;
			}
			while (written < size) {
				ssize_t result;
				size_t bytes = (size_t)MIN(sizeof (buf),
					size-written);

				if ((result = write(fd, buf, bytes)) !=
				    (ssize_t)bytes) {
					saverr = errno;
					if (result < 0)
					    result = 0;
					written += result;
					(void) fprintf(stderr, gettext(
			    "%s: initialized %lu of %lu bytes: %s\n"),
					    argv[1], (ulong_t)written,
					    (ulong_t)size,
					    strerror(saverr));
					errors++;
					break;
				}
				written += bytes;
			}

			/*
			 * A write(2) call in the above loop failed so
			 * close out this file and go on (error was
			 * already incremented when the write(2) failed).
			 */
			if (written < size) {
				(void) close(fd);
				argv++;
				argc--;
				continue;
			}
		}
		if (close(fd) < 0) {
			saverr = errno;
			(void) fprintf(stderr, gettext(
			    "Error encountered when closing %s: %s\n"),
			    argv[1], strerror(saverr));
			errors++;
			argv++;
			argc--;
			continue;
		}

		/*
		 * Only set the modes (including the sticky bit) if we
		 * had no problems.  It is not an error for the chmod(2)
		 * to fail, but do issue a warning.
		 */
		if (chmod(argv[1], FILE_MODE) < 0)
			(void) fprintf(stderr,
			    "warning: couldn't set mode to %#o\n", FILE_MODE);

		argv++;
		argc--;
	}
	return (errors);
}

static void usage()
{
	(void) fprintf(stderr,
		"Usage: mkfile [-nv] <size>[g|k|b|m] <name1> [<name2>] ...\n");
	exit(1);
	/* NOTREACHED */
}
