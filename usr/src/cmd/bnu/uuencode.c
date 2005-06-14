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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * uuencode [-m] [input] decode_pathname
 *
 * Encode a file so it can be mailed to a remote system.
 */
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

/*
 * (Size of TABLE_SIZE octal is large enough to convert a basic 6-bit
 * data chunk.)
 */
#define		TABLE_SIZE	0x40


static unsigned char	base64_table_initializer[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned char	encode_table[TABLE_SIZE];

/* ENC is the basic 1 character encoding function to make a char printing */
#define	ENC(c)	encode_table[(c) & 077]

static void	encode(FILE *, FILE *, int);
static char	*prog;

int
main(int argc, char **argv)
{
	FILE *in;
	struct stat sbuf;
	mode_t mode = 0;
	int	c, i;
	int	errflag = 0;
	int	base64flag = 0;
	char	oline[PATH_MAX + 20];

	prog = argv[0];
	(void) signal(SIGPIPE, SIG_DFL);

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "m")) != EOF)
		switch (c) {
		case 'm':
			base64flag++;
			break;
		default:
		case '?':
			errflag++;
		}

	argc -= optind;
	argv = &argv[optind];

	/* optional 1st argument */
	if (argc > 1) {
		if ((in = fopen(*argv, "r")) == NULL) {
			perror(*argv);
			exit(1);
		}
		argv++; argc--;
	} else {
		in = stdin;
		mode = 0777;
	}

	if ((argc != 1) || errflag) {
		(void) fprintf(stderr,
		    gettext("Usage: %s [-m] [infile] remotefile\n"), prog);
		exit(2);
	}

	/* figure out the input file mode */
	errno = 0;
	if (fstat(fileno(in), &sbuf) < 0 || !S_ISREG(sbuf.st_mode)) {
		mode = 0666 & ~umask(0666);
	} else {
		mode = sbuf.st_mode & 0777;
	}

	/*
	 * encoding varies depending on whether we are
	 * using base64 encoding or the historical algorithm
	 */
	if (base64flag) {
		(void) memcpy(encode_table, base64_table_initializer,
		    sizeof (base64_table_initializer));
	} else {
		for (i = 0; i < TABLE_SIZE; i++)
			encode_table[i] = (unsigned char)i + 0x20;
	}

	/*
	 * here's the meat of the whole thing
	 */
	if (base64flag)
		(void) snprintf(oline, sizeof (oline), "begin-base64 %lo %s\n",
		    (long)mode, *argv);
	else
		(void) snprintf(oline, sizeof (oline), "begin %lo %s\n",
		    (long)mode, *argv);

	if (printf("%s", oline) < 0) {
		perror(prog);
		exit(6);
	}

	encode(in, stdout, base64flag);

	if (base64flag)
		(void) snprintf(oline, sizeof (oline), "====\n");
	else
		(void) snprintf(oline, sizeof (oline), "end\n");

	if (printf("%s", oline) < 0) {
		perror(prog);
		exit(6);
	}

	if (ferror(stdout) != 0 || fclose(stdout) != 0) {
		perror(prog);
		exit(6);
	}

	return (0);
}

/*
 * copy from in to out, encoding as you go along.
 */
static void
encode(FILE *in, FILE *out, int base64)
{
	unsigned char in_buf[80];
	unsigned char out_buf[112];
	unsigned char *iptr, *optr;
	int i;
	size_t n, opos;

	if (! base64) {
		/* historical algorithm */

		for (;;) {
			iptr = in_buf;
			optr = out_buf;

			/* 1 (up to) 45 character line */
			n = fread(iptr, 1, 45, in);

			*(optr++) = ENC(n);

			for (i = 0; i < n; i += 3) {
				*(optr++) = ENC(*iptr >> 2);
				*(optr++) = ENC((*iptr << 4) & 060 |
				    (*(iptr + 1) >> 4) & 017);
				*(optr++) = ENC((*(iptr + 1) << 2) & 074 |
				    (*(iptr + 2) >> 6) & 03);
				*(optr++) = ENC(*(iptr + 2) & 077);
				iptr += 3;
			}

			*(optr++) = '\n';

			/*LINTED*/
			(void) fwrite(out_buf, 1, (size_t)(optr - out_buf),
			    out);

			if (ferror(out)) {
				perror(prog);
				exit(6);
			}

			if (n == 0)
				break;
		}
	} else {
		/* base64 algorithm */

			optr = out_buf;
			/*
			 * read must be a multiple of 3 bytes for
			 * this algorithm to work, and also must
			 * be small enough that read_size * (4/3)
			 * will always be 76 bytes or less, since
			 * base64 lines can be no longer than that
			 */
			while ((n = fread(in_buf, 1, 51, in)) > 0) {
				opos = 0;
				iptr = in_buf;
				for (i = 0; i < n / 3; i++) {
					*(optr++) = ENC(*iptr >> 2);
					*(optr++) = ENC((*iptr << 4) & 060 |
					    (*(iptr + 1) >> 4) & 017);
					*(optr++) = ENC((*(iptr + 1) << 2)
					    & 074 | (*(iptr + 2) >> 6) & 03);
					*(optr++) = ENC(*(iptr + 2) & 077);
					iptr += 3;
					opos += 3;

					/* need output padding ? */
					if (n - opos < 3)
						break;

					(void) fwrite(out_buf, 1,
					    /*LINTED*/
					    (size_t)(optr - out_buf), out);

					if (ferror(out)) {
						perror(prog);
						exit(6);
					}

					optr = out_buf;
				}
				/*
				 * Take care of any output padding that is
				 * necessary.
				 */
				assert(n - opos < 3);
				switch (n - opos) {
				case 0:
					/* no-op  - 24 bits of data encoded */
					*(optr++) = '\n';
					break;
				case 1:
					/* 8 bits encoded - pad with 2 '=' */
					*(optr++) = ENC((*iptr & 0xFC) >> 2);
					*(optr++) = ENC((*iptr & 0x03) << 4);
					*(optr++) = '=';
					*(optr++) = '=';
					*(optr++) = '\n';
					break;
				case 2:
					/* 16 bits encoded - pad with 1 '=' */
					*(optr++) = ENC((*iptr & 0xFC) >> 2);
					*(optr++) = ENC(((*iptr & 0x03) << 4) |
					    ((*(iptr + 1) & 0xF0) >> 4));
					*(optr++) = ENC((*(iptr + 1) & 0x0F)
					    << 2);
					*(optr++) = '=';
					*(optr++) = '\n';
					break;
				default:
					/* impossible */
					break;
				}
				(void) fwrite(out_buf, 1,
				    /*LINTED*/
				    (size_t)(optr - out_buf), out);

				if (ferror(out)) {
					perror(prog);
					exit(6);
				}

				optr = out_buf;
			}
	}
}
