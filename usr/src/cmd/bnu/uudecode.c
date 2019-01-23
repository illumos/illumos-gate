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

/*	Copyright 2004 Sun Microsystems, Inc.  All rights reserved. */
/*	Use is subject to license terms. */

/*
 * uudecode [-o outfile | -p] [input]
 *
 * create the specified file, decoding as you go.
 * used with uuencode.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <locale.h>
#include <nl_types.h>
#include <langinfo.h>
#include <iconv.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>

#define	BUFSIZE	90	/* must be a multiple of 3 */

#define	TABLE_SIZE	0x40

#define	isvalid(octet)	(octet <= 0x40)

/*
 * base64 decoding table
 */
/* BEGIN CSTYLED */
static char base64tab[] = {
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377',     62, '\377', '\377', '\377',     63,
	    52,     53,     54,     55,     56,     57,     58,     59,
	    60,     61, '\377', '\377', '\377', '\377', '\377', '\377',
	'\377',      0,      1,      2,      3,      4,      5,      6,
	     7,      8,      9,     10,     11,     12,     13,     14,
	    15,     16,     17,     18,     19,     20,     21,     22,
	    23,     24,     25, '\377', '\377', '\377', '\377', '\377',
	'\377',     26,     27,     28,     29,     30,     31,     32,
	    33,     34,     35,     36,     37,     38,     39,     40,
	    41,     42,     43,     44,     45,     46,     47,     48,
	    49,     50,     51, '\377', '\377', '\377', '\377', '\377'
};
/* END CSTYLED */

static char	decode_table[UCHAR_MAX + 1];

/* DEC is the basic 1 character decoding function (historical algorithm) */
#define	DEC(c)	decode_table[c]

/* true if the character is in the base64 encoding table */
#define	validbase64(c) (('A' <= (c) && (c) <= 'Z') || \
		('a' <= (c) && (c) <= 'z') || \
		('0' <= (c) && (c) <= '9') || \
		(c) == '+' || (c) == '/')

static void	decode(FILE *, FILE *, int);
static int	outdec(unsigned char *, unsigned char *, int);
static int	outdec64(unsigned char *, unsigned char *, int);

/* from usr/src/cmd/chmod/common.c */

void errmsg(int severity, int code, char *format, ...);

extern mode_t newmode(char *ms, mode_t new_mode, mode_t umsk,
    char *file, char *path);

static char	*prog;
static char	outfile[PATH_MAX];
static int	mode_err = 0;	/* mode conversion error flag */

int
main(int argc, char **argv)
{
	FILE *in, *out;
	int pipeout = 0;
	int oflag = 0;
	int i;
	mode_t mode, p_umask;
	char dest[PATH_MAX];
	char modebits[1024];
	char buf[LINE_MAX];
	int	c, errflag = 0;
	struct stat sbuf;
	int base64flag = 0;

	prog = argv[0];
	(void) signal(SIGPIPE, SIG_DFL);
	bzero(dest, sizeof (dest));
	outfile[0] = '\0';

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);
	p_umask = umask((mode_t)0);

	while ((c = getopt(argc, argv, "o:p")) != EOF) {
		switch (c) {
		case 'o':
			oflag++;
			(void) strncpy(outfile, optarg, sizeof (outfile));
			break;
		case 'p':
			pipeout++;
			break;
		default:
		case '?':
			errflag++;
			break;
		}
	}
	argc -= optind;
	argv = &argv[optind];

	/* optional input arg */
	if (argc > 0) {
		if ((in = fopen(*argv, "r")) == NULL) {
			perror(*argv);
			exit(1);
		}
		argv++; argc--;
	} else {
		in = stdin;
		errno = 0;
		if (fstat(fileno(in), &sbuf) < 0) {
			perror("stdin");
			exit(1);
		}
	}

	if ((argc > 0) || errflag || (oflag && pipeout)) {
		(void) fprintf(stderr,
		    gettext("Usage: %s [-o outfile | -p] [infile]\n"), prog);
		exit(2);
	}

	/* search for header line */
	for (;;) {
		if (fgets(buf, sizeof (buf), in) == NULL) {
			/* suppress message if we printed a mode error */
			if (mode_err == 0)
				(void) fprintf(stderr,
				    gettext("No begin line\n"));
			exit(3);
		}
		/*
		 * the check for begin-base64 obviously needs to come
		 * first, since both algorithms' begin strings start
		 * with 'begin'.  Also verify that there is a valid
		 * octal or symbolic file mode.
		 */
		if (strncmp(buf, "begin-base64", 12) == 0) {
			base64flag = 1;
			mode_err = 0;
			if ((sscanf(buf + 13, "%1023s %1023s",
			    modebits, dest) == 2) &&
			    ((sscanf(modebits, "%lo", &mode) == 1) ||
				((mode = newmode(modebits, 0, p_umask,
				    "", "")) != 0) && mode_err == 0))
				break;
		} else if (strncmp(buf, "begin", 5) == 0) {
			base64flag = 0;
			mode_err = 0;
			if ((sscanf(buf + 6, "%1023s %1023s",
			    modebits, dest) == 2) &&
			    ((sscanf(modebits, "%lo", &mode) == 1) ||
				((mode = newmode(modebits, 0, p_umask,
				    "", "")) != 0) && mode_err == 0))
				break;
		}
	}

	/*
	 * Now that we know the type of encoding used, we can
	 * initialize the decode table.
	 */
	if (base64flag == 0) {
		(void) memset(decode_table, 0xFF, sizeof (decode_table));
		for (i = 0; i <= TABLE_SIZE; i++)
			decode_table[(unsigned char)i + 0x20] =
			    (unsigned char)i & 0x3F;
	} else
		(void) memcpy(decode_table, base64tab, sizeof (base64tab));

	/*
	 * Filename specified on the command line with -o
	 * overrides filename in the encoded file.
	 */
	if (outfile[0] != '\0')
		(void) strncpy(dest, outfile, sizeof (dest));

	if (pipeout ||
	    (dest[0] == '-' && dest[1] == '\0' && outfile[0] == '\0')) {
		out = stdout;
		bzero(outfile, sizeof (outfile));
		bzero(dest, sizeof (dest));
	} else {
		/* handle ~user/file format */
		if (dest[0] == '~') {
			char *sl;
			struct passwd *user;
			char dnbuf[100];

			sl = strchr(dest, '/');
			if (sl == NULL) {
				(void) fprintf(stderr,
				    gettext("Illegal ~user\n"));
				exit(3);
			}
			*sl++ = 0;
			user = getpwnam(dest+1);
			if (user == NULL) {
				(void) fprintf(stderr,
				    gettext("No such user as %s\n"), dest);
				exit(4);
			}
			(void) strncpy(dnbuf, user->pw_dir, sizeof (dnbuf));
			(void) strlcat(dnbuf, "/", sizeof (dnbuf));
			(void) strlcat(dnbuf, sl, sizeof (dnbuf));
			(void) strncpy(dest, dnbuf, sizeof (dest));
		}
	}
	/* if not using stdout, create file */
	if (dest[0] != '\0') {
		if ((out = fopen(dest, "w")) == NULL) {
			perror(dest);
			exit(4);
		}
		(void) chmod(dest, mode & 0777);
	}

	decode(in, out, base64flag);

	if (fclose(out) == EOF) {
		perror(prog);
		exit(6);
	}

	return (0);
}

/*
 * copy from in to out, decoding as you go along.
 */

static void
decode(FILE *in, FILE *out, int base64)
{
	char	inbuf[120], *ibp, *iptr;
	unsigned char 	outbuf[BUFSIZE], *obp, *optr;
	int	n, octets, warned, endseen, numbase64chars;
	unsigned char chr[4], curchr, ch;
	longlong_t line;

	if (! base64) {	/* use historical algorithm */
		warned = 0;
		for (line = 1; ; line++) {
			/* for each input line */
			if (fgets(inbuf, sizeof (inbuf), in) == NULL) {
				(void) fprintf(stderr,
				    gettext("No end line\n"));
				exit(5);
			}

			/* Is line == 'end\n'? */
			if (strcmp(inbuf, "end\n") == 0) {
				break;
			}

			n = DEC(inbuf[0]);

			if (n < 0)
				continue;

			/*
			 * Decode data lines.
			 *
			 * Note that uuencode/uudecode uses only the portable
			 * character set for encoded data and the portable
			 * character set characters must be represented in
			 * a single byte.  We use this knowledge to reuse
			 * buffer space while decoding.
			 */
			octets = n;
			obp = (unsigned char *) &inbuf[0];
			ibp = &inbuf[1];
			while (octets > 0) {
				if ((ch = outdec((unsigned char *)obp,
				    (unsigned char *)ibp, octets))
				    != 0x20) {
					/* invalid characters where detected */
					if (!warned) {
						warned = 1;
						(void) fprintf(stderr,
						    gettext("Invalid character"
							" (0x%x) on line"
							" %lld\n"), ch, line);
					}
					break;
				}
				ibp += 4;
				obp += 3;
				octets -= 3;
			}
			/*
			 * Only write out uncorrupted lines
			 */
			if (octets <= 0) {
				(void) fwrite(inbuf, n, 1, out);
			}
		}
	} else {	/* use base64 algorithm */
		endseen = numbase64chars = 0;
		optr = outbuf;
		while ((fgets(inbuf, sizeof (inbuf), in)) != NULL) {
			/* process an input line */
			iptr = inbuf;
			while ((curchr = *(iptr++)) != '\0') {
				/* decode chars */
				if (curchr == '=') /* if end */
					endseen++;

				if (validbase64(curchr))
					chr[numbase64chars++] = curchr;
				/*
				 * if we've gathered 4 base64 octets
				 * we need to decode and output them
				 */
				if (numbase64chars == 4) {
					/*LINTED*/
					if (optr - outbuf > BUFSIZE - 3) {
						(void) fwrite(outbuf,
						    /*LINTED*/
						    (size_t)(optr - outbuf),
						    1, out);
						if (ferror(out)) {
							perror(prog);
							exit(6);
						}
						optr = outbuf;
					}
					octets = outdec64(optr, chr, 4);
					optr += octets;
					numbase64chars = 0;
				}
			}
			/*
			 * handle any remaining base64 octets at end
			 */
			if (endseen && numbase64chars > 0) {
				octets = outdec64(optr, chr, numbase64chars);
				optr += octets;
				numbase64chars = 0;
			}
		}
		/*
		 * if we have generated any additional output
		 * in the buffer, write it out
		 */
		if (optr != outbuf) {
			/*LINTED*/
			(void) fwrite(outbuf, (size_t)(optr - outbuf),
			    1, out);
			if (ferror(out)) {
				perror(prog);
				exit(6);
			}
		}

		if (endseen == 0) {
			(void) fprintf(stderr, gettext("No end line\n"));
			exit(5);
		}
	}
}

/*
 * historical algorithm
 *
 * output a group of 3 bytes (4 input characters).
 * the input chars are pointed to by p, they are to
 * be output to file f.  n is used to tell us not to
 * output all of them at the end of the file.
 */

static int
outdec(unsigned char *out, unsigned char *in, int n)
{
	unsigned char	b0 = DEC(*(in++));
	unsigned char	b1 = DEC(*(in++));
	unsigned char	b2 = DEC(*(in++));
	unsigned char	b3 = DEC(*in);

	if (!isvalid(b0)) {
		return (*(in-3));
	}
	if (!isvalid(b1)) {
		return (*(in-2));
	}

	*(out++) = (b0 << 2) | (b1 >> 4);

	if (n >= 2) {
		if (!isvalid(b2)) {
			return (*(in - 1));
		}

		*(out++) = (b1 << 4) | (b2 >> 2);

		if (n >= 3) {
			if (!isvalid(b3)) {
				return (*in);
			}
			*out = (b2 << 6) | b3;
		}
	}
	return (0x20); /* a know good value */
}

/*
 * base64 algorithm
 *
 * Takes a pointer to the current position in the output buffer,
 * a pointer to the (up to) 4 byte base64 input buffer and a
 * count of the number of valid input bytes.
 *
 * Return the number of bytes placed in the output buffer
 */
static int
outdec64(unsigned char *out, unsigned char *chr, int num)
{

	unsigned char char1, char2, char3, char4;
	unsigned char *outptr = out;
	int rc = 0;

	switch (num) {
	case 0:
	case 1: 	/* these are impossible */
	default:
		break;
	case 2:		/* 2 base64 bytes == 1 decoded byte */
		char1 = base64tab[chr[0]] & 0xFF;
		char2 = base64tab[chr[1]] & 0xFF;
		*(outptr++) = ((char1 << 2) & 0xFC) |
		    ((char2 >> 4) & 0x03);
		rc = 1;
		break;
	case 3:		/* 3 base64 bytes == 2 decoded bytes */
		char1 = base64tab[chr[0]] & 0xFF;
		char2 = base64tab[chr[1]] & 0xFF;
		char3 = base64tab[chr[2]] & 0xFF;
		*(outptr++) = ((char1 << 2) & 0xFC) |
		    ((char2 >> 4) & 0x03);
		*(outptr++) = ((char2 << 4) & 0xF0) |
		    ((char3 >> 2) & 0x0F);
		rc = 2;
		break;
	case 4:		/* 4 base64 bytes == 3 decoded bytes */
		char1 = base64tab[chr[0]] & 0xFF;
		char2 = base64tab[chr[1]] & 0xFF;
		char3 = base64tab[chr[2]] & 0xFF;
		char4 = base64tab[chr[3]] & 0xFF;
		*(outptr++) = ((char1 << 2) & 0xFC) |
		    ((char2 >> 4) & 0x03);
		*(outptr++) = ((char2 << 4) & 0xF0) |
		    ((char3 >> 2) & 0x0F);
		*(outptr++) = ((char3 << 6) & 0xC0) |
		    (char4 & 0x3F);
		rc = 3;
		break;
	}
	return (rc);
}

/*
 * error message routine called by newmode.
 *
 * The severity and code are ignored here.  If this routine gets
 * called, we set a global flag (which can be tested after return
 * from here) which tells us whether or not a valid mode has been
 * parsed or if we printed an error message.
 */

/*ARGSUSED*/
void
errmsg(int severity, int code, char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	(void) fprintf(stderr, "uudecode: ");
	(void) fprintf(stderr, format, ap);

	va_end(ap);

	mode_err = 1;
}
