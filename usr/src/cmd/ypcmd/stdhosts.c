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

#include <stdio.h>
#include <ndbm.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/*
 * Filter to convert both IPv4 and IPv6 addresses from /etc/hosts file.
 */

/*
 * Size of buffer for input lines. Add two bytes on input for newline
 * and terminating NULL. Note that the practical limit for data
 * storage in ndbm is (PBLKSIZ - 3 * sizeof (short)). Though this
 * differs from spec 1170 the common industry implementation does
 * conform to this slightly lower limit.
 */

#define	OUTPUTSIZ (PBLKSIZ - 3 * sizeof (short))
#define	INPUTSIZ (OUTPUTSIZ + 2)

static int ipv4 = -1;
static char *cmd;
int warning = 0;

static void verify_and_output(const char *key, char *value, int lineno);

void
usage()
{
	fprintf(stderr, "stdhosts [-w] [-n] [in-file]\n");
	fprintf(stderr, "\t-w\tprint malformed warning messages.\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	char line[INPUTSIZ];
	char adr[INPUTSIZ];
	char nadr[INET6_ADDRSTRLEN]; /* Contains normalised address */
	const char *nadrp;	/* Pointer to the normalised address */
	char *trailer;
	char *commentp;		/* Pointer to comment character '#' */
	int c;
	FILE *fp;
	int lineno = 0;		/* Input line counter */
	struct in_addr in;	/* Used for normalising the IPv4 address */
	struct in6_addr in6;	/* Used for normalising the IPv6 address */
	char *fgetsp;		/* Holds return value for fgets() calls */
	int endoffile = 0;	/* Set when end of file reached */

	if (cmd = strrchr(argv[0], '/'))
		++cmd;
	else
		cmd = argv[0];

	while ((c = getopt(argc, argv, "v:wn")) != -1) {
		switch (c) {
		case 'w':	/* Send warning messages to stderr */
			warning = 1;
			break;
		case 'n':
			ipv4 = 0;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (optind < argc) {
		fp = fopen(argv[optind], "r");
		if (fp == NULL) {
			fprintf(stderr, "%s: can't open %s\n",
			    cmd, argv[optind]);
			exit(1);
		}
	} else
		fp = stdin;

	while (!endoffile &&
	    (fgetsp = fgets(line, sizeof (line), fp)) != NULL) {
		lineno++;

		/* Check for comments */
		if ((commentp = strchr(line, '#')) != NULL) {
			if ((line[strlen(line) - 1] != '\n') &&
			    (strlen(line) >= (sizeof (line) - 1))) {
				/*
				 * Discard the remainder of the line
				 * until the newline or EOF, then
				 * continue to parse the line. Use
				 * adr[] rather then line[] to
				 * preserve the contents of line[].
				 */
				while ((fgetsp = fgets(adr, sizeof (adr),
				    fp)) != NULL) {
					if (adr[strlen(adr) - 1] == '\n')
						break;
				}
				if (fgetsp == NULL)
					endoffile = 1;
			}
			/* Terminate line[] at the comment character */
			*commentp = '\0';
		} else if ((line[strlen(line) - 1] != '\n') &&
		    (strlen(line) >= (sizeof (line) - 1))) {
			/*
			 * Catch long lines but not if this is a short
			 * line with no '\n' at the end of the input.
			 */
			if (warning)
				fprintf(stderr,
				    "%s: Warning: more than %d "
				    "bytes on line %d, ignored\n",
				    cmd, sizeof (line) - 2, lineno);
			/*
			 * Discard the remaining lines until the
			 * newline or EOF.
			 */
			while ((fgetsp = fgets(line, sizeof (line),
			    fp)) != NULL)
				if (line[strlen(line) - 1] == '\n')
					break;
			if (fgetsp == NULL)
				endoffile = 1;
			continue;
		}

		if (sscanf(line, "%s", adr) != 1) { /* Blank line, ignore */
			continue;
		}

		if ((trailer = strpbrk(line, " \t")) == NULL) {
			if (warning)
				fprintf(stderr,
				    "%s: Warning: no host names on line %d, "
				    "ignored\n", cmd, lineno);
			continue;
		}

		/*
		 * check for valid addresses
		 *
		 * Attempt an ipv4 conversion, this accepts all valid
		 * ipv4 addresses including:
		 *	d
		 *	d.d
		 *	d.d.d
		 * Unfortunately inet_pton() doesn't recognise these.
		 */

		in.s_addr = inet_addr(adr);
		if (-1 != (int)in.s_addr) {
			/*
			 * It's safe not to check return of NULL as
			 * nadrp is checked for validity later.
			 */
			nadrp = inet_ntop(AF_INET, &in, nadr, sizeof (nadr));
		} else {
			nadrp = NULL; /* Not a valid IPv4 address */
		}

		if (nadrp == NULL) {
			if (inet_pton(AF_INET6, adr, &in6) == 1) {
				nadrp = inet_ntop(AF_INET6, &in6,
				    nadr, sizeof (nadr));
			}
			if (nadrp == NULL) { /* Invalid IPv6 too */
				if (warning)
					fprintf(stderr,
					    "%s: Warning: malformed"
					    " address on"
					    " line %d, ignored\n",
					    cmd, lineno);
				continue;
			} else if (ipv4) {
				continue; /* Ignore valid IPv6  */
			}
		}

		verify_and_output(nadrp, trailer, lineno);

	}	/* while */
	return (0);
	/* NOTREACHED */
}

/*
 * verify_and_output
 *
 * Builds and verifies the output key and value string
 *
 * It makes sure these rules are followed:
 *	key + separator + value <= OUTPUTSIZ (for ndbm)
 *	names <= MAXALIASES + 1, ie one canonical name + MAXALIASES aliases
 * It will also ignore everything after a '#' comment character
 */
static void
verify_and_output(const char *key, char *value, int lineno)
{
	char *p;			/* General char pointer */
	char *endp;			/* Points to the NULL at the end */
	char *namep;			/* First character of a name */
	char tmpbuf[OUTPUTSIZ+1];	/* Buffer before writing out */
	char *tmpbufp = tmpbuf;		/* Current point in output string */
	int n = 0;			/* Length of output */
	int names = 0;			/* Number of names found */
	int namelen;			/* Length of the name */

	if (key) {		/* Just in case key is NULL */
		n = strlen(key);
		if (n > OUTPUTSIZ) {
			if (warning)
				fprintf(stderr,
				    "%s: address too long on "
				    "line %d, line discarded\n",
				    cmd, lineno);
			return;
		}
		memcpy(tmpbufp, key, n+1); /* Plus the '\0' */
		tmpbufp += n;
	}

	if (value) {		/* Just in case value is NULL */
		p = value;
		if ((endp = strchr(value, '#')) == 0)	/* Ignore # comments */
			endp = p + strlen(p);		/* Or endp = EOL */
		do {
			/*
			 * Skip white space. Type conversion is
			 * necessary to avoid unfortunate effects of
			 * 8-bit characters appearing negative.
			 */
			while ((p < endp) && isspace((unsigned char)*p))
				p++;

			if (p == endp)	/* End of the string */
				break;

			names++;
			if (names > (MAXALIASES+1)) { /* cname + MAXALIASES */
				if (warning)
					fprintf(stderr,
					    "%s: Warning: too many "
					    "host names on line %d, "
					    "truncating\n",
					    cmd, lineno);
				break;
			}

			namep = p;
			while ((p < endp) && !isspace((unsigned char)*p))
				p++;

			namelen = p - namep;
			n += namelen + 1; /* single white space + name */
			*p = '\0';	   /* Terminate the name string */
			if (n > OUTPUTSIZ) {
				if (warning)
					fprintf(stderr,
					    "%s: Warning: %d byte ndbm limit "
					    "reached on line %d, truncating\n",
					    cmd, OUTPUTSIZ, lineno);
				break;
			}

			if (names == 1) /* First space is a '\t' */
				*tmpbufp++ = '\t';
			else
				*tmpbufp++ = ' ';

			memcpy(tmpbufp, namep, namelen+1); /* Plus the '\0' */
			tmpbufp += namelen;

			if (p < endp)
				p++;	/* Skip the added NULL */

		} while (p < endp);
	}

	if (names > 0) {
		fputs(tmpbuf, stdout);
		fputc('\n', stdout);
	} else {
		if (warning)
			fprintf(stderr,
			    "%s: Warning: no host names on line %d, "
			    "ignored\n", cmd, lineno);
	}
}
