/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Tom Lane <tgl@sss.pgh.pa.us>
 * Copyright 2017 Nexenta Systems, Inc.
 */

#include <err.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * #6907: generate random UTF8 strings, strxfrm'ing them in process.
 * Walk through comparing each string with all strings, and checking
 * that strcoll() and strcmp() for strxfrm'ed data produce same results.
 */
#define	NSTRINGS 2000
#define	MAXSTRLEN 20
#define	MAXXFRMLEN (MAXSTRLEN * 20)

typedef struct {
	char	sval[MAXSTRLEN];
	char	xval[MAXXFRMLEN];
} cstr;

int
main(void)
{
	cstr	data[NSTRINGS];
	char	*curloc;
	int	i, j;

	if ((curloc = setlocale(LC_ALL, "")) == NULL)
		err(1, "setlocale");

	/* Ensure new random() values on every run */
	srandom((unsigned int) time(NULL));

	/* Generate random UTF8 strings of length less than MAXSTRLEN bytes */
	for (i = 0; i < NSTRINGS; i++) {
		char	*p;
		int	len;

again:
		p = data[i].sval;
		len = 1 + (random() % (MAXSTRLEN - 1));
		while (len > 0) {
			int c;

			/*
			 * Generate random printable char in ISO8859-1 range.
			 * Bias towards producing a lot of spaces.
			 */
			if ((random() % 16) < 3) {
				c = ' ';
			} else {
				do {
					c = random() & 0xFF;
				} while (!((c >= ' ' && c <= 127) ||
				    (c >= 0xA0 && c <= 0xFF)));
			}

			if (c <= 127) {
				*p++ = c;
				len--;
			} else {
				if (len < 2)
					break;
				/* Poor man's utf8-ification */
				*p++ = 0xC0 + (c >> 6);
				len--;
				*p++ = 0x80 + (c & 0x3F);
				len--;
			}
		}
		*p = '\0';

		/* strxfrm() each string as we produce it */
		errno = 0;
		if (strxfrm(data[i].xval, data[i].sval,
		    MAXXFRMLEN) >= MAXXFRMLEN) {
			errx(1, "strxfrm() result for %d-length string "
			    "exceeded %d bytes", (int)strlen(data[i].sval),
			    MAXXFRMLEN);
		}
		/* Amend strxfrm() failing for certain characters (#7962) */
		if (errno != 0)
			goto again;
	}

	for (i = 0; i < NSTRINGS; i++) {
		for (j = 0; j < NSTRINGS; j++) {
			int sr = strcoll(data[i].sval, data[j].sval);
			int sx = strcmp(data[i].xval, data[j].xval);

			if ((sr * sx < 0) || (sr * sx == 0 && sr + sx != 0)) {
				errx(1, "%s: diff for \"%s\" and \"%s\"",
				    curloc, data[i].sval, data[j].sval);
			}
		}
	}

	return (0);
}
