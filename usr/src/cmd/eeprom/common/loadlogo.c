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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>

extern int _error(int do_perror, char *fmt, ...);
#define	NO_PERROR	0
#define	PERROR		1

/*
 * Icon loader for eeprom command.
 *
 * Based on libsuntool/icon/icon_load.c 10.10 88/02/08
 * See <suntool/icon_load.h> for icon file format.
 */

int
loadlogo(char *name, int w, int h, char *logo)
{
	FILE *f;
	int c = 0;
	unsigned int val;
	int icw = 64, ich = 64, bits = 16;
	int count;

	if (!(f = fopen(name, "r")))
		return (_error(PERROR, "cannot open %s", name));

	do {
		int nval;
		char slash;

		if ((c = fscanf(f, "%*[^DFHVW*]")) == EOF)
			break;

		switch (c = getc(f)) {
		case 'D':
			if ((c = fscanf(f, "epth=%d", &nval)) == 1 &&
			    nval != 1)
				goto badform;
			break;
		case 'F':
			if ((c = fscanf(f, "ormat_version=%d", &nval)) == 1 &&
			    nval != 1)
				goto badform;
			break;
		case 'H':
			c = fscanf(f, "eight=%d", &ich);
			break;
		case 'V':
			c = fscanf(f, "alid_bits_per_item=%d", &bits);
			break;
		case 'W':
			c = fscanf(f, "idth=%d", &icw);
			break;
		case '*':
			c = fscanf(f, "%c", &slash);
			if (slash == '/')
				goto eoh; /* end of header */
			else
				(void) ungetc(slash, f);
			break;
		}
	} while (c != EOF);

eoh:
	if (c == EOF ||
	    icw != w || ich != h ||
	    bits != 16 && bits != 32) {
badform:
		(void) fclose(f);
		return (_error(NO_PERROR, "header format error in %s", name));
	}

	for (count = ((w + (bits - 1)) / bits) * h; count > 0; count--) {
		c = fscanf(f, " 0x%x,", &val);
		if (c == 0 || c == EOF)
			break;

		switch (bits) {
		case 32:
			*logo++ = val >> 24;
			*logo++ = val >> 16;
			/* FALLTHRU */
		case 16:
			*logo++ = val >> 8;
			*logo++ = val;
			break;
		}
	}

	(void) fclose(f);

	if (count > 0)
		return (_error(NO_PERROR, "data format error in %s", name));

	return (0);
}
