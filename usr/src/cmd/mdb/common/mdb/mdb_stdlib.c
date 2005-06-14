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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_stdlib.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>

#include <sys/types.h>
#include <floatingpoint.h>
#include <poll.h>

/*
 * Post-processing routine for econvert and qeconvert.  This function is
 * called by both doubletos() and longdoubletos() below.
 */
static const char *
fptos(const char *p, char *buf, size_t buflen, int decpt, int sign, char expchr)
{
	char *q = buf;

	*q++ = sign ? '-' : '+';

	/*
	 * If the initial character is not a digit, the result is a special
	 * identifier such as "NaN" or "Inf"; just copy it verbatim.
	 */
	if (*p < '0' || *p > '9') {
		(void) strncpy(q, p, buflen);
		buf[buflen - 1] = '\0';
		return (buf);
	}

	*q++ = *p++;
	*q++ = '.';

	(void) strcpy(q, p);
	q += strlen(q);
	*q++ = expchr;

	if (--decpt < 0) {
		decpt = -decpt;
		*q++ = '-';
	} else
		*q++ = '+';

	if (decpt < 10)
		*q++ = '0';

	(void) strcpy(q, numtostr((uint_t)decpt, 10, 0));
	return (buf);
}

/*
 * Convert the specified double to a string, and return a pointer to a static
 * buffer containing the string value.  The double is converted using the
 * same formatting conventions as sprintf(buf, "%+.*e", precision, d).  The
 * expchr parameter specifies the character used to denote the exponent,
 * and is usually 'e' or 'E'.
 */
const char *
doubletos(double d, int precision, char expchr)
{
	static char buf[DECIMAL_STRING_LENGTH];
	char digits[DECIMAL_STRING_LENGTH];
	int decpt, sign;
	char *p;

	p = econvert(d, precision + 1, &decpt, &sign, digits);
	return (fptos(p, buf, sizeof (buf), decpt, sign, expchr));
}

/*
 * Same as doubletos(), but for long doubles (quad precision floating point).
 */
const char *
longdoubletos(long double *ldp, int precision, char expchr)
{
	static char buf[DECIMAL_STRING_LENGTH];
	char digits[DECIMAL_STRING_LENGTH];
	int decpt, sign;
	char *p;

	p = qeconvert(ldp, precision + 1, &decpt, &sign, digits);
	return (fptos(p, buf, sizeof (buf), decpt, sign, expchr));
}
