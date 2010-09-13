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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <wchar.h>

#include <utils.h>

static const char PNAME_FMT[] = "%s: ";
static const char ERRNO_FMT[] = ": %s\n";

static const char *pname;

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	int err = errno;
	va_list alist;

	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERRNO_FMT), strerror(err));
}

/*PRINTFLIKE1*/
void
die(const char *format, ...)
{
	int err = errno;
	va_list alist;

	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERRNO_FMT), strerror(err));

	exit(E_ERROR);
}

const char *
getpname(const char *arg0)
{
	const char *p = strrchr(arg0, '/');

	if (p == NULL)
		p = arg0;
	else
		p++;

	pname = p;
	return (p);
}

void *
safe_malloc(size_t size)
{
	void *a;

	if ((a = malloc(size)) == NULL)
		die(gettext("out of memory\n"));

	return (a);
}

/*
 * getdefault() reads from one of the /etc/default files. It takes
 * input of the filename, a variable name to search for, and a
 * prefix to prepend to the result.
 *
 * The file and varname arguments are required. The varname argument
 * must be of the form "VAR=". If the prefix argument
 * is non-null, it will be prepended to the returned string.
 * Double and single quotes are stripped from the result.
 *
 * getdefault() returns NULL if the file cannot be opened, or the
 * variable cannot be found.
 */
char *
getdefault(char *file, char *varname, char *prefix)
{
	FILE *fp;
	char cp[PATH_MAX];
	char *tmp_cp, *ret_str = NULL;
	size_t varlen;

	if ((fp = fopen(file, "r")) == NULL)
		return (ret_str);
	varlen = strlen(varname);
	while (fgets(cp, PATH_MAX, fp) != NULL) {
		size_t len;

		if (cp[0] == '#' || cp[0] == '\n')
			continue;
		len = strlen(cp);
		if (cp[len - 1] == '\n') {
			len--;
			cp[len] = '\0';
		}
		/* Find line containing varname */
		if (strncmp(varname, cp, varlen) == 0) {
			char *cp2, *strip_ptr = NULL;
			size_t tlen;
			int inquotes = 0;

			cp2 = tmp_cp = cp + varlen;
			/*
			 * Remove extra characters after any space,
			 * tab, or unquoted semicolon, and strip quotes.
			 */
			while ((*cp2 != '\0') &&
			    (*cp2 != ' ') && (*cp2 != '\t') &&
			    !((*cp2 == ';') && (inquotes == 0))) {
				if (*cp2 == '\"' || *cp2 == '\'') {
					if (*cp2 == '\"') {
						inquotes =
						    inquotes == 0 ? 1 : 0;
					}
					if (strip_ptr == NULL) {
						strip_ptr = cp2;
					}
				} else {
					if (strip_ptr != NULL) {
						*strip_ptr++ = *cp2;
					}
				}
				cp2++;
			}
			if (strip_ptr != NULL) {
				*strip_ptr = '\0';
			}
			len = cp2 - tmp_cp;
			if (prefix) {
				tlen = len + strlen(prefix) + 1;
				ret_str = safe_malloc(tlen);
				(void) snprintf(ret_str, tlen, "%s%s",
				    prefix, tmp_cp);
			} else {
				tlen = len + 1;
				ret_str = safe_malloc(tlen);
				(void) snprintf(ret_str, tlen, "%s", tmp_cp);
			}
			break;
		}
	}
	(void) fclose(fp);
	return (ret_str);
}
