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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mms_strapp.h"

#define	MMS_ESCAPE_PAR_NUM 5
#define	MMS_ESCAPE_DB_NUM 2

typedef struct mms_escape mms_escape_t;
struct mms_escape {
	char		ch;
	char		*sequence;
};

static mms_escape_t mms_escape_par[MMS_ESCAPE_PAR_NUM] = {
	{ '\'', "&apos;" },
	{ '"', "&quot;" },
	{ '>', "&gt;" },
	{ '<', "&lt;" },
	{ '&', "&amp;" }
};

static char *
mms_str_escape_sequence(char *string, mms_escape_t *mms_escape, int escape_num);

/*
 * mms_strpar_escape_sequence(string)
 *
 * Convert plain text to xml parser mms_escape sequence.
 */
char *
mms_strpar_escape_sequence(char *string)
{
	return (mms_str_escape_sequence(string, mms_escape_par,
	    MMS_ESCAPE_PAR_NUM));
}

char *
mms_strpar_undo_escape_sequence(char *string)
{
	int	len;
	char	*p;
	int	i;
	char	*buf;

	if (string == NULL) {
		return (NULL);
	}
	if ((buf = strdup(string)) == NULL) {
		return (NULL);
	}
	for (i = 0; i < MMS_ESCAPE_PAR_NUM; i++) {
		p = buf;
		len = strlen(mms_escape_par[i].sequence) - 1;
		while (p = strstr(p, mms_escape_par[i].sequence)) {
			*p = mms_escape_par[i].ch;
			p++;
			(void) memmove(p, p + len, strlen(p + len) + 1);
		}
	}
	return (buf);
}

/*
 * mms_str_escape_sequence(string)
 *
 * Convert plain text to mms_escape sequence.
 */
static char *
mms_str_escape_sequence(char *string, mms_escape_t *mms_escape, int escape_num)
{
	int		 i;
	int		 j;
	int		 k;
	int		 m;
	int		 len;
	char		*nstr;
	int		 sub;

	if (!string) {
		return (NULL);
	}
	for (i = 0, len = 0; string[i] != '\0'; i++) {
		for (j = 0; j < escape_num; j++) {
			if (string[i] == mms_escape[j].ch) {
				len += strlen(mms_escape[j].sequence);
			}
		}
	}

	if ((nstr = (char *)malloc(strlen(string) + len + 1)) == NULL) {
		return (NULL);
	}
	for (i = 0, m = 0; string[i] != '\0'; i++) {
		for (j = 0, sub = 0; !sub && j < escape_num; j++) {
			if (string[i] == mms_escape[j].ch) {
				len = strlen(mms_escape[j].sequence);
				for (k = 0; k < len; k++) {
					nstr[m++] = mms_escape[j].sequence[k];
				}
				sub = 1;
			}
		}
		if (!sub) {
			nstr[m++] = string[i];
		}
	}
	nstr[m] = '\0';
	return (nstr);
}

/*
 * mms_strnew(fmt, ...)
 *
 * Create a new string with variable number of arguments.
 */
char *
mms_strnew(const char *fmt, ...)
{
	va_list		 args;
	char		*ptr;

	if (fmt == NULL) {
		return (NULL);
	}
	va_start(args, fmt);

	ptr = mms_vstrapp(NULL, fmt, args);

	va_end(args);

	return (ptr);
}

/*
 * mms_strapp(str, fmt, ...)
 *
 * Append string with variable number of arguments.
 */
char *
mms_strapp(char *str, const char *fmt, ...)
{
	va_list		 args;
	char		*ptr;

	if (fmt == NULL) {
		return (NULL);
	}
	va_start(args, fmt);

	ptr = mms_vstrapp(str, fmt, args);

	va_end(args);

	return (ptr);
}

/*
 * mms_vstrapp(str, fmt, args)
 *
 * Append string with variable argument list.
 *
 * Typical usage example,
 *	a = strdup("start of ");
 *	a = strapp(a, "larger string");
 *
 * On error, str is freed.
 */
char *
mms_vstrapp(char *str, const char *fmt, va_list args)
{
	int		 count;
	int		 offset;
	char		*ptr;

	if (fmt == NULL) {
		if (str != NULL)
			free(str);
		return (NULL);
	}
	if ((count = vsnprintf(NULL, 0, fmt, args)) < 0) {
		if (str != NULL)
			free(str);
		return (NULL);
	}
	if (str == NULL) {
		if ((ptr = (char *)malloc(count + 1)) == NULL) {
			return (NULL);
		}
		ptr[0] = '\0';
		offset = 0;
	} else {
		offset = strlen(str);
		if ((ptr = (char *)realloc(str, offset +
		    count + 1)) == NULL) {
			free(str);
			return (NULL);
		}
	}

	if (vsprintf(ptr + offset, fmt, args) < 0) {
		free(ptr);
		return (NULL);
	}
	return (ptr);
}

/*
 *
 * mms_strnapp(char *str, int n, char *str2)
 *
 * Parameters:
 *	str	pointer to the string being appended to
 *		If str is not NULL, then it must point to a string which
 *		may be freed by free() or realloc().
 *	n	number of characters to append
 *	str2	a string of any length to append to str.
 *
 * Return a new string with at most n characters from str2 appended to str.
 *
 * Return Values:
 *	Address of new string.
 *
 * Note: new string must be freed by caller.
 *
 */

char *
mms_strnapp(char *str, int n, char *str2)
{
	char		fmt[64];
	int		len;
	char		*rc;

	if (n == 0) {
		return (str);
	}

	/* Construct format to get n chars */
	len = snprintf(fmt, sizeof (fmt), "%%.%ds", n);
	if (len < 0 || len >= sizeof (fmt)) {
		/* not enough space */
		return (NULL);
	}
	rc = mms_strapp(str, (const char *)fmt, str2);
	return (rc);
}
