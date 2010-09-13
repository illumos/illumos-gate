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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * General purpse string manipulation routines
 */

#include	<stdio.h>
#include	<_conv.h>


/*
 * Implementation of isspace() that does not require <ctype.h>
 * or <sys/ctype.h>, appropriate for simple non-localized use.
 */
int
conv_strproc_isspace(int c)
{
	return ((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n'));
}

/*
 * Remove leading and trailing whitespace from the given string.
 *
 * entry:
 *	str - String to be trimmed
 *
 * exit:
 *	The pointer to the trimmed string is returned.
 *
 * note:
 *	Leading whitespace is trimmed by advancing the given str pointer,
 *	and not by making a copy or allocing more memory. Hence, the caller
 *	should retain a copy of the original str pointer if they need to
 *	free the original memory or otherwise access it.
 *
 *	Trailing whitespace is trimmed by inserting a NULL termination
 *	in the position at which the first trailing whitespce character
 *	lies. This routine can therefore modify the memory used by
 *	the input string.
 */
char *
conv_strproc_trim(char *str)
{
	char	*tail;

	/* Skip leading whitespace */
	while (conv_strproc_isspace(*str))
		str++;

	/* Back up over trailing whitespace */
	tail = str + strlen(str);
	while ((tail > str) && conv_strproc_isspace(*(tail - 1)))
		tail--;
	*tail = '\0';

	return (str);
}

/*
 * Given a debug token of the form:
 *
 *	token=value
 *
 * extract and return a pointer to the value.
 *
 * entry:
 *	str - String to process
 *	token_len = Length of the token, not counting the '=' character,
 *		or any whitespace between the token and the '='.
 *	to_upper - True to convert the returned value to upper case.
 *	value - Address of pointer to receive the value string.
 *
 * exit:
 *	On success, *value is updated to point at the value string,
 *	and True (1) is returned. On failure, False (0) is returned.
 *
 * note:
 *	If CONV_SPEXV_F_UCASE is specified, this routine modifies
 *	the memory pointed at by str.
 */
Boolean
conv_strproc_extract_value(char *str, size_t token_len, int flags,
    const char **value)
{
	int	trim = (flags & CONV_SPEXV_F_NOTRIM) == 0;

	/* Skip the token */
	str += token_len;

	/*
	 * If TRIM, skip whitespace between token and '='
	 */
	if (trim)
		while (conv_strproc_isspace(*str))
			str++;

	/* If there's not a '=' here, this isn't the token we thought it was */
	if (*str != '=')
		return (FALSE);

	str++;			/* skip the '=' */

	/* if TRIM, skip whitespace following the '=' */
	if (trim)
		while (conv_strproc_isspace(*str))
			str++;

	/* Null value and it's not OK? Make it an error. */
	if (((flags & CONV_SPEXV_F_NULLOK) == 0) && (*str == '\0'))
		return (FALSE);

	*value = str;

	/* Convert to uppercase on request */
	if (flags & CONV_SPEXV_F_UCASE)
		for (; *str; str++)
			if ((*str >= 'a') && (*str <= 'z'))
				*str = *str - ('a' - 'A');

	return (TRUE);
}
