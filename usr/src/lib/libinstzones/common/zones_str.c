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
 * Module:	zones_str.c
 * Group:	libinstzones
 * Description:	Private functions used by zones library functions to manipulate
 *		strings
 *
 * Public Methods:
 *
 * _z_strAddToken - Add a token to a string
 * _z_strContainsToken - Does a given string contain a specified substring
 * _z_strGetToken - Get a separator delimited token from a string
 * _z_strGetToken_r - Get separator delimited token from string to fixed buffer
 * _z_strPrintf - Create string from printf style format and arguments
 * _z_strPrintf_r - Create string from printf style format and arguments
 * _z_strRemoveLeadingWhitespace - Remove leading whitespace from string
 * _z_strRemoveToken - Remove a token from a string
 */

/*
 * System includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <limits.h>
#include <stropts.h>
#include <libintl.h>
#include <locale.h>
#include <assert.h>

/*
 * local includes
 */

#include "instzones_lib.h"
#include "zones_strings.h"

/*
 * Private structures
 */

/*
 * Library Function Prototypes
 */

/*
 * Local Function Prototypes
 */

/*
 * Global internal (private) declarations
 */

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	_z_strAddToken
 * Synopsis:	Add a token to a string
 * Description:	Append a token (sequence of one or more characters) to a
 *		string that is in allocated space - create new string if
 *		no string to append to exists
 * Arguments:	a_old - [RO, *RW] - (char **)
 *			- Pointer to handle to string to append token to
 *			  == NULL - new string is created
 *		a_new - [RO, *RO] - (char *)
 *			- Pointer to string representing token to append
 *			  to the end of the "a_old" string
 *			  == NULL - no action is performed
 *			  a_new[0] == '\0' - no action is performed
 *		a_separator - [RO, *RO] - (char)
 *			- One character placed between the old (existing)
 *			  string and the new token to be added IF the old
 *			  string exists and is not empty (zero length)
 * Returns:	void
 * CAUTION:	The old (existing) string must be allocated space (via lu_mem*
 *		or _z_str* methods) - it must not be a static or inline
 *		character string
 * NOTE:	The old (existing) string may be freed with 'free'
 *		if a token is appended to it
 * NOTE:    	Any string returned in 'a_old' is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the token string is no longer needed.
 */

void
_z_strAddToken(char **a_old, char *a_new, char a_separator)
{
	/* entry assertions */

	assert(a_old != NULL);
	assert(a_separator != '\0');

	/* if token to add is null or token is zero length, just return */

	if (a_new == NULL || *a_new == '\0') {
		return;
	}

	/* make sure that new token does not contain the separator */

	assert(strchr(a_new, (int)a_separator) == NULL);

	/* if old string is empty (zero length), deallocate */

	if ((*a_old != NULL) && ((*a_old)[0] == '\0')) {
		/* *a_old is set to NULL by free */
		free(*a_old);
		*a_old = NULL;
	}

	/* if old string exists, append separator and token */

	if (*a_old != NULL) {
		char *p;
		p = _z_strPrintf("%s%c%s", *a_old, a_separator, a_new);
		free(*a_old);
		*a_old = p;
		return;
	}

	/* old string does not exist - return duplicate of token */

	assert(*a_old == NULL);
	*a_old = _z_strdup(a_new);
}

/*
 * Name:	_z_strContainsToken
 * Synopsis:	Does a given string contain a specified substring
 * Description:	Determine if a given substring exists in a larger string
 * Arguments:	a_string - [RO, *RO] - (char *)
 *			Pointer to string to look for substring in
 *		a_token - [RO, *RO] - (char *)
 *			Pointer to substring to look for in larger string
 * Results:	boolean_t
 *			B_TRUE - substring exists in larger string
 *			B_FALSE - substring does NOT exist in larger string
 * NOTE:	The substring must match on a "token" basis; that is, the
 *		substring must exist in the larger string delineated with
 *		either spaces or tabs to match.
 */

boolean_t
_z_strContainsToken(char *a_string, char *a_token, char *a_separators)
{
	char	*lasts;
	char	*current;
	char	*p;

	/* entry assertions */

	assert(a_separators != NULL);
	assert(*a_separators != '\0');

	/*
	 * if token is not supplied, no string provided,
	 * or the string is an empty string, return false
	 */

	if (a_token == NULL || a_string == NULL || *a_string == '\0') {
		return (B_FALSE);
	}

	/* if no string provided, return false */

	/* if string empty (zero length), return false */

	/* duplicate larger string because strtok_r changes it */

	p = _z_strdup(a_string);

	lasts = p;

	/* scan each token looking for a match */

	while ((current = strtok_r(NULL, a_separators, &lasts)) !=
	    NULL) {
		if (strcmp(current, a_token) == 0) {
			free(p);
			return (B_TRUE);
		}
	}

	/* free up temporary storage */

	free(p);

	/* not found */

	return (B_FALSE);
}

/*
 * Name:	_z_strGetToken
 * Synopsis:	Get a separator delimited token from a string
 * Description:	Given a string and a list of one or more separators,
 *		return the position specified token (sequence of one or
 *		more characters that do not include any of the separators)
 * Arguments:	r_sep - [*RW] - (char *)
 *			- separator that ended the token returned
 *			- NOTE: this is a pointer to a "char", e.g.:
 *				- char a;
 *				- _z_strGetToken(&a, ...)
 *		a_string - [RO, *RO] - (char *)
 *			- pointer to string to extract token from
 *		a_index - [RO, *RO] - (int)
 *			- Index of token to return; '0' is first matching
 *			  token, '1' is second matching token, etc.
 *		a_separators - [RO, *RO] - (char *)
 *			- String containing one or more characters that
 *			  can separate one "token" from another
 * Returns:	char *
 *			== NULL - no token matching criteria found
 *			!= NULL - token matching criteria
 * NOTE:    	Any token string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the token string is no longer needed.
 */

char *
_z_strGetToken(char *r_sep, char *a_string, int a_index, char *a_separators)
{
	char	*p;
	char	*q;
	char	*lasts;

	/* entry assertions */

	assert(a_string != NULL);
	assert(a_index >= 0);
	assert(a_separators != NULL);
	assert(*a_separators != '\0');

	/* if returned separator requested, reset to null until token found */

	if (r_sep != NULL) {
		*r_sep = '\0';
	}

	/* duplicate original string before breaking down into tokens */

	p = _z_strdup(a_string);

	lasts = p;

	/* scan for separators and return 'index'th token found */

	while (q = strtok_r(NULL, a_separators, &lasts)) {
		/* retrieve separator if requested */

		if (r_sep != NULL) {
			char	*x;

			x = strpbrk(a_string, a_separators);
			if (x != NULL) {
				*r_sep = *x;
			}
		}

		/* if this is the 'index'th token requested return it */

		if (a_index-- == 0) {
			char	*tmp;

			/* duplicate token into its own storage */

			tmp = _z_strdup(q);

			/* free up copy of original input string */

			free(p);

			/* return token found */

			return (tmp);
		}
	}

	/*
	 * token not found
	 */

	/* free up copy of original input string */

	free(p);

	/* return NULL pointer (token not found) */

	return (NULL);
}

/*
 * Name:	_z_strGetToken_r
 * Synopsis:	Get separator delimited token from a string into a fixed buffer
 * Description:	Given a string and a list of one or more separators,
 *		return the position specified token (sequence of one or
 *		more characters that do not include any of the separators)
 *		into a specified buffer of a fixed maximum size
 * Arguments:	r_sep - [*RW] - (char *)
 *			- separator that ended the token returned
 *			- NOTE: this is a pointer to a "char", e.g.:
 *				- char a;
 *				- _z_strGetToken(&a, ...)
 *		a_string - [RO, *RO] - (char *)
 *			- pointer to string to extract token from
 *		a_index - [RO, *RO] - (int)
 *			- Index of token to return; '0' is first matching
 *			  token, '1' is second matching token, etc.
 *		a_separators - [RO, *RO] - (char *)
 *			- String containing one or more characters that
 *			  can separate one "token" from another
 *		a_buf - [RO, *RW] - (char *)
 *			- Pointer to buffer used as storage space for the
 *			  returned token - the returned token is always
 *			  null terminated
 *			  a_buf[0] == '\0' - no token meeting criteria found
 *			  a_buf[0] != '\0' - token meeting criteria returned
 *		a_bufLen - [RO, *RO] - (int)
 *			- Size of 'a_buf' in bytes - a maximum of 'a_bufLen-1'
 *			  bytes will be placed in 'a_buf' - the returned
 *			  token is always null terminated
 * Returns:	void
 */

void
_z_strGetToken_r(char *r_sep, char *a_string, int a_index,
    char *a_separators, char *a_buf, int a_bufLen)
{
	char	*p;
	char	*q;
	char	*lasts;

	/* entry assertions */

	assert(a_string != NULL);
	assert(a_index >= 0);
	assert(a_separators != NULL);
	assert(*a_separators != '\0');
	assert(a_buf != NULL);
	assert(a_bufLen > 0);

	/* reset returned separator */

	if (r_sep != NULL) {
		*r_sep = '\0';
	}

	/* zero out contents of return buffer */

	bzero(a_buf, a_bufLen);

	/* duplicate original string before breaking down into tokens */

	p = _z_strdup(a_string);

	lasts = p;

	/* scan for separators and return 'index'th token found */

	while (q = strtok_r(NULL, a_separators, &lasts)) {
		/* retrieve separator if requested */

		if (r_sep != NULL) {
			char	*x;
			x = strpbrk(a_string, a_separators);
			if (x != NULL) {
				*r_sep = *x;
			}
		}

		/* if this is the 'index'th token requested return it */

		if (a_index-- == 0) {
			/* copy as many characters as possible to return buf */

			(void) strncpy(a_buf, q, a_bufLen-1);
			break;
		}
	}

	/* free up copy of original input string */

	free(p);
}

/*
 * Name:	_z_strPrintf
 * Synopsis:	Create string from printf style format and arguments
 * Description:	Call to convert a printf style format and arguments into a
 *		string of characters placed in allocated storage
 * Arguments:	format - [RO, RO*] (char *)
 *			printf-style format for string to be formatted
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	char *
 *			A string representing the printf conversion results
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * Errors:	If the string cannot be created, the process exits
 */

/*PRINTFLIKE1*/
char *
_z_strPrintf(char *a_format, ...)
{
	va_list		ap;
	size_t		vres = 0;
	char		bfr[1];
	char		*rstr = NULL;

	/* entry assertions */

	assert(a_format != NULL);
	assert(*a_format != '\0');

	/* determine size of the message in bytes */

	va_start(ap, a_format);
	vres = vsnprintf(bfr, 1, a_format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(vres < LINE_MAX);

	/* allocate storage to hold the message */

	rstr = (char *)_z_calloc(vres+2);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	vres = vsnprintf(rstr, vres+1, a_format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(vres < LINE_MAX);
	assert(*rstr != '\0');

	/* return the results */

	return (rstr);
}

/*
 * Name:	_z_strPrintf_r
 * Synopsis:	Create string from printf style format and arguments
 * Description:	Call to convert a printf style format and arguments into a
 *		string of characters placed in allocated storage
 * Arguments:	a_buf - [RO, *RW] - (char *)
 *			- Pointer to buffer used as storage space for the
 *			  returned string created
 *		a_bufLen - [RO, *RO] - (int)
 *			- Size of 'a_buf' in bytes - a maximum of 'a_bufLen-1'
 *			  bytes will be placed in 'a_buf' - the returned
 *			  string is always null terminated
 *		a_format - [RO, RO*] (char *)
 *			printf-style format for string to be formatted
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 */

/*PRINTFLIKE3*/
void
_z_strPrintf_r(char *a_buf, int a_bufLen, char *a_format, ...)
{
	va_list		ap;
	size_t		vres = 0;

	/* entry assertions */

	assert(a_format != NULL);
	assert(*a_format != '\0');
	assert(a_buf != NULL);
	assert(a_bufLen > 1);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	vres = vsnprintf(a_buf, a_bufLen-1, a_format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(vres < a_bufLen);

	a_buf[a_bufLen-1] = '\0';
}

/*
 * Name:	_z_strRemoveLeadingWhitespace
 * Synopsis:	Remove leading whitespace from string
 * Description:	Remove all leading whitespace characters from a string
 * Arguments:	a_str - [RO, *RW] - (char **)
 *			Pointer to handle to string (in allocated storage) to
 *			remove all leading whitespace from
 * Returns:	void
 *			The input string is modified as follows:
 *			== NULL:
 *				- input string was NULL
 *				- input string is all whitespace
 *			!= NULL:
 *				- copy of input string with leading
 *				  whitespace removed
 * CAUTION:	The input string must be allocated space (via mem* or
 *		_z_str* methods) - it must not be a static or inline
 *		character string
 * NOTE:	The input string a_str will be freed with 'free'
 *		if it is all whitespace, or if it contains any leading
 *		whitespace characters
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * Errors:	If the string cannot be created, the process exits
 */

void
_z_strRemoveLeadingWhitespace(char **a_str)
{
	char	*o_str;

	/* entry assertions */

	assert(a_str != NULL);

	/* if string is null, just return */

	if (*a_str == NULL) {
		return;
	}
	o_str = *a_str;

	/* if string is empty, deallocate and return NULL */

	if (*o_str == '\0') {
		/* free string - handle is not reset to NULL by free */
		free(*a_str);
		*a_str = NULL;
		return;
	}

	/* if first character is not a space, just return */

	if (!isspace(*o_str)) {
		return;
	}

	/* advance past all space characters */

	while ((*o_str != '\0') && (isspace(*o_str))) {
		o_str++;
	}

	/* if string was all space characters, deallocate and return NULL */

	if (*o_str == '\0') {
		/* free string - *a_str is not reset to NULL by free */
		free(*a_str);
		*a_str = NULL;
		return;
	}

	/* have non-space/null byte, return dup, deallocate original */

	free(*a_str);
	*a_str = _z_strdup(o_str);
}

/*
 * Name:	_z_strRemoveToken
 * Synopsis:	Remove a token from a string
 * Description:	Remove a token (sequence of one or more characters) from a
 *		string that is in allocated space
 * Arguments:	r_string - [RO, *RW] - (char **)
 *			- Pointer to handle to string to remove token from
 *		a_token - [RO, *RO] - (char *)
 *			Pointer to token (substring) to look for and remove
 *			from r_string provided
 *		a_separators - [RO, *RO] - (char *)
 *			- String containing one or more characters that
 *			  separate one "token" from another in r_string
 *		a_index - [RO, *RO] - (int)
 *			- Index of token to remove; '0' is first matching
 *			  token, '1' is second matching token, etc.
 * Returns:	void
 * CAUTION:	The input string must be allocated space (via lu_mem* or
 *		_z_str* methods) - it must not be a static or inline
 *		character string
 * NOTE:	The input string r_string will be freed with 'free'
 *		if the token to be removed is found
 * NOTE:    	Any token string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the token string is no longer needed.
 * Errors:	If the new token string cannot be created, the process exits
 */

void
_z_strRemoveToken(char **r_string, char *a_token, char *a_separators,
	int a_index)
{
	char	*a_string;
	char	*copyString;
	char	sep = 0;
	int	copyLength;
	int	i;

	/* entry assertions */

	assert(r_string != NULL);
	assert(a_token != NULL);
	assert(*a_token != '\0');
	assert(a_separators != NULL);
	assert(*a_separators != '\0');

	/* simple case: input string is null; return empty string */

	a_string = *r_string;
	if (*a_string == '\0') {
		return;
	}

	/* simple case: token == input string; return empty string */

	if (strcmp(a_string, a_token) == 0) {
		/*
		 * deallocate input string; free doesn't
		 * set *r_string to NULL
		 */
		free(*r_string);
		*r_string = NULL;
		return;
	}

	/* simple case: token not in input string: return */

	if (!_z_strContainsToken(a_string, a_token, a_separators)) {
		return;
	}

	/*
	 * Pick apart the old string building the new one as we go along
	 * removing the first occurance of the token provided
	 */

	copyLength = (strlen(a_string)-strlen(a_token))+2;
	copyString = (char *)_z_calloc(copyLength);

	for (i = 0; ; i++) {
		char	*p;

		p = _z_strGetToken(&sep, a_string, i, a_separators);
		if (p == NULL) {
			break;
		}

		if ((strcmp(p, a_token) == 0) && (a_index-- == 0)) {
			free(p);
			continue;
		}

		if (*copyString) {
			assert(sep != '\0');
			(void) strncat(copyString, &sep, 1);
		}

		(void) strcat(copyString, p);
		free(p);
	}

	free(*r_string);
	assert(*copyString);
	*r_string = copyString;
}
