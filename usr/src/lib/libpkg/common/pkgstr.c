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
 * Copyright 2009 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Module:	pkgstr.c
 * Synopsis:	general string services
 * Taxonomy:	project private
 * Debug Flag:	str
 * Description:
 *
 *   This module implements general string utility services
 *
 * Public Methods:
 *
 *   pkgstrAddToken - Add a token to a string
 *   pkgstrContainsToken - Determine if a string contains a specified token
 *   pkgstrConvertPathToBasename - Return copy of base name in path string
 *   pkgstrConvertPathToDirname - Return copy of directory name in path string
 *   pkgstrConvertUllToTimeString_r - convert unsigned long long to time string
 *   pkgstrExpandTokens - Expand tokens from string appending tokens to another
 *   pkgstrGetToken - Get a token from a string
 *   pkgstrGetToken_r - Get a token from a string into a fixed buffer
 *   pkgstrLocatePathBasename - Locate position of base name in path string
 *   pkgstrNumTokens - Determine number of tokens in string
 *   pkgstrPrintf - Create a string from a printf style format and arguments
 *   pkgstrPrintf_r - Create a string from a printf style format and arguments
 *			into a fixed buffer
 *   pkgstrRemoveToken - Remove a token from a string
 *   pkgstrRemoveLeadingWhitespace - remove leading whitespace from string
 *   pkgstrScaleNumericString - Convert unsigned long long to human
 *	readable form
 */

/*
 * Unix Includes
 */

#define	__EXTENSIONS__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <limits.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <ctype.h>
#include <unistd.h>
#include <strings.h>
#include <stdarg.h>

/*
 * pkglib Includes
 */

#include "pkglib.h"
#include "pkgstrct.h"
#include "libintl.h"
#include "pkglocale.h"

/*
 * External definitions
 */

/*
 * Public methods
 */

/*
 * Name:	pkgstrRemoveLeadingWhitespace
 * Synopsis:	Remove leading whitespace from string
 * Description:	Remove all leading whitespace characters from a string
 * Arguments:	a_str - [RO, *RW] - (char **)
 *			Pointer to handle to string (in allocated storage) to
 *			remove all leading whitespace from
 * Returns:	void
 *			The input string is modified as follows:
 *			== (char *)NULL:
 *				- input string was (char *)NULL
 *				- input string is all whitespace
 *			!= (char *)NULL:
 *				- copy of input string with leading
 *				  whitespace removed
 * CAUTION:	The input string must be allocated space (via mem* or
 *		pkgstr* methods) - it must not be a static or inline
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
pkgstrRemoveLeadingWhitespace(char **a_str)
{
	char	*o_str;

	/* entry assertions */

	assert(a_str != (char **)NULL);

	/* if string is null, just return */

	if (*a_str == (char *)NULL) {
		return;
	}
	o_str = *a_str;

	/* if string is empty, deallocate and return NULL */

	if (*o_str == '\0') {
		/* free string - handle is reset to NULL by free */
		free(*a_str);
		*a_str = (char *)NULL;
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
		/* free string - *a_str is reset to NULL by free */
		free(*a_str);
		*a_str = (char *)NULL;
		return;
	}

	/* have non-space/null byte, return dup, deallocate original */

	o_str = strdup(o_str);
	assert(o_str != (char *)NULL);
	if (o_str != (char *)NULL) {
		free(*a_str);
		*a_str = o_str;
	}
}

unsigned long
pkgstrNumTokens(char *a_string, char *a_separators)
{
	int	index;

	if (a_string == (char *)NULL) {
		return (0);
	}

	if (*a_string == '\0') {
		return (0);
	}

	for (index = 0 ; ; index ++) {
		char *p;

		p = pkgstrGetToken((char *)NULL, a_string, index, a_separators);
		if (p == (char *)NULL) {
			return (index);
		}
		free(p);
	}
}

/*
 * Name:	pkgstrPrintf_r
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
pkgstrPrintf_r(char *a_buf, int a_bufLen, char *a_format, ...)
{
	va_list		ap;
	size_t		vres = 0;

	/* entry assertions */

	assert(a_format != (char *)NULL);
	assert(*a_format != '\0');
	assert(a_buf != (char *)NULL);
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
 * Name:	pkgstrPrintf
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
pkgstrPrintf(char *a_format, ...)
{
	va_list		ap;
	size_t		vres = 0;
	char		bfr[1];
	char		*rstr = (char *)NULL;

	/* entry assertions */

	assert(a_format != (char *)NULL);
	assert(*a_format != '\0');

	/* determine size of the message in bytes */

	va_start(ap, a_format);
	vres = vsnprintf(bfr, 1, a_format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(vres < LINE_MAX);

	/* allocate storage to hold the message */

	rstr = (char *)calloc(1, vres+2);
	assert(rstr != (char *)NULL);
	if (rstr == (char *)NULL) {
		return ((char *)NULL);
	}

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
 * Name:	pkgstrExpandTokens
 * Synopsis:	Expand tokens from string appending tokens to another
 * Description:	Given a string and a list of one or more separators,
 *		expand each token from the string and append those tokens
 *		to a string that is in allocated space - create new string
 *		if no string to append to exists.
 * Arguments:	a_old - [RO, *RW] - (char **)
 *			- Pointer to handle to string to append token to
 *			  == (char *)NULL - new string is created
 *		a_separator - [RO, *RO] - (char *)
 *			- separator to end tokens returned
 *		a_separators - [RO, *RO] - (char *)
 *			- String containing one or more characters that
 *			  can separate one "token" from a_string from another
 * Returns:	void
 * NOTE:    	Any token string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the token string is no longer needed.
 */

void
pkgstrExpandTokens(char **a_old, char *a_string, char a_separator,
	char *a_separators)
{
	int		i;
	char		sep[2] = {'\0', '\0'};

	/* convert single separator character into character string */

	sep[0] = a_separator;

	/*
	 * iterate extracting tokens from the source string and adding
	 * those tokens to the target string when the tokens are not
	 * already present in the target string
	 */

	for (i = 0; ; i++) {
		char	*p;

		/* extract the next matching token from the source string */

		p = pkgstrGetToken((char *)NULL, a_string, i, a_separators);

		/* return if no token is available */

		if (p == (char *)NULL) {
			return;
		}

		/*
		 * obtained token from source string: if the token is not
		 * in the target string, add the token to the target string
		 */

		if (pkgstrContainsToken(*a_old, p, sep) == B_FALSE) {
			pkgstrAddToken(a_old, p, *sep);
		}

		/* free up temporary storage used by token from source string */

		free(p);
	}
	/*NOTREACHED*/
}


/*
 * Name:	pkgstrGetToken
 * Synopsis:	Get a separator delimited token from a string
 * Description:	Given a string and a list of one or more separators,
 *		return the position specified token (sequence of one or
 *		more characters that do not include any of the separators)
 * Arguments:	r_sep - [*RW] - (char *)
 *			- separator that ended the token returned
 *			- NOTE: this is a pointer to a "char", e.g.:
 *				- char a;
 *				- pkgstrGetToken(&a, ...)
 *		a_string - [RO, *RO] - (char *)
 *			- pointer to string to extract token from
 *		a_index - [RO, *RO] - (int)
 *			- Index of token to return; '0' is first matching
 *			  token, '1' is second matching token, etc.
 *		a_separators - [RO, *RO] - (char *)
 *			- String containing one or more characters that
 *			  can separate one "token" from another
 * Returns:	char *
 *			== (char *)NULL - no token matching criteria found
 *			!= (char *)NULL - token matching criteria
 * NOTE:    	Any token string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the token string is no longer needed.
 */

char *
pkgstrGetToken(char *r_sep, char *a_string, int a_index, char *a_separators)
{
	char	*p;
	char	*q;
	char	*lasts;

	/* entry assertions */

	assert(a_string != (char *)NULL);
	assert(a_index >= 0);
	assert(a_separators != (char *)NULL);
	assert(*a_separators != '\0');

	/* if returned separator requested, reset to null until token found */

	if (r_sep != (char *)NULL) {
		*r_sep = '\0';
	}

	/* duplicate original string before breaking down into tokens */

	p = strdup(a_string);
	assert(p != (char *)NULL);
	if (p == (char *)NULL) {
		return ((char *)NULL);
	}
	lasts = p;

	/* scan for separators and return 'index'th token found */

	while (q = strtok_r((char *)NULL, a_separators, &lasts)) {
		/* retrieve separator if requested */

		if (r_sep != (char *)NULL) {
			char	*x;

			x = strpbrk(a_string, a_separators);
			if (x) {
				*r_sep = *x;
			}
		}

		/* if this is the 'index'th token requested return it */

		if (a_index-- == 0) {
			char	*tmp;

			/* duplicate token into its own storage */

			tmp = strdup(q);
			assert(tmp != (char *)NULL);
			if (tmp == (char *)NULL) {
				return ((char *)NULL);
			}

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

	return ((char *)NULL);
}

/*
 * Name:	pkgstrGetToken
 * Synopsis:	Get separator delimited token from a string into a fixed buffer
 * Description:	Given a string and a list of one or more separators,
 *		return the position specified token (sequence of one or
 *		more characters that do not include any of the separators)
 *		into a specified buffer of a fixed maximum size
 * Arguments:	r_sep - [*RW] - (char *)
 *			- separator that ended the token returned
 *			- NOTE: this is a pointer to a "char", e.g.:
 *				- char a;
 *				- pkgstrGetToken(&a, ...)
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
pkgstrGetToken_r(char *r_sep, char *a_string, int a_index,
	char *a_separators, char *a_buf, int a_bufLen)
{
	char	*p;
	char	*q;
	char	*lasts;

	/* entry assertions */

	assert(a_string != (char *)NULL);
	assert(a_index >= 0);
	assert(a_separators != (char *)NULL);
	assert(*a_separators != '\0');
	assert(a_buf != (char *)NULL);
	assert(a_bufLen > 0);

	/* reset returned separator */

	if (r_sep != (char *)NULL) {
		*r_sep = '\0';
	}

	/* zero out contents of return buffer */

	bzero(a_buf, a_bufLen);

	/* duplicate original string before breaking down into tokens */

	p = strdup(a_string);
	assert(p != (char *)NULL);
	if (p == (char *)NULL) {
		return;
	}
	lasts = p;

	/* scan for separators and return 'index'th token found */

	while (q = strtok_r((char *)NULL, a_separators, &lasts)) {
		/* retrieve separator if requested */

		if (r_sep != (char *)NULL) {
			char	*x;
			x = strpbrk(a_string, a_separators);
			if (x) {
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
 * Name:	pkgstrAddToken
 * Synopsis:	Add a token to a string
 * Description:	Append a token (sequence of one or more characters) to a
 *		string that is in allocated space - create new string if
 *		no string to append to exists
 * Arguments:	a_old - [RO, *RW] - (char **)
 *			- Pointer to handle to string to append token to
 *			  == (char *)NULL - new string is created
 *		a_new - [RO, *RO] - (char *)
 *			- Pointer to string representing token to append
 *			  to the end of the "a_old" string
 *			  == (char *)NULL - no action is performed
 *			  a_new[0] == '\0' - no action is performed
 *		a_separator - [RO, *RO] - (char)
 *			- One character placed between the old (existing)
 *			  string and the new token to be added IF the old
 *			  string exists and is not empty (zero length)
 * Returns:	void
 * CAUTION:	The old (existing) string must be allocated space (via lu_mem*
 *		or pkgstr* methods) - it must not be a static or inline
 *		character string
 * NOTE:	The old (existing) string may be freed with 'free'
 *		if a token is appended to it
 * NOTE:    	Any string returned in 'a_old' is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the token string is no longer needed.
 */

void
pkgstrAddToken(char **a_old, char *a_new, char a_separator)
{
	/* entry assertions */

	assert(a_old != (char **)NULL);
	assert(a_separator != '\0');

	/* if token to add is null, just return */

	if (a_new == (char *)NULL) {
		return;
	}

	/* if token to add is empty (zero length), just return */

	if (*a_new == '\0') {
		return;
	}

	/* make sure that new token does not contain the separator */

	assert(strchr(a_new, (int)a_separator) == (char *)NULL);

	/* if old string is empty (zero length), deallocate */

	if ((*a_old != (char *)NULL) && ((*a_old)[0] == '\0')) {
		/* *a_old is set to NULL by free */
		free(*a_old);
		*a_old = (char *)NULL;
	}

	/* if old string is exists, append separator and token */

	if (*a_old != (char *)NULL) {
		char *p;
		p = pkgstrPrintf("%s%c%s", *a_old, a_separator, a_new);
		free(*a_old);
		*a_old = p;
		return;
	}

	/* old string does not exist - return duplicate of token */

	assert(*a_old == (char *)NULL);
	*a_old = strdup(a_new);
	assert(*a_old != (char *)NULL);
}

/*
 * Name:	pkgstrContainsToken
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
pkgstrContainsToken(char *a_string, char *a_token, char *a_separators)
{
	char	*lasts;
	char	*current;
	char	*p;

	/* entry assertions */

	assert(a_separators != (char *)NULL);
	assert(*a_separators != '\0');

	/* if token is not supplied, return false */

	if (a_token == (char *)NULL) {
		return (B_FALSE);
	}

	/* if no string provided, return false */

	if (a_string == (char *)NULL) {
		return (B_FALSE);
	}

	/* if string empty (zero length), return false */

	if (*a_string == '\0') {
		return (B_FALSE);
	}

	/* duplicate larger string because strtok_r changes it */

	p = strdup(a_string);
	assert(p != (char *)NULL);
	if (p == (char *)NULL) {
		return (B_FALSE);
	}

	lasts = p;

	/* scan each token looking for a match */

	while ((current = strtok_r((char *)NULL, a_separators, &lasts)) !=
			(char *)NULL) {
		if (streq(current, a_token)) {
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
 * Name:	pkgstrRemoveToken
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
 *		pkgstr* methods) - it must not be a static or inline
 *		character string
 * NOTE:	The input string r_string will be freed with 'free'
 *		if the token to be removed is found
 * NOTE:    	Any token string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the token string is no longer needed.
 * Errors:	If the new token string cannot be created, the process exits
 */

void
pkgstrRemoveToken(char **r_string, char *a_token, char *a_separators,
	int a_index)
{
	char	*a_string;
	char	*copyString;
	char	sep = 0;
	int	copyLength;
	int	i;

	/* entry assertions */

	assert(r_string != (char **)NULL);
	assert(a_token != (char *)NULL);
	assert(*a_token != '\0');
	assert(a_separators != (char *)NULL);
	assert(*a_separators != '\0');

	/* simple case: input string is null; return empty string */

	a_string = *r_string;
	if (*a_string == '\0') {
		return;
	}

	/* simple case: token == input string; return empty string */

	if (streq(a_string, a_token)) {
		/* deallocate input string; free sets *r_string to NULL */

		free(*r_string);
		*r_string = (char *)NULL;
		return;
	}

	/* simple case: token not in input string: return */

	if (!pkgstrContainsToken(a_string, a_token, a_separators)) {
		return;
	}

	/*
	 * Pick apart the old string building the new one as we go along
	 * removing the first occurance of the token provided
	 */

	copyLength = (strlen(a_string)-strlen(a_token))+2;
	copyString = calloc(1, copyLength);
	assert(copyString != (char *)NULL);
	if (copyString == (char *)NULL) {
		return;
	}

	for (i = 0; ; i++) {
		char	*p;

		p = pkgstrGetToken(&sep, a_string, i, a_separators);
		if (p == (char *)NULL) {
			break;
		}

		if (streq(p, a_token) && (a_index-- == 0)) {
			continue;
		}

		if (*copyString) {
			assert(sep != '\0');
			(void) strncat(copyString, &sep, 1);
		}

		(void) strcat(copyString, p);
	}

	free(*r_string);
	assert(*copyString);
	*r_string = copyString;
}

/*
 * Name:	pkgstrScaleNumericString
 * Synopsis:	Convert unsigned long long to human readable form
 * Description:	Convert a string containing an unsigned long long representation
 *		and convert it into a human readable numeric string. The number
 *		is scaled down until it is small enough to be in a good human
 *		readable format i.e. in the range 0 thru scale-1.
 * Arguments:	a_buf - [RO, *RW] - (char *)
 *			Pointer to buffer containing string representation
 *			of unsigned long long to convert
 *		scale - [RO, *RO] - (unsigned long long)
 *			Value to scale the number into
 * Returns:	a_buf - contains human readable scaled representation of
 *			original value contained in the buffer
 * Note:	The value "(unsigned long long)-1" is a special case and
 *		is always converted to "-1".
 * Errors:	If the string cannot be created, the process exits
 */

void
pkgstrScaleNumericString(char *a_buf, unsigned long long scale)
{
static char		*M = " KMGTPE"; /* Measurement: */
					/* kilo, mega, giga, tera, peta, exa */

	unsigned long long number = 0;	/* convert this number */
	unsigned long long save = 0;
	char	*uom = M;    /* unit of measurement, initially ' ' (=M[0]) */

	/* entry assertions */

	assert(scale > (unsigned long long)0);
	assert(scale <=  (unsigned long long)1048576);

	/*
	 * Get the number - if no number of empty number, just return
	 */

	if (a_buf == (char *)NULL) {
		return;
	}

	if (*a_buf == '\0') {
		(void) strcpy(a_buf, "0");
		return;
	}

	/* convert out the number from the input buffer */

	number = strtoull(a_buf, (char **)NULL, 10);

	/* if conversion error, return "-1" */

	if ((long long)number == (long long)-1) {
		(void) strcpy(a_buf, "-1");
		return;
	}

	/*
	 * Now have number as a count of scale units.
	 * Stop scaling when we reached exa-bytes, then something is
	 * probably wrong with our number (it is improbably large)
	 */

	while ((number >= scale) && (*uom != 'E')) {
		uom++; /* next unit of measurement */
		save = number;
		number = (number + (scale / 2)) / scale;
	}

	/* check if we should output a decimal place after the point */

	if (save && ((save / scale) < 10)) {
		/* sprintf() will round for us */
		float fnum = (float)save / scale;
		(void) sprintf(a_buf, "%4.1f%c", fnum, *uom);
	} else {
		(void) sprintf(a_buf, "%4llu%c", number, *uom);
	}
}

/*
 * Name:	pkgstrLocatePathBasename
 * Synopsis:	Locate position of base name in path string
 * Description:	Locate the base name (last path item) in a path and
 *		return a pointer to the first byte of the base name
 *		within the given path
 * Arguments:	a_path - [RO, *RO] - (char *)
 *			- Pointer to string representing path to scan
 * Returns:	char *
 *			- Pointer into string of first byte of path base name
 *			- == (char *)NULL - input path is (char *)NULL
 */

char *
pkgstrLocatePathBasename(char *a_path)
{
	char	*p;

	/* if path is NULL, return NULL */

	if (!a_path) {
		return (a_path);
	}

	/* locate last occurance of '/' in path */

	p = strrchr(a_path, '/');
	if (p != (char *)NULL) {
		/* base name located - return -> first byte */
		return (p+1);
	}

	/* no occurance of '/' - entry path must be basename */

	return (a_path);
}

/*
 * Name:	pkgstrConvertPathToBasename
 * Synopsis:	Return copy of base name in path string
 * Description:	Locate the base name (last path item) in a path and
 *		return a copy of the base name in allocated storage
 * Arguments:	a_path - [RO, *RO] - (char *)
 *			- Pointer to string representing path to scan
 * Returns:	char *
 *			- String containing path base name
 *			- == (char *)NULL - input path is (char *)NULL
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * Errors:	If the string cannot be created, the process exits
 */

char *
pkgstrConvertPathToBasename(char *a_path)
{
	char	*p;

	/* if path is NULL, return NULL */

	if (a_path == (char *)NULL) {
		return ((char *)NULL);
	}

	/* if path is empty (zero length), return NULL */

	if (*a_path == '\0') {
		return ((char *)NULL);
	}

	/* locate last occurance of '/' in path */

	p = strrchr(a_path, '/');
	if (p == (char *)NULL) {
		/* no occurance of '/' - entry path must be basename */

		return (strdup(a_path));
	}

	/* base name located - return string from -> first byte */

	return (strdup(p+1));
}

/*
 * Name:	pkgstrConvertPathToDirname
 * Synopsis:	Return copy of directory in path string
 * Description:	Locate the directory name (everything but last path item) in a
 *		path and return a copy of the dir name in allocated storage
 * Arguments:	a_path - [RO, *RO] - (char *)
 *			- Pointer to string representing path to scan
 * Returns:	char *
 *			- String containing path directory name
 *			- == (char *)NULL - input path is (char *)NULL,
 *			  or a_path is empty (*a_path == '\0'), or the
 *			  a_path has no directory name in it.
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * Errors:	If the string cannot be created, the process exits
 */

char *
pkgstrConvertPathToDirname(char *a_path)
{
	char	*p;
	char	*retPath;

	/* if path is NULL, return NULL */

	if (a_path == (char *)NULL) {
		return ((char *)NULL);
	}

	/* if path is empty (zero length), return NULL */

	if (*a_path == '\0') {
		return ((char *)NULL);
	}

	/* locate last occurance of '/' in path */

	p = strrchr(a_path, '/');
	if (p == (char *)NULL) {
		/* no occurance of '/' - entire path must be basename */

		return ((char *)NULL);
	}

	/* duplicate original path */

	retPath = strdup(a_path);
	assert(retPath != (char *)NULL);
	if (retPath == (char *)NULL) {
		return ((char *)NULL);
	}

	/* remove all trailing '/'s from copy of path */

	for (p = strrchr(retPath, '/');	(p > retPath) && (*p == '/'); p--) {
		*p = '\0';
	}

	/* if entire path was '/'s, return null string - no directory present */

	if (*retPath == '\0') {
		free(retPath);
		return ((char *)NULL);
	}

	/* path has at least one non-'/' in it - return -> directory portion */

	return (retPath);
}

/*
 * Name:	pkgstrConvertUllToTimeString_r
 * Synopsis:	Convert an unsigned long long into a "time string"
 * Description:	Given an unsigned long long, return a "time string" which is a
 *		conversion of the unsigned long long interpreted as a number of
 *		nanoseconds into a "hour:minute:second.ns" ascii string
 * Arguments:	a_time - [RO, *RO] - (unsigned long long)n
 *			- value to convert
 *		a_buf - [RO, *RW] - (char *)
 *			- Pointer to buffer used as storage space for the
 *			  returned string
 *		a_bufLen - [RO, *RO] - (int)
 *			- Size of 'a_buf' in bytes - a maximum of 'a_bufLen-1'
 *			  bytes will be placed in 'a_buf'
 * Returns:	char *
 *			- String containing converted value
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * Errors:	If the string cannot be created, the process exits
 */

void
pkgstrConvertUllToTimeString_r(unsigned long long a_time,
	char *a_buf, int a_bufLen)
{
	unsigned long long	seconds;
	unsigned long long	minutes;
	unsigned long long	hours;
	unsigned long long	ns;

	/* entry assertions */

	assert(a_buf != (char *)NULL);
	assert(a_bufLen > 0);

	/* if time is 0, return immediate result */

	if (a_time == 0) {
		pkgstrPrintf_r(a_buf, a_bufLen, "%s", "0:00:00.000000000");
		return;
	}

	/* break out individual time components */

	ns = a_time % 1000000000ll;	/* nanoseconds left over from seconds */
	seconds = a_time / 1000000000ll;	/* total seconds */
	minutes = seconds / 60ll;	/* total minutes */
	seconds = seconds % 60ll;	/* seconds left over from minutes */
	hours = minutes / 60ll;		/* total hours */
	minutes = minutes % 60ll;	/* minutes left over from hours */

	/* return a converted string */

	pkgstrPrintf_r(a_buf, a_bufLen, "%llu:%02llu:%02llu.%09llu",
						hours, minutes, seconds, ns);
}
