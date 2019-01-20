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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * See getopt(3C) and SUS/XPG getopt() for function definition and
 * requirements.
 *
 * This actual implementation is a bit looser than the specification
 * as it allows any character other than ':' and '(' to be used as
 * a short option character - The specification only guarantees the
 * alnum characters ([a-z][A-Z][0-9]).
 */

#pragma weak _getopt = getopt

#include "lint.h"
#include "_libc_gettext.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>

/*
 * Generalized error processing macro. The parameter i is a pointer to
 * the failed option string. If it is NULL, the character in c is converted
 * to a string and displayed instead. s is the error text.
 *
 * This could be / should be a static function if it is used more, but
 * that would require moving the 'optstring[0]' test outside of the
 * function.
 */
#define	ERR(s, c, i)	if (opterr && optstring[0] != ':') { \
	char errbuf[256]; \
	char cbuf[2]; \
	cbuf[0] = c; \
	cbuf[1] = '\0'; \
	(void) snprintf(errbuf, sizeof (errbuf), s, argv[0], \
	    (i ? argv[i]+2 : cbuf)); \
	(void) write(2, errbuf, strlen(errbuf)); }

/*
 * _sp is required to keep state between successive calls to getopt() while
 * extracting aggregated short-options (ie: -abcd). Hence, getopt() is not
 * thread safe or reentrant, but it really doesn't matter.
 *
 * So, why isn't this "static" you ask?  Because the historical Bourne
 * shell has actually latched on to this little piece of private data.
 */
int _sp = 1;

/*
 * Determine if the specified character (c) is present in the string
 * (optstring) as a regular, single character option. If the option is found,
 * return a pointer into optstring pointing at the short-option character,
 * otherwise return null. The characters ':' and '(' are not allowed.
 */
static char *
parseshort(const char *optstring, const char c)
{
	char *cp = (char *)optstring;

	if (c == ':' || c == '(')
		return (NULL);
	do {
		if (*cp == c)
			return (cp);
		while (*cp == '(')
			while (*cp != '\0' && *cp != ')')
				cp++;
	} while (*cp++ != '\0');
	return (NULL);
}

/*
 * Determine if the specified string (opt) is present in the string
 * (optstring) as a long-option contained within parenthesis. If the
 * long-option specifies option-argument, return a pointer to it in
 * longoptarg.  Otherwise set longoptarg to null. If the option is found,
 * return a pointer into optstring pointing at the short-option character
 * associated with this long-option; otherwise return null.
 *
 * optstring 	The entire optstring passed to getopt() by the caller
 *
 * opt		The long option read from the command line
 *
 * longoptarg	The argument to the option is returned in this parameter,
 *              if an option exists. Possible return values in longoptarg
 *              are:
 *                  NULL		No argument was found
 *		    empty string ("")	Argument was explicitly left empty
 *					by the user (e.g., --option= )
 *		    valid string	Argument found on the command line
 *
 * returns	Pointer to equivalent short-option in optstring, null
 *              if option not found in optstring.
 *
 * ASSUMES: No parameters are NULL
 *
 */
static char *
parselong(const char *optstring, const char *opt, char **longoptarg)
{
	char	*cp;	/* ptr into optstring, beginning of one option spec. */
	char	*ip;	/* ptr into optstring, traverses every char */
	char	*op;	/* pointer into opt */
	int	match;	/* nonzero if opt is matching part of optstring */

	cp = ip = (char *)optstring;
	do {
		if (*ip != '(' && *++ip == '\0')
			break;
		if (*ip == ':' && *++ip == '\0')
			break;
		while (*ip == '(') {
			if (*++ip == '\0')
				break;
			op = (char *)opt;
			match = 1;
			while (*ip != ')' && *ip != '\0' && *op != '\0')
				match = (*ip++ == *op++ && match);
			if (match && *ip == ')' &&
			    (*op == '\0' || *op == '=')) {
				if ((*op) == '=') {
					/* may be an empty string - OK */
					(*longoptarg) = op + 1;
				} else {
					(*longoptarg) = NULL;
				}
				return (cp);
			}
			if (*ip == ')' && *++ip == '\0')
				break;
		}
		cp = ip;
		/*
		 * Handle double-colon in optstring ("a::(longa)")
		 * The old getopt() accepts it and treats it as a
		 * required argument.
		 */
		while ((cp > optstring) && ((*cp) == ':')) {
			--cp;
		}
	} while (*cp != '\0');
	return (NULL);
} /* parselong() */

/*
 * External function entry point.
 */
int
getopt(int argc, char *const *argv, const char *optstring)
{
	char	c;
	char	*cp;
	int	longopt;
	char	*longoptarg;

	/*
	 * Has the end of the options been encountered?  The following
	 * implements the SUS requirements:
	 *
	 * If, when getopt() is called:
	 *	argv[optind]	is a null pointer
	 *	*argv[optind]	is not the character '-'
	 *	argv[optind]	points to the string "-"
	 * getopt() returns -1 without changing optind. If
	 *	argv[optind]	points to the string "--"
	 * getopt() returns -1 after incrementing optind.
	 */
	if (_sp == 1) {
		if (optind >= argc || argv[optind][0] != '-' ||
		    argv[optind] == NULL || argv[optind][1] == '\0')
			return (EOF);
		else if (strcmp(argv[optind], "--") == 0) {
			optind++;
			return (EOF);
		}
	}

	/*
	 * Getting this far indicates that an option has been encountered.
	 * Note that the syntax of optstring applies special meanings to
	 * the characters ':' and '(', so they are not permissible as
	 * option letters. A special meaning is also applied to the ')'
	 * character, but its meaning can be determined from context.
	 * Note that the specification only requires that the alnum
	 * characters be accepted.
	 *
	 * If the second character of the argument is a '-' this must be
	 * a long-option, otherwise it must be a short option.  Scan for
	 * the option in optstring by the appropriate algorithm. Either
	 * scan will return a pointer to the short-option character in
	 * optstring if the option is found and NULL otherwise.
	 *
	 * For an unrecognized long-option, optopt will equal 0, but
	 * since long-options can't aggregate the failing option can
	 * be identified by argv[optind-1].
	 */
	optopt = c = (unsigned char)argv[optind][_sp];
	optarg = NULL;
	longopt = (_sp == 1 && c == '-');
	if (!(longopt ?
	    ((cp = parselong(optstring, argv[optind]+2, &longoptarg)) != NULL) :
	    ((cp = parseshort(optstring, c)) != NULL))) {
		ERR(_libc_gettext("%s: illegal option -- %s\n"),
		    c, (longopt ? optind : 0));
		/*
		 * Note: When the long option is unrecognized, optopt
		 * will be '-' here, which matches the specification.
		 */
		if (argv[optind][++_sp] == '\0' || longopt) {
			optind++;
			_sp = 1;
		}
		return ('?');
	}
	optopt = c = *cp;

	/*
	 * A valid option has been identified.  If it should have an
	 * option-argument, process that now.  SUS defines the setting
	 * of optarg as follows:
	 *
	 *   1.	If the option was the last character in the string pointed to
	 *	by an element of argv, then optarg contains the next element
	 *	of argv, and optind is incremented by 2. If the resulting
	 *	value of optind is not less than argc, this indicates a
	 *	missing option-argument, and getopt() returns an error
	 *	indication.
	 *
	 *   2.	Otherwise, optarg points to the string following the option
	 *	character in that element of argv, and optind is incremented
	 *	by 1.
	 *
	 * The second clause allows -abcd (where b requires an option-argument)
	 * to be interpreted as "-a -b cd".
	 *
	 * Note that the option-argument can legally be an empty string,
	 * such as:
	 * 	command --option= operand
	 * which explicitly sets the value of --option to nil
	 */
	if (*(cp + 1) == ':') {
		/* The option takes an argument */
		if (!longopt && argv[optind][_sp+1] != '\0') {
			optarg = &argv[optind++][_sp+1];
		} else if (longopt && longoptarg) {
			/*
			 * The option argument was explicitly set to
			 * the empty string on the command line (--option=)
			 */
			optind++;
			optarg = longoptarg;
		} else if (++optind >= argc) {
			ERR(_libc_gettext("%s: option requires an argument" \
			    " -- %s\n"), c, (longopt ? optind - 1 : 0));
			_sp = 1;
			optarg = NULL;
			return (optstring[0] == ':' ? ':' : '?');
		} else
			optarg = argv[optind++];
		_sp = 1;
	} else {
		/* The option does NOT take an argument */
		if (longopt && (longoptarg != NULL)) {
			/* User supplied an arg to an option that takes none */
			ERR(_libc_gettext(
			    "%s: option doesn't take an argument -- %s\n"),
			    0, (longopt ? optind : 0));
			optarg = longoptarg = NULL;
			c = '?';
		}

		if (longopt || argv[optind][++_sp] == '\0') {
			_sp = 1;
			optind++;
		}
		optarg = NULL;
	}
	return (c);
} /* getopt() */
