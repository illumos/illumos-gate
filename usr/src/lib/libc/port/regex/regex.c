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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2025 MNX Cloud, Inc.
 */

/*
 * IMPORTANT NOTE:
 *
 * regex() WORKS **ONLY** WITH THE ASCII AND THE Solaris EUC CHARACTER SETS.
 * IT IS **NOT** CHARACTER SET INDEPENDENT.
 *
 */

#pragma weak _regex = regex

#include "lint.h"
/* CONSTANTS SHARED WITH regcmp() */
#include "regex.h"
#include "mtlib.h"
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <thread.h>
#include <widec.h>
#include "tsd.h"


/* PRIVATE CONSTANTS */

#define	ADD_256_TO_GROUP_LENGTH	0x1
#define	ADD_512_TO_GROUP_LENGTH	0x2
#define	ADD_768_TO_GROUP_LENGTH	0x3
#define	ADDED_LENGTH_BITS	0x3
#define	SINGLE_BYTE_MASK	0xff
#define	STRINGP_STACK_SIZE	50


/* PRIVATE TYPE DEFINITIONS */

typedef enum {
	NOT_IN_CLASS = 0,
	IN_CLASS
} char_test_condition_t;

typedef enum {
	TESTING_CHAR = 0,
	CONDITION_TRUE,
	CONDITION_FALSE,
	CHAR_TEST_ERROR
} char_test_result_t;


/* PRIVATE GLOBAL VARIABLES */

static mutex_t		regex_lock = DEFAULTMUTEX;
static int		return_arg_number[NSUBSTRINGS];
static const char	*substring_endp[NSUBSTRINGS];
static const char	*substring_startp[NSUBSTRINGS];
static const char	*stringp_stack[STRINGP_STACK_SIZE];
static const char	**stringp_stackp;


/* DECLARATIONS OF PRIVATE FUNCTIONS */

static int get_wchar(wchar_t *wcharp, const char *stringp);
static void get_match_counts(int *nmust_matchp, int *nextra_matches_allowedp,
    const char *count_stringp);
static boolean_t in_wchar_range(wchar_t test_char, wchar_t lower_char,
    wchar_t upper_char);
static const char *pop_stringp(void);
static const char *previous_charp(const char *current_charp);
static const char *push_stringp(const char *stringp);
static char_test_result_t test_char_against_ascii_class(char test_char,
    const char *classp, char_test_condition_t test_condition);
static char_test_result_t test_char_against_multibyte_class(wchar_t test_char,
    const char *classp, char_test_condition_t test_condition);

/* FOR COMPATIBILITY WITH PREVIOUS ASCII VERSIONS OF regcmp() */

static char_test_result_t test_char_against_old_ascii_class(char test_char,
    const char *classp, char_test_condition_t test_condition);
static const char *test_repeated_ascii_char(const char *repeat_startp,
    const char *stringp, const char *regexp);
static const char *test_repeated_multibyte_char(const char *repeat_startp,
    const char *stringp, const char *regexp);
static const char *test_repeated_group(const char *repeat_startp,
    const char *stringp, const char *regexp);
static const char *test_string(const char *stringp, const char *regexp);

/* DEFINITIONS OF PUBLIC VARIABLES */

char *__loc1;

/*
 * reserve thread-specific storage for __loc1
 */
char **
____loc1(void)
{
	if (thr_main())
		return (&__loc1);
	return ((char **)tsdalloc(_T_REGEX_LOC1, sizeof (char *), NULL));
}

#define	__loc1 (*(____loc1()))

/* DEFINITION OF regex() */

extern char *
regex(const char *regexp, const char *stringp, ...)
{
	va_list		arg_listp;
	int		char_size;
	const char	*end_of_matchp;
	wchar_t		regex_wchar;
	char		*return_argp[NSUBSTRINGS];
	char		*returned_substringp;
	int		substringn;
	const char	*substringp;
	wchar_t		string_wchar;

	if (____loc1() == (char **)0) {
		return ((char *)0);
	} else {
		lmutex_lock(&regex_lock);
		__loc1 = (char *)0;
	}

	if ((stringp == (char *)0) || (regexp == (char *)0)) {
		lmutex_unlock(&regex_lock);
		return ((char *)0);
	}


	/* INITIALIZE SUBSTRINGS THAT MIGHT BE RETURNED IN VARARGS  */

	substringn = 0;
	va_start(arg_listp, stringp);
	while (substringn < NSUBSTRINGS) {
		return_argp[substringn] = va_arg(arg_listp, char *);
		substring_startp[substringn] = (char *)0;
		return_arg_number[substringn] = -1;
		substringn++;
	}
	va_end(arg_listp);


	/* TEST THE STRING AGAINST THE REGULAR EXPRESSION */

	end_of_matchp = (char *)0;
	stringp_stackp = &stringp_stack[STRINGP_STACK_SIZE];

	if ((int)*regexp == (int)START_OF_STRING_MARK) {

		/*
		 * the match must start at the beginning of the string
		 */

		__loc1 = (char *)stringp;
		regexp++;
		end_of_matchp = test_string(stringp, regexp);

	} else if ((int)*regexp == (int)ASCII_CHAR) {

		/*
		 * test a string against a regular expression
		 * that starts with a single ASCII character:
		 *
		 * move to each character in the string that matches
		 * the first character in the regular expression
		 * and test the remaining string
		 */

		while ((*stringp != *(regexp + 1)) && (*stringp != '\0')) {
			stringp++;
		}
		while ((end_of_matchp == (char *)0) && (*stringp != '\0')) {
			end_of_matchp = test_string(stringp, regexp);
			if (end_of_matchp != (char *)0) {
				__loc1 = (char *)stringp;
			} else {
				stringp++;
				while ((*stringp != *(regexp + 1)) &&
				    (*stringp != '\0')) {
					stringp++;
				}
			}
		}

	} else if (!multibyte) {

		/*
		 * if the value of the "multibyte" macro defined in <euc.h>
		 * is false, regex() is running in an ASCII locale;
		 * test an ASCII string against an ASCII regular expression
		 * that doesn't start with a single ASCII character:
		 *
		 * move forward in the string one byte at a time, testing
		 * the remaining string against the regular expression
		 */

		end_of_matchp = test_string(stringp, regexp);
		while ((end_of_matchp == (char *)0) && (*stringp != '\0')) {
			stringp++;
			end_of_matchp = test_string(stringp, regexp);
		}
		if (end_of_matchp != (char *)0) {
			__loc1 = (char *)stringp;
		}

	} else if ((int)*regexp == (int)MULTIBYTE_CHAR) {

		/*
		 * test a multibyte string against a multibyte regular
		 * expression that starts with a single multibyte character:
		 *
		 * move to each character in the string that matches
		 * the first character in the regular expression
		 * and test the remaining string
		 */

		(void) get_wchar(&regex_wchar, regexp + 1);
		char_size = get_wchar(&string_wchar, stringp);
		while ((string_wchar != regex_wchar) && (char_size > 0)) {
			stringp += char_size;
			char_size = get_wchar(&string_wchar, stringp);
		}
		while ((end_of_matchp == (char *)0) && (char_size > 0)) {
			end_of_matchp = test_string(stringp, regexp);
			if (end_of_matchp != (char *)0) {
				__loc1 = (char *)stringp;
			} else {
				stringp += char_size;
				char_size = get_wchar(&string_wchar, stringp);
				while ((string_wchar != regex_wchar) &&
				    (char_size > 0)) {
					stringp += char_size;
					char_size = get_wchar(&string_wchar,
					    stringp);
				}
			}
		}

	} else {

		/*
		 * test a multibyte string against a multibyte regular
		 * expression that doesn't start with a single multibyte
		 * character
		 *
		 * move forward in the string one multibyte character at a time,
		 * testing the remaining string against the regular expression
		 */

		end_of_matchp = test_string(stringp, regexp);
		char_size = get_wchar(&string_wchar, stringp);
		while ((end_of_matchp == (char *)0) && (char_size > 0)) {
			stringp += char_size;
			end_of_matchp = test_string(stringp, regexp);
			char_size = get_wchar(&string_wchar, stringp);
		}
		if (end_of_matchp != (char *)0) {
			__loc1 = (char *)stringp;
		}
	}

	/*
	 * Return substrings that matched subexpressions for which
	 * matching substrings are to be returned.
	 *
	 * NOTE:
	 *
	 * According to manual page regcmp(3C), regex() returns substrings
	 * that match subexpressions even when no substring matches the
	 * entire regular expression.
	 */

	substringn = 0;
	while (substringn < NSUBSTRINGS) {
		substringp = substring_startp[substringn];
		if ((substringp != (char *)0) &&
		    (return_arg_number[substringn] >= 0)) {
			returned_substringp =
			    return_argp[return_arg_number[substringn]];
			if (returned_substringp != (char *)0) {
				while (substringp <
				    substring_endp[substringn]) {
					*returned_substringp =
					    (char)*substringp;
					returned_substringp++;
					substringp++;
				}
				*returned_substringp = '\0';
			}
		}
		substringn++;
	}
	lmutex_unlock(&regex_lock);
	return ((char *)end_of_matchp);
}  /* regex() */


/* DEFINITIONS OF PRIVATE FUNCTIONS */

static int
get_wchar(wchar_t *wcharp, const char *stringp)
{
	int char_size;

	if (stringp == (char *)0) {
		char_size = 0;
		*wcharp = (wchar_t)((unsigned int)'\0');
	} else if (*stringp == '\0') {
		char_size = 0;
		*wcharp = (wchar_t)((unsigned int)*stringp);
	} else if ((unsigned char)*stringp <= (unsigned char)0x7f) {
		char_size = 1;
		*wcharp = (wchar_t)((unsigned int)*stringp);
	} else {
		char_size = mbtowc(wcharp, stringp, MB_LEN_MAX);
	}
	return (char_size);
}

static void
get_match_counts(int *nmust_matchp, int *nextra_matches_allowedp,
    const char *count_stringp)
{
	int minimum_match_count;
	int maximum_match_count;

	minimum_match_count =
	    (int)((unsigned int)*count_stringp & SINGLE_BYTE_MASK);
	*nmust_matchp = minimum_match_count;

	count_stringp++;
	maximum_match_count =
	    (int)((unsigned int)*count_stringp & SINGLE_BYTE_MASK);
	if (maximum_match_count == (int)UNLIMITED) {
		*nextra_matches_allowedp = (int)UNLIMITED;
	} else {
		*nextra_matches_allowedp =
		    maximum_match_count - minimum_match_count;
	}
	return;

} /* get_match_counts() */

static boolean_t
in_wchar_range(wchar_t test_char, wchar_t lower_char, wchar_t upper_char)
{
	return (((lower_char <= 0x7f) && (upper_char <= 0x7f) &&
	    (lower_char <= test_char) && (test_char <= upper_char)) ||
	    (((test_char & WCHAR_CSMASK) == (lower_char & WCHAR_CSMASK)) &&
	    ((test_char & WCHAR_CSMASK) == (upper_char & WCHAR_CSMASK)) &&
	    (lower_char <= test_char) && (test_char <= upper_char)));

} /* in_wchar_range() */

static const char *
pop_stringp(void)
{
	const char *stringp;

	if (stringp_stackp >= &stringp_stack[STRINGP_STACK_SIZE]) {
		return ((char *)0);
	} else {
		stringp = *stringp_stackp;
		stringp_stackp++;
		return (stringp);
	}
}


static const char *
previous_charp(const char *current_charp)
{
	/*
	 * returns the pointer to the previous character in
	 * a string of multibyte characters
	 */

	const char *prev_cs0 = current_charp - 1;
	const char *prev_cs1 = current_charp - eucw1;
	const char *prev_cs2 = current_charp - eucw2 - 1;
	const char *prev_cs3 = current_charp - eucw3 - 1;
	const char *prev_charp;

	if ((unsigned char)*prev_cs0 <= 0x7f) {
		prev_charp = prev_cs0;
	} else if ((unsigned char)*prev_cs2 == SS2) {
		prev_charp = prev_cs2;
	} else if ((unsigned char)*prev_cs3 == SS3) {
		prev_charp = prev_cs3;
	} else {
		prev_charp = prev_cs1;
	}
	return (prev_charp);

} /* previous_charp() */

static const char *
push_stringp(const char *stringp)
{
	if (stringp_stackp <= &stringp_stack[0]) {
		return ((char *)0);
	} else {
		stringp_stackp--;
		*stringp_stackp = stringp;
		return (stringp);
	}
}


static char_test_result_t
test_char_against_ascii_class(char test_char, const char *classp,
    char_test_condition_t test_condition)
{
	/*
	 * tests a character for membership in an ASCII character class compiled
	 * by the internationalized version of regcmp();
	 *
	 * NOTE: The internationalized version of regcmp() compiles
	 *	the range a-z in an ASCII character class to aTHRUz.
	 */

	int	nbytes_to_check;

	nbytes_to_check = (int)*classp;
	classp++;
	nbytes_to_check--;

	while (nbytes_to_check > 0) {
		if (test_char == *classp) {
			if (test_condition == IN_CLASS)
				return (CONDITION_TRUE);
			else
				return (CONDITION_FALSE);
		} else if (*classp == THRU) {
			if ((*(classp - 1) <= test_char) &&
			    (test_char <= *(classp + 1))) {
				if (test_condition == IN_CLASS)
					return (CONDITION_TRUE);
				else
					return (CONDITION_FALSE);
			} else {
				classp += 2;
				nbytes_to_check -= 2;
			}
		} else {
			classp++;
			nbytes_to_check--;
		}
	}
	if (test_condition == NOT_IN_CLASS) {
		return (CONDITION_TRUE);
	} else {
		return (CONDITION_FALSE);
	}
} /* test_char_against_ascii_class() */

static char_test_result_t
test_char_against_multibyte_class(wchar_t test_char, const char *classp,
    char_test_condition_t test_condition)
{
	/*
	 * tests a character for membership in a multibyte character class;
	 *
	 * NOTE: The range a-z in a multibyte character class compiles to
	 *	aTHRUz.
	 */

	int		char_size;
	wchar_t		current_char;
	int		nbytes_to_check;
	wchar_t		previous_char;

	nbytes_to_check = (int)*classp;
	classp++;
	nbytes_to_check--;

	char_size = get_wchar(&current_char, classp);
	if (char_size <= 0) {
		return (CHAR_TEST_ERROR);
	} else if (test_char == current_char) {
		if (test_condition == IN_CLASS) {
			return (CONDITION_TRUE);
		} else {
			return (CONDITION_FALSE);
		}
	} else {
		classp += char_size;
		nbytes_to_check -= char_size;
	}

	while (nbytes_to_check > 0) {
		previous_char = current_char;
		char_size = get_wchar(&current_char, classp);
		if (char_size <= 0) {
			return (CHAR_TEST_ERROR);
		} else if (test_char == current_char) {
			if (test_condition == IN_CLASS) {
				return (CONDITION_TRUE);
			} else {
				return (CONDITION_FALSE);
			}
		} else if (current_char == THRU) {
			classp += char_size;
			nbytes_to_check -= char_size;
			char_size = get_wchar(&current_char, classp);
			if (char_size <= 0) {
				return (CHAR_TEST_ERROR);
			} else if (in_wchar_range(test_char, previous_char,
			    current_char)) {
				if (test_condition == IN_CLASS) {
					return (CONDITION_TRUE);
				} else {
					return (CONDITION_FALSE);
				}
			} else {
				classp += char_size;
				nbytes_to_check -= char_size;
			}
		} else {
			classp += char_size;
			nbytes_to_check -= char_size;
		}
	}
	if (test_condition == NOT_IN_CLASS) {
		return (CONDITION_TRUE);
	} else {
		return (CONDITION_FALSE);
	}
} /* test_char_against_multibyte_class() */


/* FOR COMPATIBILITY WITH PREVIOUS ASCII VERSIONS OF regcmp() */

static char_test_result_t
test_char_against_old_ascii_class(char test_char, const char *classp,
    char_test_condition_t test_condition)
{
	/*
	 * tests a character for membership in an ASCII character class compiled
	 * by the ASCII version of regcmp();
	 *
	 * NOTE: ASCII versions of regcmp() compile the range a-z in an
	 *	ASCII character class to THRUaz.  The internationalized
	 *	version compiles the same range to aTHRUz.
	 */

	int	nbytes_to_check;

	nbytes_to_check = (int)*classp;
	classp++;
	nbytes_to_check--;

	while (nbytes_to_check > 0) {
		if (test_char == *classp) {
			if (test_condition == IN_CLASS) {
				return (CONDITION_TRUE);
			} else {
				return (CONDITION_FALSE);
			}
		} else if (*classp == THRU) {
		if ((*(classp + 1) <= test_char) &&
		    (test_char <= *(classp + 2))) {
				if (test_condition == IN_CLASS) {
					return (CONDITION_TRUE);
				} else {
					return (CONDITION_FALSE);
				}
			} else {
				classp += 3;
				nbytes_to_check -= 3;
			}
		} else {
			classp++;
			nbytes_to_check--;
		}
	}
	if (test_condition == NOT_IN_CLASS) {
		return (CONDITION_TRUE);
	} else {
		return (CONDITION_FALSE);
	}
} /* test_char_against_old_ascii_class() */

static const char *
test_repeated_ascii_char(const char *repeat_startp, const char *stringp,
    const char *regexp)
{
	const char *end_of_matchp;

	end_of_matchp = test_string(stringp, regexp);
	while ((end_of_matchp == (char *)0) &&
	    (stringp > repeat_startp)) {
		stringp--;
		end_of_matchp = test_string(stringp, regexp);
	}
	return (end_of_matchp);
}

static const char *
test_repeated_multibyte_char(const char *repeat_startp, const char *stringp,
    const char *regexp)
{
	const char *end_of_matchp;

	end_of_matchp = test_string(stringp, regexp);
	while ((end_of_matchp == (char *)0) &&
	    (stringp > repeat_startp)) {
		stringp = previous_charp(stringp);
		end_of_matchp = test_string(stringp, regexp);
	}
	return (end_of_matchp);
}

static const char *
test_repeated_group(const char *repeat_startp, const char *stringp,
    const char *regexp)
{
	const char *end_of_matchp;

	end_of_matchp = test_string(stringp, regexp);
	while ((end_of_matchp == (char *)0) &&
	    (stringp > repeat_startp)) {
		stringp = pop_stringp();
		if (stringp == (char *)0) {
			return ((char *)0);
		}
		end_of_matchp = test_string(stringp, regexp);
	}
	return (end_of_matchp);
}

static const char *
test_string(const char *stringp, const char *regexp)
{
	/*
	 * returns a pointer to the first character following the first
	 * substring of the string addressed by stringp that matches
	 * the compiled regular expression addressed by regexp
	 */

	unsigned int		group_length;
	int			nextra_matches_allowed;
	int			nmust_match;
	wchar_t			regex_wchar;
	int			regex_char_size;
	const char		*repeat_startp;
	unsigned int		return_argn;
	wchar_t			string_wchar;
	int			string_char_size;
	unsigned int		substringn;
	char_test_condition_t	test_condition;
	const char		*test_stringp;

	for (;;) {

		/*
		 * Exit the loop via a return whenever there's a match
		 * or it's clear that there can be no match.
		 */

		switch ((int)*regexp) {

		/*
		 * No fall-through.
		 * Each case ends with either a return or with stringp
		 * addressing the next character to be tested and regexp
		 * addressing the next compiled regular expression
		 *
		 * NOTE: The comments for each case give the meaning
		 *	of the compiled regular expression decoded by the case
		 *	and the character string that the compiled regular
		 *	expression uses to encode the case.  Each single
		 *	character encoded in the compiled regular expression
		 *	is shown enclosed in angle brackets (<>).  Each
		 *	compiled regular expression begins with a marker
		 *	character which is shown as a named constant
		 *	(e.g. <ASCII_CHAR>). Character constants are shown
		 *	enclosed in single quotes (e.g. <'$'>).  All other
		 *	single characters encoded in the compiled regular
		 *	expression are shown as lower case variable names
		 *	(e.g. <ascii_char> or <multibyte_char>). Multicharacter
		 *	strings encoded in the compiled regular expression
		 *	are shown as variable names followed by elipses
		 *	(e.g. <compiled_regex...>).
		 */

		case ASCII_CHAR: /* single ASCII char */

		/* encoded as <ASCII_CHAR><ascii_char> */

			regexp++;
			if (*regexp == *stringp) {
				regexp++;
				stringp++;
			} else {
				return ((char *)0);
			}
			break;		/* end case ASCII_CHAR */

		case MULTIBYTE_CHAR: /* single multibyte char */

		/* encoded as <MULTIBYTE_CHAR><multibyte_char> */

			regexp++;
			regex_char_size = get_wchar(&regex_wchar, regexp);
			string_char_size = get_wchar(&string_wchar, stringp);
			if ((string_char_size <= 0) ||
			    (string_wchar != regex_wchar)) {
				return ((char *)0);
			} else {
				regexp += regex_char_size;
				stringp += string_char_size;
			}
			break;		/* end case MULTIBYTE_CHAR */

		case ANY_CHAR: /* any single ASCII or multibyte char */

			/* encoded as <ANY_CHAR> */

			if (!multibyte) {
				if (*stringp == '\0') {
					return ((char *)0);
				} else {
					regexp++;
					stringp++;
				}
			} else {
				string_char_size =
				    get_wchar(&string_wchar, stringp);
				if (string_char_size <= 0) {
					return ((char *)0);
				} else {
					regexp++;
					stringp += string_char_size;
				}
			}
			break;	/* end case ANY_CHAR */

		case IN_ASCII_CHAR_CLASS:		/* [.....] */
		case NOT_IN_ASCII_CHAR_CLASS:

		/*
		 * encoded as <IN_ASCII_CHAR_CLASS><class_length><class...>
		 *	or <NOT_IN_ASCII_CHAR_CLASS><class_length><class...>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 */

			if ((int)*regexp == (int)IN_ASCII_CHAR_CLASS) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			if ((*stringp != '\0') &&
			    (test_char_against_ascii_class(*stringp, regexp,
			    test_condition) == CONDITION_TRUE)) {
				/* add the class length to regexp */
				regexp += (int)*regexp;
				stringp++;
			} else {
				return ((char *)0);
			}
			break; /* end case IN_ASCII_CHAR_CLASS */

		case IN_MULTIBYTE_CHAR_CLASS:	/* [....] */
		case NOT_IN_MULTIBYTE_CHAR_CLASS:

		/*
		 * encoded as <IN_MULTIBYTE_CHAR_CLASS><class_length><class...>
		 *	or <NOT_IN_MULTIBYTE_CHAR_CLASS><class_length><class...>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 */

			if ((int)*regexp == (int)IN_MULTIBYTE_CHAR_CLASS) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			string_char_size = get_wchar(&string_wchar, stringp);
			if ((string_char_size > 0) &&
			    (test_char_against_multibyte_class(string_wchar,
			    regexp, test_condition) == CONDITION_TRUE)) {
				/* add the class length to regexp */
				regexp += (int)*regexp;
				stringp += string_char_size;
			} else {
				return ((char *)0);
			}
			break; /* end case IN_MULTIBYTE_CHAR_CLASS */

		case IN_OLD_ASCII_CHAR_CLASS:	/* [...] */
		case NOT_IN_OLD_ASCII_CHAR_CLASS:

		/*
		 * encoded as <IN_OLD_ASCII_CHAR_CLASS><class_length><class...>
		 *	or <NOT_IN_OLD_ASCII_CHAR_CLASS><class_length><class...>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 */

			if ((int)*regexp == (int)IN_OLD_ASCII_CHAR_CLASS) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			if ((*stringp != '\0') &&
			    (test_char_against_old_ascii_class(*stringp, regexp,
			    test_condition) == CONDITION_TRUE)) {
				/* add the class length to regexp */
				regexp += (int)*regexp;
				stringp++;
			} else {
				return ((char *)0);
			}
			break; /* end case [NOT_]IN_OLD_ASCII_CHAR_CLASS */

		case SIMPLE_GROUP: /* (.....) */

		/* encoded as <SIMPLE_GROUP><group_length> */

			regexp += 2;
			break;		/* end case SIMPLE_GROUP */

		case END_GROUP:	/* (.....) */

			/* encoded as <END_GROUP><groupn> */

			regexp += 2;
			break;		/* end case END_GROUP */

		case SAVED_GROUP:	/* (.....)$0-9 */

		/* encoded as <SAVED_GROUP><substringn> */

			regexp++;
			substringn = (unsigned int)*regexp;
			if (substringn >= NSUBSTRINGS)
				return ((char *)0);
			substring_startp[substringn] = stringp;
			regexp++;
			break;		/* end case SAVED_GROUP */

		case END_SAVED_GROUP:	/* (.....)$0-9 */

		/*
		 * encoded as <END_SAVED_GROUP><substringn>\
		 *	<return_arg_number[substringn]>
		 */

			regexp++;
			substringn = (unsigned int)*regexp;
			if (substringn >= NSUBSTRINGS)
				return ((char *)0);
			substring_endp[substringn] = stringp;
			regexp++;
			return_argn = (unsigned int)*regexp;
			if (return_argn >= NSUBSTRINGS)
				return ((char *)0);
			return_arg_number[substringn] = return_argn;
			regexp++;
			break;		/* end case END_SAVED_GROUP */

		case ASCII_CHAR|ZERO_OR_MORE:  /* char* */

		/* encoded as <ASCII_CHAR|ZERO_OR_MORE><ascii_char> */

			regexp++;
			repeat_startp = stringp;
			while (*stringp == *regexp) {
				stringp++;
			}
			regexp++;
			return (test_repeated_ascii_char(repeat_startp,
			    stringp, regexp));

			/* end case ASCII_CHAR|ZERO_OR_MORE */

		case ASCII_CHAR|ONE_OR_MORE:   /* char+ */

		/* encoded as <ASCII_CHAR|ONE_OR_MORE><ascii_char> */

			regexp++;
			if (*stringp != *regexp) {
				return ((char *)0);
			} else {
				stringp++;
				repeat_startp = stringp;
				while (*stringp == *regexp) {
					stringp++;
				}
				regexp++;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			}
			/* end case ASCII_CHAR|ONE_OR_MORE */

		case ASCII_CHAR|COUNT:	/* char{min_count,max_count} */

		/*
		 * encoded as <ASCII_CHAR|COUNT><ascii_char>\
		 *	<minimum_match_count><maximum_match_count>
		 */

			regexp++;
			get_match_counts(&nmust_match, &nextra_matches_allowed,
			    regexp + 1);
			while ((*stringp == *regexp) && (nmust_match > 0)) {
				nmust_match--;
				stringp++;
			}
			if (nmust_match > 0) {
				return ((char *)0);
			} else if (nextra_matches_allowed == UNLIMITED) {
				repeat_startp = stringp;
				while (*stringp == *regexp) {
				stringp++;
				}
				regexp += 3;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			} else {
				repeat_startp = stringp;
				while ((*stringp == *regexp) &&
				    (nextra_matches_allowed > 0)) {
					nextra_matches_allowed--;
					stringp++;
				}
				regexp += 3;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			}
			/* end case ASCII_CHAR|COUNT */

		case MULTIBYTE_CHAR|ZERO_OR_MORE:   /* char* */

		/* encoded as <MULTIBYTE_CHAR|ZERO_OR_MORE><multibyte_char> */

			regexp++;
			regex_char_size = get_wchar(&regex_wchar, regexp);
			repeat_startp = stringp;
			string_char_size = get_wchar(&string_wchar, stringp);
			while ((string_char_size > 0) &&
			    (string_wchar == regex_wchar)) {
				stringp += string_char_size;
				string_char_size =
				    get_wchar(&string_wchar, stringp);
			}
			regexp += regex_char_size;
			return (test_repeated_multibyte_char(repeat_startp,
			    stringp, regexp));

			/* end case MULTIBYTE_CHAR|ZERO_OR_MORE */

		case MULTIBYTE_CHAR|ONE_OR_MORE:    /* char+ */

		/* encoded as <MULTIBYTE_CHAR|ONE_OR_MORE><multibyte_char> */

			regexp++;
			regex_char_size = get_wchar(&regex_wchar, regexp);
			string_char_size = get_wchar(&string_wchar, stringp);
			if ((string_char_size <= 0) ||
			    (string_wchar != regex_wchar)) {
				return ((char *)0);
			} else {
				stringp += string_char_size;
				repeat_startp = stringp;
				string_char_size =
				    get_wchar(&string_wchar, stringp);
				while ((string_char_size > 0) &&
				    (string_wchar == regex_wchar)) {
					stringp += string_char_size;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
				}
				regexp += regex_char_size;
				return (test_repeated_multibyte_char(
				    repeat_startp, stringp, regexp));
			}
			/* end case MULTIBYTE_CHAR|ONE_OR_MORE */

		case MULTIBYTE_CHAR|COUNT:	/* char{min_count,max_count} */

		/*
		 * encoded as <MULTIBYTE_CHAR|COUNT><multibyte_char>\
		 *	<minimum_match_count><maximum_match_count>
		 */

			regexp++;
			regex_char_size = get_wchar(&regex_wchar, regexp);
			get_match_counts(&nmust_match, &nextra_matches_allowed,
			    regexp + regex_char_size);
			string_char_size = get_wchar(&string_wchar, stringp);
			while ((string_char_size > 0) &&
			    (string_wchar == regex_wchar) &&
			    (nmust_match > 0)) {
				nmust_match--;
				stringp += string_char_size;
				string_char_size =
				    get_wchar(&string_wchar, stringp);
			}
			if (nmust_match > 0) {
				return ((char *)0);
			} else if (nextra_matches_allowed == UNLIMITED) {
				repeat_startp = stringp;
				while ((string_char_size > 0) &&
				    (string_wchar == regex_wchar)) {
					stringp += string_char_size;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
				}
				regexp += regex_char_size + 2;
				return (test_repeated_multibyte_char(
				    repeat_startp, stringp, regexp));
			} else {
				repeat_startp = stringp;
				while ((string_char_size > 0) &&
				    (string_wchar == regex_wchar) &&
				    (nextra_matches_allowed > 0)) {
					nextra_matches_allowed--;
					stringp += string_char_size;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
				}
				regexp += regex_char_size + 2;
				return (test_repeated_multibyte_char(
				    repeat_startp, stringp, regexp));
			}
			/* end case MULTIBYTE_CHAR|COUNT */

		case ANY_CHAR|ZERO_OR_MORE:		/* .* */

		/* encoded as <ANY_CHAR|ZERO_OR_MORE> */

			repeat_startp = stringp;
			if (!multibyte) {
				while (*stringp != '\0') {
					stringp++;
				}
				regexp++;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			} else {
				string_char_size =
				    get_wchar(&string_wchar, stringp);
				while (string_char_size > 0) {
					stringp += string_char_size;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
				}
				regexp++;
				return (test_repeated_multibyte_char(
				    repeat_startp, stringp, regexp));
			}
			/* end case <ANY_CHAR|ZERO_OR_MORE> */

		case ANY_CHAR|ONE_OR_MORE:		/* .+ */

		/* encoded as <ANY_CHAR|ONE_OR_MORE> */

			if (!multibyte) {
				if (*stringp == '\0') {
					return ((char *)0);
				} else {
					stringp++;
					repeat_startp = stringp;
					while (*stringp != '\0') {
						stringp++;
					}
					regexp++;
					return (test_repeated_ascii_char(
					    repeat_startp, stringp, regexp));
				}
			} else {
				string_char_size =
				    get_wchar(&string_wchar, stringp);
				if (string_char_size <= 0) {
					return ((char *)0);
				} else {
					stringp += string_char_size;
					repeat_startp = stringp;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
					while (string_char_size > 0) {
						stringp += string_char_size;
						string_char_size =
						    get_wchar(&string_wchar,
						    stringp);
					}
					regexp++;
					return (test_repeated_multibyte_char(
					    repeat_startp, stringp, regexp));
				}
			}
			/* end case <ANY_CHAR|ONE_OR_MORE> */

		case ANY_CHAR|COUNT:	/* .{min_count,max_count} */

		/*
		 * encoded as	<ANY_CHAR|COUNT>\
		 *		<minimum_match_count><maximum_match_count>
		 */

			get_match_counts(&nmust_match, &nextra_matches_allowed,
			    regexp + 1);
			if (!multibyte) {
				while ((*stringp != '\0') &&
				    (nmust_match > 0)) {
					nmust_match--;
					stringp++;
				}
				if (nmust_match > 0) {
					return ((char *)0);
				} else if (nextra_matches_allowed ==
				    UNLIMITED) {
					repeat_startp = stringp;
					while (*stringp != '\0') {
						stringp++;
					}
					regexp += 3;
					return (test_repeated_ascii_char(
					    repeat_startp, stringp, regexp));
				} else {
					repeat_startp = stringp;
					while ((*stringp != '\0') &&
					    (nextra_matches_allowed > 0)) {
						nextra_matches_allowed--;
						stringp++;
					}
					regexp += 3;
					return (test_repeated_ascii_char(
					    repeat_startp, stringp, regexp));
				}
			} else { /* multibyte character */

				string_char_size =
				    get_wchar(&string_wchar, stringp);
				while ((string_char_size > 0) &&
				    (nmust_match > 0)) {
					nmust_match--;
					stringp += string_char_size;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
				}
				if (nmust_match > 0) {
					return ((char *)0);
				} else if (nextra_matches_allowed ==
				    UNLIMITED) {
					repeat_startp = stringp;
					while (string_char_size > 0) {
						stringp += string_char_size;
						string_char_size =
						    get_wchar(&string_wchar,
						    stringp);
					}
					regexp += 3;
					return (test_repeated_multibyte_char(
					    repeat_startp, stringp, regexp));
				} else {
					repeat_startp = stringp;
					while ((string_char_size > 0) &&
					    (nextra_matches_allowed > 0)) {
						nextra_matches_allowed--;
						stringp += string_char_size;
						string_char_size =
						    get_wchar(&string_wchar,
						    stringp);
					}
					regexp += 3;
					return (test_repeated_multibyte_char(
					    repeat_startp, stringp, regexp));
				}
			} /* end case ANY_CHAR|COUNT */

		case IN_ASCII_CHAR_CLASS|ZERO_OR_MORE:	/* [.....]* */
		case NOT_IN_ASCII_CHAR_CLASS|ZERO_OR_MORE:

		/*
		 * encoded as	<IN_ASCII_CHAR_CLASS|ZERO_OR_MORE>\
		 *		<class_length><class ...>
		 *	or	<NOT_IN_ASCII_CHAR_CLASS|ZERO_OR_MORE>\
		 *		<class_length><class ...>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 */

		if ((int)*regexp == (int)(IN_ASCII_CHAR_CLASS|ZERO_OR_MORE)) {
			test_condition = IN_CLASS;
		} else {
			test_condition = NOT_IN_CLASS;
		}
		regexp++; /* point to the <class_length> byte */

		repeat_startp = stringp;
		while ((*stringp != '\0') &&
		    (test_char_against_ascii_class(*stringp, regexp,
		    test_condition) == CONDITION_TRUE)) {
			stringp++;
		}
		regexp += (int)*regexp; /* add the class length to regexp */
		return (test_repeated_ascii_char(repeat_startp, stringp,
		    regexp));

		/* end case IN_ASCII_CHAR_CLASS|ZERO_OR_MORE */

		case IN_ASCII_CHAR_CLASS|ONE_OR_MORE:	/* [.....]+ */
		case NOT_IN_ASCII_CHAR_CLASS|ONE_OR_MORE:

		/*
		 * encoded as	<IN_ASCII_CHAR_CLASS|ONE_OR_MORE>\
		 *		<class_length><class ...>
		 *	or	<NOT_IN_ASCII_CHAR_CLASS|ONE_OR_MORE>\
		 *		<class_length><class ...>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 */

			if ((int)*regexp ==
			    (int)(IN_ASCII_CHAR_CLASS|ONE_OR_MORE)) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			if ((*stringp == '\0') ||
			    (test_char_against_ascii_class(*stringp, regexp,
			    test_condition) != CONDITION_TRUE)) {
				return ((char *)0);
			} else {
				stringp++;
				repeat_startp = stringp;
				while ((*stringp != '\0') &&
				    (test_char_against_ascii_class(*stringp,
				    regexp, test_condition) ==
				    CONDITION_TRUE)) {
					stringp++;
				}
				/* add the class length to regexp */
				regexp += (int)*regexp;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			}
			/* end case IN_ASCII_CHAR_CLASS|ONE_OR_MORE */

		/* [.....]{max_count,min_count} */
		case IN_ASCII_CHAR_CLASS | COUNT:
		case NOT_IN_ASCII_CHAR_CLASS | COUNT:

		/*
		 * endoded as	<IN_ASCII_CHAR_CLASS|COUNT><class_length>\
		 *		<class ...><minimum_match_count>\
		 *		<maximum_match_count>
		 *	or	<NOT_IN_ASCII_CHAR_CLASS|COUNT><class_length>\
		 *		<class ...><minimum_match_count>\
		 *		<maximum_match_count>
		 *
		 * NOTE: <class_length> includes the <class_length> byte,
		 *	but not the <minimum_match_count> or
		 *	<maximum_match_count> bytes
		 */

			if ((int)*regexp == (int)(IN_ASCII_CHAR_CLASS|COUNT)) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			get_match_counts(&nmust_match, &nextra_matches_allowed,
			    regexp + (int)*regexp);
			while ((*stringp != '\0') &&
			    (test_char_against_ascii_class(*stringp, regexp,
			    test_condition) == CONDITION_TRUE) &&
			    (nmust_match > 0)) {
				nmust_match--;
				stringp++;
			}
			if (nmust_match > 0) {
				return ((char *)0);
			} else if (nextra_matches_allowed == UNLIMITED) {
				repeat_startp = stringp;
				while ((*stringp != '\0') &&
				    (test_char_against_ascii_class(*stringp,
				    regexp, test_condition) ==
				    CONDITION_TRUE)) {
					stringp++;
				}
				regexp += (int)*regexp + 2;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			} else {
				repeat_startp = stringp;
				while ((*stringp != '\0') &&
				    (test_char_against_ascii_class(*stringp,
				    regexp, test_condition) ==
				    CONDITION_TRUE) &&
				    (nextra_matches_allowed > 0)) {
					nextra_matches_allowed--;
					stringp++;
				}
				regexp += (int)*regexp + 2;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			}
			/* end case IN_ASCII_CHAR_CLASS|COUNT */

		case IN_MULTIBYTE_CHAR_CLASS|ZERO_OR_MORE:	/* [.....]* */
		case NOT_IN_MULTIBYTE_CHAR_CLASS|ZERO_OR_MORE:

		/*
		 * encoded as	<IN_MULTIBYTE_CHAR_CLASS|ZERO_OR_MORE>\
		 *		<class_length><class ...>
		 *	or	<NOT_IN_MULTIBYTE_CHAR_CLASS|ZERO_OR_MORE>\
		 *		<class_length><class ...>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 */

			if ((int)*regexp ==
			    (int)(IN_MULTIBYTE_CHAR_CLASS|ZERO_OR_MORE)) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			repeat_startp = stringp;
			string_char_size = get_wchar(&string_wchar, stringp);
			while ((string_char_size > 0) &&
			    (test_char_against_multibyte_class(string_wchar,
			    regexp, test_condition) == CONDITION_TRUE)) {
				stringp += string_char_size;
				string_char_size =
				    get_wchar(&string_wchar, stringp);
			}
			/* add the class length to regexp */
			regexp += (int)*regexp;
			return (test_repeated_multibyte_char(repeat_startp,
			    stringp, regexp));

			/* end case IN_MULTIBYTE_CHAR_CLASS|ZERO_OR_MORE */

		case IN_MULTIBYTE_CHAR_CLASS|ONE_OR_MORE:	/* [.....]+ */
		case NOT_IN_MULTIBYTE_CHAR_CLASS|ONE_OR_MORE:

		/*
		 * encoded as	<IN_MULTIBYTE_CHAR_CLASS|ONE_OR_MORE>\
		 *		<class_length><class ...>
		 *	or	<NOT_IN_MULTIBYTE_CHAR_CLASS|ONE_OR_MORE>\
		 *		<class_length><class ...>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 */

			if ((int)*regexp ==
			    (int)(IN_MULTIBYTE_CHAR_CLASS|ONE_OR_MORE)) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			string_char_size = get_wchar(&string_wchar, stringp);
			if ((string_char_size <= 0) ||
			    (test_char_against_multibyte_class(string_wchar,
			    regexp, test_condition) != CONDITION_TRUE)) {
				return ((char *)0);
			} else {
				stringp += string_char_size;
				repeat_startp = stringp;
				string_char_size =
				    get_wchar(&string_wchar, stringp);
				while ((string_char_size > 0) &&
				    (test_char_against_multibyte_class(
				    string_wchar, regexp, test_condition) ==
				    CONDITION_TRUE)) {
					stringp += string_char_size;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
				}
				/* add the class length to regexp */
				regexp += (int)*regexp;
				return (test_repeated_multibyte_char(
				    repeat_startp, stringp, regexp));
			}
			/* end case IN_MULTIBYTE_CHAR_CLASS|ONE_OR_MORE */

		/* [...]{min_count,max_count} */
		case IN_MULTIBYTE_CHAR_CLASS|COUNT:
		case NOT_IN_MULTIBYTE_CHAR_CLASS|COUNT:

		/*
		 * encoded as	<IN_MULTIBYTE_CHAR_CLASS|COUNT>\
		 *		<class_length><class ...><min_count><max_count>
		 *	or	<NOT_IN_MULTIBYTE_CHAR_CLASS|COUNT>\
		 *		<class_length><class ...><min_count><max_count>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 *	but not the <minimum_match_count> or
		 *	<maximum_match_count> bytes
		 */

			if ((int)*regexp ==
			    (int)(IN_MULTIBYTE_CHAR_CLASS|COUNT)) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			get_match_counts(&nmust_match, &nextra_matches_allowed,
			    regexp + (int)*regexp);
			string_char_size = get_wchar(&string_wchar, stringp);
			while ((string_char_size > 0) &&
			    (test_char_against_multibyte_class(string_wchar,
			    regexp, test_condition) == CONDITION_TRUE) &&
			    (nmust_match > 0)) {
				nmust_match--;
				stringp += string_char_size;
				string_char_size =
				    get_wchar(&string_wchar, stringp);
			}
			if (nmust_match > 0) {
				return ((char *)0);
			} else if (nextra_matches_allowed == UNLIMITED) {
				repeat_startp = stringp;
				while ((string_char_size > 0) &&
				    (test_char_against_multibyte_class(
				    string_wchar, regexp, test_condition) ==
				    CONDITION_TRUE)) {
					stringp += string_char_size;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
				}
				regexp += (int)*regexp + 2;
				return (test_repeated_multibyte_char(
				    repeat_startp, stringp, regexp));
			} else {
				repeat_startp = stringp;
				while ((string_char_size > 0) &&
				    (test_char_against_multibyte_class(
				    string_wchar, regexp, test_condition) ==
				    CONDITION_TRUE) &&
				    (nextra_matches_allowed > 0)) {
					nextra_matches_allowed--;
					stringp += string_char_size;
					string_char_size =
					    get_wchar(&string_wchar, stringp);
				}
				regexp += (int)*regexp + 2;
				return (test_repeated_multibyte_char(
				    repeat_startp, stringp, regexp));
			}
			/* end case IN_MULTIBYTE_CHAR_CLASS|COUNT */

		case IN_OLD_ASCII_CHAR_CLASS|ZERO_OR_MORE:	/* [.....]* */
		case NOT_IN_OLD_ASCII_CHAR_CLASS|ZERO_OR_MORE:

		/*
		 * encoded as	<IN_OLD_ASCII_CHAR_CLASS|ZERO_OR_MORE>\
		 *		<class_length><class ...>
		 *	or	<NOT_IN_OLD_ASCII_CHAR_CLASS|ZERO_OR_MORE>\
		 *		<class_length><class ...>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 */

			if ((int)*regexp ==
			    (int)(IN_OLD_ASCII_CHAR_CLASS|ZERO_OR_MORE)) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			repeat_startp = stringp;
			while ((*stringp != '\0') &&
			    (test_char_against_old_ascii_class(*stringp, regexp,
			    test_condition) == CONDITION_TRUE)) {
				stringp++;
			}
			/* add the class length to regexp */
			regexp += (int)*regexp;
			return (test_repeated_ascii_char(repeat_startp, stringp,
			    regexp));

			/* end case IN_OLD_ASCII_CHAR_CLASS|ZERO_OR_MORE */

		case IN_OLD_ASCII_CHAR_CLASS|ONE_OR_MORE:	/* [.....]+ */
		case NOT_IN_OLD_ASCII_CHAR_CLASS|ONE_OR_MORE:

		/*
		 * encoded as	<IN_OLD_ASCII_CHAR_CLASS|ONE_OR_MORE>\
		 *		<class_length><class ...>
		 *	or	<NOT_IN_OLD_ASCII_CHAR_CLASS|ONE_OR_MORE>\
		 *		<class_length><class ...>
		 *
		 * NOTE: <class length> includes the <class_length> byte
		 */

			if ((int)*regexp ==
			    (int)(IN_OLD_ASCII_CHAR_CLASS|ONE_OR_MORE)) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			if ((*stringp == '\0') ||
			    (test_char_against_old_ascii_class(*stringp, regexp,
			    test_condition) != CONDITION_TRUE)) {
				return ((char *)0);
			} else {
				stringp++;
				repeat_startp = stringp;
				while ((*stringp != '\0') &&
				    (test_char_against_old_ascii_class(*stringp,
				    regexp, test_condition) ==
				    CONDITION_TRUE)) {
					stringp++;
				}
				/* add the class length to regexp */
				regexp += (int)*regexp;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			}
			/* end case IN_OLD_ASCII_CHAR_CLASS | ONE_OR_MORE */

		/* [...]{min_count,max_count} */
		case IN_OLD_ASCII_CHAR_CLASS|COUNT:
		case NOT_IN_OLD_ASCII_CHAR_CLASS|COUNT:

		/*
		 * encoded as	<IN_OLD_ASCII_CHAR_CLASS|COUNT><class_length>\
		 *		<class ...><minimum_match_count>\
		 *		<maximum_match_count>
		 *	or	<NOT_IN_OLD_ASCII_CHAR_CLASS|COUNT>\
		 *		<class_length><class ...><minimum_match_count>\
		 *		<maximum_match_count>
		 *
		 * NOTE: <class_length> includes the <class_length> byte
		 *	but not the <minimum_match_count> or
		 *	<maximum_match_count> bytes
		 */

			if ((int)*regexp ==
			    (int)(IN_OLD_ASCII_CHAR_CLASS|COUNT)) {
				test_condition = IN_CLASS;
			} else {
				test_condition = NOT_IN_CLASS;
			}
			regexp++; /* point to the <class_length> byte */

			get_match_counts(&nmust_match, &nextra_matches_allowed,
			    regexp + (int)*regexp);
			while ((*stringp != '\0') &&
			    (test_char_against_old_ascii_class(*stringp, regexp,
			    test_condition) == CONDITION_TRUE) &&
			    (nmust_match > 0)) {
				nmust_match--;
				stringp++;
			}
			if (nmust_match > 0) {
				return ((char *)0);
			} else if (nextra_matches_allowed == UNLIMITED) {
				repeat_startp = stringp;
				while ((*stringp != '\0') &&
				    (test_char_against_old_ascii_class(*stringp,
				    regexp,
				    test_condition) == CONDITION_TRUE)) {
					stringp++;
				}
				regexp += (int)*regexp + 2;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			} else {
				repeat_startp = stringp;
				while ((*stringp != '\0') &&
				    (test_char_against_old_ascii_class(*stringp,
				    regexp,
				    test_condition) == CONDITION_TRUE) &&
				    (nextra_matches_allowed > 0)) {
					nextra_matches_allowed--;
					stringp++;
				}
				regexp += (int)*regexp + 2;
				return (test_repeated_ascii_char(repeat_startp,
				    stringp, regexp));
			}
			/* end case IN_OLD_ASCII_CHAR_CLASS|COUNT */

		case ZERO_OR_MORE_GROUP:		/* (.....)* */
		case ZERO_OR_MORE_GROUP|ADD_256_TO_GROUP_LENGTH:
		case ZERO_OR_MORE_GROUP|ADD_512_TO_GROUP_LENGTH:
		case ZERO_OR_MORE_GROUP|ADD_768_TO_GROUP_LENGTH:

		/*
		 * encoded as	<ZERO_OR_MORE_GROUP|ADDED_LENGTH_BITS>\
		 *		<group_length><compiled_regex...>\
		 *		<END_GROUP|ZERO_OR_MORE><groupn>
		 *
		 * NOTE:
		 *
		 * group_length + (256 * ADDED_LENGTH_BITS) ==
		 *	length_of(<compiled_regex...><END_GROUP|ZERO_OR_MORE>\
		 *		<groupn>)
		 *
		 */

			group_length =
			    (((unsigned int)*regexp & ADDED_LENGTH_BITS) <<
			    TIMES_256_SHIFT);
			regexp++;
			group_length += (unsigned int)*regexp;
			regexp++;
			repeat_startp = stringp;
			test_stringp = test_string(stringp, regexp);
			while (test_stringp != (char *)0) {
				if (push_stringp(stringp) == (char *)0)
					return ((char *)0);
				stringp = test_stringp;
				test_stringp = test_string(stringp, regexp);
			}
			regexp += group_length;
			return (test_repeated_group(repeat_startp, stringp,
			    regexp));

			/* end case ZERO_OR_MORE_GROUP */

		case END_GROUP|ZERO_OR_MORE:	/* (.....)* */

			/* encoded as <END_GROUP|ZERO_OR_MORE> */

			/* return from recursive call to test_string() */

			return ((char *)stringp);

		/* end case END_GROUP|ZERO_OR_MORE */

		case ONE_OR_MORE_GROUP:		/* (.....)+ */
		case ONE_OR_MORE_GROUP|ADD_256_TO_GROUP_LENGTH:
		case ONE_OR_MORE_GROUP|ADD_512_TO_GROUP_LENGTH:
		case ONE_OR_MORE_GROUP|ADD_768_TO_GROUP_LENGTH:

		/*
		 * encoded as	<ONE_OR_MORE_GROUP|ADDED_LENGTH_BITS>\
		 *		<group_length><compiled_regex...>\
		 *		<END_GROUP|ONE_OR_MORE><groupn>
		 *
		 * NOTE:
		 *
		 * group_length + (256 * ADDED_LENGTH_BITS) ==
		 *	length_of(<compiled_regex...><END_GROUP|ONE_OR_MORE>\
		 *		<groupn>)
		 */

			group_length =
			    (((unsigned int)*regexp & ADDED_LENGTH_BITS) <<
			    TIMES_256_SHIFT);
			regexp++;
			group_length += (unsigned int)*regexp;
			regexp++;
			stringp = test_string(stringp, regexp);
			if (stringp == (char *)0)
				return ((char *)0);
			repeat_startp = stringp;
			test_stringp = test_string(stringp, regexp);
			while (test_stringp != (char *)0) {
				if (push_stringp(stringp) == (char *)0)
					return ((char *)0);
				stringp = test_stringp;
				test_stringp = test_string(stringp, regexp);
			}
			regexp += group_length;
			return (test_repeated_group(repeat_startp, stringp,
			    regexp));

			/* end case ONE_OR_MORE_GROUP */

		case END_GROUP|ONE_OR_MORE:		/* (.....)+ */

		/* encoded as <END_GROUP|ONE_OR_MORE><groupn> */

		/* return from recursive call to test_string() */

		return ((char *)stringp);

		/* end case END_GROUP|ONE_OR_MORE */

		case COUNTED_GROUP:	/* (.....){max_count,min_count} */
		case COUNTED_GROUP|ADD_256_TO_GROUP_LENGTH:
		case COUNTED_GROUP|ADD_512_TO_GROUP_LENGTH:
		case COUNTED_GROUP|ADD_768_TO_GROUP_LENGTH:

		/*
		 * encoded as	<COUNTED_GROUP|ADDED_LENGTH_BITS><group_length>\
		 *		<compiled_regex...>\<END_GROUP|COUNT><groupn>\
		 *		<minimum_match_count><maximum_match_count>
		 *
		 * NOTE:
		 *
		 * group_length + (256 * ADDED_LENGTH_BITS) ==
		 *	length_of(<compiled_regex...><END_GROUP|COUNT><groupn>)
		 *
		 * but does not include the <minimum_match_count> or
		 *	<maximum_match_count> bytes
		 */

			group_length =
			    (((unsigned int)*regexp & ADDED_LENGTH_BITS) <<
			    TIMES_256_SHIFT);
			regexp++;
			group_length += (unsigned int)*regexp;
			regexp++;
			get_match_counts(&nmust_match, &nextra_matches_allowed,
			    regexp + group_length);
			test_stringp = test_string(stringp, regexp);
			while ((test_stringp != NULL) && (nmust_match > 0)) {
				stringp = test_stringp;
				nmust_match--;
				test_stringp = test_string(stringp, regexp);
			}
			if (nmust_match > 0) {
				return ((char *)0);
			} else if (nextra_matches_allowed == UNLIMITED) {
				repeat_startp = stringp;
				while (test_stringp != (char *)0) {
					if (push_stringp(stringp) == (char *)0)
						return ((char *)0);
					stringp = test_stringp;
					test_stringp = test_string(stringp,
					    regexp);
				}
				regexp += group_length + 2;
				return (test_repeated_group(repeat_startp,
				    stringp, regexp));
			} else {
				repeat_startp = stringp;
				while ((test_stringp != (char *)0) &&
				    (nextra_matches_allowed > 0)) {
					nextra_matches_allowed--;
					if (push_stringp(stringp) == (char *)0)
						return ((char *)0);
					stringp = test_stringp;
					test_stringp =
					    test_string(stringp, regexp);
				}
				regexp += group_length + 2;
				return (test_repeated_group(repeat_startp,
				    stringp, regexp));
			}
			/* end case COUNTED_GROUP */

		case END_GROUP|COUNT:	/* (.....){max_count,min_count} */

			/* encoded as <END_GROUP|COUNT> */

			/* return from recursive call to test_string() */

			return (stringp);

			/* end case END_GROUP|COUNT */

		case END_OF_STRING_MARK:

			/* encoded as <END_OF_STRING_MARK><END_REGEX> */

			if (*stringp == '\0') {
				regexp++;
			} else {
				return ((char *)0);
			}
			break; /* end case END_OF_STRING_MARK */

		case END_REGEX: /* end of the compiled regular expression */

			/* encoded as <END_REGEX> */

			return (stringp);

			/* end case END_REGEX */

		default:

			return ((char *)0);

		} /* end switch (*regexp) */

	} /* end for (;;) */

} /* test_string() */
