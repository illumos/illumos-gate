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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IMPORTANT NOTE:
 *
 * regcmp() WORKS **ONLY** WITH THE ASCII AND THE Solaris EUC CHARACTER SETS.
 * IT IS **NOT** CHARACTER SET INDEPENDENT.
 *
 */

#pragma weak _regcmp = regcmp

#include "lint.h"
#include "mtlib.h"
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <thread.h>
#include <wctype.h>
#include <widec.h>
#include <string.h>
#include "tsd.h"


/* CONSTANTS SHARED WITH regex() */

#include "regex.h"

/* PRIVATE CONSTANTS */

#define	BACKSLASH		'\\'
#define	CIRCUMFLEX		'^'
#define	COMMA			','
#define	DASH			'-'
#define	DOLLAR_SIGN		'$'
#define	DOT			'.'
#define	LEFT_CURLY_BRACE	'{'
#define	LEFT_PAREN		'('
#define	LEFT_SQUARE_BRACKET	'['
#define	PLUS			'+'
#define	RIGHT_CURLY_BRACE	'}'
#define	RIGHT_PAREN		')'
#define	RIGHT_SQUARE_BRACKET	']'
#define	SINGLE_BYTE_MASK	0xff
#define	STRINGP_STACK_SIZE	50
#define	STAR			'*'

/* PRIVATE GLOBAL VARIABLES */

static char	*compilep_stack[STRINGP_STACK_SIZE];
static char	**compilep_stackp;
static mutex_t  regcmp_lock = DEFAULTMUTEX;

/* DECLARATIONS OF PRIVATE FUNCTIONS */

static int add_char(char *compilep, wchar_t wchar);
static int add_single_char_expr(char *compilep, wchar_t wchar);

#define	ERROR_EXIT(mutex_lockp, arg_listp, compile_startp) \
\
	va_end(arg_listp); \
	lmutex_unlock(mutex_lockp); \
	if ((compile_startp) != (char *)0) \
		free((void *)compile_startp); \
	return ((char *)0)

static int get_count(int *countp, const char *regexp);
static int get_digit(const char *regexp);
static int get_wchar(wchar_t *wchar, const char *regexp);
static char *pop_compilep(void);
static char *push_compilep(char *compilep);
static boolean_t valid_range(wchar_t lower_char, wchar_t upper_char);


/* DEFINITIONS OF PUBLIC VARIABLES */

int __i_size;

/*
 * define thread-specific storage for __i_size
 *
 */
int *
___i_size(void)
{
	if (thr_main())
		return (&__i_size);
	return ((int *)tsdalloc(_T_REGCMP_ISIZE, sizeof (int), NULL));
}

#define		__i_size (*(___i_size()))

/* DEFINITION OF regcmp() */

extern char *
regcmp(const char *regexp, ...)
{
	va_list		arg_listp;
	size_t		arg_strlen;
	boolean_t	can_repeat;
	int		char_size;
	unsigned int	class_length;
	char		*compilep;
	char		*compile_startp = (char *)0;
	int		count_length;
	wchar_t		current_char;
	int		expr_length;
	int		groupn;
	unsigned int	group_length;
	unsigned int	high_bits;
	boolean_t	dash_indicates_range;
	unsigned int	low_bits;
	int		max_count;
	int		min_count;
	const char	*next_argp;
	wchar_t		first_char_in_range;
	char		*regex_typep;
	int		return_arg_number;
	int		substringn;

	if (___i_size() == (int *)0)
		return ((char *)0);

	/*
	 * When compiling a regular expression, regcmp() generates at most
	 * two extra single-byte characters for each character in the
	 * expression, so allocating three times the number of bytes in all
	 * the strings that comprise the regular expression will ensure that
	 * regcmp() won't overwrite the end of the allocated block when
	 * compiling the expression.
	 */

	va_start(arg_listp, regexp);
	next_argp = regexp;
	arg_strlen = 0;
	while (next_argp != (char *)0) {
		arg_strlen += strlen(next_argp);
		next_argp = va_arg(arg_listp, /* const */ char *);
	}
	va_end(arg_listp);

	if (arg_strlen == 0)
		return ((char *)0);
	compile_startp = (char *)malloc(3 * arg_strlen);
	if (compile_startp == (char *)0)
		return ((char *)0);

	lmutex_lock(&regcmp_lock);
	__i_size = 0;
	compilep = compile_startp;
	compilep_stackp = &compilep_stack[STRINGP_STACK_SIZE];

	/* GET THE FIRST CHARACTER IN THE REGULAR EXPRESSION */
	va_start(arg_listp, regexp);
	next_argp = va_arg(arg_listp, /* const */ char *);
	char_size = get_wchar(&current_char, regexp);
	if (char_size < 0) {
		ERROR_EXIT(&regcmp_lock, arg_listp, compile_startp);
	} else if (char_size > 0) {
		regexp += char_size;
	} else /* (char_size == 0 ) */ {
		regexp = next_argp;
		next_argp = va_arg(arg_listp, /* const */ char *);
		char_size = get_wchar(&current_char, regexp);
		if (char_size <= 0) {
			ERROR_EXIT(&regcmp_lock, arg_listp, compile_startp);
		} else {
			regexp += char_size;
		}
	}

	/* FIND OUT IF THE EXPRESSION MUST START AT THE START OF A STRING */

	if (current_char == CIRCUMFLEX) {
		char_size = get_wchar(&current_char, regexp);
		if (char_size < 0) {
			ERROR_EXIT(&regcmp_lock, arg_listp, compile_startp);
		} else if (char_size > 0) {
			regexp += char_size;
			*compilep = (unsigned char)START_OF_STRING_MARK;
			compilep++;
		} else if /* (char_size == 0) && */ (next_argp != (char *)0) {
			regexp = next_argp;
			next_argp = va_arg(arg_listp, /* const */ char *);
			char_size = get_wchar(&current_char, regexp);
			if (char_size <= 0) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
				    compile_startp);
			} else {
				regexp += char_size;
			}
			*compilep = (unsigned char)START_OF_STRING_MARK;
			compilep++;
		} else {
			/* ((char_size==0) && (next_argp==(char *)0)) */
			/*
			 * the regular expression is "^"
			 */
			*compilep = (unsigned char)START_OF_STRING_MARK;
			compilep++;
			*compilep = (unsigned char)END_REGEX;
			compilep++;
			*compilep = '\0';
			compilep++;
			__i_size = (int)(compilep - compile_startp);
			va_end(arg_listp);
			lmutex_unlock(&regcmp_lock);
			return (compile_startp);
		}
	}

	/* COMPILE THE REGULAR EXPRESSION */

	groupn = 0;
	substringn = 0;
	can_repeat = B_FALSE;
	for (;;) {

		/*
		 * At the end of each iteration get the next character
		 * from the regular expression and increment regexp to
		 * point to the following character.  Exit when all
		 * the characters in all the strings in the argument
		 * list have been read.
		 */

		switch (current_char) {

			/*
			 * No fall-through.  Each case ends with either
			 * a break or an error exit.  Each case starts
			 * with compilep addressing the next location to
			 * be written in the compiled regular expression,
			 * and with regexp addressing the next character
			 * to be read from the regular expression being
			 * compiled.  Each case that doesn't return
			 * increments regexp to address the next character
			 * to be read from the regular expression and
			 * increments compilep to address the next
			 * location to be written in the compiled
			 * regular expression.
			 *
			 * NOTE: The comments for each case give the meaning
			 * of the regular expression compiled by the case
			 * and the character string written to the compiled
			 * regular expression by the case.  Each single
			 * character
			 * written to the compiled regular expression is
			 * shown enclosed in angle brackets (<>).  Each
			 * compiled regular expression begins with a marker
			 * character which is shown as a named constant
			 * (e.g. <ASCII_CHAR>). Character constants are
			 * shown enclosed in single quotes (e.g. <'$'>).
			 * All other single characters written to the
			 * compiled regular expression are shown as lower
			 * case variable names (e.g. <ascii_char> or
			 * <multibyte_char>). Multicharacter
			 * strings written to the compiled regular expression
			 * are shown as variable names followed by elipses
			 * (e.g. <regex...>).
			 */

		case DOLLAR_SIGN:
			/* end of string marker or simple dollar sign */
			/* compiles to <END_OF_STRING_MARK> or */
			/* <ASCII_CHAR><'$'> */

			char_size = get_wchar(&current_char, regexp);
			if ((char_size == 0) && (next_argp == (char *)0)) {
				can_repeat = B_FALSE;
				*compilep = (unsigned char)END_OF_STRING_MARK;
				compilep++;
			} else {
				can_repeat = B_TRUE;
				*compilep = (unsigned char)ASCII_CHAR;
				regex_typep = compilep;
				compilep++;
				*compilep = DOLLAR_SIGN;
				compilep++;
			}
			break; /* end case DOLLAR_SIGN */

		case DOT: /* any character */

			/* compiles to <ANY_CHAR> */

			can_repeat = B_TRUE;
			*compilep = (unsigned char)ANY_CHAR;
			regex_typep = compilep;
			compilep++;

			break; /* end case DOT */

		case BACKSLASH: /* escaped character */

			/*
			 * compiles to <ASCII_CHAR><ascii_char> or
			 * <MULTIBYTE_CHAR><multibyte_char>
			 */

			char_size = get_wchar(&current_char, regexp);
			if (char_size <= 0) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
				    compile_startp);
			} else {
				regexp += char_size;
				can_repeat = B_TRUE;
				expr_length = add_single_char_expr(
				    compilep, current_char);
				regex_typep = compilep;
				compilep += expr_length;
			}
			break; /* end case '\\' */

		case LEFT_SQUARE_BRACKET:
			/* start of a character class expression */

			/*
			 * [^...c...] compiles to
			 * <NOT_IN_CLASS><class_length><...c...>
			 * [^...a-z...] compiles to
			 * <NOT_IN_CLASS><class_length><...a<THRU>z...>
			 * [...c...] compiles to
			 * <IN_CLASS><class_length><...c...>
			 * [...a-z...] compiles to
			 * <IN_CLASS><class_length><...a<THRU>z...>
			 *
			 * NOTE: <class_length> includes the
			 * <class_length> byte
			 */

			can_repeat = B_TRUE;
			regex_typep = compilep;

			/* DETERMINE THE CLASS TYPE */

			/*
			 * NOTE: This algorithm checks the value of the
			 * "multibyte"
			 * macro in <euc.h> (included in <widec.h> )
			 * to find out if regcmp()
			 * is compiling the regular expression in a
			 * multibyte locale.
			 */
			char_size = get_wchar(&current_char, regexp);
			if (char_size <= 0) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
				    compile_startp);
			} else if (current_char == CIRCUMFLEX) {
				regexp++;
				char_size = get_wchar(&current_char, regexp);
				if (char_size <= 0) {
					ERROR_EXIT(&regcmp_lock,
					    arg_listp, compile_startp);
				} else {
					regexp += char_size;
					if (!multibyte) {
						*compilep = (unsigned char)
						    NOT_IN_ASCII_CHAR_CLASS;
					} else {
						*compilep = (unsigned char)
						    NOT_IN_MULTIBYTE_CHAR_CLASS;
					}
					/* leave space for <class_length> */
					compilep += 2;
				}
			} else {
				regexp += char_size;
				if (!multibyte) {
					*compilep = (unsigned char)
					    IN_ASCII_CHAR_CLASS;
				} else {
					*compilep = (unsigned char)
					    IN_MULTIBYTE_CHAR_CLASS;
				}
				/* leave space for <class_length> */
				compilep += 2;
			}

			/* COMPILE THE CLASS */
			/*
			 * check for a leading right square bracket,
			 * which is allowed
			 */

			if (current_char == RIGHT_SQUARE_BRACKET) {
				/*
				 * the leading RIGHT_SQUARE_BRACKET may
				 * be part of a character range
				 * expression like "[]-\]"
				 */
				dash_indicates_range = B_TRUE;
				first_char_in_range = current_char;
				char_size = get_wchar(&current_char, regexp);
				if (char_size <= 0) {
					ERROR_EXIT(&regcmp_lock,
					    arg_listp, compile_startp);
				} else {
					regexp += char_size;
					*compilep = RIGHT_SQUARE_BRACKET;
					compilep++;
				}
			} else {
				/*
				 * decode the character in the following
				 * while loop and decide then if it can
				 * be the first character
				 * in a character range expression
				 */
				dash_indicates_range = B_FALSE;
			}

			while (current_char != RIGHT_SQUARE_BRACKET) {
				if (current_char != DASH) {
					/*
					 * if a DASH follows current_char,
					 *  current_char, the DASH and the
					 * character that follows the DASH
					 * may form a character range
					 * expression
					 */
					dash_indicates_range = B_TRUE;
					first_char_in_range = current_char;
					expr_length = add_char(
					    compilep, current_char);
					compilep += expr_length;

				} else if /* (current_char == DASH) && */
					(dash_indicates_range == B_FALSE) {
					/*
					 * current_char is a DASH, but
					 * either begins the entire
					 * character class or follows a
					 * character that's already
					 * part of a character range
					 * expression, so it simply
					 * represents the DASH character
					 * itself
					 */
					*compilep = DASH;
					compilep ++;
					/*
					 * if another DASH follows this
					 * one, this DASH is part
					 * of a character range expression
					 * like "[--\]"
					 */
					dash_indicates_range = B_TRUE;
					first_char_in_range = current_char;

				} else /* ((current_char == DASH && */
				/* (dash_indicates_range == B_TRUE)) */ {
					/*
					 * the DASH appears after a single
					 * character that isn't
					 * already part of a character
					 * range expression, so it
					 * and the characters preceding
					 * and following it can form a
					 * character range expression
					 * like "[a-z]"
					 */
					char_size = get_wchar(
					    &current_char, regexp);
					if (char_size <= 0) {
						ERROR_EXIT(&regcmp_lock,
						    arg_listp, compile_startp);

					} else if (current_char ==
						RIGHT_SQUARE_BRACKET) {
						/*
						 * the preceding DASH is
						 * the last character in the
						 * class and represents the
						 * DASH character itself
						 */
						*compilep = DASH;
						compilep++;

					} else if (valid_range(
					    first_char_in_range,
					    current_char) == B_FALSE) {

						ERROR_EXIT(&regcmp_lock,
						arg_listp, compile_startp);

					} else {
						/*
						 * the DASH is part of a
						 * character range
						 * expression; encode the
						 * rest of the expression
						 */
						regexp += char_size;
						*compilep = (unsigned char)
						    THRU;
						compilep++;
						expr_length = add_char(
						    compilep, current_char);
						compilep += expr_length;
						/*
						 * if a DASH follows this
						 * character range
						 * expression,
						 * it represents the DASH
						 * character itself
						 */
						dash_indicates_range =
						    B_FALSE;
					}
				}

				/* GET THE NEXT CHARACTER */

				char_size = get_wchar(&current_char, regexp);
				if (char_size <= 0) {
					ERROR_EXIT(&regcmp_lock,
					    arg_listp, compile_startp);
				} else {
					regexp += char_size;
				}

			}
			/* end while (current_char != RIGHT_SQUARE_BRACKET) */

			/* INSERT THE LENGTH OF THE CLASS INTO THE */
			/* COMPILED EXPRESSION */

			class_length = (unsigned int)
			    (compilep - regex_typep - 1);
			if ((class_length < 2) ||
			    (class_length > MAX_SINGLE_BYTE_INT)) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
				    compile_startp);
			} else {
				*(regex_typep + 1) = (unsigned char)
				    class_length;
			}
			break; /* end case LEFT_SQUARE_BRACKET */

		case LEFT_PAREN:

			/*
			 * start of a parenthesized group of regular
			 * expressions compiles to <'\0'><'\0'>, leaving
			 * space in the compiled regular expression for
			 * <group_type|ADDED_LENGTH_BITS><group_length>
			 */

			if (push_compilep(compilep) == (char *)0) {
				/*
				 * groups can contain groups, so group
				 * start pointers
				 * must be saved and restored in sequence
				 */
				ERROR_EXIT(&regcmp_lock, arg_listp,
				    compile_startp);
			} else {
				can_repeat = B_FALSE;
				*compilep = '\0';	/* for debugging */
				compilep++;
				*compilep = '\0';	/* for debugging */
				compilep++;
			}
			break; /* end case LEFT_PAREN */

		case RIGHT_PAREN:
			/* end of a marked group of regular expressions */

			/*
			 * (<regex>)$0-9 compiles to
			 * <SAVED_GROUP><substringn><compiled_regex...>\
			 * <END_SAVED_GROUP><substringn><return_arg_number>
			 * (<regex>)* compiles to
			 * <ZERO_OR_MORE_GROUP|ADDED_LENGTH_BITS>
			 * <group_length> <compiled_regex...>
			 * <END_GROUP|ZERO_OR_MORE><groupn>
			 * (<regex>)+ compiles to
			 * <ONE_OR_MORE_GROUP|ADDED_LENGTH_BITS>
			 * <group_length>\
			 * <compiled_regex...><END_GROUP|ONE_OR_MORE>
			 * <groupn>
			 * (<regex>){...} compiles to
			 * <COUNTED_GROUP|ADDED_LENGTH_BITS><group_length>\
			 * <compiled_regex...><END_GROUP|COUNT><groupn>\
			 * <minimum_repeat_count><maximum_repeat_count>
			 * otherwise (<regex>) compiles to
			 * <SIMPLE_GROUP><blank><compiled_regex...>
			 * <END_GROUP><groupn>
			 *
			 * NOTE:
			 *
			 * group_length + (256 * ADDED_LENGTH_BITS) ==
			 * length_of(<compiled_regex...><END_GROUP|...>
			 * <groupn>)
			 * which also ==
			 * length_of(<group_type|ADDED_LENGTH_BITS>
			 * <group_length>\ <compiled_regex...>)
			 * groupn no longer seems to be used, but the code
			 * still computes it to preserve backward
			 * compatibility
			 * with earlier versions of regex().
			 */

			/* RETRIEVE THE ADDRESS OF THE START OF THE GROUP */

			regex_typep = pop_compilep();
			if (regex_typep == (char *)0) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
				    compile_startp);
			}
			char_size = get_wchar(&current_char, regexp);
			if (char_size < 0) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
				    compile_startp);
			} else if (char_size == 0) {
				*regex_typep = SIMPLE_GROUP;
				can_repeat = B_TRUE;
				*compilep = (unsigned char)END_GROUP;
				regex_typep = compilep;
				compilep++;
				*compilep = (unsigned char)groupn;
				groupn++;
				compilep++;
			} else if (current_char == DOLLAR_SIGN) {
				*regex_typep = SAVED_GROUP;
				regex_typep++;
				*regex_typep = (char)substringn;
				can_repeat = B_FALSE;
				regexp ++;
				return_arg_number = get_digit(regexp);
				if ((return_arg_number < 0) ||
				    (substringn >= NSUBSTRINGS)) {
					ERROR_EXIT(&regcmp_lock, arg_listp,
					    compile_startp);
				}
				regexp++;
				*compilep = (unsigned char)END_SAVED_GROUP;
				compilep++;
				*compilep = (unsigned char)substringn;
				substringn++;
				compilep++;
				*compilep = (unsigned char)return_arg_number;
				compilep++;
			} else {
				switch (current_char) {
				case STAR:
					*regex_typep = ZERO_OR_MORE_GROUP;
					break;
				case PLUS:
					*regex_typep = ONE_OR_MORE_GROUP;
					break;
				case LEFT_CURLY_BRACE:
					*regex_typep = COUNTED_GROUP;
					break;
				default:
					*regex_typep = SIMPLE_GROUP;
				}
				if (*regex_typep != SIMPLE_GROUP) {
					group_length = (unsigned int)
						(compilep - regex_typep);
					if (group_length >= 1024) {
						ERROR_EXIT(&regcmp_lock,
						arg_listp, compile_startp);
					}
					high_bits = group_length >>
					    TIMES_256_SHIFT;
					low_bits = group_length &
					    SINGLE_BYTE_MASK;
					*regex_typep =
					    (unsigned char)
					    ((unsigned int)
						*regex_typep | high_bits);
					regex_typep++;
					*regex_typep =
					    (unsigned char)low_bits;
				}
				can_repeat = B_TRUE;
				*compilep = (unsigned char)END_GROUP;
				regex_typep = compilep;
				compilep++;
				*compilep = (unsigned char)groupn;
				groupn++;
				compilep++;
			}

			break; /* end case RIGHT_PAREN */

		case STAR: /* zero or more repetitions of the */
				/* preceding expression */

			/*
			 * <regex...>* compiles to <regex_type|ZERO_OR_MORE>\
			 * <compiled_regex...>
			 * (<regex...>)* compiles to
			 * <ZERO_OR_MORE_GROUP|ADDED_LENGTH_BITS>\
			 * <group_length><compiled_regex...>\
			 * <END_GROUP|ZERO_OR_MORE><groupn>
			 */

			if (can_repeat == B_FALSE) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
				    compile_startp);
			} else {
				can_repeat = B_FALSE;
				*regex_typep = (unsigned char)
				((unsigned int)*regex_typep | ZERO_OR_MORE);
			}
			break; /* end case '*' */

		case PLUS:
			/* one or more repetitions of the preceding */
				/* expression */

			/*
			 * <regex...>+ compiles to <regex_type|ONE_OR_MORE>\
			 * <compiled_regex...> (<regex...>)+ compiles to
			 * <ONE_OR_MORE_GROUP|ADDED_LENGTH_BITS>\
			 * <group_length><compiled_regex...>\
			 * <END_GROUP|ONE_OR_MORE><groupn>
			 */

			if (can_repeat == B_FALSE) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
					compile_startp);
			} else {
				can_repeat = B_FALSE;
				*regex_typep =
					(unsigned char)((unsigned int)*
					regex_typep | ONE_OR_MORE);
			}
			break; /* end case '+' */

		case LEFT_CURLY_BRACE:

			/*
			 * repeat the preceding regular expression
			 * at least min_count times
			 * and at most max_count times
			 *
			 * <regex...>{min_count} compiles to
			 * <regex type|COUNT><compiled_regex...>
			 * <min_count><min_count>
			 *
			 * <regex...>{min_count,} compiles to
			 * <regex type|COUNT><compiled_regex...>
			 * <min_count><UNLIMITED>
			 *
			 * <regex...>{min_count,max_count} compiles to
			 * <regex type>|COUNT><compiled_regex...>
			 * <min_count><max_count>
			 *
			 * (<regex...>){min_count,max_count} compiles to
			 * <COUNTED_GROUP|ADDED_LENGTH_BITS><group_length>\
			 * <compiled_regex...><END_GROUP|COUNT><groupn>\
			 * <minimum_match_count><maximum_match_count>
			 */

			if (can_repeat == B_FALSE) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
					compile_startp);
			}
			can_repeat = B_FALSE;
			*regex_typep = (unsigned char)((unsigned int)*
					regex_typep | COUNT);
			count_length = get_count(&min_count, regexp);
			if (count_length <= 0) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
					compile_startp);
			}
			regexp += count_length;

			if (*regexp == RIGHT_CURLY_BRACE) { /* {min_count} */
				regexp++;
				max_count = min_count;
			} else if (*regexp == COMMA) { /* {min_count,..} */
				regexp++;
				/* {min_count,}   */
				if (*regexp == RIGHT_CURLY_BRACE) {
					regexp++;
					max_count = UNLIMITED;
				} else { /* {min_count,max_count} */
					count_length = get_count(
						&max_count, regexp);
					if (count_length <= 0) {
						ERROR_EXIT(&regcmp_lock,
						arg_listp, compile_startp);
					}
					regexp += count_length;
					if (*regexp != RIGHT_CURLY_BRACE) {
						ERROR_EXIT(&regcmp_lock,
						arg_listp, compile_startp);
					}
					regexp++;
				}
			} else { /* invalid expression */
				ERROR_EXIT(&regcmp_lock, arg_listp,
					compile_startp);
			}

			if ((min_count > MAX_SINGLE_BYTE_INT) ||
				((max_count != UNLIMITED) &&
				(min_count > max_count))) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
					compile_startp);
			} else {
				*compilep = (unsigned char)min_count;
				compilep++;
				*compilep = (unsigned char)max_count;
				compilep++;
			}
			break; /* end case LEFT_CURLY_BRACE */

		default: /* a single non-special character */

			/*
			 * compiles to <ASCII_CHAR><ascii_char> or
			 * <MULTIBYTE_CHAR><multibyte_char>
			 */

			can_repeat = B_TRUE;
			regex_typep = compilep;
			expr_length = add_single_char_expr(compilep,
					current_char);
			compilep += expr_length;

		} /* end switch (current_char) */

		/* GET THE NEXT CHARACTER FOR THE WHILE LOOP */

		char_size = get_wchar(&current_char, regexp);
		if (char_size < 0) {
			ERROR_EXIT(&regcmp_lock, arg_listp, compile_startp);
		} else if (char_size > 0) {
			regexp += char_size;
		} else if /* (char_size == 0) && */ (next_argp != (char *)0) {
			regexp = next_argp;
			next_argp = va_arg(arg_listp, /* const */ char *);
			char_size = get_wchar(&current_char, regexp);
			if (char_size <= 0) {
				ERROR_EXIT(&regcmp_lock, arg_listp,
					compile_startp);
			} else {
				regexp += char_size;
			}
		} else /* ((char_size == 0) && (next_argp == (char *)0)) */ {
			if (pop_compilep() != (char *)0) {
				/* unmatched parentheses */
				ERROR_EXIT(&regcmp_lock, arg_listp,
					compile_startp);
			}
			*compilep = (unsigned char)END_REGEX;
			compilep++;
			*compilep = '\0';
			compilep++;
			__i_size = (int)(compilep - compile_startp);
			va_end(arg_listp);
			lmutex_unlock(&regcmp_lock);
			return (compile_startp);
		}
	} /* end for (;;) */

} /* regcmp() */


/* DEFINITIONS OF PRIVATE FUNCTIONS */

static int
add_char(char *compilep, wchar_t wchar)
{
	int expr_length;

	if ((unsigned int)wchar <= (unsigned int)0x7f) {
		*compilep = (unsigned char)wchar;
		expr_length = 1;
	} else {
		expr_length = wctomb(compilep, wchar);
	}
	return (expr_length);
}

static int
add_single_char_expr(char *compilep, wchar_t wchar)
{
	int expr_length = 0;

	if ((unsigned int)wchar <= (unsigned int)0x7f) {
		*compilep = (unsigned char)ASCII_CHAR;
		compilep++;
		*compilep = (unsigned char)wchar;
		expr_length += 2;
	} else {
		*compilep = (unsigned char)MULTIBYTE_CHAR;
		compilep++;
		expr_length++;
		expr_length += wctomb(compilep, wchar);
	}
	return (expr_length);
}

static int
get_count(int *countp, const char *regexp)
{
	char count_char = '0';
	int count = 0;
	int count_length = 0;

	if (regexp == (char *)0) {
		return ((int)0);
	} else {
		count_char = *regexp;
		while (('0' <= count_char) && (count_char <= '9')) {
			count = (10 * count) + (int)(count_char - '0');
			count_length++;
			regexp++;
			count_char = *regexp;
		}
	}
	*countp = count;
	return (count_length);
}

static int
get_digit(const char *regexp)
{
	char digit;

	if (regexp == (char *)0) {
		return ((int)-1);
	} else {
		digit = *regexp;
		if (('0' <= digit) && (digit <= '9')) {
			return ((int)(digit - '0'));
		} else {
			return ((int)-1);
		}
	}
}

static int
get_wchar(wchar_t *wcharp, const char *regexp)
{
	int char_size;

	if (regexp == (char *)0) {
		char_size = 0;
		*wcharp = (wchar_t)((unsigned int)'\0');
	} else if (*regexp == '\0') {
		char_size = 0;
		*wcharp = (wchar_t)((unsigned int)*regexp);
	} else if ((unsigned char)*regexp <= (unsigned char)0x7f) {
		char_size = 1;
		*wcharp = (wchar_t)((unsigned int)*regexp);
	} else {
		char_size = mbtowc(wcharp, regexp, MB_LEN_MAX);
	}
	return (char_size);
}

static char *
pop_compilep(void)
{
	char *compilep;

	if (compilep_stackp >= &compilep_stack[STRINGP_STACK_SIZE]) {
		return ((char *)0);
	} else {
		compilep = *compilep_stackp;
		compilep_stackp++;
		return (compilep);
	}
}

static char *
push_compilep(char *compilep)
{
	if (compilep_stackp <= &compilep_stack[0]) {
		return ((char *)0);
	} else {
		compilep_stackp--;
		*compilep_stackp = compilep;
		return (compilep);
	}
}

static boolean_t
valid_range(wchar_t lower_char, wchar_t upper_char)
{
	return (((lower_char <= 0x7f) && (upper_char <= 0x7f) &&
	    !iswcntrl(lower_char) && !iswcntrl(upper_char) &&
	    (lower_char < upper_char)) ||
	    (((lower_char & WCHAR_CSMASK) ==
	    (upper_char & WCHAR_CSMASK)) &&
	    (lower_char < upper_char)));
}
