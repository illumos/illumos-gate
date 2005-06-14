/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This program is copyright Alec Muffett 1993. The author disclaims all
 * responsibility or liability with respect to it's usage or its effect
 * upon hardware or computer systems, and maintains copyright as set out
 * in the "LICENCE" document which accompanies distributions of Crack v4.0
 * and upwards.
 */

#include "packer.h"


#define	RULE_NOOP	':'
#define	RULE_PREPEND	'^'
#define	RULE_APPEND	'$'
#define	RULE_REVERSE	'r'
#define	RULE_UPPERCASE	'u'
#define	RULE_LOWERCASE	'l'
#define	RULE_PLURALISE	'p'
#define	RULE_CAPITALISE	'c'
#define	RULE_DUPLICATE	'd'
#define	RULE_REFLECT	'f'
#define	RULE_SUBSTITUTE	's'
#define	RULE_MATCH	'/'
#define	RULE_NOT	'!'
#define	RULE_LT		'<'
#define	RULE_GT		'>'
#define	RULE_EXTRACT	'x'
#define	RULE_OVERSTRIKE	'o'
#define	RULE_INSERT	'i'
#define	RULE_EQUALS	'='
#define	RULE_PURGE	'@'
#define	RULE_CLASS	'?'	/* class rule? socialist ethic in cracker? */
#define	RULE_DFIRST	'['
#define	RULE_DLAST	']'
#define	RULE_MFIRST	'('
#define	RULE_MLAST	')'

int
Suffix(char *myword, char *suffix)
{
	register int i;
	register int j;

	i = strlen(myword);
	j = strlen(suffix);

	if (i > j) {
		return (STRCMP((myword + i - j), suffix));
	} else {
		return (-1);
	}
}

char *
Reverse(register char *str)		/* return a pointer to a reversal */
{
	register int i;
	register int j;
	static char area[PATH_MAX];

	j = i = strlen(str);
	while (*str) {
		area[--i] = *str++;
	}
	area[j] = '\0';
	return (area);
}

char *
Uppercase(register char *str)		/* return a pointer to an uppercase */
{
	register char *ptr;
	static char area[PATH_MAX];

	ptr = area;
	while (*str) {
		*(ptr++) = CRACK_TOUPPER(*str);
		str++;
	}
	*ptr = '\0';

	return (area);
}

char *
Lowercase(register char *str)		/* return a pointer to an lowercase */
{
	register char *ptr;
	static char area[PATH_MAX];

	ptr = area;
	while (*str) {
		*(ptr++) = CRACK_TOLOWER(*str);
		str++;
	}
	*ptr = '\0';

	return (area);
}

char *
Capitalise(register char *str)		/* return a pointer to an capitalised */
{
	register char *ptr;
	static char area[PATH_MAX];

	ptr = area;

	while (*str) {
		*(ptr++) = CRACK_TOLOWER(*str);
		str++;
	}

	*ptr = '\0';
	area[0] = CRACK_TOUPPER(area[0]);
	return (area);
}

char *
Pluralise(register char *string)	/* returns a pointer to a plural */
{
	register int length;
	static char area[PATH_MAX];

	length = strlen(string);
	(void) strlcpy(area, string, PATH_MAX);

	if (!Suffix(string, "ch") ||
	    !Suffix(string, "ex") ||
	    !Suffix(string, "ix") ||
	    !Suffix(string, "sh") ||
	    !Suffix(string, "ss")) {
		/* bench -> benches */
		(void) strcat(area, "es");
	} else if (length > 2 && string[length - 1] == 'y') {
		if (strchr("aeiou", string[length - 2])) {
			/* alloy -> alloys */
			(void) strcat(area, "s");
		} else {
			/* gully -> gullies */
			(void) strcpy(area + length - 1, "ies");
		}
	} else if (string[length - 1] == 's') {
		/* bias -> biases */
		(void) strcat(area, "es");
	} else {
		/* catchall */
		(void) strcat(area, "s");
	}

	return (area);
}

char *
Substitute(register char *string, register char old,
	register char new)	/* returns pointer to a swapped about copy */
{
	register char *ptr;
	static char area[PATH_MAX];

	ptr = area;
	while (*string) {
		*(ptr++) = (*string == old ? new : *string);
		string++;
	}
	*ptr = '\0';
	return (area);
}

/* returns pointer to a purged copy */
char *
Purge(register char *string, register char target)
{
	register char *ptr;
	static char area[PATH_MAX];
	ptr = area;
	while (*string) {
		if (*string != target) {
			*(ptr++) = *string;
		}
		string++;
	}
	*ptr = '\0';
	return (area);
}
/* -------- CHARACTER CLASSES START HERE -------- */

/*
 * this function takes two inputs, a class identifier and a character, and
 * returns non-null if the given character is a member of the class, based
 * upon restrictions set out below
 */

int
MatchClass(register char class, register char input)
{
	register char c;
	register int retval;

	retval = 0;

	switch (class) {
	/* ESCAPE */

		case '?':			/* ?? -> ? */
			if (input == '?') {
				retval = 1;
			}
			break;

	/* ILLOGICAL GROUPINGS (ie: not in ctype.h) */

		case 'V':
		case 'v':			/* vowels */
			c = CRACK_TOLOWER(input);
			if (strchr("aeiou", c)) {
				retval = 1;
			}
			break;

		case 'C':
		case 'c':			/* consonants */
			c = CRACK_TOLOWER(input);
			if (strchr("bcdfghjklmnpqrstvwxyz", c)) {
				retval = 1;
			}
			break;

		case 'W':
		case 'w':			/* whitespace */
			if (strchr("\t ", input)) {
				retval = 1;
			}
			break;

		case 'P':
		case 'p':			/* punctuation */
			if (strchr(".`,:;'!?\"", input)) {
				retval = 1;
			}
			break;

		case 'S':
		case 's':			/* symbols */
			if (strchr("$%%^&*()-_+=|\\[]{}#@/~", input)) {
				retval = 1;
			}
			break;

		/* LOGICAL GROUPINGS */

		case 'L':
		case 'l':			/* lowercase */
			if (islower(input)) {
				retval = 1;
			}
			break;

		case 'U':
		case 'u':			/* uppercase */
			if (isupper(input)) {
				retval = 1;
			}
			break;

		case 'A':
		case 'a':			/* alphabetic */
			if (isalpha(input)) {
				retval = 1;
			}
			break;

		case 'X':
		case 'x':			/* alphanumeric */
			if (isalnum(input)) {
				retval = 1;
			}
			break;

		case 'D':
		case 'd':			/* digits */
			if (isdigit(input)) {
				retval = 1;
			}
			break;
	}

	if (isupper(class)) {
		return (!retval);
	}
	return (retval);
}

char *
PolyStrchr(register char *string, register char class)
{
	while (*string) {
		if (MatchClass(class, *string)) {
			return (string);
		}
		string++;
	}
	return ((char *)0);
}

/* returns pointer to a swapped about copy */
char *
PolySubst(register char *string, register char class, register char new)
{
	register char *ptr;
	static char area[PATH_MAX];

	ptr = area;
	while (*string) {
		*(ptr++) = (MatchClass(class, *string) ? new : *string);
		string++;
	}
	*ptr = '\0';
	return (area);
}

/* returns pointer to a purged copy */
char *
PolyPurge(register char *string, register char class)
{
	register char *ptr;
	static char area[PATH_MAX];

	ptr = area;
	while (*string) {
		if (!MatchClass(class, *string)) {
			*(ptr++) = *string;
		}
		string++;
	}
	*ptr = '\0';
	return (area);
}
/* -------- BACK TO NORMALITY -------- */

int
Char2Int(char character)
{
	if (isdigit(character)) {
		return (character - '0');
	} else if (islower(character)) {
		return (character - 'a' + 10);
	} else if (isupper(character)) {
		return (character - 'A' + 10);
	}
	return (-1);
}

/* returns a pointer to a controlled Mangle */
char *
Mangle(char *input, char *control)
{
	int limit;
	register char *ptr;
	static char area[PATH_MAX];
	char area2[PATH_MAX];

	area[0] = '\0';
	(void) strlcpy(area, input, PATH_MAX);

	for (ptr = control; *ptr; ptr++) {
		switch (*ptr) {
			case RULE_NOOP:
				break;
			case RULE_REVERSE:
				(void) strlcpy(area, Reverse(area), PATH_MAX);
				break;
			case RULE_UPPERCASE:
				(void) strlcpy(area, Uppercase(area), PATH_MAX);
				break;
			case RULE_LOWERCASE:
				(void) strlcpy(area, Lowercase(area), PATH_MAX);
				break;
			case RULE_CAPITALISE:
				(void) strlcpy(area, Capitalise(area),
				    PATH_MAX);
				break;
			case RULE_PLURALISE:
				(void) strlcpy(area, Pluralise(area), PATH_MAX);
				break;
			case RULE_REFLECT:
				(void) strlcat(area, Reverse(area), PATH_MAX);
				break;
			case RULE_DUPLICATE:
				(void) strlcpy(area2, area, PATH_MAX);
				(void) strlcat(area, area2, PATH_MAX);
				break;
			case RULE_GT:
				if (!ptr[1]) {
					return ((char *)0);
				} else {
					limit = Char2Int(*(++ptr));
					if (limit < 0) {
						return ((char *)0);
					}
					if (strlen(area) <= limit) {
						return ((char *)0);
					}
				}
				break;
			case RULE_LT:
				if (!ptr[1]) {
					return ((char *)0);
				} else {
					limit = Char2Int(*(++ptr));
					if (limit < 0) {
						return ((char *)0);
					}
					if (strlen(area) >= limit) {
						return ((char *)0);
					}
				}
				break;
			case RULE_PREPEND:
				if (!ptr[1]) {
					return ((char *)0);
				} else {
					area2[0] = *(++ptr);
					(void) strlcpy(area2 + 1, area,
					    PATH_MAX);
					(void) strlcpy(area, area2, PATH_MAX);
				}
				break;
			case RULE_APPEND:
				if (!ptr[1]) {
					return ((char *)0);
				} else {
					register char *string;

					string = area;
					while (*(string++));
					string[-1] = *(++ptr);
					*string = '\0';
				}
				break;
			case RULE_EXTRACT:
				if (!ptr[1] || !ptr[2]) {
					return ((char *)0);
				} else {
					register int i;
					int start;
					int length;

					start = Char2Int(*(++ptr));
					length = Char2Int(*(++ptr));
					if (start < 0 || length < 0) {
						return ((char *)0);
					}
					(void) strlcpy(area2, area, PATH_MAX);
					for (i = 0; length-- &&
					    area2[start + i]; i++) {
						area[i] = area2[start + i];
					}
					/* cant use strncpy()-no trailing NUL */
					area[i] = '\0';
				}
				break;
			case RULE_OVERSTRIKE:
				if (!ptr[1] || !ptr[2]) {
					return ((char *)0);
				} else {
					register int i;

					i = Char2Int(*(++ptr));
					if (i < 0) {
						return ((char *)0);
					} else {
						++ptr;
						if (area[i]) {
							area[i] = *ptr;
						}
					}
				}
				break;
			case RULE_INSERT:
				if (!ptr[1] || !ptr[2]) {
					return ((char *)0);
				} else {
					register int i;
					register char *p1;
					register char *p2;

					i = Char2Int(*(++ptr));
					if (i < 0) {
						return ((char *)0);
					}
					p1 = area;
					p2 = area2;
					while (i && *p1) {
						i--;
						*(p2++) = *(p1++);
					}
					*(p2++) = *(++ptr);
					(void) strlcpy(p2, p1, PATH_MAX);
					(void) strlcpy(area, area2, PATH_MAX);
				}
				break;
	    /* THE FOLLOWING RULES REQUIRE CLASS MATCHING */

			case RULE_PURGE:	/* @x or @?c */
				if (!ptr[1] || (ptr[1] ==
				    RULE_CLASS && !ptr[2])) {
					return ((char *)0);
				} else if (ptr[1] != RULE_CLASS) {
					(void) strlcpy(area, Purge(area,
					    *(++ptr)), PATH_MAX);
				} else {
					(void) strlcpy(area, PolyPurge(area,
					    ptr[2]), PATH_MAX);
					ptr += 2;
				}
				break;
			case RULE_SUBSTITUTE:	/* sxy || s?cy */
				if (!ptr[1] || !ptr[2] ||
				    (ptr[1] == RULE_CLASS && !ptr[3])) {
					return ((char *)0);
				} else if (ptr[1] != RULE_CLASS) {
					ptr += 2;
				} else {
					(void) strlcpy(area, PolySubst(area,
					    ptr[2], ptr[3]), PATH_MAX);
					ptr += 3;
				}
				break;
			case RULE_MATCH:	/* /x || /?c */
				if (!ptr[1] ||
				    (ptr[1] == RULE_CLASS && !ptr[2])) {
					return ((char *)0);
				} else if (ptr[1] != RULE_CLASS) {
					if (!strchr(area, *(++ptr))) {
						return ((char *)0);
					}
				} else {
					if (!PolyStrchr(area, ptr[2])) {
						return ((char *)0);
					}
					ptr += 2;
				}
				break;
			case RULE_NOT:		/* !x || !?c */
				if (!ptr[1] ||
				    (ptr[1] == RULE_CLASS && !ptr[2])) {
					return ((char *)0);
				} else if (ptr[1] != RULE_CLASS) {
					if (strchr(area, *(++ptr))) {
						return ((char *)0);
					}
				} else {
					if (PolyStrchr(area, ptr[2])) {
						return ((char *)0);
					}
					ptr += 2;
				}
				break;
	/*
	 * alternative use for a boomerang, number 1: a standard throwing
	 * boomerang is an ideal thing to use to tuck the sheets under
	 * the mattress when making your bed.  The streamlined shape of
	 * the boomerang allows it to slip easily 'twixt mattress and
	 * bedframe, and it's curve makes it very easy to hook sheets
	 * into the gap.
	 */

			case RULE_EQUALS:	/* =nx || =n?c */
				if (!ptr[1] || !ptr[2] ||
				    (ptr[2] == RULE_CLASS && !ptr[3])) {
					return ((char *)0);
				} else {
					register int i;

					if ((i = Char2Int(ptr[1])) < 0) {
						return ((char *)0);
					}
					if (ptr[2] != RULE_CLASS) {
						ptr += 2;
						if (area[i] != *ptr) {
							return ((char *)0);
						}
					} else {
						ptr += 3;
						if (!MatchClass(*ptr,
						    area[i])) {
							return ((char *)0);
						}
					}
				}
				break;

			case RULE_DFIRST:
				if (area[0]) {
					register int i;

					for (i = 1; area[i]; i++) {
						area[i - 1] = area[i];
					}
					area[i - 1] = '\0';
				}
				break;

			case RULE_DLAST:
				if (area[0]) {
					register int i;

					for (i = 1; area[i]; i++);
					area[i - 1] = '\0';
				}
				break;

			case RULE_MFIRST:
				if (!ptr[1] ||
				    (ptr[1] == RULE_CLASS && !ptr[2])) {
					return ((char *)0);
				} else {
					if (ptr[1] != RULE_CLASS) {
						ptr++;
						if (area[0] != *ptr) {
							return ((char *)0);
						}
					} else {
						ptr += 2;
						if (!MatchClass(*ptr,
						    area[0])) {
							return ((char *)0);
						}
					}
				}
				break;
			case RULE_MLAST:
				if (!ptr[1] ||
				    (ptr[1] == RULE_CLASS && !ptr[2])) {
					return ((char *)0);
				} else {
					register int i;

					for (i = 0; area[i]; i++);

					if (i > 0) {
						i--;
					} else {
						return ((char *)0);
					}
					if (ptr[1] != RULE_CLASS) {
						ptr++;
						if (area[i] != *ptr) {
							return ((char *)0);
						}
					} else {
						ptr += 2;
						if (!MatchClass(*ptr,
						    area[i])) {
							return ((char *)0);
						}
					}
				}
				break;
		}
	}
	if (!area[0]) {		/* have we deweted de poor widdle fing away? */
		return ((char *)0);
	}
	return (area);
}
/*
 * int
 * PMatch(register char *control, register char *string)
 * {
 * 	while (*string && *control) {
 * 		if (!MatchClass(*control, *string)) {
 * 			return (0);
 * 		}
 *
 * 		string++;
 * 		control++;
 * 	}
 *
 * 	if (*string || *control) {
 * 		return (0);
 * 	}
 *
 * 	return (1);
 * }
 */
