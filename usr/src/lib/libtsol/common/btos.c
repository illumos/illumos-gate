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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *      Binary label to label string translations.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wchar.h>

#include <sys/mman.h>

#include <tsol/label.h>

#include "clnt.h"
#include "labeld.h"
#include <sys/tsol/label_macro.h>

#if	!defined(TEXT_DOMAIN)		/* should be defined by Makefiles */
#define	TEXT_DOMAIN "SYS_TEST"
#endif	/* TEXT_DOMAIN */

static bslabel_t slow;	/* static admin_low high sensitivity label */
static bslabel_t shigh;	/* static admin_high sensitivity label */
static bclear_t clrlow, clrhigh; /* static admin_low and admin_high Clearance */

static char	*sstring;	/* return string for sb*tos */
static size_t	ssize;		/* current size of return string */

static int
return_string(char **string, int str_len, char *val)
{
	char	*cpyptr;
	size_t	val_len = strlen(val) + 1;

	if (*string == NULL) {
		if ((*string = malloc(val_len)) == NULL)
			return (0);
	} else if (val_len > str_len) {
		**string = '\0';
		return (0);
	}

	cpyptr = *string;
	bcopy(val, cpyptr, val_len);

	return (val_len);
}

void
set_label_view(uint_t *callflags, uint_t flags)
{
	if (flags&VIEW_INTERNAL) {
		*callflags |= LABELS_VIEW_INTERNAL;
	} else if (flags&VIEW_EXTERNAL) {
		*callflags |= LABELS_VIEW_EXTERNAL;
	}
}

int
alloc_string(char **string, size_t size, char val)
{
	if (*string == NULL) {
		if ((*string = malloc(ALLOC_CHUNK)) == NULL)
			return (0);
	} else {
		if ((*string = realloc(*string, size + ALLOC_CHUNK)) == NULL) {
			**string = val;
			return (0);
		}
	}
	**string = val;
	return (ALLOC_CHUNK);
}

#define	slcall callp->param.acall.cargs.bsltos_arg
#define	slret callp->param.aret.rvals.bsltos_ret
/*
 *	bsltos - Convert Binary Sensitivity Label to Sensitivity Label string.
 *
 *	Entry	label = Binary Sensitivity Label to be converted.
 *		string = NULL ((char *) 0), if memory to be allocated,
 *			 otherwise, pointer to preallocated memory.
 *		str_len = Length of preallocated memory, else ignored.
 *		flags = Logical sum of:
 *				LONG_CLASSIFICATION or SHORT_CLASSIFICATION,
 *				LONG_WORDS or SHORT_WORDS,
 *				VIEW_INTERNAL or VIEW_EXTERNAL, and
 *				NO_CLASSIFICATION.
 *			LONG_CLASSIFICATION, use long classification names.
 *			SHORT_CLASSIFICATION, use short classification
 *						names (default).
 *			NO_CLASSIFICATION, don't translate classification.
 *			LONG_WORDS, use the long form of words (default).
 *			SHORTWORDS, use the short form of words where available.
 *			VIEW_INTERNAL, don't promote/demote admin low/high.
 *			VIEW_EXTERNAL, promote/demote admin low/high.
 *
 *	Exit	string = Sensitivity Label string, or empty string if
 *			 not enough preallocated memory.
 *
 *	Returns	-1, If unable to access label encodings database.
 *		 0, If unable to allocate string,
 *			or allocated string to short
 *			(and **string = '\0').
 *		length (including null) of Sensitivity Label string,
 *			If successful.
 *
 *	Calls	RPC - LABELS_BSLTOS, BCLHIGH, BCLLOW, BCLTOSL, BLEQUAL,
 *			BLTYPE, SETBSLABEL, UCLNT, memcpy, clnt_call,
 *			clnt_perror, malloc, strcat, strlen.
 *
 *	Uses	ADMIN_HIGH, ADMIN_LOW, shigh, slow.
 */

ssize_t
bsltos(const bslabel_t *label, char **string, size_t str_len,
    int flags)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(bsltos_call_t, 0);
	int	rval;

	if (!BLTYPE(label, SUN_SL_ID)) {
		return (-1);
	}

	call.callop = BSLTOS;
	slcall.label = *label;
	slcall.flags = (flags&NO_CLASSIFICATION) ? LABELS_NO_CLASS : 0;
	slcall.flags |= (flags&SHORT_CLASSIFICATION ||
	    !(flags&LONG_CLASSIFICATION)) ? LABELS_SHORT_CLASS : 0;
	slcall.flags |= (flags&SHORT_WORDS && !(flags&LONG_WORDS)) ?
	    LABELS_SHORT_WORDS : 0;
	set_label_view(&slcall.flags, flags);

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) == SUCCESS) {

		if (callp->reterr != 0)
			return (-1);

		/* unpack Sensitivity Label */

		rval = return_string(string, str_len, slret.slabel);

		if (callp != &call)
			(void) munmap((void *)callp, bufsize);
		return (rval);
	} else if (rval == NOSERVER) {
		/* server not present */
		/* special case admin_high and admin_low */

		if (!BLTYPE(&slow, SUN_SL_ID)) {
			/* initialize static labels */

			BSLLOW(&slow);
			BSLHIGH(&shigh);
		}

		if (BLEQUAL(label, &slow)) {
			return (return_string(string, str_len, ADMIN_LOW));
		} else if (BLEQUAL(label, &shigh)) {
			return (return_string(string, str_len, ADMIN_HIGH));
		}
	}
	return (-1);
}  /* bsltos */
#undef	slcall
#undef	slret

#define	clrcall callp->param.acall.cargs.bcleartos_arg
#define	clrret callp->param.aret.rvals.bcleartos_ret
/*
 *	bcleartos - Convert Binary Clearance to Clearance string.
 *
 *	Entry	clearance = Binary Clearance to be converted.
 *		string = NULL ((char *) 0), if memory to be allocated,
 *			 otherwise, pointer to preallocated memory.
 *		str_len = Length of preallocated memory, else ignored.
 *		flags = Logical sum of:
 *				LONG_CLASSIFICATION or SHORT_CLASSIFICATION,
 *				LONG_WORDS or SHORT_WORDS,
 *				VIEW_INTERNAL or VIEW_EXTERNAL.
 *			LONG_CLASSIFICATION, use long classification names.
 *			SHORT_CLASSIFICATION, use short classification
 *						names (default).
 *			LONG_WORDS, use the long form of words (default).
 *			SHORTWORDS, use the short form of words where available.
 *			VIEW_INTERNAL, don't promote/demote admin low/high.
 *			VIEW_EXTERNAL, promote/demote admin low/high.
 *
 *	Exit	string = Clearance string, or empty string if not
 *			enough preallocated memory.
 *
 *	Returns	-1, If unable to access label encodings database.
 *		 0, If unable to allocate string,
 *			or allocated string to short
 *			(and **string = '\0').
 *		length (including null) of Clearance string,
 *			If successful.
 *
 *	Calls	RPC - LABELS_BSLTOS, BCLHIGH, BCLLOW, BCLTOSL, BLEQUAL,
 *			BLTYPE, SETBSLABEL, UCLNT, memcpy, clnt_call,
 *			clnt_perror, malloc, strcat, strlen.
 *
 *	Uses	ADMIN_HIGH, ADMIN_LOW, clrhigh, clrlow.
 */

ssize_t
bcleartos(const bclear_t *clearance, char **string, size_t str_len,
    int flags)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(bcleartos_call_t, 0);
	int	rval;

	if (!BLTYPE(clearance, SUN_CLR_ID)) {
		return (-1);
	}

	call.callop = BCLEARTOS;
	clrcall.clear = *clearance;
	clrcall.flags = (flags&SHORT_CLASSIFICATION ||
	    !(flags&LONG_CLASSIFICATION)) ? LABELS_SHORT_CLASS : 0;
	clrcall.flags |= (flags&SHORT_WORDS && !(flags&LONG_WORDS)) ?
	    LABELS_SHORT_WORDS : 0;
	set_label_view(&clrcall.flags, flags);

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) == SUCCESS) {

		if (callp->reterr != 0)
			return (-1);

		/* unpack Clearance */

		rval = return_string(string, str_len, clrret.cslabel);

		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (rval);
	} else if (rval == NOSERVER) {
		/* server not present */
		/* special case admin_high and admin_low */

		if (!BLTYPE(&clrlow, SUN_CLR_ID)) {
			/* initialize static labels */

			BCLEARLOW(&clrlow);
			BCLEARHIGH(&clrhigh);
		}
		if (BLEQUAL(clearance, &clrlow)) {
			return (return_string(string, str_len, ADMIN_LOW));
		} else if (BLEQUAL(clearance, &clrhigh)) {
			return (return_string(string, str_len, ADMIN_HIGH));
		}
	}
	return (-1);
}  /* bcleartos */
#undef	clrcall
#undef	clrret

/*
 *	sbsltos - Convert Sensitivity Label to canonical clipped form.
 *
 *	Entry	label = Sensitivity Label to be converted.
 *		len = Maximum length of translated string, excluding NULL.
 *		      0, full string.
 *		sstring = address of string to translate into.
 *		ssize = size of memory currently allocated to sstring.
 *
 *	Exit	sstring = Newly translated string.
 *		ssize = Updated if more memory pre-allocated.
 *
 *	Returns	NULL, If error, len too small, unable to translate, or get
 *		      memory for string.
 *		Address of string containing converted value.
 *
 *	Calls	alloc_string, bsltos, strcpy.
 *
 *	Uses	ssize, sstring.
 */

char *
sbsltos(const bslabel_t *label, size_t len)
{
	ssize_t	slen;		/* length including NULL */
	wchar_t *wstring;
	int	wccount;

	if (ssize == 0) {
		/* Allocate string memory. */
		if ((ssize = alloc_string(&sstring, ssize, 's')) == 0)
			/* can't get initial memory for string */
			return (NULL);
	}

again:
	if ((slen = bsltos(label, &sstring, ssize,
	    (SHORT_CLASSIFICATION | LONG_WORDS))) <= 0) {
		/* error in translation */
		if (slen == 0) {
			if (*sstring == '\0') {
				int newsize;
				/* sstring not long enough */
				if ((newsize = alloc_string(&sstring, ssize,
				    's')) == 0) {
					/* Can't get more memory */
					return (NULL);
				}
				ssize += newsize;
				goto again;
			}
		}
		return (NULL);
	}
	if (len == 0) {
		return (sstring);
	} else if (len < MIN_SL_LEN) {
		return (NULL);
	}
	if ((wstring = malloc(slen * sizeof (wchar_t))) == NULL)
		return (NULL);
	if ((wccount = mbstowcs(wstring, sstring, slen - 1)) == -1) {
		free(wstring);
		return (NULL);
	}
	if (wccount > len) {
		wchar_t *clipp = wstring + (len - 2);

		/* Adjust string size to desired length */

		clipp[0] = L'<';
		clipp[1] = L'-';
		clipp[2] = L'\0';

		while (wcstombs(NULL, wstring, 0) >= ssize) {
			int newsize;

			/* sstring not long enough */
			if ((newsize = alloc_string(&sstring, ssize, 's')) ==
			    0) {
				/* Can't get more memory */
				return (NULL);
			}
			ssize += newsize;
		}

		if ((wccount = wcstombs(sstring, wstring, ssize)) == -1) {
			free(wstring);
			return (NULL);
		}
	}
	free(wstring);

	return (sstring);
}  /* sbsltos */

/*
 *	sbcleartos - Convert Clearance to canonical clipped form.
 *
 *	Entry	clearance = Clearance to be converted.
 *		len = Maximum length of translated string, excluding NULL.
 *		      0, full string.
 *		sstring = address of string to translate into.
 *		ssize = size of memory currently allocated to sstring.
 *
 *	Exit	sstring = Newly translated string.
 *		ssize = Updated if more memory pre-allocated.
 *
 *	Returns	NULL, If error, len too small, unable to translate, or get
 *		      memory for string.
 *		Address of string containing converted value.
 *
 *	Calls	alloc_string, bcleartos, strcpy.
 *
 *	Uses	ssize, sstring.
 */

char *
sbcleartos(const bclear_t *clearance, size_t len)
{
	ssize_t	slen;		/* length including NULL */
	wchar_t *wstring;
	int	wccount;

	if (ssize == 0) {
		/* Allocate string memory. */
		if ((ssize = alloc_string(&sstring, ssize, 'c')) == 0)
			/* can't get initial memory for string */
			return (NULL);
	}

again:
	if ((slen = bcleartos(clearance, &sstring, ssize,
	    (SHORT_CLASSIFICATION | LONG_WORDS))) <= 0) {
		/* error in translation */
		if (slen == 0) {
			if (*sstring == '\0') {
				int newsize;
				/* sstring not long enough */
				if ((newsize = alloc_string(&sstring, ssize,
				    'c')) == 0) {
					/* Can't get more memory */
					return (NULL);
				}
				ssize += newsize;
				goto again;
			}
		}
		return (NULL);
	}
	if (len == 0) {
		return (sstring);
	} else if (len < MIN_CLR_LEN) {
		return (NULL);
	}
	if ((wstring = malloc(slen * sizeof (wchar_t))) == NULL)
		return (NULL);
	if ((wccount = mbstowcs(wstring, sstring, slen - 1)) == -1) {
		free(wstring);
		return (NULL);
	}
	if (wccount > len) {
		wchar_t *clipp = wstring + (len - 2);

		/* Adjust string size to desired length */

		clipp[0] = L'<';
		clipp[1] = L'-';
		clipp[2] = L'\0';

		while (wcstombs(NULL, wstring, 0) >= ssize) {
			int newsize;

			/* sstring not long enough */
			if ((newsize = alloc_string(&sstring, ssize, 'c')) ==
			    0) {
				/* Can't get more memory */
				free(wstring);
				return (NULL);
			}
			ssize += newsize;
		}
		if ((wccount = wcstombs(sstring, wstring, ssize)) == -1) {
			free(wstring);
			return (NULL);
		}
	}
	free(wstring);

	return (sstring);
}  /* sbcleartos */
