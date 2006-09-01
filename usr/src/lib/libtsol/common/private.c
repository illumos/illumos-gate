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
 *	Label library contract private interfaces.
 *
 *	Binary labels to String labels with dimming word lists.
 *	Dimming word list titles.
 *	Default user labels.
 */

#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include <sys/mman.h>

#include <tsol/label.h>

#include "clnt.h"
#include "labeld.h"

/*
 *	cvt memory:
 *
 * cvt:	char	*long_words[display_size];	Pointers to long words
 *	char	*short_words[display_size];	Pointers to short words
 * dim:	char	display[display_size];		Dim | Set
 *
 *	    strings associated with long and short words.
 *
 */

/*
 *	Sensitivity Label words.
 */

static	char *slcvt = NULL;
static	int   slcvtsize = 0;
static	char *sldim;

static	char *slstring = NULL;
static	int   slstringsize = 0;
static	brange_t sbounds;

/*
 *	Clearance words.
 */

static	char *clrcvt = NULL;
static	int   clrcvtsize = 0;
static	char *clrdim;

static	char *clrstring = NULL;
static	int   clrstringsize = 0;
static	brange_t cbounds;

static
int
alloc_words(char **words, const size_t size)
{
	if (*words == NULL) {
		if ((*words = malloc(size)) == NULL)
			return (0);
	} else {
		if ((*words = realloc(*words, size)) == NULL) {
			return (0);
		}
	}
	return (1);
}

/*
 *	build_strings - Build the static strings and dimming list for a
 *			converted label.
 *
 *	Entry	new_string = Newly converted string.
 *		new_words_size = Size of words associated with newly converted
 *				 label.
 *		number_of_words = Number of words associated with newly
 *				  converted label.
 *		full =	1, if static words lists to be updated.
 *			0, if only string and dimming list to be updated.
 *
 *	Exit	static_string_size = Updated if needed.
 *		static_string = Updated to new label string.
 *		static_words_size = Updated if needed.
 *		static_words = Updated to new words list, if needed.
 *		static_dimming = Updated to new dimming state.
 *		long_words = Updated to new long words pointers, if needed.
 *		short_words = Updated to new short words pointers, if needed.
 *
 *
 *	Returns	0, If unable to allocate memory.
 *		1, If successful.
 *
 *	Calls	alloc_string, alloc_words, memcpy, strcpy, strlen.
 */

static
int
build_strings(int *static_string_size, char **static_string, char *new_string,
    int *static_words_size, int new_words_size, char **static_words,
    char **static_dimming, int number_of_words, char *long_words,
    char *short_words, char *dimming_list, int full)
{
	char	**l;
	char	**s;
	char	*w;
	char	*l_w = long_words;
	char	*s_w = short_words;
	int	i;
	int	len;
	int	newsize;

	if (*static_string_size == 0) { /* Allocate string memory. */
		if ((*static_string_size = alloc_string(static_string,
		    *static_string_size, 'C')) == 0)
			/* can't get string memory for string */
			return (0);
	}

again:
	if (*static_string_size < (int)strlen(new_string)+1) {
		/* need longer string */
		if ((newsize = alloc_string(static_string, *static_string_size,
		    'C')) == 0)
			/* can't get more string memory */
			return (0);

		*static_string_size += newsize;
		goto again;
	}
	bcopy(new_string, *static_string, strlen(new_string) + 1);

	if (full) {
		if (*static_words_size < new_words_size &&
		    !alloc_words(static_words, new_words_size)) {
			/* can't get more words memory */
			return (0);
		} else {
			*static_words_size = new_words_size;
		}
		/*LINTED*/
		l = (char **)*static_words;
		s = l + number_of_words;
		*static_dimming = (char *)(s + number_of_words);
		w = *static_dimming + number_of_words;
		for (i = 0; i < number_of_words; i++) {
			*l = w;
			(void) strcpy(w, l_w);
			w += (len = strlen(l_w) + 1);
			l_w += len;
			if (*s_w == '\000') {
				*s = NULL;
				s_w++;
			} else {
				*s = w;
				(void) strcpy(w, s_w);
				w += (len = strlen(s_w) + 1);
				s_w += len;
			}

			l++;
			s++;
		}  /* for each word entry */
	}  /* if (full) */

	bcopy(dimming_list, *static_dimming, number_of_words);
	return (1);
}  /* build_strings */

#define	bsfcall callp->param.acall.cargs.bslcvt_arg
#define	bsfret callp->param.aret.rvals.bslcvt_ret
/*
 *	bslcvtfull - Convert Sensitivity Label and initialize static
 *			information.
 *
 *	Entry	label = Sensitivity Label to convert and get dimming list.
 *			This label should lie within the bounds or the
 *			results may not be meaningful.
 *		bounds = Lower and upper bounds for words lists. Must be
 *			dominated by clearance.
 *		flags = VIEW_INTERNAL, don't promote/demote admin low/high.
 *			VIEW_EXTERNAL, promote/demote admin low/high.
 *
 *	Exit	string = ASCII coded Sensitivity Label.
 *		long_words = Array of pointers to visible long word names.
 *		short_words = Array of pointers to visible short word names.
 *		display = Array of indicators as to whether the word is present
 *			  in the converted label (CVT_SET), and/or changeable
 *			  (CVT_DIM).
 *		first_compartment = Zero based index of first compartment.
 *		display_size = Number of entries in the display/words lists.
 *
 *	Returns	-1, If unable to access label encodings database, or
 *			invalid label.
 *		 0, If unable to allocate static memory.
 *		 1, If successful.
 *
 *	Calls	RPC - LABELS_BSLCONVERT, STTBLEVEL, SETBSLABEL, TCLNT,
 *			build_strings, clnt_call, clnt_perror.
 *
 *	Uses	sbounds, slrcvt, slrcvtsize, slrdim, slrstring,
 *			slrstringsize.
 */

int
bslcvtfull(const bslabel_t *label, const blrange_t *bounds, int flags,
    char **string, char **long_words[], char **short_words[], char *display[],
    int *first_compartment, int *display_size)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(bslcvt_call_t, 0);
	int	new_words_size;
	int	rval;

	call.callop = BSLCVT;
	bsfcall.label = *label;
	bsfcall.bounds.upper_bound = *bounds->upper_bound;
	bsfcall.bounds.lower_bound = *bounds->lower_bound;
	bsfcall.flags = LABELS_FULL_CONVERT;
	set_label_view(&bsfcall.flags, flags);

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) == NOSERVER) {
#ifdef	DEBUG
		(void) fprintf(stderr, "No label server.\n");
#endif	/* DEBUG */
		return (-1);
	} else if (rval != SUCCESS) {
		return (-1);
	} else {
		if (callp->reterr != 0)
			return (-1);
	}

	*first_compartment = bsfret.first_comp;
	*display_size = bsfret.d_len;

	new_words_size = bsfret.l_len + bsfret.s_len + bsfret.d_len +
	    (2 * sizeof (char *)) * bsfret.d_len;

	if (build_strings(&slstringsize, &slstring, &bsfret.buf[bsfret.string],
	    &slcvtsize, new_words_size, &slcvt, &sldim, bsfret.d_len,
	    &bsfret.buf[bsfret.lwords], &bsfret.buf[bsfret.swords],
	    &bsfret.buf[bsfret.dim], 1) != 1) {
		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (0);
	}

	/* save for bslcvt call */
	sbounds.upper_bound = *bounds->upper_bound;
	sbounds.lower_bound = *bounds->lower_bound;

	*string = slstring;
	*display = sldim;
	/*LINTED*/
	*long_words = (char **)slcvt;
	/*LINTED*/
	*short_words = (char **)(slcvt + *display_size * sizeof (char *));
	if (callp != &call)
		/* release return buffer */
		(void) munmap((void *)callp, bufsize);
	return (1);
}  /* bslcvtfull */
#undef	bsfcall
#undef	bsfret

#define	bsccall callp->param.acall.cargs.bslcvt_arg
#define	bscret callp->param.aret.rvals.bslcvt_ret
/*
 *	bslcvt - Convert Sensitivity Label and update dimming information.
 *
 *	Entry	label = Sensitivity Label to convert and get dimming list.
 *			This label should lie within the bounds of the
 *			corresponding bslcvtfull call or the results may
 *			not be meaningful.
 *		flags = VIEW_INTERNAL, don't promote/demote admin low/high.
 *			VIEW_EXTERNAL, promote/demote admin low/high.
 *
 *	Exit	string = ASCII coded Sensitivity Label.
 *		display = Array of indicators as to whether the word is present
 *			  in the converted label (CVT_SET), and/or changeable
 *			  (CVT_DIM).
 *
 *	Returns	-1, If unable to access label encodings database, or
 *			invalid label.
 *		 0, If unable to allocate static memory.
 *		 1, If successful.
 *
 *	Calls	RPC - LABELS_BSLCONVERT, SETBLEVEL, SETBSLABEL, build_strings
 *			clnt_call, clnt_perror.
 *
 *	Uses	sbounds, slrdim, slrstring.
 */

int
bslcvt(const bslabel_t *label, int flags, char **string, char *display[])
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(bslcvt_call_t, 0);
	int	rval;

	if (slcvt == NULL)
		return (-1);	/* conversion not initialized */

	call.callop = BSLCVT;
	bsccall.label = *label;
	bsccall.bounds = sbounds;	/* save from last bslcvtfull() call */
	bsccall.flags = 0;
	set_label_view(&bsccall.flags, flags);

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) == NOSERVER) {
#ifdef	DEBUG
		(void) fprintf(stderr, "No label server.\n");
#endif	/* DEBUG */
		return (-1);
	} else if (rval != SUCCESS) {
		return (-1);
	} else {
		if (callp->reterr != 0)
			return (-1);
	}

	if (build_strings(&slstringsize, &slstring, &bscret.buf[bscret.string],
	    &slcvtsize, 0, &slcvt, &sldim, bscret.d_len,
	    &bscret.buf[bscret.lwords], &bscret.buf[bscret.swords],
	    &bscret.buf[bscret.dim], 0) != 1) {
		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (0);
	}

	*string = slstring;
	*display = sldim;
	if (callp != &call)
		/* release return buffer */
		(void) munmap((void *)callp, bufsize);
	return (1);
}  /* bslcvt */
#undef	bsccall
#undef	bscret

#define	bcfcall callp->param.acall.cargs.bclearcvt_arg
#define	bcfret callp->param.aret.rvals.bclearcvt_ret
/*
 *	bclearcvtfull - Convert Clearance and initialize static information.
 *
 *	Entry	clearance = Clearance to convert and get dimming list.
 *			    This clearance should lie within the bounds or
 *			    the results may not be meaningful.
 *		bounds = Lower and upper bounds for words lists. Must be
 *			dominated by clearance.
 *		flags = VIEW_INTERNAL, don't promote/demote admin low/high.
 *			VIEW_EXTERNAL, promote/demote admin low/high.
 *
 *	Exit	string = ASCII coded Clearance.
 *		long_words = Array of pointers to visible long word names.
 *		short_words = Array of pointers to visible short word names.
 *		display = Array of indicators as to whether the word is present
 *			  in the converted label (CVT_SET), and/or changeable
 *			  (CVT_DIM).
 *		first_compartment = Zero based index of first compartment.
 *		display_size = Number of entries in the display/words lists.
 *
 *	Returns	-1, If unable to access label encodings database, or
 *			invalid label.
 *		 0, If unable to allocate static memory.
 *		 1, If successful.
 *
 *	Calls	RPC - LABELS_BCLEARCONVERT, SETBCLEAR, SETBLEVEL, TCLNT,
 *			build_strings, clnt_call, clnt_perror.
 *
 *	Uses	cbounds, clrcvt, clrcvtsize, clrdim, clrstring,
 *			clrstringsize.
 */

int
bclearcvtfull(const bclear_t *clearance, const blrange_t *bounds,
    int flags, char **string, char **long_words[], char **short_words[],
    char *display[], int *first_compartment, int *display_size)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(bclearcvt_call_t, 0);
	int	new_words_size;
	int	rval;

	call.callop = BCLEARCVT;
	bcfcall.clear = *clearance;
	bcfcall.bounds.upper_bound = *bounds->upper_bound;
	bcfcall.bounds.lower_bound = *bounds->lower_bound;
	bcfcall.flags = LABELS_FULL_CONVERT;
	set_label_view(&bcfcall.flags, flags);

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) == NOSERVER) {
#ifdef	DEBUG
		(void) fprintf(stderr, "No label server.\n");
#endif	/* DEBUG */
		return (-1);
	} else if (rval != SUCCESS) {
		return (-1);
	} else {
		if (callp->reterr != 0)
			return (-1);
	}

	*first_compartment = bcfret.first_comp;
	*display_size = bcfret.d_len;

	new_words_size = bcfret.l_len + bcfret.s_len + bcfret.d_len +
	    (2 * sizeof (char *)) * bcfret.d_len;

	if (build_strings(&clrstringsize, &clrstring,
	    &bcfret.buf[bcfret.string],
	    &clrcvtsize, new_words_size, &clrcvt,
	    &clrdim, bcfret.d_len,
	    &bcfret.buf[bcfret.lwords], &bcfret.buf[bcfret.swords],
	    &bcfret.buf[bcfret.dim], 1) != 1) {
		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (0);
	}

	/* save for bclearcvt call */
	cbounds.upper_bound = *bounds->upper_bound;
	cbounds.lower_bound = *bounds->lower_bound;

	*string = clrstring;
	*display = clrdim;
	/*LINTED*/
	*long_words = (char **)clrcvt;
	/*LINTED*/
	*short_words = (char **)(clrcvt + *display_size * sizeof (char *));
	if (callp != &call)
		/* release return buffer */
		(void) munmap((void *)callp, bufsize);
	return (1);
}  /* bclearcvtfull */
#undef	bcfcall
#undef	bcfret

#define	bcccall callp->param.acall.cargs.bclearcvt_arg
#define	bccret callp->param.aret.rvals.bclearcvt_ret
/*
 *	bclearcvt - Convert Clearance and update dimming inforamtion.
 *
 *	Entry	clearance = Clearance to convert and get dimming list.
 *			    This clearance should lie within the bounds of the
 *			    corresponding bclearcvtfull call or the results may
 *			    not be meaningful.
 *		flags = VIEW_INTERNAL, don't promote/demote admin low/high.
 *			VIEW_EXTERNAL, promote/demote admin low/high.
 *
 *	Exit	string = ASCII coded Clearance.
 *		display = Array of indicators as to whether the word is present
 *			  in the converted label (CVT_SET), and/or changeable
 *			  (CVT_DIM).
 *
 *	Returns	-1, If unable to access label encodings database, or
 *			invalid label.
 *		 0, If unable to allocate static memory.
 *		 1, If successful.
 *
 *	Calls	RPC - LABELS_BCLEARCONVERT, SETBCLEAR, SETBLEVEL, build_strings,
 *			clnt_call, clnt_perror.
 *
 *	Uses	cbounds, clrdim, clrstring.
 */

int
bclearcvt(const bclear_t *clearance, int flags, char **string,
    char *display[])
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(bclearcvt_call_t, 0);
	int	rval;

	if (clrcvt == NULL)
		return (-1);	/* conversion not initialized */

	call.callop = BCLEARCVT;
	bcccall.clear = *clearance;
	bcccall.bounds = cbounds;	/* save from last bslcvtfull() call */
	bcccall.flags = 0;
	set_label_view(&bcccall.flags, flags);

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) == NOSERVER) {
#ifdef	DEBUG
		(void) fprintf(stderr, "No label server.\n");
#endif	/* DEBUG */
		return (-1);
	} else if (rval != SUCCESS) {
		return (-1);
	} else {
		if (callp->reterr != 0)
			return (-1);
	}

	if (build_strings(&clrstringsize, &clrstring,
	    &bccret.buf[bccret.string],
	    &clrcvtsize, 0, &clrcvt, &clrdim, bccret.d_len,
	    &bccret.buf[bccret.lwords], &bccret.buf[bccret.swords],
	    &bccret.buf[bccret.dim], 0) != 1) {
		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (0);
	}

	*string = clrstring;
	*display = clrdim;
	if (callp != &call)
		/* release return buffer */
		(void) munmap((void *)callp, bufsize);
	return (1);
}  /* bclearcvt */
#undef	bcccall
#undef	bccret

#define	lfret callp->param.aret.rvals.fields_ret
/*
 *	labelfields - Return names for the label fields.
 *
 *	Entry	None
 *
 *	Exit	fields = Updated.
 *
 *	Returns	-1, If unable to access label encodings file, or
 *			labels server failure.
 *		 0, If unable to allocate memory.
 *		 1, If successful.
 *
 *	Calls __call_labeld(LABELFIELDS).
 */

int
labelfields(struct name_fields *fields)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(fields_call_t, 0);
	int	rval;

	call.callop = LABELFIELDS;

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) != SUCCESS) {

		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (-1);
	}

	/* unpack results */

	if ((fields->class_name = strdup(&lfret.buf[lfret.classi])) == NULL) {
		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (0);
	}
	if ((fields->comps_name = strdup(&lfret.buf[lfret.compsi])) == NULL) {
		free(fields->class_name);
		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (0);
	}
	if ((fields->marks_name = strdup(&lfret.buf[lfret.marksi])) == NULL) {
		free(fields->class_name);
		free(fields->comps_name);
		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (0);
	}

	if (callp != &call)
		/* release return buffer */
		(void) munmap((void *)callp, bufsize);
	return (rval);
}  /* labelfields */
#undef	lfret

#define	udret callp->param.aret.rvals.udefs_ret
/*
 *	userdefs - Get default user Sensitivity Label and/or Clearance.
 *
 *	Entry   None.
 *
 *	Exit	sl = default user Sensitivity Label.
 *		clear = default user Clearance.
 *
 *	Returns -1, If unable to access label encodings file, or
 *			labels server failure.
 *		1, If successful.
 *
 *	Calls	__call_labeld(UDEFS).
 */

int
userdefs(bslabel_t *sl, bclear_t *clear)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(udefs_call_t, 0);
	int	rval;

	call.callop = UDEFS;

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) != SUCCESS) {
		/* process error */

		return (-1);
	}

	if (sl != NULL)
		*sl = udret.sl;
	if (clear != NULL)
		*clear = udret.clear;
	return (rval);
}  /* userdefs */
#undef	udret
