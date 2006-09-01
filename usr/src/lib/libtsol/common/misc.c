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
 *	Miscellaneous user interfaces to trusted label functions.
 *
 */


#include <ctype.h>
#include <stdlib.h>
#include <strings.h>

#include <sys/mman.h>

#include <tsol/label.h>

#include "labeld.h"
#include "clnt.h"
#include <sys/tsol/label_macro.h>
#include <secdb.h>
#include <user_attr.h>

static	bslabel_t slow, shigh;	/* static Admin Low and High SLs */
static	bclear_t  clow, chigh;	/* static Admin Low and High CLRs */

static char color[MAXCOLOR];


#define	incall callp->param.acall.cargs.inset_arg
#define	inret callp->param.aret.rvals.inset_ret
/*
 *	blinset - Check in a label set.
 *
 *	Entry	label = Sensitivity Label to check.
 *		id    = Label set identifier of set to check.
 *
 *	Exit	None.
 *
 *	Returns	-1, If label set unavailable, or server failure.
 *		 0, If label not in label set.
 *		 1, If label is in the label set.
 *
 *	Calls	__call_labeld(BLINSET), BLTYPE, BSLLOW, BSLHIGH.
 *
 *	Uses	slow, shigh.
 */

int
blinset(const bslabel_t *label, const set_id *id)
{
	if (id->type == SYSTEM_ACCREDITATION_RANGE) {
		if (!BLTYPE(&slow, SUN_SL_ID)) {
			/* initialize static labels. */

			BSLLOW(&slow);
			BSLHIGH(&shigh);
		}

		if (BLTYPE(label, SUN_SL_ID) &&
		    (BLEQUAL(label, &slow) || BLEQUAL(label, &shigh)))

			return (1);
	}
	if (id->type == USER_ACCREDITATION_RANGE ||
	    id->type == SYSTEM_ACCREDITATION_RANGE) {
		labeld_data_t	call;
		labeld_data_t	*callp = &call;
		size_t	bufsize = sizeof (labeld_data_t);
		size_t	datasize = CALL_SIZE(inset_call_t, 0);

		call.callop = BLINSET;
		incall.label = *label;
		incall.type = id->type;

		if (__call_labeld(&callp, &bufsize, &datasize) != SUCCESS) {
			/* process error */

			return (-1);
		}
		return (inret.inset);
	} else {
		/*
		 * Only System and User Accreditation Ranges presently
		 * implemented.
		 */
		return (-1);
	}
}
#undef	incall
#undef	inret

#define	slvcall callp->param.acall.cargs.slvalid_arg
#define	slvret callp->param.aret.rvals.slvalid_ret
/*
 *	bslvalid - Check Sensitivity Label for validity.
 *
 *	Entry	label = Sensitivity Label to check.
 *
 *	Exit	None.
 *
 *	Returns	-1, If unable to access label encodings file, or server failure.
 *		 0, If label not valid.
 *		 1, If label is valid.
 *
 *	Calls	__call_labeld(BSLVALID), BLTYPE, BSLLOW, BSLHIGH.
 *
 *	Uses	slow, shigh.
 *
 */

int
bslvalid(const bslabel_t *label)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(slvalid_call_t, 0);

	if (!BLTYPE(&slow, SUN_SL_ID)) {
		/* initialize static labels. */

		BSLLOW(&slow);
		BSLHIGH(&shigh);
	}

	if (BLTYPE(label, SUN_SL_ID) &&
	    (BLEQUAL(label, &slow) || BLEQUAL(label, &shigh))) {

		return (1);
	}

	call.callop = BSLVALID;
	slvcall.label = *label;

	if (__call_labeld(&callp, &bufsize, &datasize) != SUCCESS) {
		/* process error */

		return (-1);
	}
	return (slvret.valid);
}
#undef	slvcall
#undef	slvret

#define	clrvcall callp->param.acall.cargs.clrvalid_arg
#define	clrvret callp->param.aret.rvals.clrvalid_ret
/*
 *	bclearvalid - Check Clearance for validity.
 *
 *	Entry	clearance = Clearance to check.
 *
 *	Exit	None.
 *
 *	Returns	-1, If unable to access label encodings file, or server failure.
 *		 0, If label not valid.
 *		 1, If label is valid.
 *
 *	Calls	__call_labeld(BCLEARVALID), BLTYPE, BCLEARLOW, BCLEARHIGH.
 *
 *	Uses	clow, chigh.
 *
 */

int
bclearvalid(const bclear_t *clearance)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(clrvalid_call_t, 0);

	if (!BLTYPE(&clow, SUN_CLR_ID)) {
		/* initialize static labels. */

		BCLEARLOW(&clow);
		BCLEARHIGH(&chigh);
	}

	if (BLTYPE(clearance, SUN_CLR_ID) &&
	    (BLEQUAL(clearance, &clow) || BLEQUAL(clearance, &chigh))) {

		return (1);
	}

	call.callop = BCLEARVALID;
	clrvcall.clear = *clearance;

	if (__call_labeld(&callp, &bufsize, &datasize) != SUCCESS) {
		/* process error */

		return (-1);
	}
	return (clrvret.valid);
}
#undef	clrvcall
#undef	clrvret

#define	inforet callp->param.aret.rvals.info_ret
/*
 *	labelinfo - Get information about the label encodings file.
 *
 *	Entry	info = Address of label_info structure to update.
 *
 *	Exit	info = Updated.
 *
 *	Returns	-1, If unable to access label encodings file, or server failure.
 *		 1, If successful.
 *
 *	Calls	__call_labeld(LABELINFO).
 */

int
labelinfo(struct label_info *info)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(info_call_t, 0);
	int	rval;

	call.callop = LABELINFO;

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) != SUCCESS) {
		/* process error */

		return (-1);
	}
	*info = inforet.info;
	return (rval);
}
#undef	inforet

#define	lvret callp->param.aret.rvals.vers_ret
/*
 *	labelvers - Get version string of the label encodings file.
 *
 *	Entry	version = Address of string pointer to return.
 *		len = Length of string if pre-allocated.
 *
 *	Exit	version = Updated.
 *
 *	Returns	-1, If unable to access label encodings file, or server failure.
 *		 0, If unable to allocate version string,
 *			or pre-allocated version string to short
 *			(and **version = '\0').
 *		length (including null) of version string, If successful.
 *
 *	Calls	__call_labeld(LABELVERS)
 *			malloc, strlen.
 */

ssize_t
labelvers(char **version, size_t len)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(vers_call_t, 0);
	size_t	ver_len;

	call.callop = LABELVERS;

	if (__call_labeld(&callp, &bufsize, &datasize) != SUCCESS) {

		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (-1);
	}

	/* unpack length */

	ver_len = strlen(lvret.vers) + 1;
	if (*version == NULL) {
		if ((*version = malloc(ver_len)) == NULL) {
			if (callp != &call)
				/* release return buffer */
				(void) munmap((void *)callp, bufsize);
			return (0);
		}
	} else if (ver_len > len) {
		**version = '\0';
		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (0);
	}
	(void) strcpy(*version, lvret.vers);

	if (callp != &call)
		/* release return buffer */
		(void) munmap((void *)callp, bufsize);
	return (ver_len);
}  /* labelvers */
#undef	lvret

#define	ccall callp->param.acall.cargs.color_arg
#define	cret callp->param.aret.rvals.color_ret
/*
 *	bltocolor - get ASCII color name of label.
 *
 *	Entry	label = Sensitivity Level of color to get.
 *		size  = Size of the color_name array.
 *		color_name = Storage for ASCII color name string to be returned.
 *
 *	Exit	None.
 *
 *	Returns	NULL, If error (label encodings file not accessible,
 *			   invalid label, no color for this label).
 *		Address of color_name parameter containing ASCII color name
 *			defined for the label.
 *
 *	Calls	__call_labeld(BLTOCOLOR), strlen.
 */

char *
bltocolor_r(const blevel_t *label, size_t size, char *color_name)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(color_call_t, 0);
	char	*colorp;

	call.callop = BLTOCOLOR;
	ccall.label = *label;

	if ((__call_labeld(&callp, &bufsize, &datasize) != SUCCESS) ||
	    (callp->reterr != 0) ||
	    (strlen(cret.color) >= size)) {

		if (callp != &call)
			/* release return buffer */
			(void) munmap((void *)callp, bufsize);
		return (NULL);
	}

	colorp = strcpy(color_name, cret.color);

	if (callp != &call)
		/* release return buffer */
		(void) munmap((void *)callp, bufsize);
	return (colorp);
}  /* bltocolor_r */
#undef	ccall
#undef	cret

/*
 *	bltocolor - get ASCII color name of label.
 *
 *	Entry	label = Sensitivity Level of color to get.
 *
 *	Exit	None.
 *
 *	Returns	NULL, If error (label encodings file not accessible,
 *			   invalid label, no color for this label).
 *		Address of statically allocated string containing ASCII
 *			color name defined for the classification contained
 *			in label.
 *
 *	Uses	color.
 *
 *	Calls	bltocolor_r.
 */

char *
bltocolor(const blevel_t *label)
{
	return (bltocolor_r(label, sizeof (color), color));
}  /* bltocolor */

blevel_t *
blabel_alloc(void)
{
	return (m_label_alloc(MAC_LABEL));
}

void
blabel_free(blevel_t *label_p)
{
	free(label_p);
}

size_t
blabel_size(void)
{
	return (sizeof (blevel_t));
}

/*
 *	getuserrange - get label range for user
 *
 *	Entry	username of user
 *
 *	Exit	None.
 *
 *	Returns	NULL, If memory allocation failure or userdefs failure.
 *		otherwise returns the allocates m_range_t with the
 *		user's min and max labels set.
 */

m_range_t *
getuserrange(const char *username)
{
	char		*kv_str = NULL;
	userattr_t 	*userp = NULL;
	m_range_t 	*range;
	m_label_t	*def_min, *def_clr;

	/*
	 * Get some memory
	 */

	if ((range = malloc(sizeof (m_range_t))) == NULL) {
		return (NULL);
	}
	if ((range->lower_bound = m_label_alloc(MAC_LABEL)) == NULL) {
		free(range);
		return (NULL);
	}
	def_min = range->lower_bound;
	if ((range->upper_bound = m_label_alloc(USER_CLEAR)) == NULL) {
		m_label_free(range->lower_bound);
		free(range);
		return (NULL);
	}
	def_clr = range->upper_bound;

	/* If the user has an explicit min_label or clearance, use it. */
	if ((userp = getusernam(username)) != NULL) {
		if ((kv_str = kva_match(userp->attr, USERATTR_MINLABEL))
		    != NULL) {
			(void) str_to_label(kv_str, &range->lower_bound,
			    MAC_LABEL, L_NO_CORRECTION, NULL);
			def_min = NULL;		/* don't get default later */
		}
		if ((kv_str = kva_match(userp->attr, USERATTR_CLEARANCE))
		    != NULL) {
			(void) str_to_label(kv_str, &range->upper_bound,
			    USER_CLEAR, L_NO_CORRECTION, NULL);
			def_clr = NULL;		/* don't get default later */
		}
		free_userattr(userp);
	}
	if (def_min || def_clr) {
		/* Need to use system default clearance and/or min_label */
		if ((userdefs(def_min, def_clr)) == -1) {
			m_label_free(range->lower_bound);
			m_label_free(range->upper_bound);
			free(range);
			return (NULL);
		}
	}

	return (range);
}
