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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	String to binary label translations.
 */

#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <tsol/label.h>

#include "labeld.h"
#include <sys/tsol/label_macro.h>

#undef	CALL_SIZE
#define	CALL_SIZE(type, buf)	(size_t)(sizeof (type) - BUFSIZE + sizeof (int)\
	+ (buf))

#if	!defined(TEXT_DOMAIN)		/* should be defined by Makefiles */
#define	TEXT_DOMAIN "SYS_TEST"
#endif	/* TEXT_DOMAIN */

/* short hands */

#define	IS_ADMIN_LOW(sl) \
	((strncasecmp(sl, ADMIN_LOW, (sizeof (ADMIN_LOW) - 1)) == 0))

#define	IS_ADMIN_HIGH(sh) \
	((strncasecmp(sh, ADMIN_HIGH, (sizeof (ADMIN_HIGH) - 1)) == 0))

#define	ISHEX(f, s) \
	(((((f) & NEW_LABEL) == ((f) | NEW_LABEL)) || \
	(((f) & NO_CORRECTION) == ((f) | NO_CORRECTION))) && \
	(((s)[0] == '0') && (((s)[1] == 'x') || ((s)[1] == 'X'))))

#define	slcall callp->param.acall.cargs.stobsl_arg
#define	slret callp->param.aret.rvals.stobsl_ret
/*
 *	stobsl - Translate Sensitivity Label string to a Binary Sensitivity
 *		Label.
 *
 *	Entry	string = Sensitivity Label string to be translated.
 *		label = Address of Binary Sensitivity Label to be initialized or
 *			updated.
 *		flags = Flags to control translation:
 *			NO_CORRECTION implies NEW_LABEL.
 *			NEW_LABEL, Initialize the label to a valid empty
 *				Sensitivity Label structure.
 *			NO_CORRECTION, Initialize the label to a valid
 *				empty Sensitivity Label structure.
 *				Prohibit correction to the Sensitivity Label.
 *			Other, pass existing Sensitivity Label through for
 *				modification.
 *
 *	Exit	label = Translated (updated) Binary Sensitivity Label.
 *		error = If error reported, the error indicator,
 *				-1, Unable to access label encodings file;
 *				 0, Invalid binary label passed;
 *				>0, Position after the first character in
 *				    string of error, 1 indicates entire string.
 *			Otherwise, unchanged.
 *
 *	Returns	0, If error.
 *		1, If successful.
 *
 *	Calls	__call_labeld(STOBSL), ISHEX, htobsl, strlen,
 *			isspace,
 *			strncasecmp.
 *
 *	Uses	ADMIN_HIGH, ADMIN_LOW.
 */

int
stobsl(const char *string, bslabel_t *label, int flags, int *error)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(stobsl_call_t, strlen(string) + 1);
	int	rval;
	char	*s = (char *)string;

	while (isspace(*s))
		s++;
	/* accept a leading '[' */
	if (*s == '[') {
		s++;
		while (isspace(*s))
			s++;
	}
	if (ISHEX(flags, s)) {
		if (htobsl(s, label)) {
			return (1);
		} else {
			if (error != NULL)
				*error = 1;
			return (0);
		}
	}

	if (datasize > bufsize) {
		if ((callp = malloc(datasize)) == NULL) {
			if (error != NULL)
				*error = -1;
			return (0);
		}
		bufsize = datasize;
	}
	callp->callop = STOBSL;
	slcall.flags  = (flags&NEW_LABEL) ? LABELS_NEW_LABEL : 0;
	slcall.flags |= (flags&NO_CORRECTION) ? LABELS_FULL_PARSE : 0;
	slcall.label = *label;
	(void) strcpy(slcall.string, string);

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) == SUCCESS) {
		int err = callp->reterr;

		if (callp != &call) {
			/* free allocated buffer */
			free(callp);
		}
		/*
		 * reterr == 0, OK,
		 * reterr < 0, invalid binary label,
		 * reterr > 0 error position, 1 == whole string
		 */
		if (err == 0) {
			*label = slret.label;
			return (1);
		} else if (err < 0) {
			err = 0;
		}
		if (error != NULL)
			*error = err;
		return (0);
	} else if (rval == NOSERVER) {
		if (callp != &call) {
			/* free allocated buffer */
			free(callp);
		}
		/* server not present */
		/* special case Admin High and Admin Low */
		if (IS_ADMIN_LOW(s)) {
			BSLLOW(label);
		} else if (IS_ADMIN_HIGH(s)) {
			BSLHIGH(label);
		} else {
			goto err1;
		}
		return (1);
	}
	if (callp != &call) {
		/* free allocated buffer */
		free(callp);
	}
err1:
	if (error != NULL)
		*error = -1;
	return (0);
}  /* stobsl */
#undef	slcall
#undef	slret

#define	clrcall callp->param.acall.cargs.stobclear_arg
#define	clrret callp->param.aret.rvals.stobclear_ret
/*
 *	stobclear - Translate Clearance string to a Binary Clearance.
 *
 *	Entry	string = Clearance string to be translated.
 *		clearance = Address of Binary Clearance to be initialized or
 *			updated.
 *		flags = Flags to control translation:
 *			NO_CORRECTION implies NEW_LABEL.
 *			NEW_LABEL, Initialize the label to a valid empty
 *				Sensitivity Label structure.
 *			NO_CORRECTION, Initialize the label to a valid
 *				empty Sensitivity Label structure.
 *				Prohibit correction to the Sensitivity Label.
 *			Other, pass existing Sensitivity Label through for
 *				modification.
 *
 *	Exit	clearance = Translated (updated) Binary Clearance.
 *		error = If error reported, the error indicator,
 *				-1, Unable to access label encodings file;
 *				 0, Invalid binary label passed;
 *				>0, Position after the first character in
 *				    string of error, 1 indicates entire string.
 *			Otherwise, unchanged.
 *
 *	Returns	0, If error.
 *		1, If successful.
 *
 *	Calls	__call_labeld(STOBCLEAR), ISHEX, htobsl, strlen,
 *			isspace,
 *			strncasecmp.
 *
 *	Uses	ADMIN_HIGH, ADMIN_LOW.
 */

int
stobclear(const char *string, bclear_t *clearance, int flags, int *error)
{
	labeld_data_t	call;
	labeld_data_t	*callp = &call;
	size_t	bufsize = sizeof (labeld_data_t);
	size_t	datasize = CALL_SIZE(stobclear_call_t, strlen(string) + 1);
	int	rval;

	if (ISHEX(flags, string)) {
		if (htobclear(string, clearance)) {
			return (1);
		} else {
			if (error != NULL)
				*error = 1;
			return (0);
		}
	}

	if (datasize > bufsize) {
		if ((callp = malloc(datasize)) == NULL) {
			if (error != NULL)
				*error = -1;
			return (0);
		}
		bufsize = datasize;
	}
	callp->callop = STOBCLEAR;
	clrcall.flags  = (flags&NEW_LABEL) ? LABELS_NEW_LABEL : 0;
	clrcall.flags |= (flags&NO_CORRECTION) ? LABELS_FULL_PARSE : 0;
	clrcall.clear = *clearance;
	(void) strcpy(clrcall.string, string);

	if ((rval = __call_labeld(&callp, &bufsize, &datasize)) == SUCCESS) {
		int err = callp->reterr;

		if (callp != &call) {
			/* free allocated buffer */
			free(callp);
		}
		/*
		 * reterr == 0, OK,
		 * reterr < 0, invalid binary label,
		 * reterr > 0 error position, 1 == whole string
		 */
		if (err == 0) {
			*clearance = clrret.clear;
			return (1);
		} else if (err < 0) {
			err = 0;
		}
		if (error != NULL)
			*error = err;
		return (0);
	} else if (rval == NOSERVER) {
		char *s = (char *)string;

		if (callp != &call) {
			/* free allocated buffer */
			free(callp);
		}
		/* server not present */
		/* special case Admin High and Admin Low */
		while (isspace(*s))
			s++;
		if (IS_ADMIN_LOW(s)) {
			BCLEARLOW(clearance);
		} else if (IS_ADMIN_HIGH(s)) {
			BCLEARHIGH(clearance);
		} else {
			goto err1;
		}
		return (1);
	}
	if (callp != &call) {
		/* free allocated buffer */
		free(callp);
	}
err1:
	if (error != NULL)
		*error = -1;
	return (0);
}  /* stobclear */
#undef	clrcall
#undef	clrret
