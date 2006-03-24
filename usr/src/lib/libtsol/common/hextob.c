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
 *      hextob.c - Hexadecimal string to binary label conversion.
 *
 *              These routines convert canonical hexadecimal representations
 *	of internal labels into binary form.
 *
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <tsol/label.h>
#include <sys/tsol/label_macro.h>

/*
 *	htobsl - Convert a Hexadecimal label string to a Sensitivity Label.
 *
 *	Entry	s = Hexadecimal label string to be converted.
 *
 *	Exit	label = Sensitivity Label converted, if successful.
 *			Unchanged, if not successful.
 *
 *	Returns	1, If successful.
 *		0, Otherwise.
 *
 *	Calls	str_to_label, m_label_free.
 */

int
htobsl(const char *s, m_label_t *label)
{
	m_label_t *l = NULL;

	if (str_to_label(s, &l, MAC_LABEL, L_NO_CORRECTION, NULL) == -1) {
		m_label_free(l);
		return (0);
	}
	*label = *l;
	m_label_free(l);
	return (1);
}

/*
 *	htobclear - Convert a Hexadecimal label string to a Clearance.
 *
 *	Entry	s = Hexadecimal label string to be converted.
 *
 *	Exit	clearance = Clearnace converted, if successful.
 *			    Unchanged, if not successful.
 *
 *	Returns	1, If successful.
 *		0, Otherwise.
 *
 *	Calls	str_to_label, m_label_free.
 */

int
htobclear(const char *s, m_label_t *clearance)
{
	m_label_t *c = NULL;

	if (str_to_label(s, &c, USER_CLEAR, L_NO_CORRECTION, NULL) == -1) {
		m_label_free(c);
		return (0);
	}
	*clearance = *c;
	m_label_free(c);
	return (1);
}
