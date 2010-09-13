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
 *      btohex.c - Binary to Hexadecimal string conversion.
 *
 *		These routines convert binary labels into canonical
 *	hexadecimal representations of the binary form.
 */

#include <stdlib.h>
#include <strings.h>
#include <tsol/label.h>
#include <sys/tsol/label_macro.h>

/* 0x + Classification + '-' + ll + '-' + Compartments + end of string */
#define	_HEX_SIZE 2+(sizeof (Classification_t)*2)+4+\
	(sizeof (Compartments_t)*2)+1

static char hex_buf[_HEX_SIZE];

/*
 *	h_alloc - Allocate data storage for a Hexadecimal label string.
 *
 *	Entry	id = Type of label to allocate storage for.
 *		     SUN_SL_ID  - Sensitivity Label.
 *		     SUN_CLR_ID - Clearance.
 *
 *	Returns	NULL, If unable to allocate storage.
 *		Address of buffer.
 *
 *	Calls	malloc;
 */

char *
h_alloc(unsigned char id)
{
	size_t size;

	switch (id) {

	case SUN_SL_ID:
		size = _HEX_SIZE;
		break;

	case SUN_CLR_ID:
		size = _HEX_SIZE;
		break;

	default:
		return (NULL);
	}

	return ((char *)malloc(size));
}


/*
 *	h_free - Free a Hexadecimal label string.
 *
 *	Entry	hex = Hexadecimal label string.
 *
 *	Returns	none.
 *
 *	Calls	free.
 */

void
h_free(char *hex)
{

	if (hex == NULL)
		return;

	free(hex);
}


/*
 *	bsltoh_r - Convert a Sensitivity Label into a Hexadecimal label string.
 *
 *	Entry	label = Sensitivity Label to be translated.
 *		hex = Buffer to place converted label.
 *		len = Length of buffer.
 *
 *	Returns	NULL, If invalid label type.
 *		Address of buffer.
 *
 *	Calls	label_to_str, strncpy.
 */

char *
bsltoh_r(const m_label_t *label, char *hex)
{
	char *h;

	if (label_to_str(label, &h, M_INTERNAL, DEF_NAMES) != 0) {
		free(h);
		return (NULL);
	}

	(void) strncpy(hex, (const char *)h, _HEX_SIZE);
	free(h);
	return (hex);
}


/*
 *	bsltoh - Convert a Sensitivity Label into a Hexadecimal label string.
 *
 *	Entry	label = Sensitivity Label to be translated.
 *
 *	Returns	NULL, If invalid label type.
 *		Address of statically allocated hex label string.
 *
 *	Calls	bsltoh_r.
 *
 *	Uses	hex_buf.
 */

char *
bsltoh(const m_label_t *label)
{

	return (bsltoh_r(label, hex_buf));
}


/*
 *	bcleartoh_r - Convert a Clearance into a Hexadecimal label string.
 *
 *	Entry	clearance = Clearance to be translated.
 *		hex = Buffer to place converted label.
 *		len = Length of buffer.
 *
 *	Returns	NULL, If invalid label type.
 *		Address of buffer.
 *
 *	Calls	label_to_str, strncpy.
 */

char *
bcleartoh_r(const m_label_t *clearance, char *hex)
{
	char *h;

	if (label_to_str(clearance, &h, M_INTERNAL, DEF_NAMES) != 0) {
		free(h);
		return (NULL);
	}

	(void) strncpy(hex, (const char *)h, _HEX_SIZE);
	free(h);
	return (hex);
}


/*
 *	bcleartoh - Convert a Clearance into a Hexadecimal label string.
 *
 *	Entry	clearance = Clearance to be translated.
 *
 *	Returns	NULL, If invalid label type.
 *		Address of statically allocated hex label string.
 *
 *	Calls	bcleartoh_r.
 *
 *	Uses	hex_buf.
 */

char *
bcleartoh(const m_label_t *clearance)
{

	return (bcleartoh_r(clearance, hex_buf));
}
