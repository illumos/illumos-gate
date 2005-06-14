/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/dhcp.h>
#include "hash.h"
#include "dhcpd.h"
#include "per_dnet.h"

/*
 * This file contains the code which creates, manipulates, and frees encode
 * structures.
 */

/*
 * Free an individual encode structure, including data.
 */
void
free_encode(ENCODE *ecp)
{
	if (ecp != NULL) {
		if (ecp->data)
			free(ecp->data);
		free(ecp);
	}
}

/*
 * Dump an entire encode list, including data.
 */
void
free_encode_list(ENCODE *ecp)
{
	ENCODE *tmp;

	while (ecp != NULL) {
		tmp = ecp;
		ecp = ecp->next;
		free_encode(tmp);
	}
}

/*
 * Allocate an ENCODE structure, and fill it in with the passed data.
 *
 * Doesn't copy data if copy_flag is not set.
 *
 * Returns: ptr for success. Doesn't return if a failure occurs.
 */
ENCODE *
make_encode(uchar_t cat, ushort_t code, uchar_t len, void *data,
    int copy_flag)
{
	ENCODE *ecp;

	ecp = (ENCODE *)smalloc(sizeof (ENCODE));

	ecp->category = cat;
	ecp->code = code;
	ecp->len = len;

	if (data != NULL && len != 0) {
		if (copy_flag == ENC_COPY) {
			ecp->data = (uchar_t *)smalloc(len);
			(void) memcpy(ecp->data, data, len);
		} else
			ecp->data = data;
	}
	return (ecp);
}

/*
 * Find a specific code in the ENCODE list. Doesn't consider class.
 *
 * Returns: ptr if successful, NULL otherwise.
 */
ENCODE *
find_encode(ENCODE *eclp, uchar_t cat, ushort_t code)
{
	for (; eclp != NULL; eclp = eclp->next) {
		if (eclp->category == cat && eclp->code == code)
			return (eclp);
	}
	return (NULL);
}

/*
 * Duplicate the passed encode structure.
 */
ENCODE *
dup_encode(ENCODE *ecp)
{
	assert(ecp != NULL);
	return (make_encode(ecp->category, ecp->code, ecp->len, ecp->data,
	    ENC_COPY));
}

/*
 * Duplicate an encode list. May be called with NULL as a convenience.
 */
ENCODE *
dup_encode_list(ENCODE *ecp)
{
	ENCODE *pp, *np, *headp;

	if (ecp == NULL)
		return (NULL);

	/*
	 * Note: pp/np are used as placeholders in parallel list.
	 */
	pp = headp = NULL;
	for (; ecp != NULL; ecp = ecp->next) {
		np = dup_encode(ecp);
		if (pp == NULL) {
			headp = np;
			np->prev = NULL;
		} else {
			pp->next = np;
			np->prev = pp;
		}
		pp = np;
	}
	return (headp);
}

/*
 * Given two ENCODE lists,  produce NEW ENCODE list by "OR"ing the first
 * encode list with the second. Note that the settings in the second encode
 * list override any identical code settings in the first encode list.
 *
 * The primary list is copied if flags argument is ENC_COPY. Class is not
 * considered.
 *
 * Returns a ptr to the merged list for success, NULL ptr otherwise.
 */
ENCODE *
combine_encodes(ENCODE *first_ecp, ENCODE *second_ecp, int flags)
{
	ENCODE *ep;

	if (first_ecp != NULL) {
		if (flags == ENC_COPY)
			first_ecp = dup_encode_list(first_ecp);

		for (ep = second_ecp; ep != NULL; ep = ep->next)
			replace_encode(&first_ecp, ep, ENC_COPY);
	} else {
		first_ecp = dup_encode_list(second_ecp);
	}
	return (first_ecp);
}

/*
 * Replace/add the encode matching the code value of the second ENCODE
 * parameter in the list represented by the first ENCODE parameter.
 */
void
replace_encode(ENCODE **elistpp, ENCODE *rp, int flags)
{
	ENCODE *wp;

	assert(elistpp != NULL && rp != NULL);

	if (flags == ENC_COPY)
		rp = dup_encode(rp);

	if (*elistpp == NULL) {
		*elistpp = rp;
		return;
	}
	wp = find_encode(*elistpp, rp->category, rp->code);

	if (wp == NULL) {
		rp->next = *elistpp;
		rp->next->prev = rp;
		*elistpp = rp;
		rp->prev = NULL;
	} else {
		if (wp->prev == NULL) {
			rp->next = wp->next;
			*elistpp = rp;
			rp->prev = NULL;
		} else {
			rp->next = wp->next;
			rp->prev = wp->prev;
			wp->prev->next = rp;
		}
		if (wp->next != NULL)
			wp->next->prev = rp;
		free_encode(wp);
	}
}

/*
 * Given a MACRO and a class name, return the ENCODE list for
 * that class name, or null if a ENCODE list by that class doesn't exist.
 */
ENCODE *
vendor_encodes(MACRO *mp, char *class)
{
	VNDLIST **tvpp;
	int	i;

	assert(mp != NULL && class != NULL);

	for (tvpp = mp->list, i = 0; tvpp != NULL && i < mp->classes; i++) {
		if (strcmp(tvpp[i]->class, class) == 0)
			return (tvpp[i]->head);
	}
	return (NULL);
}
