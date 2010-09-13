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
/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains the glue functions necessary for gluing in
 * the selected public module API into the private API.
 */

#include <stdlib.h>
#include <string.h>
#include <dhcp_svc_public.h>

/*
 * Allocate a dt_rec_t structure.  Argument values are copied and set
 * to the respective fields within the allocated dt_rec_t structure.
 * Caller is should free structure using free_dtrec().
 */
dt_rec_t *
alloc_dtrec(const char *key, char type, const char *value)
{
	dt_rec_t *retval = malloc(sizeof (dt_rec_t));

	if (key == NULL || value == NULL || retval == NULL) {
		free(retval);
		return (NULL);
	}

	(void) strlcpy(retval->dt_key, key, sizeof (retval->dt_key));
	retval->dt_sig = 0;
	retval->dt_type = type;
	retval->dt_value = strdup(value);
	if (retval->dt_value == NULL) {
		free(retval);
		return (NULL);
	}
	return (retval);
}

/*
 * Allocate a dn_rec_t structure.  Argument values are copied and set
 * to the respective fields within the allocated dn_rec_t structure.
 */
dn_rec_t *
alloc_dnrec(const uchar_t *cid, uchar_t cid_len, uchar_t flags,
    struct in_addr cip, struct in_addr sip, lease_t lease, const char *macro,
    const char *comment)
{
	dn_rec_t *retval = malloc(sizeof (dn_rec_t));

	if (cid == NULL || retval == NULL) {
		free(retval);
		return (NULL);
	}

	retval->dn_cid_len	= cid_len;
	retval->dn_flags	= flags;
	retval->dn_cip		= cip;
	retval->dn_sip		= sip;
	retval->dn_lease	= lease;
	retval->dn_macro[0]	= '\0';
	retval->dn_comment[0]	= '\0';
	retval->dn_sig		= 0;
	(void) memcpy(retval->dn_cid, cid, cid_len);

	if (macro != NULL)
		(void) strlcpy(retval->dn_macro, macro,
		    sizeof (retval->dn_macro));

	if (comment != NULL)
		(void) strlcpy(retval->dn_comment, comment,
		    sizeof (retval->dn_comment));

	return (retval);
}

/*
 * Prepend a dt_rec_t to a dt_rec_list_t; if `listp' is NULL, then
 * the list is created.
 */
dt_rec_list_t *
add_dtrec_to_list(dt_rec_t *entryp, dt_rec_list_t *listp)
{
	dt_rec_list_t *retval = malloc(sizeof (dt_rec_list_t));

	if (entryp == NULL || retval == NULL) {
		free(retval);
		return (NULL);
	}

	retval->dtl_next = listp;
	retval->dtl_rec = entryp;
	return (retval);
}

/*
 * Prepend a dn_rec_t to a dn_rec_list_t; if `listp' is NULL, then
 * the list is created.
 */
dn_rec_list_t *
add_dnrec_to_list(dn_rec_t *entryp, dn_rec_list_t *listp)
{
	dn_rec_list_t *retval = malloc(sizeof (dn_rec_list_t));

	if (entryp == NULL || retval == NULL) {
		free(retval);
		return (NULL);
	}

	retval->dnl_next = listp;
	retval->dnl_rec = entryp;
	return (retval);
}

/*
 * Free all elements of dtp, as well as the dt_rec_t structure itself.
 */
void
free_dtrec(dt_rec_t *dtp)
{
	if (dtp != NULL) {
		free(dtp->dt_value);
		free(dtp);
	}
}

/*
 * Free a list of dt_rec_t's
 */
void
free_dtrec_list(dt_rec_list_t *dtlp)
{
	dt_rec_list_t *next;

	for (; dtlp != NULL; dtlp = next) {
		free_dtrec(dtlp->dtl_rec);
		next = dtlp->dtl_next;
		free(dtlp);
	}
}

/*
 * Free the dn_rec_t structure.
 */
void
free_dnrec(dn_rec_t *dnp)
{
	free(dnp);
}

/*
 * Free a list of dn_rec_t's
 */
void
free_dnrec_list(dn_rec_list_t *dnlp)
{
	dn_rec_list_t *next;

	for (; dnlp != NULL; dnlp = next) {
		free_dnrec(dnlp->dnl_rec);
		next = dnlp->dnl_next;
		free(dnlp);
	}
}
