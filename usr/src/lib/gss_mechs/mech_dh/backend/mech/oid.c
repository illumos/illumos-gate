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
 *	oid.c
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include "dh_gssapi.h"

/*
 * These are private mech_dh oid support routines.
 */

/* See if two oids have the same value */
int
__OID_equal(const gss_OID_desc * const oid1, const gss_OID_desc * const oid2)
{
	if (oid1->length != oid2->length)
		return (0);
	return (memcmp(oid1->elements, oid2->elements, oid1->length) == 0);
}


/* Count the number of elements in an oid. Return -1 on badly formed OID */
int
__OID_nel(const gss_OID_desc * const oid)
{
	int i;
	unsigned char *p = (unsigned char *)oid->elements;
	unsigned char *e = p + oid->length;

	/* For each byte */
	for (i = 0; p < e; i++) {
		/* If the upper bit is set it is part of this element */
		while (*p & 0x80) {
			p++;
			if (p == e)
				return (-1);
		}
		p++;
	}

	return (i);
}

/* Copy an oid to an allocated gss_OID_desc */
OM_uint32
__OID_copy_desc(gss_OID dest, const gss_OID_desc * const source)
{
	dest->length = 0;
	/* Allocate the elements of the new OID */
	dest->elements = (void *)New(char, source->length);
	if (dest->elements == NULL)
		return (DH_NOMEM_FAILURE);

	/* Set the length */
	dest->length = source->length;

	/* And copy the elements */
	memcpy(dest->elements, source->elements, dest->length);

	return (DH_SUCCESS);
}

/* Copy an oid, allocating storage */
OM_uint32
__OID_copy(gss_OID *dest, const gss_OID_desc * const source)
{
	/* Allocate a new OID */
	gss_OID oid = New(gss_OID_desc, 1);

	/* Clear the destination */
	*dest = NULL;

	/* return failure if no memory for oid */
	if (oid == NULL)
		return (DH_NOMEM_FAILURE);

	/* Copy the soure oid in to the new OID */
	if (__OID_copy_desc(oid, source) != DH_SUCCESS) {
		Free(oid);
		return (DH_NOMEM_FAILURE);
	}

	/* Set the destination oid */
	*dest = oid;
	return (DH_SUCCESS);
}

/* Check if an oid is a member of an oid set */
int
__OID_is_member(gss_OID_set set, const gss_OID_desc * const element)
{
	int i;

	/* For each member in the set ... */
	for (i = 0; i < set->count; i++)
		if (__OID_equal(element, &set->elements[i]))
			return (TRUE);

	return (FALSE);
}

/* Copy oid set to a newly allocated set */
OM_uint32
__OID_copy_set(gss_OID_set *dest, gss_OID_set source)
{
	gss_OID_set set;
	int i;

	/* Clear the destination */
	*dest = GSS_C_NO_OID_SET;

	/* Allocate a new container for the set */
	set = New(gss_OID_set_desc, 1);
	if (set == NULL)
		return (DH_NOMEM_FAILURE);

	/* Allocate storage for the elements of the set */
	set->elements = New(gss_OID_desc, source->count);
	if (set->elements == NULL) {
		Free(set);
		return (DH_NOMEM_FAILURE);
	}
	/* set the number of elements in the set */
	set->count = source->count;

	/* Add each member of the source set to the new set */
	for (i = 0; i < source->count; i++)
		if (__OID_copy_desc(&set->elements[i], &source->elements[i])
		    != DH_SUCCESS)
			break;

	/* Free partially allocated set on error */
	if (i != source->count) {
		for (; i >= 0; i--)
			Free(set->elements[i].elements);
		Free(set->elements);
		Free(set);
		return (DH_NOMEM_FAILURE);
	}

	/* Set the destination to the set */
	*dest = set;

	return (DH_SUCCESS);
}

/*
 * Form a gss_OID_set from an array of gss_OID_desc.
 */
OM_uint32
__OID_copy_set_from_array(gss_OID_set *dest,
    const gss_OID_desc *array[], size_t nel)
{
	gss_OID_set set;
	int i;

	/* Clear the output set */
	*dest = GSS_C_NO_OID_SET;

	/* Allocate the set */
	set = New(gss_OID_set_desc, 1);
	if (set == NULL)
		return (DH_NOMEM_FAILURE);

	/* And space for the members */
	set->elements = New(gss_OID_desc, nel);
	if (set->elements == NULL) {
		Free(set);
		return (DH_NOMEM_FAILURE);
	}
	/* Set the set count */
	set->count = nel;

	/* For each element in the array, addit to the set */
	for (i = 0; i < set->count; i++)
		if (__OID_copy_desc(&set->elements[i], array[i])
		    != DH_SUCCESS)
			break;

	/* if we failed recover memory */
	if (i != set->count) {
		for (; i >= 0; i--)
			Free(set->elements[i].elements);
		Free(set->elements);
		Free(set);
		return (DH_NOMEM_FAILURE);
	}

	/* Set the destination */
	*dest = set;

	return (DH_SUCCESS);
}

/*
 * Given an oid create a GSS_OID_set with a copy of that oid as its
 * sole member.
 */
OM_uint32
__OID_to_OID_set(gss_OID_set *set, const gss_OID_desc * const oid)
{
	int rc;
	gss_OID_set s;

	/* Nothing to do */
	if (set == NULL)
		return (DH_SUCCESS);

	/* Allocate a set description */
	if ((s = New(gss_OID_set_desc, 1)) == NULL)
		return (DH_NOMEM_FAILURE);

	/* Add the OID to the set */
	s->count = 1;
	if (rc = __OID_copy(&s->elements, oid)) {
		Free(s);
		return (rc);
	}

	/* return the set */
	*set = s;

	return (DH_SUCCESS);
}
