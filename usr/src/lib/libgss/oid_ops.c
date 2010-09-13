/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/gssapi/generic/oid_ops.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * oid_ops.c - GSS-API V2 interfaces to manipulate OIDs
 */

#include <mechglueP.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

/*
 * this oid is defined in the oid structure but not exported to
 * external callers; we must still ensure that we do not delete it.
 */
extern const gss_OID_desc * const gss_nt_service_name;


OM_uint32
generic_gss_release_oid(minor_status, oid)
OM_uint32	*minor_status;
gss_OID	*oid;
{
	if (minor_status)
		*minor_status = 0;

	if (oid == NULL || *oid == GSS_C_NO_OID)
		return (GSS_S_COMPLETE);

	/*
	 * The V2 API says the following!
	 *
	 * gss_release_oid[()] will recognize any of the GSSAPI's own OID
	 * values, and will silently ignore attempts to free these OIDs;
	 * for other OIDs it will call the C free() routine for both the OID
	 * data and the descriptor.  This allows applications to freely mix
	 * their own heap allocated OID values with OIDs returned by GSS-API.
	 */

	/*
	 * We use the official OID definitions instead of the unofficial OID
	 * defintions. But we continue to support the unofficial OID
	 * gss_nt_service_name just in case if some gss applications use
	 * the old OID.
	 */

	if ((*oid != GSS_C_NT_USER_NAME) &&
		(*oid != GSS_C_NT_MACHINE_UID_NAME) &&
		(*oid != GSS_C_NT_STRING_UID_NAME) &&
		(*oid != GSS_C_NT_HOSTBASED_SERVICE) &&
		(*oid != GSS_C_NT_ANONYMOUS) &&
		(*oid != GSS_C_NT_EXPORT_NAME) &&
		(*oid != gss_nt_service_name)) {
		free((*oid)->elements);
		free(*oid);
	}
	*oid = GSS_C_NO_OID;
	return (GSS_S_COMPLETE);
}

OM_uint32
generic_gss_copy_oid(minor_status, oid, new_oid)
	OM_uint32	*minor_status;
	const gss_OID	oid;
	gss_OID		*new_oid;
{
	gss_OID p;

	if (minor_status)
		*minor_status = 0;

	if (new_oid == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (oid == GSS_C_NO_OID)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	p = (gss_OID) malloc(sizeof (gss_OID_desc));
	if (!p) {
		return (GSS_S_FAILURE);
	}
	p->length = oid->length;
	p->elements = malloc(p->length);
	if (!p->elements) {
		free(p);
		return (GSS_S_FAILURE);
	}
	(void) memcpy(p->elements, oid->elements, p->length);
	*new_oid = p;
	return (GSS_S_COMPLETE);
}


OM_uint32
generic_gss_create_empty_oid_set(minor_status, oid_set)
OM_uint32 *minor_status;
gss_OID_set *oid_set;
{
	if (minor_status)
		*minor_status = 0;

	if (oid_set == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if ((*oid_set = (gss_OID_set) malloc(sizeof (gss_OID_set_desc)))) {
		(void) memset(*oid_set, 0, sizeof (gss_OID_set_desc));
		return (GSS_S_COMPLETE);
	} else {
		return (GSS_S_FAILURE);
	}
}

OM_uint32
generic_gss_add_oid_set_member(minor_status, member_oid, oid_set)
OM_uint32 *minor_status;
const gss_OID member_oid;
gss_OID_set *oid_set;
{
	gss_OID elist;
	gss_OID lastel;

	if (minor_status)
		*minor_status = 0;

	if (member_oid == GSS_C_NO_OID || member_oid->length == 0 ||
		member_oid->elements == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (oid_set == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	elist = (*oid_set)->elements;
	/* Get an enlarged copy of the array */
	if (((*oid_set)->elements = (gss_OID) malloc(((*oid_set)->count+1) *
					sizeof (gss_OID_desc)))) {
		/* Copy in the old junk */
		if (elist)
			(void) memcpy((*oid_set)->elements, elist,
				((*oid_set)->count * sizeof (gss_OID_desc)));

		/* Duplicate the input element */
		lastel = &(*oid_set)->elements[(*oid_set)->count];
		if ((lastel->elements =
			(void *) malloc(member_oid->length))) {

			/* Success - copy elements */
			(void) memcpy(lastel->elements, member_oid->elements,
					member_oid->length);
			/* Set length */
			lastel->length = member_oid->length;

			/* Update count */
			(*oid_set)->count++;
			if (elist)
				free(elist);
			return (GSS_S_COMPLETE);
		} else
			free((*oid_set)->elements);
	}
	/* Failure - restore old contents of list */
	(*oid_set)->elements = elist;
	return (GSS_S_FAILURE);
}

OM_uint32
generic_gss_test_oid_set_member(minor_status, member, set, present)
    OM_uint32		*minor_status;
    const gss_OID	member;
    const gss_OID_set	set;
    int			*present;
{
	OM_uint32 i;
	int result;

	if (minor_status)
		*minor_status = 0;

	if (member == GSS_C_NO_OID || set == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (present == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	result = 0;
	for (i = 0; i < set->count; i++) {
		if ((set->elements[i].length == member->length) &&
			!memcmp(set->elements[i].elements,
				member->elements, member->length)) {
			result = 1;
			break;
		}
	}
	*present = result;
	return (GSS_S_COMPLETE);
}

/*
 * OID<->string routines.  These are uuuuugly.
 */
OM_uint32
generic_gss_oid_to_str(minor_status, oid, oid_str)
OM_uint32 *minor_status;
const gss_OID oid;
gss_buffer_t oid_str;
{
	char numstr[128];
	OM_uint32 number;
	int numshift;
	OM_uint32 string_length;
	OM_uint32 i;
	unsigned char *cp;
	char *bp;

	if (minor_status != NULL)
		*minor_status = 0;

	if (oid_str != GSS_C_NO_BUFFER) {
		oid_str->length = 0;
		oid_str->value = NULL;
	}

	if (oid == GSS_C_NO_OID || oid->length == 0 || oid->elements == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (oid_str == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* First determine the size of the string */
	string_length = 0;
	number = 0;
	numshift = 0;
	cp = (unsigned char *) oid->elements;
	number = (OM_uint32) cp[0];
	(void) sprintf(numstr, "%d ", number/40);
	string_length += strlen(numstr);
	(void) sprintf(numstr, "%d ", number%40);
	string_length += strlen(numstr);
	for (i = 1; i < oid->length; i++) {
		if ((OM_uint32) (numshift+7) < (sizeof (OM_uint32)*8)) {
			number = (number << 7) | (cp[i] & 0x7f);
			numshift += 7;
		} else {
			return (GSS_S_FAILURE);
		}

		if ((cp[i] & 0x80) == 0) {
			(void) sprintf(numstr, "%d ", number);
			string_length += strlen(numstr);
			number = 0;
			numshift = 0;
		}
	}
	/*
	 * If we get here, we've calculated the length of "n n n ... n ".  Add 4
	 * here for "{ " and "}\0".
	 */
	string_length += 4;
	if ((bp = (char *)malloc(string_length))) {
		(void) strcpy(bp, "{ ");
		number = (OM_uint32) cp[0];
		(void) sprintf(numstr, "%d ", number/40);
		(void) strcat(bp, numstr);
		(void) sprintf(numstr, "%d ", number%40);
		(void) strcat(bp, numstr);
		number = 0;
		cp = (unsigned char *) oid->elements;
		for (i = 1; i < oid->length; i++) {
			number = (number << 7) | (cp[i] & 0x7f);
			if ((cp[i] & 0x80) == 0) {
				(void) sprintf(numstr, "%d ", number);
				(void) strcat(bp, numstr);
				number = 0;
			}
		}
		(void) strcat(bp, "}");
		oid_str->length = strlen(bp)+1;
		oid_str->value = (void *) bp;
		return (GSS_S_COMPLETE);
	}
	return (GSS_S_FAILURE);
}

/*
 * This routine will handle 2 types of oid string formats:
 * 	1 - { 1 2 3 4 }  where the braces are optional
 *	2 - 1.2.3.4 this is an alernative format
 * The first format is mandated by the gss spec.  The
 * second format is popular outside of the gss community so
 * has been added.
 */
OM_uint32
generic_gss_str_to_oid(minor_status, oid_str, oid)
OM_uint32 *minor_status;
const gss_buffer_t oid_str;
gss_OID *oid;
{
	char *cp, *bp, *startp;
	int brace;
	int numbuf;
	int onumbuf;
	OM_uint32 nbytes;
	int index;
	unsigned char *op;

	if (minor_status != NULL)
		*minor_status = 0;

	if (oid != NULL)
		*oid = GSS_C_NO_OID;

	if (GSS_EMPTY_BUFFER(oid_str))
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (oid == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	brace = 0;
	bp = (char *)oid_str->value;
	cp = bp;
	/* Skip over leading space */
	while ((bp < &cp[oid_str->length]) && isspace(*bp))
		bp++;
	if (*bp == '{') {
		brace = 1;
		bp++;
	}
	while ((bp < &cp[oid_str->length]) && isspace(*bp))
		bp++;
	startp = bp;
	nbytes = 0;

	/*
	 * The first two numbers are chewed up by the first octet.
	 */
	if (sscanf(bp, "%d", &numbuf) != 1) {
		return (GSS_S_FAILURE);
	}
	while ((bp < &cp[oid_str->length]) && isdigit(*bp))
		bp++;
	while ((bp < &cp[oid_str->length]) &&
		(isspace(*bp) || *bp == '.'))
		bp++;
	if (sscanf(bp, "%d", &numbuf) != 1) {
		return (GSS_S_FAILURE);
	}
	while ((bp < &cp[oid_str->length]) && isdigit(*bp))
		bp++;
	while ((bp < &cp[oid_str->length]) &&
		(isspace(*bp) || *bp == '.'))
		bp++;
	nbytes++;
	while (isdigit(*bp)) {
		if (sscanf(bp, "%d", &numbuf) != 1) {
			return (GSS_S_FAILURE);
		}
		while (numbuf) {
			nbytes++;
			numbuf >>= 7;
		}
		while ((bp < &cp[oid_str->length]) && isdigit(*bp))
			bp++;
		while ((bp < &cp[oid_str->length]) &&
			(isspace(*bp) || *bp == '.'))
			bp++;
	}
	if (brace && (*bp != '}')) {
		return (GSS_S_FAILURE);
	}

	/*
	 * Phew!  We've come this far, so the syntax is good.
	 */
	if ((*oid = (gss_OID) malloc(sizeof (gss_OID_desc)))) {
		if (((*oid)->elements = (void *) malloc(nbytes))) {
			(*oid)->length = nbytes;
			op = (unsigned char *) (*oid)->elements;
			bp = startp;
			(void) sscanf(bp, "%d", &numbuf);
			while (isdigit(*bp))
				bp++;
			while (isspace(*bp) || *bp == '.')
				bp++;
			onumbuf = 40*numbuf;
			(void) sscanf(bp, "%d", &numbuf);
			onumbuf += numbuf;
			*op = (unsigned char) onumbuf;
			op++;
			while (isdigit(*bp))
				bp++;
			while (isspace(*bp) || *bp == '.')
				bp++;
			while (isdigit(*bp)) {
				(void) sscanf(bp, "%d", &numbuf);
				nbytes = 0;
		/* Have to fill in the bytes msb-first */
				onumbuf = numbuf;
				while (numbuf) {
					nbytes++;
					numbuf >>= 7;
				}
				numbuf = onumbuf;
				op += nbytes;
				index = -1;
				while (numbuf) {
					op[index] = (unsigned char)
							numbuf & 0x7f;
					if (index != -1)
						op[index] |= 0x80;
					index--;
					numbuf >>= 7;
				}
				while (isdigit(*bp))
					bp++;
				while (isspace(*bp) || *bp == '.')
					bp++;
			}
			return (GSS_S_COMPLETE);
		} else {
			free(*oid);
			*oid = GSS_C_NO_OID;
		}
	}
	return (GSS_S_FAILURE);
}

/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
OM_uint32
gss_copy_oid_set(
	OM_uint32 *minor_status,
	const gss_OID_set_desc * const oidset,
	gss_OID_set *new_oidset
)
{
	gss_OID_set_desc *copy;
	OM_uint32 minor = 0;
	OM_uint32 major = GSS_S_COMPLETE;
	OM_uint32 index;

	if (minor_status != NULL)
		*minor_status = 0;

	if (new_oidset != NULL)
		*new_oidset = GSS_C_NO_OID_SET;

	if (oidset == GSS_C_NO_OID_SET)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (new_oidset == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if ((copy = (gss_OID_set_desc *) calloc(1, sizeof (*copy))) == NULL) {
		major = GSS_S_FAILURE;
		goto done;
	}

	if ((copy->elements = (gss_OID_desc *)
	    calloc(oidset->count, sizeof (*copy->elements))) == NULL) {
		major = GSS_S_FAILURE;
		goto done;
	}
	copy->count = oidset->count;

	for (index = 0; index < copy->count; index++) {
		gss_OID_desc *out = &copy->elements[index];
		gss_OID_desc *in = &oidset->elements[index];

		if ((out->elements = (void *) malloc(in->length)) == NULL) {
			major = GSS_S_FAILURE;
			goto done;
		}
		(void) memcpy(out->elements, in->elements, in->length);
		out->length = in->length;
	}

	*new_oidset = copy;
done:
	if (major != GSS_S_COMPLETE) {
		(void) gss_release_oid_set(&minor, &copy);
	}

	return (major);
}
