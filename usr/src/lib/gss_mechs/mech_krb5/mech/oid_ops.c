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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * oid_ops.c - GSS-API V2 interfaces to manipulate OIDs
 */

#include "mglueP.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gssapi_generic.h>
#include <errno.h>
#include <ctype.h>

OM_uint32
generic_gss_release_oid(minor_status, oid)
    OM_uint32	*minor_status;
    gss_OID	*oid;
{
    if (minor_status)
	*minor_status = 0;

    if (oid == NULL || *oid == GSS_C_NO_OID)
	return(GSS_S_COMPLETE);

    /*
     * The V2 API says the following!
     *
     * gss_release_oid[()] will recognize any of the GSSAPI's own OID values,
     * and will silently ignore attempts to free these OIDs; for other OIDs
     * it will call the C free() routine for both the OID data and the
     * descriptor.  This allows applications to freely mix their own heap-
     * allocated OID values with OIDs returned by GSS-API.
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
    return(GSS_S_COMPLETE);
}

OM_uint32
generic_gss_copy_oid(minor_status, oid, new_oid)
	OM_uint32	*minor_status;
	gss_OID_desc * const oid;
	gss_OID		*new_oid;
{
	gss_OID		p;

	*minor_status = 0;

	p = (gss_OID) malloc(sizeof(gss_OID_desc));
	if (!p) {
		*minor_status = ENOMEM;
		return GSS_S_FAILURE;
	}
	p->length = oid->length;
	p->elements = malloc(p->length);
	if (!p->elements) {
		free(p);
		return GSS_S_FAILURE;
	}
	memcpy(p->elements, oid->elements, p->length);
	*new_oid = p;
	return(GSS_S_COMPLETE);
}


OM_uint32
generic_gss_create_empty_oid_set(minor_status, oid_set)
    OM_uint32	*minor_status;
    gss_OID_set	*oid_set;
{
    *minor_status = 0;

    if ((*oid_set = (gss_OID_set) malloc(sizeof(gss_OID_set_desc)))) {
	memset(*oid_set, 0, sizeof(gss_OID_set_desc));
	return(GSS_S_COMPLETE);
    }
    else {
	*minor_status = ENOMEM;
	return(GSS_S_FAILURE);
    }
}

OM_uint32
generic_gss_add_oid_set_member(minor_status, member_oid, oid_set)
    OM_uint32	*minor_status;
    gss_OID_desc * const member_oid;
    gss_OID_set	*oid_set;
{
    gss_OID	elist;
    gss_OID	lastel;

    *minor_status = 0;

    if (member_oid == NULL || member_oid->length == 0 ||
	member_oid->elements == NULL)
	return (GSS_S_CALL_INACCESSIBLE_READ);

    elist = (*oid_set)->elements;
    /* Get an enlarged copy of the array */
    if (((*oid_set)->elements = (gss_OID) malloc(((*oid_set)->count+1) *
						  sizeof(gss_OID_desc)))) {
	/* Copy in the old junk */
	if (elist)
	    memcpy((*oid_set)->elements,
		   elist,
		   ((*oid_set)->count * sizeof(gss_OID_desc)));

	/* Duplicate the input element */
	lastel = &(*oid_set)->elements[(*oid_set)->count];
	if ((lastel->elements =
	     (void *) malloc((size_t) member_oid->length))) {
	    /* Success - copy elements */
	    memcpy(lastel->elements, member_oid->elements,
		   (size_t) member_oid->length);
	    /* Set length */
	    lastel->length = member_oid->length;

	    /* Update count */
	    (*oid_set)->count++;
	    if (elist)
		free(elist);
	    *minor_status = 0;
	    return(GSS_S_COMPLETE);
	}
	else
	    free((*oid_set)->elements);
    }
    /* Failure - restore old contents of list */
    (*oid_set)->elements = elist;
    *minor_status = ENOMEM;
    return(GSS_S_FAILURE);
}

OM_uint32
generic_gss_test_oid_set_member(minor_status, member, set, present)
    OM_uint32	*minor_status;
    gss_OID_desc * const member;
    gss_OID_set	set;
    int		*present;
{
    OM_uint32	i;
    int		result;

    *minor_status = 0;

    if (member == NULL || set == NULL)
	return (GSS_S_CALL_INACCESSIBLE_READ);

    if (present == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    result = 0;
    for (i=0; i<set->count; i++) {
	if ((set->elements[i].length == member->length) &&
	    !memcmp(set->elements[i].elements,
		    member->elements,
		    (size_t) member->length)) {
	    result = 1;
	    break;
	}
    }
    *present = result;
    return(GSS_S_COMPLETE);
}

/*
 * OID<->string routines.  These are uuuuugly.
 */
OM_uint32
generic_gss_oid_to_str(minor_status, oid, oid_str)
    OM_uint32		*minor_status;
    gss_OID_desc * const oid;
    gss_buffer_t	oid_str;
{
    char		numstr[128];
    OM_uint32		number;
    int			numshift;
    OM_uint32 string_length;
    OM_uint32 i;
    unsigned char	*cp;
    char		*bp;

    if (minor_status != NULL)
	*minor_status = 0;

    if (oid_str != GSS_C_NO_BUFFER) {
	oid_str->length = 0;
	oid_str->value = NULL;
    }

    if (oid == NULL || oid->length == 0 || oid->elements == NULL)
	return (GSS_S_CALL_INACCESSIBLE_READ);

    if (oid_str == GSS_C_NO_BUFFER)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    /* Decoded according to krb5/gssapi_krb5.c */

    /* First determine the size of the string */
    string_length = 0;
    number = 0;
    numshift = 0;
    cp = (unsigned char *) oid->elements;
    number = (unsigned long) cp[0];
    snprintf(numstr, sizeof(numstr), "%lu ", (unsigned long)number/40);
    string_length += strlen(numstr);
    snprintf(numstr, sizeof(numstr), "%lu ", (unsigned long)number%40);
    string_length += strlen(numstr);
    for (i=1; i<oid->length; i++) {
	if ((OM_uint32) (numshift+7) < (sizeof (OM_uint32)*8)) {/* XXX */
	    number = (number << 7) | (cp[i] & 0x7f);
	    numshift += 7;
	}
	else {
	    return(GSS_S_FAILURE);
	}
	if ((cp[i] & 0x80) == 0) {
	    snprintf(numstr, sizeof(numstr), "%lu ", (unsigned long)number);
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
    if ((bp = (char *) malloc(string_length))) {
	strcpy(bp, "{ ");
	number = (OM_uint32) cp[0];
	snprintf(numstr, sizeof(numstr), "%lu ", (unsigned long)number/40);
	strcat(bp, numstr);
	snprintf(numstr, sizeof(numstr), "%lu ", (unsigned long)number%40);
	strcat(bp, numstr);
	number = 0;
	cp = (unsigned char *) oid->elements;
	for (i=1; i<oid->length; i++) {
	    number = (number << 7) | (cp[i] & 0x7f);
	    if ((cp[i] & 0x80) == 0) {
	        snprintf(numstr, sizeof(numstr), "%lu ", (unsigned long)number);
		strcat(bp, numstr);
		number = 0;
	    }
	}
	strcat(bp, "}");
	oid_str->length = strlen(bp)+1;
	oid_str->value = (void *) bp;
	return(GSS_S_COMPLETE);
    }
    *minor_status = ENOMEM;
    return(GSS_S_FAILURE);
}

OM_uint32
generic_gss_str_to_oid(minor_status, oid_str, oid)
    OM_uint32		*minor_status;
    gss_buffer_t	oid_str;
    gss_OID		*oid;
{
    unsigned char	*cp, *bp, *startp;
    int		brace;
    long	numbuf;
    long	onumbuf;
    OM_uint32	nbytes;
    int		index;
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
    bp = oid_str->value;
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
    if (sscanf((char *)bp, "%ld", &numbuf) != 1) {
	*minor_status = EINVAL;
	return(GSS_S_FAILURE);
    }
    while ((bp < &cp[oid_str->length]) && isdigit(*bp))
	bp++;
    while ((bp < &cp[oid_str->length]) && isspace(*bp))
	bp++;
    if (sscanf((char *)bp, "%ld", &numbuf) != 1) {
	*minor_status = EINVAL;
	return(GSS_S_FAILURE);
    }
    while ((bp < &cp[oid_str->length]) && isdigit(*bp))
	bp++;
    while ((bp < &cp[oid_str->length]) &&
	   (isspace(*bp) || *bp == '.'))
	bp++;
    nbytes++;
    while (isdigit(*bp)) {
	if (sscanf((char *)bp, "%ld", &numbuf) != 1) {
	    return(GSS_S_FAILURE);
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
	return(GSS_S_FAILURE);
    }

    /*
     * Phew!  We've come this far, so the syntax is good.
     */
    if ((*oid = (gss_OID) malloc(sizeof(gss_OID_desc)))) {
	if (((*oid)->elements = (void *) malloc(nbytes))) {
	    (*oid)->length = nbytes;
	    op = (unsigned char *) (*oid)->elements;
	    bp = startp;
	    (void) sscanf((char *)bp, "%ld", &numbuf);
	    while (isdigit(*bp))
		bp++;
	    while (isspace(*bp) || *bp == '.')
		bp++;
	    onumbuf = 40*numbuf;
	    (void) sscanf((char *)bp, "%ld", &numbuf);
	    onumbuf += numbuf;
	    *op = (unsigned char) onumbuf;
	    op++;
	    while (isdigit(*bp))
		bp++;
	    while (isspace(*bp) || *bp == '.')
		bp++;
	    while (isdigit(*bp)) {
		(void) sscanf((char *)bp, "%ld", &numbuf);
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
		    op[index] = (unsigned char) numbuf & 0x7f;
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
	    return(GSS_S_COMPLETE);
	}
	else {
	    free(*oid);
	    *oid = GSS_C_NO_OID;
	}
    }
    return(GSS_S_FAILURE);
}

/* Compose an OID of a prefix and an integer suffix */
OM_uint32
generic_gss_oid_compose(
    OM_uint32 *minor_status,
    const char *prefix,
    size_t prefix_len,
    int suffix,
    gss_OID_desc *oid)
{
    int osuffix, i;
    size_t nbytes;
    unsigned char *op;

    if (oid == GSS_C_NO_OID) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }
    if (oid->length < prefix_len) {
	*minor_status = ERANGE;
	return GSS_S_FAILURE;
    }

    memcpy(oid->elements, prefix, prefix_len);

    nbytes = 0;
    osuffix = suffix;
    while (suffix) {
	nbytes++;
	suffix >>= 7;
    }
    suffix = osuffix;

    if (oid->length < prefix_len + nbytes) {
	*minor_status = ERANGE;
	return GSS_S_FAILURE;
    }

    op = (unsigned char *) oid->elements + prefix_len + nbytes;
    i = -1;
    while (suffix) {
	op[i] = (unsigned char)suffix & 0x7f;
	if (i != -1)
	    op[i] |= 0x80;
	i--;
	suffix >>= 7;
    }

    oid->length = prefix_len + nbytes;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
generic_gss_oid_decompose(
    OM_uint32 *minor_status,
    const char *prefix,
    size_t prefix_len,
    gss_OID_desc *oid,
    int *suffix)
{
    size_t i, slen;
    unsigned char *op;

    if (oid->length < prefix_len ||
	memcmp(oid->elements, prefix, prefix_len) != 0) {
	return GSS_S_BAD_MECH;
    }

    op = (unsigned char *) oid->elements + prefix_len;

    *suffix = 0;

    slen = oid->length - prefix_len;

    for (i = 0; i < slen; i++) {
	*suffix = (*suffix << 7) | (op[i] & 0x7f);
	if (i + 1 != slen && (op[i] & 0x80) == 0) {
	    *minor_status = EINVAL;
	    return GSS_S_FAILURE;
	}
    }

    return GSS_S_COMPLETE;
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
gssint_copy_oid_set(
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
