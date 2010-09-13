/*
 * src/lib/krb5/asn.1/asn1_get.c
 * 
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
 */

#include "asn1_get.h"

asn1_error_code
asn1_get_tag_2(asn1buf *buf, taginfo *t)
{
    asn1_error_code retval;

    if (buf == NULL || buf->base == NULL ||
	buf->bound - buf->next + 1 <= 0) {
	t->tagnum = ASN1_TAGNUM_CEILING; /* emphatically not an EOC tag */
	t->asn1class = UNIVERSAL;
	t->construction = PRIMITIVE;
	t->length = 0;
	t->indef = 0;
	return 0;
    }
    {
	/* asn1_get_id(buf, t) */
	asn1_tagnum tn=0;
	asn1_octet o;

#define ASN1_CLASS_MASK 0xC0
#define ASN1_CONSTRUCTION_MASK 0x20
#define ASN1_TAG_NUMBER_MASK 0x1F

	retval = asn1buf_remove_octet(buf,&o);
	if (retval)
	    return retval;

	t->asn1class = (asn1_class)(o&ASN1_CLASS_MASK);
	t->construction = (asn1_construction)(o&ASN1_CONSTRUCTION_MASK);
	if ((o&ASN1_TAG_NUMBER_MASK) != ASN1_TAG_NUMBER_MASK){
	    /* low-tag-number form */
	    t->tagnum = (asn1_tagnum)(o&ASN1_TAG_NUMBER_MASK);
	} else {
	    /* high-tag-number form */
	    do {
		retval = asn1buf_remove_octet(buf,&o);
		if (retval) return retval;
		tn = (tn<<7) + (asn1_tagnum)(o&0x7F);
	    }while(o&0x80);
	    t->tagnum = tn;
	}
    }

    {
	/* asn1_get_length(buf, t) */
	asn1_octet o;

	t->indef = 0;
	retval = asn1buf_remove_octet(buf,&o);
	if (retval) return retval;
	if ((o&0x80) == 0) {
	    t->length = (int)(o&0x7F);
	} else {
	    int num;
	    int len=0;
    
	    for (num = (int)(o&0x7F); num>0; num--) {
		retval = asn1buf_remove_octet(buf,&o);
		if(retval) return retval;
		len = (len<<8) + (int)o;
	    }
	    if (len < 0)
		return ASN1_OVERRUN;
	    if (!len)
		t->indef = 1;
	    t->length = len;
	}
    }
    if (t->indef && t->construction != CONSTRUCTED)
	return ASN1_MISMATCH_INDEF;
    return 0;
}

asn1_error_code asn1_get_sequence(asn1buf *buf, unsigned int *retlen, int *indef)
{
    taginfo t;
    asn1_error_code retval;

    retval = asn1_get_tag_2(buf, &t);
    if (retval)
	return retval;
    if (t.asn1class != UNIVERSAL || t.construction != CONSTRUCTED ||
	t.tagnum != ASN1_SEQUENCE)
	return ASN1_BAD_ID;
    if (retlen)
	*retlen = t.length;
    if (indef)
	*indef = t.indef;
    return 0;
}
