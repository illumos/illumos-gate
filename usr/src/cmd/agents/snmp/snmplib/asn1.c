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
 * Copyright 2001,2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "snmp_msg.h"
#include "asn1.h"


/*
 * asn_parse_int - pulls a int32_t out of an ASN int type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_int(
    u_char	    *data,	/* IN - pointer to start of object */
    uint32_t	    *datalength,/* IN/OUT - number of valid bytes left in buffer */
    u_char	    *type,	/* OUT - asn type of object */
    int32_t	    *intp,	/* IN/OUT - pointer to start of output buffer */
    uint32_t	    intsize,    /* IN - size of output buffer */
    char 	    *error_label)
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */
    u_char *bufp = data;
    uint32_t  asn_length = 0;
    int32_t   value = 0;


	error_label[0] = '\0';

    if (intsize != sizeof (int32_t)){
	(void)sprintf(error_label, ERR_MSG_NOT_LONG);
	return NULL;
    }
    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length, error_label);
    if (bufp == NULL){
	(void)sprintf(error_label, ERR_MSG_BAD_LENGTH);
	return NULL;
    }
    /* LINTED */
    if (asn_length + (uint32_t)(bufp - data) > *datalength){
	(void)sprintf(error_label, ERR_MSG_OVERFLOW);
	return NULL;
    }
    if (asn_length > intsize){
	(void)sprintf(error_label, ERR_MSG_DONT_SUPPORT_LARGE_INT);
	return NULL;
    }
    /* LINTED */
    *datalength -= asn_length + (uint32_t)(bufp - data);
    if (*bufp & 0x80)
	value = -1; /* integer is negative */
    while(asn_length--)
	value = (value << 8) | *bufp++;
    *intp = value;
    return bufp;
}

/*
 * asn_parse_unsigned_int - pulls an unsigned int32_t out of an ASN int type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_unsigned_int(
    u_char      *data,      /* IN - pointer to start of object */
    uint32_t *	datalength,/* IN/OUT - number of valid bytes left in buffer */
    u_char      *type,      /* OUT - asn type of object */
    int32_t    *intp,      /* IN/OUT - pointer to start of output buffer */
    uint32_t    intsize,    /* IN - size of output buffer */
    char        *error_label)
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */
    u_char *bufp = data;
    uint32_t asn_length;
    uint32_t value = 0;

    error_label[0] = '\0';

    if (intsize != sizeof (int32_t)){
	(void)sprintf(error_label, ERR_MSG_NOT_LONG);
	return NULL;
    }
    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length, error_label);
    if (bufp == NULL){
	(void)sprintf(error_label, ERR_MSG_BAD_LENGTH);
        return NULL;
    }
    /* LINTED */
    if (asn_length + (uint32_t)(bufp - data) > *datalength){
	(void)sprintf(error_label, ERR_MSG_OVERFLOW);
        return NULL;
    }
    if ((asn_length > (intsize + 1)) ||
        ((asn_length == intsize + 1) && *bufp != 0x00)){
	(void)sprintf(error_label, ERR_MSG_DONT_SUPPORT_LARGE_INT);
        return NULL;
    }
    /* LINTED */
    *datalength -= asn_length + (uint32_t)(bufp - data);
    if (*bufp & 0x80)
        value = -1U; /* integer is negative */
    while(asn_length--)
        value = (value << 8) | *bufp++;
    *intp = value;
    return bufp;
}


/*
 * asn_build_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_int(
    u_char *data,	/* IN - pointer to start of output buffer */
    uint32_t * datalength,/* IN/OUT - number of valid bytes left in buffer */
    u_char    type,	/* IN - asn type of object */
    int32_t   *intp,	/* IN - pointer to start of integer */
    uint32_t    intsize,    /* IN - size of *intp */
    char *error_label)
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    int32_t integer;
    uint32_t mask;

	error_label[0] = '\0';

    if (intsize != sizeof (int32_t))
	return NULL;
    integer = *intp;
    /*
     * Truncate "unnecessary" bytes off of the most significant end of this 2's
     * complement integer. There should be no sequence of 9 consecutive 1's or
     *  0's at the most significant end of the integer.
     */
	mask = ((uint32_t) 0x1FF) << ((8 * (sizeof(int32_t) - 1)) - 1);

    /* mask is 0xFF800000 on a big-endian machine */
    while((((integer & mask) == 0) || ((integer & mask) == mask)) && intsize > 1){
	intsize--;
	integer <<= 8;
    }
    data = asn_build_header(data, datalength, type, intsize, error_label);
    if (data == NULL)
	return NULL;
    if (*datalength < intsize)
	return NULL;
    *datalength -= intsize;

	mask = ((uint32_t) 0xFF) << (8 * (sizeof(int32_t) - 1));

    /* mask is 0xFF000000 on a big-endian machine */
    while(intsize--){
	/* LINTED */
	*data++ = (u_char)((integer & mask) >> (8 * (sizeof(int32_t) - 1)));
	integer <<= 8;
    }
    return data;
}

/*
 * asn_build_unsigned_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_unsigned_int(
    u_char *data,      /* IN - pointer to start of output buffer */
    uint32_t    *datalength,/* IN/OUT - number of valid bytes left in buffer */
    u_char          type,       /* IN - asn type of object */
    int32_t *intp,      /* IN - pointer to start of int32_t integer */
    uint32_t    intsize,    /* IN - size of *intp */
    char            *error_label)
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    uint32_t integer;
    uint32_t mask;
    int add_null_byte = 0;

    error_label[0] = '\0';

    if (intsize != sizeof (int32_t))
        return NULL;
    integer = *intp;
    mask = ((uint32_t) 0xFF) << (8 * (sizeof(int32_t) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
	/* LINTED */
    if ((u_char)((integer & mask) >> (8 * (sizeof(int32_t) - 1))) & 0x80){
        /* if MSB is set */
        add_null_byte = 1;
        intsize++;
    } else {
        /*
         * Truncate "unnecessary" bytes off of the most significant end of this 2's complement integer.
         * There should be no sequence of 9 consecutive 1's or 0's at the most significant end of the
         * integer.
         */
        mask = ((uint32_t) 0x1FF) << ((8 * (sizeof(int32_t) - 1)) - 1);
        /* mask is 0xFF800000 on a big-endian machine */
        while(((integer & mask) == 0) && intsize > 1){
            intsize--;
            integer <<= 8;
        }
    }
    data = asn_build_header(data, datalength, type, intsize, error_label);
    if (data == NULL)
        return NULL;
    if (*datalength < intsize)
        return NULL;
    *datalength -= intsize;
    if (add_null_byte == 1){
        *data++ = '\0';
        intsize--;
    }
    mask = ((uint32_t) 0xFF) << (8 * (sizeof(int32_t) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while(intsize--){
	/* LINTED */
        *data++ = (u_char)((integer & mask) >> (8 * (sizeof(int32_t) - 1)));
        integer <<= 8;
    }
    return data;
}


/*
 * asn_parse_string - pulls an octet string out of an ASN octet string type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the octet string.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_string(
    u_char	*data,	    /* IN - pointer to start of object */
    uint32_t    *datalength,    /* IN/OUT - number of valid bytes left in buffer */
    u_char	*type,	    /* OUT - asn type of object */
    u_char	*string,	    /* IN/OUT - pointer to start of output buffer */
    uint32_t    *strlength,     /* IN/OUT - size of output buffer */
    char *error_label)
{
/*
 * ASN.1 octet string ::= primstring | cmpdstring
 * primstring ::= 0x04 asnlength byte {byte}*
 * cmpdstring ::= 0x24 asnlength string {string}*
 * This doesn't yet support the compound string.
 */
    u_char *bufp = data;
    uint32_t	    asn_length = 0;


	error_label[0] = '\0';

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length, error_label);
    if (bufp == NULL)
	return NULL;
    /* LINTED */
    if (asn_length + (uint32_t)(bufp - data) > *datalength){
	(void)sprintf(error_label, ERR_MSG_OVERFLOW);
	return NULL;
    }
    if (asn_length > *strlength){
	(void)sprintf(error_label, ERR_MSG_DONT_SUPPORT_LARGE_STR);
	return NULL;
    }
    memcpy(string, bufp, asn_length);
    *strlength = asn_length;
    /* LINTED */
    *datalength -= asn_length + (uint32_t)(bufp - data);
    return bufp + asn_length;
}


/*
 * asn_build_string - Builds an ASN octet string object containing the input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_string(
    u_char	    *data,	    /* IN - pointer to start of object */
    uint32_t    *datalength,    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type,	    /* IN - ASN type of string */
    u_char	    *string,	    /* IN - pointer to start of input buffer */
    uint32_t    strlength,	    /* IN - size of input buffer */
    char *error_label)
{
/*
 * ASN.1 octet string ::= primstring | cmpdstring
 * primstring ::= 0x04 asnlength byte {byte}*
 * cmpdstring ::= 0x24 asnlength string {string}*
 * This code will never send a compound string.
 */

	error_label[0] = '\0';

    data = asn_build_header(data, datalength, type, strlength, error_label);
    if (data == NULL)
	return NULL;
    if (*datalength < strlength)
	return NULL;
    memcpy(data, string, strlength);
    *datalength -= strlength;
    return data + (intptr_t)strlength;
}


/*
 * asn_parse_header - interprets the ID and length of the current object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_parse_header(
    u_char	    *data,	/* IN - pointer to start of object */
    uint32_t *	    datalength,/* IN/OUT - number of valid bytes left in buffer */
    u_char	    *type,	/* OUT - ASN type of object */
    char *error_label)
{
    u_char *bufp = data;
    uint32_t	    header_len;
    uint32_t	    asn_length = 0;

    error_label[0] = '\0';

    /* this only works on data types < 30, i.e. no extension octets */
    if (IS_EXTENSION_ID(*bufp)){
	(void)sprintf(error_label, ERR_MSG_CANT_PROCESS_LONG_ID);
	return NULL;
    }
    *type = *bufp;
    bufp = asn_parse_length(bufp + 1, &asn_length, error_label);
    if (bufp == NULL)
	return NULL;

    /* LINTED */
    header_len = (uint32_t)(bufp - data);
    if (header_len + asn_length > *datalength){
	(void)sprintf(error_label, ERR_MSG_ASN_LEN_TOO_LONG);
	return NULL;
    }
    *datalength = asn_length;
    return bufp;
}

/*
 * asn_build_header - builds an ASN header for an object with the ID and
 * length specified.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *  The maximum length is 0xFFFF;
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_build_header(
    u_char *data,	/* IN - pointer to start of object */
    uint32_t   *datalength,/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type,	/* IN - ASN type of object */
    uint32_t	    length,	/* IN - length of object */
    char *error_label)
{
	error_label[0] = '\0';

    if (*datalength == 0)
	return NULL;
    *data++ = type;
    (*datalength)--;
    return asn_build_length(data, datalength, length, error_label);
    
}

/*
 * asn_parse_length - interprets the length of the current object.
 *  On exit, length contains the value of this length field.
 *
 *  Returns a pointer to the first byte after this length
 *  field (aka: the start of the data field).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_length(
    u_char  *data,	/* IN - pointer to start of length field */
    uint32_t  *length,	/* OUT - value of length field */
    char *error_label)
{
    u_char lengthbyte = *data;

	error_label[0] = '\0';

    if (lengthbyte & ASN_LONG_LEN){
	lengthbyte &= ~ASN_LONG_LEN;	/* turn MSb off */
	if (lengthbyte == 0){
		(void)sprintf(error_label, ERR_MSG_DONT_SUPPORT_INDEF_LEN);
	    return NULL;
	}
	if (lengthbyte > sizeof(int32_t)){
		(void)sprintf(error_label, ERR_MSG_DONT_SUPPORT_SUCH_LEN);
	    return NULL;
	}
	memcpy(length, data + 1, (int)lengthbyte);
	*length = ntohl(*length);
	*length >>= (8 * ((sizeof *length) - lengthbyte));
	return data + lengthbyte + 1;
    } else { /* short asnlength */
	*length = (int32_t)lengthbyte;
	return data + 1;
    }
}

u_char *
asn_build_length(
    u_char *data,	/* IN - pointer to start of object */
    uint32_t   *datalength, /* IN/OUT - number of valid bytes left in buffer */
    uint32_t    length,	/* IN - length of object */
    char *error_label)
{
    u_char    *start_data = data;

	error_label[0] = '\0';

    /* no indefinite lengths sent */
    if (length < 0x80){
	if (*datalength < 1)
		goto errout;
	/* LINTED */
	*data++ = (u_char)length;
    } else if (length <= 0xFF){
	if (*datalength < 2)
		goto errout;
	/* LINTED */
	*data++ = (u_char)(0x01 | ASN_LONG_LEN);
	/* LINTED */
	*data++ = (u_char)length;
    } else { /* 0xFF < length <= 0xFFFF */
	if (*datalength < 3)
		goto errout;
	/* LINTED */
	*data++ = (u_char)(0x02 | ASN_LONG_LEN);
	/* LINTED */
	*data++ = (u_char)((length >> 8) & 0xFF);
	/* LINTED */
	*data++ = (u_char)(length & 0xFF);
    }
    /* LINTED */
    *datalength -= (uint32_t)(data - start_data);
    return data;

errout:
    (void)sprintf(error_label, ERR_MSG_BUILD_LENGTH);
    return NULL;
}

/*
 * asn_parse_objid - pulls an object indentifier out of an ASN object identifier type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "objid" is filled with the object identifier.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_objid(
    u_char	    *data,	    /* IN - pointer to start of object */
    uint32_t 	    *datalength,    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    *type,	    /* OUT - ASN type of object */
    Subid	    *objid,	    /* IN/OUT - pointer to start of output buffer */
    int32_t	    *objidlength,   /* IN/OUT - number of sub-id's in objid */
    char *error_label)
{
/*
 * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
 * subidentifier ::= {leadingbyte}* lastbyte
 * leadingbyte ::= 1 7bitvalue
 * lastbyte ::= 0 7bitvalue
 */
    u_char *bufp = data;
    Subid *oidp = objid + 1;
    uint32_t subidentifier;
    int32_t   length;
    uint32_t	    asn_length = 0;


	error_label[0] = '\0';

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length, error_label);
    if (bufp == NULL)
	return NULL;
    /* LINTED */
    if (asn_length + (uint32_t)(bufp - data) > *datalength){
	(void)sprintf(error_label, ERR_MSG_OVERFLOW);
	return NULL;
    }
    /* LINTED */
    *datalength -= asn_length + (uint32_t)(bufp - data);

    length = asn_length;
    (*objidlength)--;	/* account for expansion of first byte */
    while (length > 0 && (*objidlength)-- > 0){
	subidentifier = 0;
	do {	/* shift and add in low order 7 bits */
	    subidentifier = (subidentifier << 7) + (*(u_char *)bufp & ~ASN_BIT8);
	    length--;
	} while (*(u_char *)bufp++ & ASN_BIT8);	/* last byte has high bit clear */
	if (subidentifier > (uint32_t)MAX_SUBID){
		(void)sprintf(error_label, ERR_MSG_SUBIDENTIFIER_TOO_LONG);
	    return NULL;
	}
	*oidp++ = (Subid)subidentifier;
    }

    /*
     * The first two subidentifiers are encoded into the first component
     * with the value (X * 40) + Y, where:
     *	X is the value of the first subidentifier.
     *  Y is the value of the second subidentifier.
     */
    subidentifier = (uint32_t)objid[1];
    /* LINTED */ 
    objid[1] = (u_char)(subidentifier % 0x28);
    /* LINTED */ 
    objid[0] = (u_char)((subidentifier - objid[1]) / 0x28);

    /* LINTED */
    *objidlength = (int32_t)(oidp - objid);
    return bufp;
}

/*
 * asn_build_objid - Builds an ASN object identifier object containing the input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_objid(
    u_char *data,	    /* IN - pointer to start of object */
    uint32_t    *datalength,    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type,	    /* IN - ASN type of object */
    Subid	    *objid,	    /* IN - pointer to start of input buffer */
    int32_t	    objidlength,    /* IN - number of sub-id's in objid */
    char *error_label)
{
/*
 * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
 * subidentifier ::= {leadingbyte}* lastbyte
 * leadingbyte ::= 1 7bitvalue
 * lastbyte ::= 0 7bitvalue
 */

	uchar_t buf[MAX_OID_LEN * 5];
	uchar_t *bp = buf;
	Subid objbuf[MAX_OID_LEN];
	Subid *op = objbuf;
	uint32_t    asnlength;
	uint32_t subid, mask, testmask;
	int bits, testbits;

	error_label[0] = '\0';

	if (objidlength > MAX_OID_LEN)
		return (NULL);

	memcpy(objbuf, objid, objidlength * (int32_t)sizeof (Subid));
	/* transform size in bytes to size in subid's */
	/* encode the first two components into the first subidentifier */
	op[1] = op[1] + (op[0] * 40);
	op++;
	objidlength--;

	while (objidlength-- > 0){
	subid = *op++;
	mask = 0x7F; /* handle subid == 0 case */
	bits = 0;
	/* testmask *MUST* !!!! be of an unsigned type */
	for (testmask = 0x7F, testbits = 0; testmask != 0;
			testmask <<= 7, testbits += 7) {
		if (subid & testmask) {	/* if any bits set */
			mask = testmask;
			bits = testbits;
		}
	}
	/* mask can't be zero here */
	for (; mask != 0x7F; mask >>= 7, bits -= 7){
		if (mask == 0x1E00000)
			/* fix a mask that got truncated above */
		mask = 0xFE00000;
	/* LINTED */
	*bp++ = (uchar_t)(((subid & mask) >> bits) | ASN_BIT8);
	}
	/* LINTED */
	*bp++ = (uchar_t)(subid & mask);
	}
	/* LINTED */
	asnlength = (uint32_t)(bp - buf);
	data = asn_build_header(data, datalength, type, asnlength, error_label);
	if (data == NULL)
		return (NULL);
	if (*datalength < asnlength)
		return (NULL);
	memcpy(data, buf, asnlength);
	*datalength -= asnlength;
	return (data + (uintptr_t)asnlength);
}

/*
 * asn_parse_null - Interprets an ASN null type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_null(
    u_char	    *data,	    /* IN - pointer to start of object */
    uint32_t	    *datalength,    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    *type,	    /* OUT - ASN type of object */
    char *error_label)
{
/*
 * ASN.1 null ::= 0x05 0x00
 */
    u_char	*bufp = data;
    uint32_t	asn_length = 0;


	error_label[0] = '\0';

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length, error_label);
    if (bufp == NULL)
	return NULL;
    if (asn_length != 0){
	(void)sprintf(error_label, ERR_MSG_MALFORMED_NULL);
	return NULL;
    }
    /* LINTED */
    *datalength -= (uint32_t)(bufp - data);
    return bufp + (uintptr_t)asn_length;
}

/*
 * asn_build_null - Builds an ASN null object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_null(
    u_char	    *data,	    /* IN - pointer to start of object */
    uint32_t	    *datalength,    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type,	    /* IN - ASN type of object */
    char *error_label)
{
/*
 * ASN.1 null ::= 0x05 0x00
 */
	error_label[0] = '\0';

	return asn_build_header(data, datalength, type, 0, error_label);
}
