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
 * Copyright 2019 Peter Tribble.
 */

/*
 * ASN.1 encoding related routines
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "asn1.h"
#include "pdu.h"

/*
 * This routine builds a 'SEQUENCE OF' ASN.1 object in the buffer
 * using the 'id' and 'length' supplied. This is probably the place
 * where using "reverse" asn encoding will help.
 */
uchar_t *
asn_build_sequence(uchar_t *buf, size_t *bufsz_p, uchar_t id, size_t length)
{
	/*
	 * When rebuilding sequence (which we do many times), we'll
	 * simply pass NULL to bufsz_p to skip the error check.
	 */
	if ((bufsz_p) && (*bufsz_p < 4))
		return (NULL);

	buf[0] = id;
	buf[1] = (uchar_t)(ASN_LONG_LEN | 0x02);	/* following 2 octets */
	buf[2] = (uchar_t)((length >> 8) & 0xff);
	buf[3] = (uchar_t)(length & 0xff);

	if (bufsz_p)
		*bufsz_p -= 4;

	return (buf + 4);
}

/*
 * The next two routines, asn_build_header() and asn_build_length(), build
 * the header and length for an arbitrary object type into the buffer. The
 * length of the object is encoded using as few length octets as possible.
 */
uchar_t *
asn_build_header(uchar_t *buf, size_t *bufsz_p, uchar_t id, size_t length)
{
	if (*bufsz_p < 1)
		return (NULL);

	buf[0] = id;
	(*bufsz_p)--;

	return (asn_build_length(buf + 1, bufsz_p, length));
}
uchar_t *
asn_build_length(uchar_t *buf, size_t *bufsz_p, size_t length)
{
	if (length < 0x80) {
		if (*bufsz_p < 1)
			return (NULL);
		buf[0] = (uchar_t)length;
		(*bufsz_p)--;

		return (buf + 1);

	} else if (length <= 0xFF) {
		if (*bufsz_p < 2)
			return (NULL);
		buf[0] = (uchar_t)(ASN_LONG_LEN | 0x01);
		buf[1] = (uchar_t)length;
		*bufsz_p -= 2;

		return (buf + 2);

	} else {
		if (*bufsz_p < 3)
			return (NULL);

		buf[0] = (uchar_t)(ASN_LONG_LEN | 0x02);
		buf[1] = (uchar_t)((length >> 8) & 0xff);
		buf[2] = (uchar_t)(length & 0xff);
		*bufsz_p -= 3;

		return (buf + 3);
	}
}
/*
 * Builds an ASN.1 encoded integer in the buffer using as few octets
 * as possible.
 */
uchar_t *
asn_build_int(uchar_t *buf, size_t *bufsz_p, uchar_t id, int val)
{
	uint_t	uival;
	int	ival, i;
	short	sval;
	char	cval;

	size_t	valsz;
	uchar_t	*p, *valp;

	/*
	 * We need to "pack" the integer before sending it, so determine
	 * the minimum number of bytes in which we can pack the integer
	 */
	uival = ((uint_t)val >> BUILD_INT_SHIFT) & BUILD_INT_MASK;
	ival = val;
	sval = (short)val;	/* yes, loss of data intended */
	cval = (char)val;	/* yes, loss of data intended */

	if (val == (int)cval)
		valsz = 1;
	else if (val == (int)sval)
		valsz = 2;
	else if (uival == BUILD_INT_MASK || uival == 0)
		valsz = 3;
	else
		valsz = 4;

	/*
	 * Prepare the ASN.1 header for the integer
	 */
	if ((p = asn_build_header(buf, bufsz_p, id, valsz)) == NULL)
		return (NULL);

	/*
	 * If we have enough space left, encode the integer
	 */
	if (*bufsz_p < valsz)
		return (NULL);
	else {
		valp = (uchar_t *)&ival;
		for (i = 0; i < valsz; i++)
			p[i] = valp[sizeof (int) - valsz + i];

		*bufsz_p -= valsz;

		return (p + valsz);
	}
}
/*
 * Builds an ASN.1 encoded octet string in the buffer. The source string
 * need not be null-terminated.
 */
uchar_t *
asn_build_string(uchar_t *buf, size_t *bufsz_p, uchar_t id, uchar_t *str,
    size_t slen)
{
	uchar_t	*p;

	if ((p = asn_build_header(buf, bufsz_p, id, slen)) == NULL)
		return (NULL);

	if (*bufsz_p < slen)
		return (NULL);
	else {
		if (str) {
			(void) memcpy(p, str, slen);
		} else {
			(void) memset(p, 0, slen);
		}

		*bufsz_p -= slen;

		return (p + slen);
	}
}

/*
 * Builds an Object Identifier into the buffer according to the OID
 * packing and encoding rules.
 */
uchar_t *
asn_build_objid(uchar_t *buf, size_t *bufsz_p, uchar_t id, void *oidp,
    size_t n_subids)
{
	oid	*objid = oidp;
	size_t	oid_asnlen;
	oid	subid, first_subid;
	uchar_t	subid_len[MAX_SUBIDS_IN_OID];
	uchar_t	*p;
	int	i, ndx;

	/*
	 * Eliminate invalid cases
	 */
	if (n_subids < MIN_SUBIDS_IN_OID || n_subids > MAX_SUBIDS_IN_OID)
		return (NULL);
	if ((objid[0] > 2) || (objid[0] < 2 && objid[1] >= 40))
		return (NULL);

	/*
	 * The BER encoding rule for the ASN.1 Object Identifier states
	 * that after packing the first two subids into one, each subsequent
	 * component is considered as the next subid. Each subidentifier is
	 * then encoded as a non-negative integer using as few 7-bit blocks
	 * as possible. The blocks are packed in octets with the first bit of
	 * each octet equal to 1, except for the last octet of each subid.
	 */
	oid_asnlen = 0;
	for (i = 0, ndx = 0; i < n_subids; i++, ndx++) {
		if (i == 0) {
			/*
			 * The packing formula for the first two subids
			 * of an OID is given by Z = (X * 40) + Y
			 */
			subid = objid[0] * 40 + objid[1];
			first_subid = subid;
			i++;	/* done with both subids 0 and 1 */
		} else {
			subid = objid[i];
		}

		if (subid < (oid) 0x80)
			subid_len[ndx] = 1;
		else if (subid < (oid) 0x4000)
			subid_len[ndx] = 2;
		else if (subid < (oid) 0x200000)
			subid_len[ndx] = 3;
		else if (subid < (oid) 0x10000000)
			subid_len[ndx] = 4;
		else {
			subid_len[ndx] = 5;
		}

		oid_asnlen += subid_len[ndx];
	}

	if ((p = asn_build_header(buf, bufsz_p, id, oid_asnlen)) == NULL)
		return (NULL);

	if (*bufsz_p < oid_asnlen)
		return (NULL);

	/*
	 * Store the encoded OID
	 */
	for (i = 0, ndx = 0; i < n_subids; i++, ndx++) {
		if (i == 0) {
			subid = first_subid;
			i++;
		} else {
			subid = objid[i];
		}

		switch (subid_len[ndx]) {
		case 1:
			*p++ = (uchar_t)subid;
			break;

		case 2:
			*p++ = (uchar_t)((subid >> 7) | 0x80);
			*p++ = (uchar_t)(subid & 0x7f);
			break;

		case 3:
			*p++ = (uchar_t)((subid >> 14) | 0x80);
			*p++ = (uchar_t)(((subid >> 7) & 0x7f) | 0x80);
			*p++ = (uchar_t)(subid & 0x7f);
			break;

		case 4:
			*p++ = (uchar_t)((subid >> 21) | 0x80);
			*p++ = (uchar_t)(((subid >> 14) & 0x7f) | 0x80);
			*p++ = (uchar_t)(((subid >> 7) & 0x7f) | 0x80);
			*p++ = (uchar_t)(subid & 0x7f);
			break;

		case 5:
			*p++ = (uchar_t)((subid >> 28) | 0x80);
			*p++ = (uchar_t)(((subid >> 21) & 0x7f) | 0x80);
			*p++ = (uchar_t)(((subid >> 14) & 0x7f) | 0x80);
			*p++ = (uchar_t)(((subid >> 7) & 0x7f) | 0x80);
			*p++ = (uchar_t)(subid & 0x7f);
			break;
		}
	}

	*bufsz_p -= oid_asnlen;

	return (p);
}
/*
 * Build an ASN_NULL object val into the request packet
 */
uchar_t *
asn_build_null(uchar_t *buf, size_t *bufsz_p, uchar_t id)
{
	uchar_t	*p;

	p = asn_build_header(buf, bufsz_p, id, 0);

	return (p);
}



/*
 * This routine parses a 'SEQUENCE OF' object header from the input
 * buffer stream. If the identifier tag (made up of class, constructed
 * type and data type tag) does not match the expected identifier tag,
 * returns failure.
 */
uchar_t *
asn_parse_sequence(uchar_t *buf, size_t *bufsz_p, uchar_t exp_id)
{
	uchar_t	*p;
	uchar_t	id;

	if ((p = asn_parse_header(buf, bufsz_p, &id)) == NULL)
		return (NULL);

	if (id != exp_id)
		return (NULL);

	return (p);
}
/*
 * Return the type identifier of the ASN object via 'id'
 */
uchar_t *
asn_parse_header(uchar_t *buf, size_t *bufsz_p, uchar_t *id)
{
	uchar_t	*p;
	size_t	asnobj_len, hdrlen;

	/*
	 * Objects with extension tag type are not supported
	 */
	if ((buf[0] & ASN_EXT_TAG) == ASN_EXT_TAG)
		return (NULL);

	/*
	 * Parse the length field of the ASN object in the header
	 */
	if ((p = asn_parse_length(buf + 1, &asnobj_len)) == NULL)
		return (NULL);

	/*
	 * Check if the rest of the msg packet is big enough for the
	 * full length of the object
	 */
	hdrlen = p - buf;
	if (*bufsz_p < (asnobj_len + hdrlen))
		return (NULL);

	*id = buf[0];
	*bufsz_p -= hdrlen;

	return (p);
}
/*
 * This routine parses the length of the object as specified in its
 * header. The 'Indefinite' form of representing length is not supported.
 */
uchar_t *
asn_parse_length(uchar_t *buf, size_t *asnobj_len_p)
{
	uchar_t	*p;
	int	n_length_octets;

	/*
	 * First, check for the short-definite form. Length of
	 * the object is simply the least significant 7-bits of
	 * the first byte.
	 */
	if ((buf[0] & ASN_LONG_LEN) == 0) {
		*asnobj_len_p = (size_t)buf[0];
		return (buf + 1);
	}

	/*
	 * Then, eliminate the indefinite form. The ASN_LONG_LEN
	 * bit of the first byte will be set and the least significant
	 * 7-bites of that byte will be zeros.
	 */
	if (buf[0] == (uchar_t)ASN_LONG_LEN)
		return (NULL);

	/*
	 * Then, eliminate the long-definite case when the number of
	 * follow-up octets is more than what the size var can hold.
	 */
	n_length_octets = buf[0] & ~ASN_LONG_LEN;
	if (n_length_octets > sizeof (*asnobj_len_p))
		return (NULL);

	/*
	 * Finally gather the length
	 */
	p = buf + 1;
	*asnobj_len_p = 0;
	while (n_length_octets--) {
		*asnobj_len_p <<= 8;
		*asnobj_len_p |= *p++;
	}

	return (p);
}
/*
 * Parses an integer out of the input buffer
 */
uchar_t *
asn_parse_int(uchar_t *buf, size_t *bufsz_p, int *ival)
{
	size_t	asnobj_len, hdrlen;
	uchar_t	int_id;
	uchar_t	*p;

	int_id = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER;
	if (buf[0] != int_id)
		return (NULL);

	/*
	 * Read in the length of the object; Note that integers are
	 * "packed" when sent from agent to manager and vice-versa,
	 * so the size of the object could be less than sizeof (int).
	 */
	if ((p = asn_parse_length(buf + 1, &asnobj_len)) == NULL)
		return (NULL);

	/*
	 * Is there sufficient space left in the packet to read the integer ?
	 */
	hdrlen = p - buf;
	if (*bufsz_p < (hdrlen + asnobj_len))
		return (NULL);

	/*
	 * Update space left in the buffer after the integer is read
	 */
	*bufsz_p -= (hdrlen + asnobj_len);

	/*
	 * Read in the integer value
	 */
	*ival = (*p & ASN_BIT8) ? -1 : 0;
	while (asnobj_len--) {
		*ival <<= 8;
		*ival |= *p++;
	}

	return (p);
}
/*
 * Parses an unsigned integer out of the input buffer
 */
uchar_t *
asn_parse_uint(uchar_t *buf, size_t *bufsz_p, uint_t *uival)
{
	size_t	asnobj_len, hdrlen;
	uchar_t	*p;

	if ((buf[0] != ASN_COUNTER) && (buf[0] != ASN_TIMETICKS))
		return (NULL);

	/*
	 * Read in the length of the object. Integers are sent the same
	 * way unsigned integers are sent.  Except that, if the MSB was 1
	 * in the unsigned int value, a null-byte is attached to the front.
	 * Otherwise, packing rules are the same as for integer values.
	 */
	if ((p = asn_parse_length(buf + 1, &asnobj_len)) == NULL)
		return (NULL);

	/*
	 * Is there sufficient space left in the packet to read in the value ?
	 */
	hdrlen = p - buf;
	if (*bufsz_p < (hdrlen + asnobj_len))
		return (NULL);

	/*
	 * Update space left in the buffer after the uint is read
	 */
	*bufsz_p -= (hdrlen + asnobj_len);

	/*
	 * Read in the unsigned integer (this should never get
	 * initialized to ~0 if it was sent right)
	 */
	*uival = (*p & ASN_BIT8) ? ~0 : 0;
	while (asnobj_len--) {
		*uival <<= 8;
		*uival |= *p++;
	}

	return (p);
}
/*
 * Parses a string (ASN_OCTET_STR or ASN_BIT_STR) out of the input buffer.
 * The memory for the string is allocated inside the routine and must be
 * freed by the caller when it is no longer needed. If the string type is
 * ASN_OCTET_STR, the returned string is null-terminated, and the returned
 * length indicates the strlen value. If the string type is ASN_BIT_STR,
 * the returned string is not null-terminated, and the returned length
 * indicates the number of bytes.
 */
uchar_t *
asn_parse_string(uchar_t *buf, size_t *bufsz_p, uchar_t **str_p, size_t *slen)
{
	uchar_t	*p;
	uchar_t	id1, id2;
	size_t	asnobj_len, hdrlen;

	/*
	 * Octet and bit strings are supported
	 */
	id1 = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR;
	id2 = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_BIT_STR;
	if ((buf[0] != id1) && (buf[0] != id2))
		return (NULL);

	/*
	 * Parse out the length of the object and verify source buf sz
	 */
	if ((p = asn_parse_length(buf + 1, &asnobj_len)) == NULL)
		return (NULL);

	hdrlen = p - buf;
	if (*bufsz_p < (hdrlen + asnobj_len))
		return (NULL);

	/*
	 * Allocate for and copy out the string
	 */
	if ((*str_p = (uchar_t *)calloc(1, asnobj_len + 1)) == NULL)
		return (NULL);

	(void) memcpy(*str_p, p, asnobj_len);

	/*
	 * Terminate the octet string with a null
	 */
	if (buf[0] == id1) {
		(*str_p)[asnobj_len] = 0;
	}

	/*
	 * Update pointers and return
	 */
	*slen = asnobj_len;
	*bufsz_p -= (hdrlen + asnobj_len);

	return (p + asnobj_len);
}
/*
 * Parses an object identifier out of the input packet buffer. Space for
 * the oid object is allocated within this routine and must be freed by the
 * caller when no longer needed.
 */
uchar_t *
asn_parse_objid(uchar_t *msg, size_t *varsz_p, void *oidp, size_t *n_subids)
{
	oid	**objid_p = oidp;
	oid	*objid;
	uchar_t	*p;
	size_t	hdrlen, asnobj_len;
	oid	subid;
	int	i, ndx;
	uchar_t	exp_id;

	/*
	 * Check id
	 */
	exp_id = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID;
	if (msg[0] != exp_id)
		return (NULL);

	/*
	 * Read object length
	 */
	if ((p = asn_parse_length(msg + 1, &asnobj_len)) == NULL)
		return (NULL);

	/*
	 * Check space in input message
	 */
	hdrlen = p - msg;
	if (*varsz_p < (hdrlen + asnobj_len))
		return (NULL);

	/*
	 * Since the OID subidentifiers are packed in 7-bit blocks with
	 * MSB set to 1 for all but the last octet, the number of subids
	 * is simply the number of octets with MSB equal to 0, plus 1
	 * (since the first two subids were packed into one subid and have
	 * to be expanded back to two).
	 */
	*n_subids = 1;
	for (i = 0; i < asnobj_len; i++) {
		if ((p[i] & ASN_BIT8) == 0)
			(*n_subids)++;
	}

	/*
	 * Now allocate for the oid and parse the OID into it
	 */
	if ((objid = (oid *) calloc(1, (*n_subids) * sizeof (oid))) == NULL)
		return (NULL);

	ndx = 1;	/* start from 1 to allow for unpacking later */
	subid = 0;
	for (i = 0; i < asnobj_len; i++) {
		subid = subid << 7;
		subid |= (p[i] & ~ASN_BIT8);

		if ((p[i] & ASN_BIT8) == 0) {
			objid[ndx] = subid;
			ndx++;
			subid = 0;
		}
	}

	/*
	 * Now unpack the first two subids from the subid at index 1.
	 */
	if (objid[1] < 40) {
		objid[0] = 0;
	} else if (objid[1] < 80) {
		objid[0] = 1;
		objid[1] -= 40;
	} else {
		objid[0] = 2;
		objid[1] -= 80;
	}

	*objid_p = objid;
	*varsz_p -= (hdrlen + asnobj_len);

	return (msg + hdrlen + asnobj_len);
}
/*
 * Parses the value of an OID object out of the input message buffer.
 * Only type tags less than ASN_EXT_TAG (0x1f) are supported.
 */
uchar_t *
asn_parse_objval(uchar_t *msg, size_t *varsz_p, void *varlistp)
{
	pdu_varlist_t	*vp = varlistp;
	uchar_t	*p;
	size_t	n_subids;
	size_t	hdrlen, asnobj_len;

	vp->type = msg[0] & ASN_EXT_TAG;
	if (vp->type == ASN_EXT_TAG)
		return (NULL);

	/*
	 * Currently we handle ASN_INTEGER, ASN_OCTET_STR, ASN_BIT_STR
	 * and ASN_TIMETICKS types.
	 */
	switch (msg[0]) {
	case ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER:
		vp->val.iptr = (int *)calloc(1, sizeof (int));
		if (vp->val.iptr == NULL)
			return (NULL);

		if ((p = asn_parse_int(msg, varsz_p, vp->val.iptr)) == NULL) {
			free(vp->val.iptr);
			return (NULL);
		}
		vp->val_len = sizeof (int);
		break;

	case ASN_COUNTER:
	case ASN_TIMETICKS:
		vp->val.uiptr = (uint_t *)calloc(1, sizeof (uint_t));
		if (vp->val.uiptr == NULL)
			return (NULL);

		if ((p = asn_parse_uint(msg, varsz_p, vp->val.uiptr)) == NULL) {
			free(vp->val.uiptr);
			return (NULL);
		}
		vp->val_len = sizeof (uint_t);
		vp->type = msg[0];
		break;

	case ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR:
	case ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_BIT_STR:
		p = asn_parse_string(msg, varsz_p, &vp->val.str, &vp->val_len);
		if (p == NULL)
			return (NULL);
		break;

	case ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID:
		p = asn_parse_objid(msg, varsz_p, &vp->val.objid, &n_subids);
		if (p == NULL)
			return (NULL);
		vp->val_len = n_subids * sizeof (oid);
		break;

	case ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_NULL:
	case SNMP_NOSUCHOBJECT:
	case SNMP_NOSUCHINSTANCE:
	case SNMP_ENDOFMIBVIEW:
	default:
		p = asn_parse_length(msg + 1, &asnobj_len);
		if (p == NULL)
			return (NULL);

		hdrlen = p - msg;
		if (*varsz_p < (hdrlen + asnobj_len))
			return (NULL);

		vp->type = msg[0];
		vp->val_len = asnobj_len;

		*varsz_p -= (hdrlen + asnobj_len);
		p += asnobj_len;
		break;
	}

	return (p);
}
