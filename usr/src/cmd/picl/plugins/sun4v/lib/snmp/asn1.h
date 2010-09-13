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
 */

#ifndef	_ASN1_H
#define	_ASN1_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ASN.1 values are encoded as octet strings based on the use of a
 * Type-Length-Value (TLV) structure. The Type indicates the ASN.1
 * type, the class of the type, and whether the encoding is primitive
 * or constructed. The Length indicates the length of the actual value
 * representation and the Value represents the value as a string
 * of octets.
 *
 *              +------------+--------+----------+
 *              | Identifier | Length | Contents |
 *              +------------+--------+----------+
 *
 * The encoding of the Identifier field is shown below (for tags less than 31):
 *
 *              +-------+-----+------------+
 *              | Class | P/C | Tag number |
 *              +-------+-----+------------+
 *          Bit   7   6    5   4  3  2  1  0
 *
 * The class field specifies one of four classes, the P/C bit specifies
 * whether this is a primitive/constructed encoding and the tag number
 * distinguishes one data type from another within the class.
 */

/*
 * Identifier classes
 */
#define	ASN_UNIVERSAL		((uchar_t)0x00)
#define	ASN_APPLICATION		((uchar_t)0x40)
#define	ASN_CONTEXT		((uchar_t)0x80)
#define	ASN_PRIVATE		((uchar_t)0xc0)

/*
 * Encoding type
 */
#define	ASN_PRIMITIVE		((uchar_t)0x00)
#define	ASN_CONSTRUCTOR		((uchar_t)0x20)

/*
 * Tag numbers for the Universal class of ASN.1 values
 */
#define	ASN_BOOLEAN		((uchar_t)0x01)
#define	ASN_INTEGER		((uchar_t)0x02)
#define	ASN_BIT_STR		((uchar_t)0x03)
#define	ASN_OCTET_STR		((uchar_t)0x04)
#define	ASN_NULL		((uchar_t)0x05)
#define	ASN_OBJECT_ID		((uchar_t)0x06)
#define	ASN_SEQUENCE		((uchar_t)0x10)
#define	ASN_SET			((uchar_t)0x11)

/*
 * ASN Extension Tag in the identifier
 */
#define	ASN_EXT_TAG		((uchar_t)0x1f)

/*
 * Application class ASN.1 identifiers
 */
#define	ASN_COUNTER	(ASN_APPLICATION | ASN_PRIMITIVE | (uchar_t)0x01)
#define	ASN_TIMETICKS	(ASN_APPLICATION | ASN_PRIMITIVE | (uchar_t)0x03)

/*
 * The Length field in the TLV structure described above is represented
 * in many ways depending on the value.
 *
 * If the length is less than 128, the length field consists of a
 * single octet beginning with a zero.
 *
 *                        +---+-----------+
 *                        | 0 | Length(L) |
 *                        +---+-----------+
 *
 * If the length is greater than 127, the first octet of the length field
 * contains a seven-bit integer that specifies the number of additional
 * length octets and the additional octets specify the actual length.
 *
 *              <-- one octet --><----- K octets ----->
 *              +---------------+---------------------+
 *              |  1  |    K    |      Length(L)      |
 *              +---------------+---------------------+
 *
 */
#define	ASN_LONG_LEN	((uchar_t)0x80)
#define	ASN_BIT8	((uchar_t)0x80)

/*
 * Some parts of the code assumes a few things -- big-endian ordering,
 * sizeof int, etc. to simplify things.
 */
#define	BUILD_INT_SHIFT	23
#define	BUILD_INT_MASK	0x1ff

/*
 * Exported ASN.1 encoding related interfaces (only exported within
 * snmplib, we need to do ld versioning to limit the scope of these to
 * within snmplib).
 */
uchar_t	*asn_build_sequence(uchar_t *, size_t *, uchar_t, size_t);
uchar_t	*asn_build_header(uchar_t *, size_t *, uchar_t, size_t);
uchar_t	*asn_build_length(uchar_t *, size_t *, size_t);
uchar_t	*asn_build_int(uchar_t *, size_t *, uchar_t, int);
uchar_t	*asn_build_string(uchar_t *, size_t *, uchar_t, uchar_t *, size_t);
uchar_t	*asn_build_objid(uchar_t *, size_t *, uchar_t, void *, size_t);
uchar_t	*asn_build_null(uchar_t *, size_t *, uchar_t);

uchar_t	*asn_parse_sequence(uchar_t *, size_t *, uchar_t);
uchar_t	*asn_parse_header(uchar_t *, size_t *, uchar_t *);
uchar_t	*asn_parse_length(uchar_t *, size_t *);
uchar_t	*asn_parse_int(uchar_t *, size_t *, int *);
uchar_t *asn_parse_uint(uchar_t *, size_t *, uint_t *);
uchar_t	*asn_parse_string(uchar_t *, size_t *, uchar_t **, size_t *);
uchar_t	*asn_parse_objid(uchar_t *, size_t *, void *, size_t *);
uchar_t	*asn_parse_objval(uchar_t *, size_t *, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _ASN1_H */
