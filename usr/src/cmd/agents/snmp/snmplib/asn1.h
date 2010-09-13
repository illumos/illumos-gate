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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASN1_H_
#define _ASN1_H_

#include <sys/types.h>
#include "impl.h"

/***** GLOBAL CONSTANTS *****/

#define MAX_SUBID   0xFFFFFFFF
                                /*SNMP imposes a restriction on the max. length     */
                                /* of any OID value to 128 numbers in the sequence. */
#define MAX_OID_LEN	    128	/* max subid's in an oid */

#define ASN_BOOLEAN	    (0x01)
#define ASN_INTEGER	    (0x02)
#define ASN_BIT_STR	    (0x03)
#define ASN_OCTET_STR	    (0x04)
#define ASN_NULL	    (0x05)
#define ASN_OBJECT_ID	    (0x06)
#define ASN_SEQUENCE	    (0x10)
#define ASN_SET		    (0x11)

#define ASN_UNIVERSAL	    (0x00)
#define ASN_APPLICATION     (0x40)
#define ASN_CONTEXT	    (0x80)
#define ASN_PRIVATE	    (0xC0)

#define ASN_PRIMITIVE	    (0x00)
#define ASN_CONSTRUCTOR	    (0x20)

#define ASN_LONG_LEN	    (0x80)
#define ASN_EXTENSION_ID    (0x1F)
#define ASN_BIT8	    (0x80)

#define IS_CONSTRUCTOR(byte)	((byte) & ASN_CONSTRUCTOR)
#define IS_EXTENSION_ID(byte)	(((byte) & ASN_EXTENSION_ID) == ASN_EXTENSION_ID)


#define INTEGER     ASN_INTEGER
#define STRING      ASN_OCTET_STR
#define OBJID       ASN_OBJECT_ID
#define NULLOBJ     ASN_NULL

/* defined types (from the SMI, RFC 1065) */
#define IPADDRESS   (ASN_APPLICATION | 0)
#define COUNTER     (ASN_APPLICATION | 1)
#define GAUGE       (ASN_APPLICATION | 2)
#define TIMETICKS   (ASN_APPLICATION | 3)
#define OPAQUE      (ASN_APPLICATION | 4)


/***** GLOBAL FUNCTIONS *****/

extern u_char *asn_parse_int(u_char *, uint32_t *, u_char *, int32_t *, uint32_t , char *);
extern u_char *asn_parse_unsigned_int(u_char *, uint32_t *, u_char *,
			int32_t *, uint32_t, char *);
extern u_char *asn_build_int(u_char *, uint32_t *, u_char, int32_t *, uint32_t, char *);
extern u_char *asn_build_unsigned_int(u_char *, uint32_t *, u_char,
			int32_t *, uint32_t, char *);
extern u_char *asn_parse_string(u_char *, uint32_t *, u_char *, u_char *, uint32_t *, char *);
extern u_char *asn_build_string(u_char *, uint32_t *, u_char, u_char *, uint32_t, char *);
extern u_char *asn_parse_header(u_char *, uint32_t *, u_char *, char *);
extern u_char *asn_build_header(u_char *, uint32_t *, u_char, uint32_t, char *);
extern u_char *asn_parse_length(u_char *, uint32_t *, char *);
extern u_char *asn_build_length(u_char *, uint32_t *, uint32_t, char *);
extern u_char *asn_parse_objid(u_char *, uint32_t *, u_char *, Subid *, int32_t *, char *);
extern u_char *asn_build_objid(u_char *, uint32_t *, u_char, Subid *, int32_t, char *);
extern u_char *asn_parse_null(u_char *, uint32_t *, u_char *, char *);
extern u_char *asn_build_null(u_char *, uint32_t *, u_char, char *);

#endif
