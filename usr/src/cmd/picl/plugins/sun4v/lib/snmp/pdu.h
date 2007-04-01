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

#ifndef	_PDU_H
#define	_PDU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint_t	oid;

/*
 * SNMP PDU variable list
 */
typedef struct pdu_varlist {
	struct pdu_varlist *nextvar;
	oid	*name;
	size_t	name_len;		/* number of subids in the name */
	union {
		uint_t	*uiptr;		/* unused except while parsing */
		int	*iptr;
		uchar_t	*str;
		oid	*objid;
	} val;
	size_t	val_len;		/* in bytes even if val is objid */
	uchar_t	type;
} pdu_varlist_t;

/*
 * Essential snmp message/PDU fields
 */
typedef struct snmp_pdu {
	int	version;
	uchar_t	*community;
	size_t	community_len;
	int	command;
	int	reqid;
	int	errstat;	/* shared with non-repeaters for GETBULK */
	int	errindex;	/* shared with max-repetitions for GETBULK */
	pdu_varlist_t	*vars;

	uchar_t	*req_pkt;	/* not really part of PDU */
	size_t	req_pktsz;	/* not really part of PDU */
	uchar_t	*reply_pkt;	/* not really part of PDU */
	size_t	reply_pktsz;	/* not really part of PDU */
} snmp_pdu_t;
#define	non_repeaters	errstat
#define	max_repetitions	errindex

/*
 * Supported SNMP versions
 */
#define	SNMP_VERSION_1		0
#define	SNMP_VERSION_2c		1

/*
 * Community strings for supported PDUs
 */
#define	SNMP_DEF_COMMUNITY	"public"
#define	SNMP_DEF_COMMUNITY_LEN	6

/*
 * PDU types (not all are supported)
 */
#define	SNMP_MSG_GET		(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x0)
#define	SNMP_MSG_GETNEXT	(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x1)
#define	SNMP_MSG_RESPONSE	(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x2)
#define	SNMP_MSG_SET		(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x3)
#define	SNMP_MSG_TRAP		(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x4)
#define	SNMP_MSG_GETBULK	(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x5)
#define	SNMP_MSG_INFORM		(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x6)
#define	SNMP_MSG_TRAP2		(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x7)
#define	SNMP_MSG_REPORT		(ASN_CONTEXT | ASN_CONSTRUCTOR | (uchar_t)0x8)

/*
 * Exception values (not all are supported)
 */
#define	SNMP_NOSUCHOBJECT	(ASN_CONTEXT | ASN_PRIMITIVE | (uchar_t)0x0)
#define	SNMP_NOSUCHINSTANCE	(ASN_CONTEXT | ASN_PRIMITIVE | (uchar_t)0x1)
#define	SNMP_ENDOFMIBVIEW	(ASN_CONTEXT | ASN_PRIMITIVE | (uchar_t)0x2)

/*
 * Error codes (not all are supported)
 */
#define	SNMP_ERR_NOERROR		(0)
#define	SNMP_ERR_TOOBIG			(1)
#define	SNMP_ERR_NOSUCHNAME		(2)
#define	SNMP_ERR_BADVALUE		(3)
#define	SNMP_ERR_READONLY		(4)
#define	SNMP_ERR_GENERR			(5)
#define	SNMP_ERR_NOACCESS		(6)
#define	SNMP_ERR_WRONGTYPE		(7)
#define	SNMP_ERR_WRONGLENGTH		(8)
#define	SNMP_ERR_WRONGENCODING		(9)
#define	SNMP_ERR_WRONGVALUE		(10)
#define	SNMP_ERR_NOCREATION		(11)
#define	SNMP_ERR_INCONSISTENTVALUE	(12)
#define	SNMP_ERR_RESOURCEUNAVAILABLE	(13)
#define	SNMP_ERR_COMMITFAILED		(14)
#define	SNMP_ERR_UNDOFAILED		(15)
#define	SNMP_ERR_AUTHORIZATIONERROR	(16)
#define	SNMP_ERR_NOTWRITABLE		(17)
#define	SNMP_ERR_INCONSISTENTNAME	(18)

/*
 * Default values
 */
#define	SNMP_DEF_NON_REPEATERS		0
#define	SNMP_DEF_MAX_REPETITIONS	25
#define	SNMP_DEF_PKTBUF_SZ		2048
#define	SNMP_PKTBUF_BLKSZ		1024
#define	SNMP_MAX_ERR    		18
#define	MIN_SUBIDS_IN_OID		2
#define	MAX_SUBIDS_IN_OID		128

/*
 * Exported interfaces used by other parts of snmplib
 */
snmp_pdu_t	*snmp_create_pdu(int, int, char *, int, int);
int		snmp_make_packet(snmp_pdu_t *);
snmp_pdu_t	*snmp_parse_reply(int, uchar_t *, size_t);
void		snmp_free_pdu(snmp_pdu_t *);

/*
 * Imported from elsewhere
 */
int		snmp_get_reqid(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _PDU_H */
