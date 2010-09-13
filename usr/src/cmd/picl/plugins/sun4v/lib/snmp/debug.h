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

#ifndef	_DEBUG_H
#define	_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef SNMP_DEBUG

/*
 * ASN Debugging keys
 */
#define	SNMP_DASN_SEQUENCE	1
#define	SNMP_DASN_LENGTH	2
#define	SNMP_DASN_INT		3
#define	SNMP_DASN_OCTET_STR	4
#define	SNMP_DASN_OID		5
#define	SNMP_DASN_NULL		6

/*
 * Debug tags
 */
#define	TAG_CMD_REQUEST		0
#define	TAG_NULL_VAR		1
#define	TAG_RESPONSE_VAR	2
#define	TAG_REQUEST_PDU		3
#define	TAG_RESPONSE_PDU	4
#define	TAG_REQUEST_PKT		5
#define	TAG_RESPONSE_PKT	6
#define	TAG_WRITE		7
#define	TAG_IOCTL		8
#define	TAG_READ		9
#define	TAG_SENDTO		10
#define	TAG_RECVFROM		11

/*
 * Debug macros
 */
#define	LOGINIT() \
	snmp_debug_init()

#define	LOGGET(tag, prefix, row) \
	snmp_log_cmd(tag, SNMP_MSG_GET, 1, prefix, row)

#define	LOGBULK(tag, n_oids, oidstrs, row) \
	snmp_log_cmd(tag, SNMP_MSG_GETBULK, n_oids, oidstrs, row)

#define	LOGNEXT(tag, prefix, row) \
	snmp_log_cmd(tag, SNMP_MSG_GETNEXT, 1, prefix, row)

#define	LOGVAR(tag, vp) \
	snmp_log_var(tag, vp)

#define	LOGPDU(tag, pdu) \
	snmp_log_pdu(tag, pdu)

#define	LOGASNSEQ(pkt, pktsz) \
	snmp_log_asn(SNMP_DASN_SEQUENCE, pkt, pktsz)

#define	LOGASNLENGTH(pkt, pktsz) \
	snmp_log_asn(SNMP_DASN_LENGTH, pkt, pktsz)

#define	LOGASNINT(pkt, pktsz) \
	snmp_log_asn(SNMP_DASN_INT, pkt, pktsz)

#define	LOGASNOCTSTR(pkt, pktsz) \
	snmp_log_asn(SNMP_DASN_OCTET_STR, pkt, pktsz)

#define	LOGASNOID(pkt, pktsz) \
	snmp_log_asn(SNMP_DASN_OID, pkt, pktsz)

#define	LOGASNNULL(pkt, pktsz) \
	snmp_log_asn(SNMP_DASN_NULL, pkt, pktsz)

#define	LOGPKT(tag, pkt, sz) \
	snmp_log_pkt(tag, pkt, sz)

#define	LOGIO(tag, a1, a2, a3) \
	snmp_log_io(tag, (int)a1, (uint_t)a2, (uint_t)a3)

/*
 * Exported debug interfaces
 */
extern void	snmp_debug_init(void);
extern void	snmp_log_cmd(uint_t tag, int cmd, int n_oids,
		    char *oidstr, int row);
extern void	snmp_log_var(uint_t tag, pdu_varlist_t *vp);
extern void	snmp_log_pdu(uint_t tag, snmp_pdu_t *pdu);
extern void	snmp_log_asn(int key, uchar_t *pkt, size_t pktsz);
extern void	snmp_log_pkt(uint_t tag, uchar_t *pkt, size_t pktsz);
extern void	snmp_log_io(uint_t tag, int a1, uint_t a2, uint_t a3);

#else /* SNMP_DEBUG */

#define	LOGINIT()
#define	LOGGET(tag, prefix, row)
#define	LOGBULK(tag, n_oids, oidstrs, row)
#define	LOGNEXT(tag, prefix, row)
#define	LOGVAR(tag, vp)
#define	LOGPDU(tag, pdu)
#define	LOGASNSEQ(pkt, pktsz)
#define	LOGASNLENGTH(pkt, pktsz)
#define	LOGASNINT(pkt, pktsz)
#define	LOGASNOCTSTR(pkt, pktsz)
#define	LOGASNOID(pkt, pktsz)
#define	LOGASNNULL(pkt, pktsz)
#define	LOGPKT(tag, pkt, sz)
#define	LOGIO(tag, a1, a2, a3)

#endif /* SNMP_DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_H */
