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
 * SNMP PDU and packet transport related routines
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "asn1.h"
#include "pdu.h"

/*
 * Static declarations
 */
static int	snmp_add_null_vars(snmp_pdu_t *, char *, int, int);
static oid	*snmp_oidstr_to_oid(int, char *, int, size_t *);
static uchar_t	*snmp_build_pdu(snmp_pdu_t *, uchar_t *, size_t *);
static uchar_t	*snmp_build_variable(uchar_t *, size_t *, oid *, size_t,
		    uchar_t, void *, size_t);
static uchar_t	*snmp_parse_pdu(int, uchar_t *, size_t *, snmp_pdu_t *);
static uchar_t	*snmp_parse_variable(uchar_t *, size_t *, pdu_varlist_t *);
static void	snmp_free_null_vars(pdu_varlist_t *);

static uchar_t *snmp_def_community = (uchar_t *)SNMP_DEF_COMMUNITY;

/*
 * Allocates and creates a PDU for the specified SNMP command. Currently
 * only SNMP_MSG_GET, SNMP_MSG_GETNEXT and SNMP_MSG_GETBULK are supported
 */
snmp_pdu_t *
snmp_create_pdu(int cmd, int max_reps, char *oidstrs, int n_oids, int row)
{
	snmp_pdu_t	*pdu;

	if ((cmd != SNMP_MSG_GET) && (cmd != SNMP_MSG_GETNEXT) &&
	    (cmd != SNMP_MSG_GETBULK)) {
		return (NULL);
	}

	pdu = (snmp_pdu_t *)calloc(1, sizeof (snmp_pdu_t));
	if (pdu == NULL)
		return (NULL);

	if (cmd == SNMP_MSG_GET || cmd == SNMP_MSG_GETNEXT) {
		pdu->version = SNMP_VERSION_1;
		pdu->errstat = 0;
		pdu->errindex = 0;
	} else if (cmd == SNMP_MSG_GETBULK) {
		pdu->version = SNMP_VERSION_2c;
		pdu->non_repeaters = 0;
		pdu->max_repetitions = max_reps ?
		    max_reps : SNMP_DEF_MAX_REPETITIONS;
	}

	pdu->command = cmd;
	pdu->reqid = snmp_get_reqid();
	pdu->community = snmp_def_community;
	pdu->community_len = SNMP_DEF_COMMUNITY_LEN;

	if (snmp_add_null_vars(pdu, oidstrs, n_oids, row) < 0) {
		free((void *) pdu);
		return (NULL);
	}

	pdu->req_pkt = NULL;
	pdu->req_pktsz = 0;
	pdu->reply_pkt = NULL;
	pdu->reply_pktsz = 0;

	return (pdu);
}

/*
 * Builds a complete ASN.1 encoded snmp message packet out of the PDU.
 * Currently the maximum request packet is limited to SNMP_DEF_PKTBUF_SZ.
 * Since we only send SNMP_MSG_GET, SNMP_MSG_GETNEXT and SNMP_MSG_GETBULK,
 * as long as the number of bulk oids are not *too* many, we're safe with
 * this limit (the typical packet size of a bulk request of 10 vars is
 * around 250 bytes).
 */
int
snmp_make_packet(snmp_pdu_t *pdu)
{
	uchar_t	*buf, *p;
	uchar_t	*msg_seq_end;
	uchar_t id;
	size_t	bufsz = SNMP_DEF_PKTBUF_SZ;
	size_t	seqlen;

	if ((buf = (uchar_t *)calloc(1, SNMP_DEF_PKTBUF_SZ)) == NULL)
		return (-1);

	/*
	 * Let's start with the ASN sequence tag. Set the length
	 * to 0 initially and fill it up once the message packetizing
	 * is complete.
	 */
	id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	if ((p = asn_build_sequence(buf, &bufsz, id, 0)) == NULL) {
		free((void *) buf);
		return (-1);
	}
	msg_seq_end = p;

	/*
	 * Store the version
	 */
	id = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER;
	if ((p = asn_build_int(p, &bufsz, id, pdu->version)) == NULL) {
		free((void *) buf);
		return (-1);
	}

	/*
	 * Store the community string
	 */
	id = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR;
	p = asn_build_string(p, &bufsz, id, pdu->community, pdu->community_len);
	if (p == NULL) {
		free((void *) buf);
		return (-1);
	}

	/*
	 * Build the PDU
	 */
	if ((p = snmp_build_pdu(pdu, p, &bufsz)) == NULL) {
		free((void *) buf);
		return (-1);
	}

	/*
	 * Complete the message pkt by updating the message sequence length
	 */
	seqlen = p - msg_seq_end;
	id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	(void) asn_build_sequence(buf, NULL, id, seqlen);

	/*
	 * Calculate packet size and return
	 */
	pdu->req_pkt = buf;
	pdu->req_pktsz = p - buf;

	return (0);
}

/*
 * Makes a PDU out of a reply packet. The reply message is parsed
 * and if the reqid of the incoming packet does not match the reqid
 * we're waiting for, an error is returned. The PDU is allocated
 * inside this routine and must be freed by the caller once it is no
 * longer needed.
 */
snmp_pdu_t *
snmp_parse_reply(int reqid, uchar_t *reply_pkt, size_t reply_pktsz)
{
	snmp_pdu_t	*reply_pdu;
	uchar_t		*p;
	size_t		msgsz = reply_pktsz;
	uchar_t		exp_id;

	reply_pdu = (snmp_pdu_t *)calloc(1, sizeof (snmp_pdu_t));
	if (reply_pdu == NULL)
		return (NULL);

	/*
	 * Try to parse the ASN sequence out of the beginning of the reply
	 * packet. If we don't find a sequence at the beginning, something's
	 * wrong.
	 */
	exp_id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	if ((p = asn_parse_sequence(reply_pkt, &msgsz, exp_id)) == NULL) {
		snmp_free_pdu(reply_pdu);
		return (NULL);
	}

	/*
	 * Now try to parse the version out of the packet
	 */
	if ((p = asn_parse_int(p, &msgsz, &reply_pdu->version)) == NULL) {
		snmp_free_pdu(reply_pdu);
		return (NULL);
	}
	if ((reply_pdu->version != SNMP_VERSION_1) &&
	    (reply_pdu->version != SNMP_VERSION_2c)) {
		snmp_free_pdu(reply_pdu);
		return (NULL);
	}

	/*
	 * Parse the community string (space allocated by asn_parse_string)
	 */
	p = asn_parse_string(p, &msgsz, &reply_pdu->community,
	    &reply_pdu->community_len);
	if (p == NULL) {
		snmp_free_pdu(reply_pdu);
		return (NULL);
	}

	/*
	 * Parse the PDU part of the message
	 */
	if ((p = snmp_parse_pdu(reqid, p, &msgsz, reply_pdu)) == NULL) {
		snmp_free_pdu(reply_pdu);
		return (NULL);
	}

	return (reply_pdu);
}


/*
 * Convert the OID strings into the standard PDU oid form (sequence of
 * integer subids) and add them to the PDU's variable list. Note that
 * this is used only for preparing the request messages (GET, GETNEXT
 * and GETBULK), so the values of the variables are always null.
 */
static int
snmp_add_null_vars(snmp_pdu_t *pdu, char *oidstrs, int n_oids, int row)
{
	pdu_varlist_t	*vp, *prev;
	pdu_varlist_t	*varblock_p = NULL;
	char	*p;
	int	i;

	prev = NULL;
	p = oidstrs;
	for (i = 0; i < n_oids; i++) {
		if ((vp = calloc(1, sizeof (pdu_varlist_t))) == NULL) {
			snmp_free_null_vars(varblock_p);
			return (-1);
		} else if (i == 0) {
			varblock_p = vp;
		} else {
			prev->nextvar = vp;
		}

		vp->name = snmp_oidstr_to_oid(pdu->command,
		    p, row, &vp->name_len);
		if (vp->name == NULL) {
			snmp_free_null_vars(varblock_p);
			return (-1);
		}
		vp->val.str = NULL;
		vp->val_len = 0;
		vp->type = ASN_NULL;
		vp->nextvar = NULL;

		prev = vp;
		p += strlen(p) + 1;
	}

	/*
	 * append the varlist to the PDU
	 */
	if (pdu->vars == NULL)
		pdu->vars = varblock_p;
	else {
		for (vp = pdu->vars; vp->nextvar; vp = vp->nextvar)
			;
		vp->nextvar = varblock_p;
	}

	return (0);
}

/*
 * Some assumptions are in place here to eliminate unnecessary complexity.
 * All OID strings passed are assumed to be in the numeric string form, have
 * no leading/trailing '.' or spaces. Since PICL plugin is currently the
 * only customer, this is quite reasonable.
 */
static oid *
snmp_oidstr_to_oid(int cmd, char *oidstr, int row, size_t *n_subids)
{
	int	i, count;
	char	*p, *q;
	char	*oidstr_dup;
	oid	*objid;

	if ((oidstr == NULL) || (n_subids == NULL))
		return (NULL);

	for (count = 1, p = oidstr; p; count++, p++) {
		if ((p = strchr(p, '.')) == NULL)
			break;
	}

	/*
	 * Add one more to count for 'row'. Need special processing
	 * for SNMP_MSG_GETNEXT and SNMP_MSG_GETBULK requests; see
	 * comment below.
	 */
	if ((cmd == SNMP_MSG_GET) || (cmd == SNMP_MSG_GETBULK && row > 0) ||
	    (cmd == SNMP_MSG_GETNEXT && row >= 0)) {
		count++;
	}

	if ((oidstr_dup = strdup(oidstr)) == NULL)
		return (NULL);

	objid = (oid *) calloc(count, sizeof (oid));
	if (objid == NULL) {
		free((void *) p);
		return (NULL);
	}

	p = oidstr_dup;
	for (i = 0; i < count - 1; i++) {
		if (q = strchr(p, '.'))
			*q = 0;
		objid[i] = (oid) strtoul(p, NULL, 10);
		p = q + 1;
	}

	/*
	 * For SNMP_MSG_GET, the leaf subid will simply be the row#.
	 *
	 * For SNMP_MSG_GETBULK, if the row# passed is greater than 0,
	 * we pass 'row-1' as the leaf subid, to include the item that
	 * is of interest to us. If the row# is less than or equal to 0,
	 * we will simply ignore it and pass only the prefix part of the
	 * oidstr. For this case, our count would have been 1 less than
	 * usual, and we are yet to save the last subid.
	 *
	 * For SNMP_MSG_GETNEXT, if the row# passed is less than 0,
	 * we'll simply ignore it and pass only the prefix part of the
	 * oidstr. For this case, our count would have been 1 less than
	 * usual, and we are yet to save the last subid. If the row#
	 * passed is greater than or equal to 0, we'll simply pass it
	 * verbatim, as the leaf subid.
	 */
	switch (cmd) {
	case SNMP_MSG_GET:
		objid[i] = (oid) row;
		break;

	case SNMP_MSG_GETBULK:
		if (row > 0)
			objid[i] = (oid) (row - 1);
		else
			objid[i] = (oid) strtoul(p, NULL, 10);
		break;

	case SNMP_MSG_GETNEXT:
		if (row < 0)
			objid[i] = (oid) strtoul(p, NULL, 10);
		else
			objid[i] = (oid) row;
		break;
	}

	*n_subids = count;

	free((void *) oidstr_dup);

	return (objid);
}

/*
 * Builds the PDU part of the snmp message packet.
 */
static uchar_t *
snmp_build_pdu(snmp_pdu_t *pdu, uchar_t *buf, size_t *bufsz_p)
{
	uchar_t	*p;
	uchar_t	*pdu_seq_begin, *pdu_seq_end;
	uchar_t	*varlist_seq_begin, *varlist_seq_end;
	uchar_t	id;
	size_t	seqlen;
	pdu_varlist_t	*vp;

	/*
	 * Build ASN sequence for the PDU command (length will be
	 * updated later once the entire command is completely formed)
	 */
	pdu_seq_begin = buf;
	p = asn_build_sequence(buf, bufsz_p, (uchar_t)pdu->command, 0);
	if (p == NULL)
		return (NULL);
	pdu_seq_end = p;

	/*
	 * Build the request id
	 */
	id = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER;
	if ((p = asn_build_int(p, bufsz_p, id, pdu->reqid)) == NULL)
		return (NULL);

	/*
	 * Build the non-repeaters and max-repetitions for SNMP_MSG_GETBULK
	 * (same as error status and error index for other message types)
	 */
	id = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER;
	if ((p = asn_build_int(p, bufsz_p, id, pdu->non_repeaters)) == NULL)
		return (NULL);

	id = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER;
	if ((p = asn_build_int(p, bufsz_p, id, pdu->max_repetitions)) == NULL)
		return (NULL);

	/*
	 * Build ASN sequence for the variables list (update length
	 * after building the varlist)
	 */
	varlist_seq_begin = p;
	id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	if ((p = asn_build_sequence(p, bufsz_p, id, 0)) == NULL)
		return (NULL);
	varlist_seq_end = p;

	/*
	 * Build the variables list
	 */
	for (vp = pdu->vars; vp; vp = vp->nextvar) {
		p = snmp_build_variable(p, bufsz_p, vp->name, vp->name_len,
		    vp->type, vp->val.str, vp->val_len);
		if (p == NULL)
			return (NULL);
	}

	/*
	 * Now update the varlist sequence length
	 */
	seqlen = p - varlist_seq_end;
	id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	(void) asn_build_sequence(varlist_seq_begin, NULL, id, seqlen);

	/*
	 * And finally, update the length for the PDU sequence
	 */
	seqlen = p - pdu_seq_end;
	(void) asn_build_sequence(pdu_seq_begin, NULL, (uchar_t)pdu->command,
	    seqlen);

	return (p);
}

/*
 * Builds an object variable into the snmp message packet. Although the
 * code is here to build variables of basic types such as integer, object id
 * and strings, the only type of variable we ever send via snmp request
 * messages is the ASN_NULL type.
 */
static uchar_t *
snmp_build_variable(uchar_t *buf, size_t *bufsz_p, oid *name, size_t name_len,
    uchar_t val_type, void *val, size_t val_len)
{
	uchar_t	*p, *varseq_end;
	size_t	seqlen;
	uchar_t	id;

	/*
	 * Each variable binding is in turn defined as a 'SEQUENCE of' by
	 * the SNMP PDU format, so we'll prepare the sequence and fill up
	 * the length later. Sigh!
	 */
	id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	if ((p = asn_build_sequence(buf, bufsz_p, id, 0)) == NULL)
		return (NULL);
	varseq_end = p;

	/*
	 * Build the object id
	 */
	id = ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID;
	if ((p = asn_build_objid(p, bufsz_p, id, name, name_len)) == NULL)
		return (NULL);

	/*
	 * Currently we only ever build ASN_NULL vars while sending requests,
	 * since we support only SNMP_MSG_GET, SNMP_MSG_GETNEXT and
	 * SNMP_MSG_GETBULK.
	 */
	id = ASN_UNIVERSAL | ASN_PRIMITIVE | val_type;
	switch (val_type) {
	case ASN_INTEGER:
		p = asn_build_int(p, bufsz_p, id, *((int *)val));
		if (p == NULL)
			return (NULL);
		break;

	case ASN_OBJECT_ID:
		p = asn_build_objid(p, bufsz_p, id, val,
		    val_len / sizeof (oid));
		if (p == NULL)
			return (NULL);
		break;

	case ASN_OCTET_STR:
		p = asn_build_string(p, bufsz_p, id, (uchar_t *)val, val_len);
		if (p == NULL)
			return (NULL);
		break;

	case ASN_NULL:
		if ((p = asn_build_null(p, bufsz_p, id)) == NULL)
			return (NULL);
		break;

	default:
		return (NULL);
	}

	/*
	 * Rebuild the variable sequence length
	 */
	seqlen = p - varseq_end;
	id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	(void) asn_build_sequence(buf, NULL, id, seqlen);

	return (p);
}

/*
 * Parse the PDU portion of the incoming snmp message into the reply_pdu.
 * Space for all structure members are allocated as needed and must be freed
 * by the caller when these are no longer needed.
 */
static uchar_t *
snmp_parse_pdu(int reqid, uchar_t *msg, size_t *msgsz_p, snmp_pdu_t *reply_pdu)
{
	uchar_t	*p;
	uchar_t	id, exp_id;
	pdu_varlist_t	*newvp, *vp = NULL;

	/*
	 * Parse the PDU header out of the message
	 */
	if ((p = asn_parse_header(msg, msgsz_p, &id)) == NULL)
		return (NULL);
	if (id != SNMP_MSG_RESPONSE && id != SNMP_MSG_REPORT)
		return (NULL);
	reply_pdu->command = (int)id;

	/*
	 * Parse the request id and verify that this is the response
	 * we're expecting.
	 */
	if ((p = asn_parse_int(p, msgsz_p, &reply_pdu->reqid)) == NULL)
		return (NULL);
	if (reply_pdu->reqid != reqid)
		return (NULL);

	/*
	 * Parse the error-status and error-index values
	 */
	if ((p = asn_parse_int(p, msgsz_p, &reply_pdu->errstat)) == NULL)
		return (NULL);
	if ((p = asn_parse_int(p, msgsz_p, &reply_pdu->errindex)) == NULL)
		return (NULL);

	/*
	 * Parse the header for the variables list sequence.
	 */
	exp_id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	if ((p = asn_parse_sequence(p, msgsz_p, exp_id)) == NULL)
		return (NULL);

	while (((int)*msgsz_p) > 0) {
		if ((newvp = calloc(1, sizeof (pdu_varlist_t))) == NULL)
			return (NULL);

		if (vp == NULL)
			reply_pdu->vars = newvp;
		else
			vp->nextvar = newvp;

		vp = newvp;
		if ((p = snmp_parse_variable(p, msgsz_p, vp)) == NULL)
			return (NULL);
	}

	return (p);
}

/*
 * Allocate and parse the next variable into the varlist
 */
static uchar_t *
snmp_parse_variable(uchar_t *msg, size_t *msgsz_p, pdu_varlist_t *vp)
{
	uchar_t	*p;
	uchar_t	exp_id;

	/*
	 * Parse this variable's sequence
	 */
	exp_id = ASN_UNIVERSAL | ASN_CONSTRUCTOR | ASN_SEQUENCE;
	if ((p = asn_parse_sequence(msg, msgsz_p, exp_id)) == NULL)
		return (NULL);

	/*
	 * Parse the variable's object identifier
	 */
	p = asn_parse_objid(p, msgsz_p, &vp->name, &vp->name_len);
	if (p == NULL)
		return (NULL);

	/*
	 * Parse the object's value
	 */
	if ((p = asn_parse_objval(p, msgsz_p, vp)) == NULL)
		return (NULL);

	return (p);
}

void
snmp_free_pdu(snmp_pdu_t *pdu)
{
	pdu_varlist_t *vp, *nxt;

	if (pdu) {
		if ((pdu->community) && (pdu->community != snmp_def_community))
			free((void *) pdu->community);

		for (vp = pdu->vars; vp; vp = nxt) {
			nxt = vp->nextvar;

			if (vp->name)
				free((void *) vp->name);
			if (vp->val.str)
				free((void *) vp->val.str);
			free((void *) vp);
		}

		if (pdu->req_pkt)
			free((void *) pdu->req_pkt);

		if (pdu->reply_pkt)
			free((void *) pdu->reply_pkt);

		free((void *) pdu);
	}
}

static void
snmp_free_null_vars(pdu_varlist_t *varblock_p)
{
	pdu_varlist_t	*vp, *nxt;

	for (vp = varblock_p; vp; vp = nxt) {
		nxt = vp->nextvar;

		if (vp->name)
			free(vp->name);
		free(vp);
	}
}
