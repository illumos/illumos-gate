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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef SNMP_DEBUG

/*
 * Debug routines
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <ctype.h>
#include <sys/types.h>
#include "asn1.h"
#include "pdu.h"
#include "snmplib.h"
#include "debug.h"

/*
 * Buffer and line limits
 */
#define	SNMP_DBLOCK_SZ		4096
#define	SNMP_DMAX_LINE		80
#define	SNMP_NCHARS_IN_A_ROW	16

/*
 * Debug flags
 */
#define	SNMP_DEBUG_CMD		0x01
#define	SNMP_DEBUG_VAR		0x02
#define	SNMP_DEBUG_PDU		0x04
#define	SNMP_DEBUG_ASN		0x08
#define	SNMP_DEBUG_PKT		0x10
#define	SNMP_DEBUG_IO		0x20

#define	SNMP_DEBUG_DEFAULT	0x15	/* cmd, pdu, pkt */
#define	SNMP_DEBUG_EXTENDED	0x35	/* cmd, pdu, pkt, io */
#define	SNMP_DEBUG_ALL		0x3f

/*
 * Formatting aids
 */
#define	SNMP_DCMD_INDENT	2
#define	SNMP_DVAR_INDENT	4
#define	SNMP_DPDU_INDENT	6
#define	SNMP_DASN_INDENT	8
#define	SNMP_DPKT_INDENT	10
#define	SNMP_DIO_INDENT		12

#define	SNMP_DHDR_PREFIX	(const char *)" ___ "
#define	SNMP_DHDR_SUFFIX	(const char *)" ___"
#define	SNMP_DTEXT_PREFIX	(const char *)"| "

/*
 * All debug vars are protected by a single lock
 */
static mutex_t	snmp_dbuf_lock;				/* debug lock */
static uint16_t	snmp_debug_flag = SNMP_DEBUG_EXTENDED;	/* debug flags */
static char	*snmp_dbuf = NULL;			/* the debug buffer */
static char	*snmp_dbuf_curp = NULL;			/* current dbuf index */
static char	*snmp_dbuf_tail = NULL;			/* current dbuf tail */
static int	snmp_dbuf_sz = 0;			/* current dbuf size */
static int	snmp_dbuf_overflow = 0;			/* no more memory */
static char	snmp_lbuf[SNMP_DMAX_LINE];		/* scratch space */

/*
 * Key-to-string
 */
typedef struct {
	int	key;
	char	*str;
} snmp_key_to_str_t;

static snmp_key_to_str_t snmp_cmds[] = {
	{ SNMP_MSG_GET, "SNMP_MSG_GET" },
	{ SNMP_MSG_GETNEXT, "SNMP_MSG_GETNEXT" },
	{ SNMP_MSG_RESPONSE, "SNMP_MSG_RESPONSE" },
	{ SNMP_MSG_SET, "SNMP_MSG_SET" },
	{ SNMP_MSG_TRAP, "SNMP_MSG_TRAP" },
	{ SNMP_MSG_GETBULK, "SNMP_MSG_GETBULK" },
	{ SNMP_MSG_INFORM, "SNMP_MSG_INFORM" },
	{ SNMP_MSG_TRAP2, "SNMP_MSG_TRAP2" },
	{ SNMP_MSG_REPORT, "SNMP_MSG_REPORT" }
};

static snmp_key_to_str_t snmp_vartypes[] = {
	{ ASN_BOOLEAN, "ASN_BOOLEAN" },
	{ ASN_INTEGER, "ASN_INTEGER" },
	{ ASN_BIT_STR, "ASN_BIT_STR" },
	{ ASN_OCTET_STR, "ASN_OCTET_STR" },
	{ ASN_NULL, "ASN_NULL" },
	{ ASN_OBJECT_ID, "ASN_OBJECT_ID" },
	{ ASN_SEQUENCE, "ASN_SEQUENCE" }
};

static snmp_key_to_str_t snmp_asnencodings[] = {
	{ SNMP_DASN_SEQUENCE, "ASN SEQUENCE" },
	{ SNMP_DASN_LENGTH, "ASN LENGTH" },
	{ SNMP_DASN_INT, "ASN INT" },
	{ SNMP_DASN_OCTET_STR, "ASN OCTET STR" },
	{ SNMP_DASN_OID, "ASN OBJECT ID" },
	{ SNMP_DASN_NULL, "ASN NULL" }
};

static char *debug_tags[] = {
	"SNMP Command Request",
	"Null Var",
	"Response Var",
	"Request PDU",
	"Response PDU",
	"Request Packet",
	"Response Packet",
	"WRITE",
	"IOCTL",
	"READ",
	"SENDTO",
	"RECVFROM"
};
static const int n_tags = sizeof (debug_tags) / sizeof (char *);

/*
 * Helpers
 */
static char	*snmp_cmdstr_lookup(int cmd);
static char	*snmp_vtypestr_lookup(int vtype);
static char	*snmp_asnencoding_lookup(int asnkey);
static void	snmp_get_dumpchars(uchar_t *abuf, uchar_t *p, int nchars);
static void	snmp_log_append(char *bufp);
static void	snmp_dbuf_realloc(void);

void
snmp_debug_init(void)
{
	(void) mutex_init(&snmp_dbuf_lock, USYNC_THREAD, NULL);

	(void) mutex_lock(&snmp_dbuf_lock);
	snmp_dbuf_realloc();
	if (snmp_dbuf == NULL)
		snmp_debug_flag = 0;	/* really tragic */
	(void) mutex_unlock(&snmp_dbuf_lock);
}

void
snmp_log_cmd(uint_t tag, int cmd, int n_oids, char *oidstr, int row)
{
	char	*cmdstr;
	int	i;

	if (oidstr == NULL)
		return;

	(void) mutex_lock(&snmp_dbuf_lock);

	if ((snmp_debug_flag & SNMP_DEBUG_CMD) == 0) {
		(void) mutex_unlock(&snmp_dbuf_lock);
		return;
	}

	snmp_log_append("\n");

	if (tag < n_tags) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s%s%s\n",
		    SNMP_DCMD_INDENT, ' ', SNMP_DHDR_PREFIX,
		    debug_tags[tag], SNMP_DHDR_SUFFIX);
		snmp_log_append(snmp_lbuf);
	}

	if ((cmdstr = snmp_cmdstr_lookup(cmd)) == NULL) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sCMD=%#x\n",
		    SNMP_DCMD_INDENT, ' ', SNMP_DTEXT_PREFIX, cmd);
	} else {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s%s\n",
		    SNMP_DCMD_INDENT, ' ', SNMP_DTEXT_PREFIX, cmdstr);
	}
	snmp_log_append(snmp_lbuf);

	for (i = 0; i < n_oids; i++) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s  %s.%d\n",
		    SNMP_DCMD_INDENT, ' ', SNMP_DTEXT_PREFIX,
		    oidstr, row);
		snmp_log_append(snmp_lbuf);

		oidstr += strlen(oidstr) + 1;
	}

	(void) mutex_unlock(&snmp_dbuf_lock);
}

void
snmp_log_var(uint_t tag, pdu_varlist_t *vp)
{
	char	*vts;

	if (vp == NULL)
		return;

	(void) mutex_lock(&snmp_dbuf_lock);

	if ((snmp_debug_flag & SNMP_DEBUG_VAR) == 0) {
		(void) mutex_unlock(&snmp_dbuf_lock);
		return;
	}

	snmp_log_append("\n");

	if (tag < n_tags) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s%s%s\n",
		    SNMP_DVAR_INDENT, ' ', SNMP_DHDR_PREFIX,
		    debug_tags[tag], SNMP_DHDR_SUFFIX);
		snmp_log_append(snmp_lbuf);
	}

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%snextvar = %#x\n",
	    SNMP_DVAR_INDENT, ' ', SNMP_DTEXT_PREFIX, vp->nextvar);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sname = %#x\n",
	    SNMP_DVAR_INDENT, ' ', SNMP_DTEXT_PREFIX, vp->name);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sname_len = %u\n",
	    SNMP_DVAR_INDENT, ' ', SNMP_DTEXT_PREFIX, vp->name_len);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sval.ptr = %#x\n",
	    SNMP_DVAR_INDENT, ' ', SNMP_DTEXT_PREFIX, vp->val.str);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sval_len = %u\n",
	    SNMP_DVAR_INDENT, ' ', SNMP_DTEXT_PREFIX, vp->val_len);
	snmp_log_append(snmp_lbuf);

	if ((vts = snmp_vtypestr_lookup(vp->type)) == NULL) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%stype = %#x\n",
		    SNMP_DVAR_INDENT, ' ', SNMP_DTEXT_PREFIX, vp->type);
	} else {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%stype = %s\n",
		    SNMP_DVAR_INDENT, ' ', SNMP_DTEXT_PREFIX, vts);
	}
	snmp_log_append(snmp_lbuf);

	(void) mutex_unlock(&snmp_dbuf_lock);
}

void
snmp_log_pdu(uint_t tag, snmp_pdu_t *pdu)
{
	char	*cmdstr;

	if (pdu == NULL)
		return;

	(void) mutex_lock(&snmp_dbuf_lock);

	if ((snmp_debug_flag & SNMP_DEBUG_PDU) == 0) {
		(void) mutex_unlock(&snmp_dbuf_lock);
		return;
	}

	snmp_log_append("\n");

	if (tag < n_tags) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s%s%s\n",
		    SNMP_DPDU_INDENT, ' ', SNMP_DHDR_PREFIX,
		    debug_tags[tag], SNMP_DHDR_SUFFIX);
		snmp_log_append(snmp_lbuf);
	}

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sversion = %d\n",
	    SNMP_DPDU_INDENT, ' ', SNMP_DTEXT_PREFIX, pdu->version);
	snmp_log_append(snmp_lbuf);

	if (pdu->community) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE,
		    "%*c%scommunity = %s\n", SNMP_DPDU_INDENT, ' ',
		    SNMP_DTEXT_PREFIX, pdu->community);
	} else {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE,
		    "%*c%scommunity = %#x\n", SNMP_DPDU_INDENT, ' ',
		    SNMP_DTEXT_PREFIX, pdu->community);
	}
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%scommunity_len = %u\n",
	    SNMP_DPDU_INDENT, ' ', SNMP_DTEXT_PREFIX, pdu->community_len);
	snmp_log_append(snmp_lbuf);

	if ((cmdstr = snmp_cmdstr_lookup(pdu->command)) == NULL) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE,
		    "%*c%scommand = %#x\n", SNMP_DPDU_INDENT, ' ',
		    SNMP_DTEXT_PREFIX, pdu->command);
	} else {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE,
		    "%*c%scommand = %s\n", SNMP_DPDU_INDENT, ' ',
		    SNMP_DTEXT_PREFIX, cmdstr);
	}
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sreqid = %d\n",
	    SNMP_DPDU_INDENT, ' ', SNMP_DTEXT_PREFIX, pdu->reqid);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE,
	    "%*c%serrstat = %#x (non-repeaters)\n", SNMP_DPDU_INDENT, ' ',
	    SNMP_DTEXT_PREFIX, pdu->errstat);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE,
	    "%*c%serrindex = %u (max-reps)\n", SNMP_DPDU_INDENT, ' ',
	    SNMP_DTEXT_PREFIX, pdu->errindex);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%svars = %#x\n",
	    SNMP_DPDU_INDENT, ' ', SNMP_DTEXT_PREFIX, pdu->vars);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sreq_pkt = %#x\n",
	    SNMP_DPDU_INDENT, ' ', SNMP_DTEXT_PREFIX, pdu->req_pkt);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sreq_pktsz = %u\n",
	    SNMP_DPDU_INDENT, ' ', SNMP_DTEXT_PREFIX, pdu->req_pktsz);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sreply_pkt = %#x\n",
	    SNMP_DPDU_INDENT, ' ', SNMP_DTEXT_PREFIX, pdu->reply_pkt);
	snmp_log_append(snmp_lbuf);

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sreply_pktsz = %u\n",
	    SNMP_DPDU_INDENT, ' ', SNMP_DTEXT_PREFIX, pdu->reply_pktsz);
	snmp_log_append(snmp_lbuf);

	snmp_log_append("\n");

	(void) mutex_unlock(&snmp_dbuf_lock);
}

void
snmp_log_asn(int key, uchar_t *pkt, size_t pktsz)
{
	char	*p, *asnstr;
	int	i, len;
	size_t	nrows, nrem;

	if (pkt == NULL)
		return;

	(void) mutex_lock(&snmp_dbuf_lock);

	if ((snmp_debug_flag & SNMP_DEBUG_ASN) == 0) {
		(void) mutex_unlock(&snmp_dbuf_lock);
		return;
	}

	if ((asnstr = snmp_asnencoding_lookup(key)) == NULL) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%sASNKEY=%#x\n",
		    SNMP_DASN_INDENT, ' ', SNMP_DTEXT_PREFIX, key);
	} else {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s%s\n",
		    SNMP_DASN_INDENT, ' ', SNMP_DTEXT_PREFIX, asnstr);
	}
	snmp_log_append(snmp_lbuf);

	nrows = pktsz / 16;
	for (i = 0; i < nrows; i++) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s  "
		    "%02x %02x %02x %02x %02x %02x %02x %02x "
		    "%02x %02x %02x %02x %02x %02x %02x %02x\n",
		    SNMP_DASN_INDENT, ' ', SNMP_DTEXT_PREFIX,
		    pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5],
		    pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11],
		    pkt[12], pkt[13], pkt[14], pkt[15]);

		pkt += 16;
		snmp_log_append(snmp_lbuf);
	}

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s ",
	    SNMP_DASN_INDENT, ' ', SNMP_DTEXT_PREFIX);

	p = snmp_lbuf + SNMP_DASN_INDENT + strlen(SNMP_DTEXT_PREFIX) + 1;
	len = SNMP_DMAX_LINE - SNMP_DASN_INDENT - strlen(SNMP_DTEXT_PREFIX) - 1;

	nrem = pktsz % 16;
	for (i = 0; i < nrem; i++) {
		(void) snprintf(p, len, " %02x", pkt[i]);

		p += 3;
		len -= 3;
	}
	(void) snprintf(p, len, "\n");
	snmp_log_append(snmp_lbuf);

	(void) mutex_unlock(&snmp_dbuf_lock);
}

void
snmp_log_pkt(uint_t tag, uchar_t *pkt, size_t pktsz)
{
	uchar_t	ascii[SNMP_NCHARS_IN_A_ROW + 1];
	uchar_t	*p = pkt;
	char	*bufp;
	int	nrows, nrem;
	int	i, len;

	if (pkt == NULL)
		return;

	(void) mutex_lock(&snmp_dbuf_lock);

	if ((snmp_debug_flag & SNMP_DEBUG_PKT) == 0) {
		(void) mutex_unlock(&snmp_dbuf_lock);
		return;
	}

	snmp_log_append("\n");

	if (tag < n_tags) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s%s%s\n",
		    SNMP_DPKT_INDENT, ' ',
		    SNMP_DHDR_PREFIX, debug_tags[tag], SNMP_DHDR_SUFFIX);
		snmp_log_append(snmp_lbuf);
	}

	nrows = pktsz / SNMP_NCHARS_IN_A_ROW;
	nrem = pktsz % SNMP_NCHARS_IN_A_ROW;

	for (i = 0; i < nrows; i++) {
		snmp_get_dumpchars(ascii, p, SNMP_NCHARS_IN_A_ROW);
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s"
		    "%02x %02x %02x %02x %02x %02x %02x %02x "
		    "%02x %02x %02x %02x %02x %02x %02x %02x "
		    "%s\n",
		    SNMP_DPKT_INDENT, ' ', SNMP_DTEXT_PREFIX,
		    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		    p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
		    ascii);
		p += 16;

		snmp_log_append(snmp_lbuf);
	}

	(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE, "%*c%s",
	    SNMP_DPKT_INDENT, ' ', SNMP_DTEXT_PREFIX);

	snmp_get_dumpchars(ascii, p, nrem);

	bufp = snmp_lbuf + SNMP_DPKT_INDENT + strlen(SNMP_DTEXT_PREFIX);
	len = SNMP_DMAX_LINE - SNMP_DPKT_INDENT + strlen(SNMP_DTEXT_PREFIX);
	for (i = 0; i < 16; i++) {
		if (i < nrem)
			(void) snprintf(bufp, len, "%02x ", p[i]);
		else
			(void) snprintf(bufp, len, "   ");

		bufp += 3;
		len -= 3;
	}
	(void) snprintf(bufp, len, "%s\n", ascii);
	snmp_log_append(snmp_lbuf);

	(void) mutex_unlock(&snmp_dbuf_lock);
}

void
snmp_log_io(uint_t tag, int a1, uint_t a2, uint_t a3)
{
	(void) mutex_lock(&snmp_dbuf_lock);

	if ((snmp_debug_flag & SNMP_DEBUG_IO) == 0) {
		(void) mutex_unlock(&snmp_dbuf_lock);
		return;
	}

	snmp_log_append("\n");

	if (tag < n_tags) {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE,
		    "%*c%s%s(%d, %#x, %#x)\n", SNMP_DIO_INDENT, ' ',
		    SNMP_DTEXT_PREFIX, debug_tags[tag], a1, a2, a3);
	} else {
		(void) snprintf(snmp_lbuf, SNMP_DMAX_LINE,
		    "%*c%s%#x(%d, %#x, %#x)\n", SNMP_DIO_INDENT, ' ',
		    SNMP_DTEXT_PREFIX, tag, a1, a2, a3);
	}

	snmp_log_append(snmp_lbuf);

	(void) mutex_unlock(&snmp_dbuf_lock);
}

static char *
snmp_cmdstr_lookup(int cmd)
{
	int	nelem = sizeof (snmp_cmds) / sizeof (snmp_key_to_str_t);
	int	i;

	for (i = 0; i < nelem; i++) {
		if (snmp_cmds[i].key == cmd)
			return (snmp_cmds[i].str);
	}

	return (NULL);
}

static char *
snmp_vtypestr_lookup(int vtype)
{
	int	nelem = sizeof (snmp_vartypes) / sizeof (snmp_key_to_str_t);
	int	i;

	for (i = 0; i < nelem; i++) {
		if (snmp_vartypes[i].key == vtype)
			return (snmp_vartypes[i].str);
	}

	return (NULL);
}

static char *
snmp_asnencoding_lookup(int asnkey)
{
	int	nelem = sizeof (snmp_asnencodings) / sizeof (snmp_key_to_str_t);
	int	i;

	for (i = 0; i < nelem; i++) {
		if (snmp_asnencodings[i].key == asnkey)
			return (snmp_asnencodings[i].str);
	}

	return (NULL);
}

static void
snmp_get_dumpchars(uchar_t *abuf, uchar_t *p, int nchars)
{
	int	i;

	if (nchars > SNMP_NCHARS_IN_A_ROW)
		nchars = SNMP_NCHARS_IN_A_ROW;

	abuf[nchars] = 0;
	for (i = 0; i < nchars; i++)
		abuf[i] = isprint(p[i]) ? p[i] : '.';
}

static void
snmp_log_append(char *bufp)
{
	int	len;

	len = strlen(bufp);
	if ((snmp_dbuf_curp + len) >= snmp_dbuf_tail)
		snmp_dbuf_realloc();

	(void) strcpy(snmp_dbuf_curp, bufp);

	snmp_dbuf_curp += len;
}

static void
snmp_dbuf_realloc(void)
{
	char	*p;
	size_t	offset = 0;
	size_t	count;

	count = snmp_dbuf_sz + SNMP_DBLOCK_SZ;
	if ((p = (char *)calloc(count, 1)) == NULL) {
		snmp_dbuf_overflow++;
		snmp_dbuf_curp = snmp_dbuf;
		return;
	}

	if (snmp_dbuf) {
		offset = snmp_dbuf_curp - snmp_dbuf;
		(void) memcpy(p, snmp_dbuf, snmp_dbuf_sz);
		free(snmp_dbuf);
	}

	snmp_dbuf = p;
	snmp_dbuf_sz += SNMP_DBLOCK_SZ;

	snmp_dbuf_curp = snmp_dbuf + offset;
	snmp_dbuf_tail = snmp_dbuf + snmp_dbuf_sz;
}

#endif
