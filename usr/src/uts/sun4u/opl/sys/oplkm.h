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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_OPLKM_H
#define	_SYS_OPLKM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Device instance structure.
 */
typedef struct okms {
	dev_info_t	*km_dip;	/* Devinfo pointer */
	major_t		km_major;	/* Major number */
	uint32_t	km_inst;	/* Device instance */
	mkey_t		km_key;		/* Mailbox key */
	target_id_t	km_target;	/* Target-id */

	ddi_iblock_cookie_t km_ibcookie;	/* Interrupt block cookie */
	kmutex_t	km_lock;	/* Lock to protect this structure */
	kcondvar_t	km_wait;	/* Cond. var to signal events */
	uint32_t	km_state;	/* State of the device */
	uint32_t	km_maxsz;	/* Max msg size */

	uint32_t	km_retries;	/* Number of retries */
	uint32_t	km_clean;	/* Cleanup flags */
	mscat_gath_t	km_sg_rcv;	/* Scatter-gather for Rx */
	mscat_gath_t	km_sg_tx;	/* Scatter-gather for Tx */

	okm_req_hdr_t	*km_reqp;	/* Cached request */
	int		km_reqlen;	/* Request length */
} okms_t;

/* km_state flags */
#define	OKM_MB_INITED		0x00000001	/* Mailbox initialized */
#define	OKM_MB_CONN		0x00000002	/* Mailbox in connected state */
#define	OKM_MB_DISC		0x00000004	/* Mailbox is disconnected */
#define	OKM_OPENED		0x00000008	/* Device opened */

#define	OKM_MBOX_READY(x)	(((x)->km_state & OKM_MB_CONN) && \
				    !((x)->km_state & OKM_MB_DISC))

/* km_clean flags */
#define	OKM_CLEAN_LOCK		0x00000001
#define	OKM_CLEAN_CV		0x00000002
#define	OKM_CLEAN_NODE		0x00000004

#ifdef DEBUG
/*
 * Debug levels
 */
#define	DBG_DRV		0x01		/* driver related traces */
#define	DBG_MBOX	0x02		/* Mailbox traces */
#define	DBG_MESG	0x04		/* Mailbox Message traces */
#define	DBG_WARN	0x10		/* warning type traces */

static void okm_print_req(okm_req_hdr_t *reqp, uint32_t len);
static void okm_print_rep(okm_rep_hdr_t *repp);

#define	DPRINTF(f, x)		if (f & okm_debug) printf x
#define	DUMP_REQ(r, l)		okm_print_req(r, l)
#define	DUMP_REPLY(r)		okm_print_rep(r)

#else /* DEBUG */

#define	DPRINTF(f, x)
#define	DUMP_REQ(r, l)
#define	DUMP_REPLY(r)

#endif /* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_OPLKM_H */
