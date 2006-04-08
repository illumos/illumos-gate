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

#ifndef	_DDM2S_H
#define	_DDM2S_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef __cplusplus
extern "C" {
#endif

#define	DM2S_MAX_SG		20	/* Max. scatter-gather elements */
#define	DM2S_MAX_RETRIES	3	/* Max. number of retries */

/*
 * Instance structure.
 */
typedef struct dm2s {
	dev_info_t	*ms_dip;	/* Devinfo pointer */
	major_t		ms_major;	/* Major number */
	uint32_t	ms_ppa;		/* Device instance */
	mkey_t		ms_key;		/* Mailbox key */
	target_id_t	ms_target;	/* Target-id */

	ddi_iblock_cookie_t ms_ibcookie;	/* Interrupt block cookie */
	kmutex_t	ms_lock;	/* Lock to protect this structure */
	kcondvar_t	ms_wait;	/* Cond. var to signal events */

	uint32_t	ms_mtu;		/* MTU supported */
	queue_t		*ms_rq;		/* Read side queue */
	queue_t		*ms_wq;		/* Write side queuee */
	uint32_t	ms_state;	/* State of the device */

	uint32_t	ms_retries;	/* Number of retries */
	timeout_id_t	ms_rq_timeoutid; /* Timeout id for read queue */
	timeout_id_t	ms_wq_timeoutid; /* Timeout id for write queue */
	bufcall_id_t	ms_rbufcid;	 /* Buffcall-id for the read */

	uint64_t	ms_obytes;	/* Number of output bytes */
	uint64_t	ms_ibytes;	/* Number of input bytes */

	uint32_t	ms_clean;	/* Cleanup flags */
	mscat_gath_t	ms_sg_rcv;	/* Scatter-gather for receive */
	mscat_gath_t	ms_sg_tx[DM2S_MAX_SG];	/* scatter-gather for Tx */
} dm2s_t;

/* ms_state flags */
#define	DM2S_MB_INITED		0x00000001	/* Mailbox initialized */
#define	DM2S_MB_CONN		0x00000002	/* Mailbox in connected state */
#define	DM2S_MB_DISC		0x00000004	/* Mailbox is disconnected */
#define	DM2S_OPENED		0x00000008	/* Device opened */

#define	DM2S_MBOX_READY(x)	((x)->ms_state & DM2S_MB_CONN)

/* ms_clean flags */
#define	DM2S_CLEAN_LOCK		0x00000001
#define	DM2S_CLEAN_CV		0x00000002
#define	DM2S_CLEAN_NODE		0x00000004

#ifdef DEBUG
/*
 * Debug levels
 */
#define	DBG_DRV		0x01		/* driver related traces */
#define	DBG_MBOX	0x02		/* Mailbox traces */
#define	DBG_MESG	0x04		/* Mailbox Message traces */
#define	DBG_WARN	0x10		/* warning type traces */

static void dm2s_dump_bytes(char *str, uint32_t total_len,
    uint32_t num_sg, mscat_gath_t *sgp);

#define	DPRINTF(f, x)		if (f & dm2s_debug) printf x
#define	DMPBYTES(s, l, n, sg)	dm2s_dump_bytes(s, l, n, sg)

#else /* DEBUG */

#define	DPRINTF(f, x)
#define	DMPBYTES(s, l, n, sg)

#endif /* DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* _DDM2S_H */
