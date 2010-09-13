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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2005
 */

#ifndef _SCFDSCPIF_H
#define	_SCFDSCPIF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t mkey_t;	/* Data type for mailbox key */
typedef uint32_t target_id_t;	/* Target ID specifying the peer */

/*
 * Mailbox event types are defined as below.
 */
typedef enum {
	SCF_MB_CONN_OK,		/* Connection OK event */
	SCF_MB_MSG_DATA,	/* A new message has received */
	SCF_MB_SPACE,		/* Mailbox has space */
	SCF_MB_DISC_ERROR	/* Disconnect error */
} scf_event_t;

#define	SCF_EVENT_PRI	DDI_SOFTINT_LOW	/* Event handler priority */

/*
 * A scatter/gather data structure used for sending/receiving mailbox
 * messages.
 */
typedef struct mscat_gath {
	caddr_t		msc_dptr; /* pointer to the data buffer */
	uint32_t	msc_len;  /* Length of data in the data buffer */
} mscat_gath_t;


/*
 * Mailbox Flush types.
 */
typedef enum {
	MB_FLUSH_SEND = 0x01,	/* Flush all messages on the send side */
	MB_FLUSH_RECEIVE,	/* Flush all messages on the recieve side */
	MB_FLUSH_ALL		/* Flush messages on the both sides */
} mflush_type_t;

int scf_mb_init(target_id_t target_id, mkey_t mkey,
    void (*event_handler)(scf_event_t mevent, void *arg), void *arg);

int scf_mb_fini(target_id_t target_id, mkey_t mkey);

int scf_mb_putmsg(target_id_t target_id, mkey_t mkey, uint32_t data_len,
    uint32_t num_sg, mscat_gath_t *sgp, clock_t timeout);

int scf_mb_canget(target_id_t target_id, mkey_t mkey, uint32_t *data_lenp);

int scf_mb_getmsg(target_id_t target_id, mkey_t mkey, uint32_t data_len,
    uint32_t num_sg, mscat_gath_t *sgp, clock_t timeout);

int scf_mb_flush(target_id_t target_id, uint32_t key, mflush_type_t flush_type);

int scf_mb_ctrl(target_id_t target_id, uint32_t key, uint32_t op, void *arg);


/*
 * The following are the operations defined for scf_mb_ctrl().
 */

/*
 * Return the maximum message length which could be received/transmitted
 * on the specified mailbox. The value is returned via the argument(arg),
 * which will be treated as a pointer to an uint32_t.
 */
#define	SCF_MBOP_MAXMSGSIZE 0x00000001

#define	DSCP_KEY	('D' << 24 | 'S' << 16 | 'C' << 8 | 'P')
#define	DKMD_KEY	('D' << 24 | 'K' << 16 | 'M' << 8 | 'D')

#ifdef	__cplusplus
}
#endif

#endif	/* _SCFDSCPIF_H */
