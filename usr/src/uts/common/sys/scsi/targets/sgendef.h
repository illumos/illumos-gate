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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright Siemens 1999
 * All rights reserved.
 */

#ifndef _SYS_SCSI_TARGETS_SGENDEF_H
#define	_SYS_SCSI_TARGETS_SGENDEF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/condvar.h>
#include <sys/mutex.h>
#include <sys/buf.h>
#include <sys/scsi/scsi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SGEN_IOC		(('S' << 16) | ('G' << 8))
#define	SGEN_IOC_READY		(SGEN_IOC | 0x01)
#define	SGEN_IOC_DIAG		(SGEN_IOC | 0x02)

#if defined(_KERNEL)

#define	SGEN_DIAG1		((1 << 8) | CE_CONT)
#define	SGEN_DIAG2		((2 << 8) | CE_CONT)
#define	SGEN_DIAG3		((3 << 8) | CE_CONT)

struct sgen_errstats {
	kstat_named_t sgen_trans_err;	/* error trying to transport pkt */
	kstat_named_t sgen_restart;	/* command restart attempted */
	kstat_named_t sgen_incmp_err;	/* command failed to complete */
	kstat_named_t sgen_autosen_rcv;	/* autosense occurred */
	kstat_named_t sgen_autosen_bad;	/* autosense data looks malformed */
	kstat_named_t sgen_sense_rcv;	/* sense fetch occurred */
	kstat_named_t sgen_sense_bad;	/* sense data looks malformed */
	kstat_named_t sgen_recov_err;	/* sense key is KEY_RECOVERABLE */
	kstat_named_t sgen_nosen_err;	/* sense key is KEY_NO_SENSE */
	kstat_named_t sgen_unrecov_err;	/* sense key indicates other err */
};

typedef struct sgen_state {
	struct scsi_device *sgen_scsidev;	/* pointer to scsi_device */
	struct uscsi_cmd *sgen_ucmd;		/* uscsi command struct */
	struct buf *sgen_cmdbuf;		/* xfer buffer */
	struct scsi_pkt *sgen_cmdpkt;		/* scsi packet for command */
	kcondvar_t sgen_cmdbuf_cv;		/* cv for cmdbuf */
	int sgen_flags;				/* see SGEN_FL_* */
	struct scsi_pkt *sgen_rqspkt;		/* request sense packet */
	struct buf *sgen_rqsbuf;		/* request sense xfer buffer */
	char *sgen_rqs_sen;			/* sense buffer */
	int sgen_arq_enabled;			/* auto request sense enabled */
	int sgen_diag;				/* diagnostic output level */
	timeout_id_t sgen_restart_timeid;	/* timeout for sgen_restart */
	kstat_t *sgen_kstats;			/* for error statistics */
} sgen_state_t;

/*
 * Convenience accessors for sgen_state_t.
 */
#define	sgen_mutex sgen_scsidev->sd_mutex
#define	sgen_devinfo sgen_scsidev->sd_dev
#define	sgen_scsiaddr sgen_scsidev->sd_address
#define	sgen_sense sgen_scsidev->sd_sense

/*
 * sgen_flags accessors/mutators
 */
#define	SGEN_FL_OPEN	0x01	/* instance is open */
#define	SGEN_FL_SUSP	0x02	/* instance suspended */
#define	SGEN_FL_BUSY	0x04	/* command buffer busy */
#define	SGEN_FL_EXCL	0x08	/* exclusive open */

#define	SGEN_SET_OPEN(stp) \
	(((sgen_state_t *)(stp))->sgen_flags |= SGEN_FL_OPEN)
#define	SGEN_CLR_OPEN(stp) \
	(((sgen_state_t *)(stp))->sgen_flags &= ~SGEN_FL_OPEN)
#define	SGEN_IS_OPEN(stp) \
	((((sgen_state_t *)(stp))->sgen_flags & SGEN_FL_OPEN) == SGEN_FL_OPEN)

#define	SGEN_SET_SUSP(stp) \
	(((sgen_state_t *)(stp))->sgen_flags |= SGEN_FL_SUSP)
#define	SGEN_CLR_SUSP(stp) \
	(((sgen_state_t *)(stp))->sgen_flags &= ~SGEN_FL_SUSP)
#define	SGEN_IS_SUSP(stp) \
	((((sgen_state_t *)(stp))->sgen_flags & SGEN_FL_SUSP) == SGEN_FL_SUSP)

#define	SGEN_SET_BUSY(stp) \
	(((sgen_state_t *)(stp))->sgen_flags |= SGEN_FL_BUSY)
#define	SGEN_CLR_BUSY(stp) \
	(((sgen_state_t *)(stp))->sgen_flags &= ~SGEN_FL_BUSY)
#define	SGEN_IS_BUSY(stp) \
	((((sgen_state_t *)(stp))->sgen_flags & SGEN_FL_BUSY) == SGEN_FL_BUSY)

#define	SGEN_SET_EXCL(stp) \
	(((sgen_state_t *)(stp))->sgen_flags |= SGEN_FL_EXCL)
#define	SGEN_CLR_EXCL(stp) \
	(((sgen_state_t *)(stp))->sgen_flags &= ~SGEN_FL_EXCL)
#define	SGEN_IS_EXCL(stp) \
	((((sgen_state_t *)(stp))->sgen_flags & SGEN_FL_EXCL) == SGEN_FL_EXCL)

/*
 * These structures form the driver's database of binding information.
 * Inquiry strings and device types from the inquiry-config-list and
 * device-type-config-list properties are stored.
 */
typedef struct sgen_inq_node {
	char *node_vendor;			/* up to 8 character vendor */
	char *node_product;			/* up to 16 character product */
	struct sgen_inq_node *node_next;
} sgen_inq_node_t;

typedef struct sgen_type_node {
	uchar_t node_type;			/* SCSI device type */
	struct sgen_type_node *node_next;
} sgen_type_node_t;

struct sgen_binddb {
	int sdb_init;				/* has this been initialized? */
	kmutex_t sdb_lock;			/* protects this structure */
	sgen_inq_node_t *sdb_inq_nodes;		/* inquiry binding nodes */
	sgen_type_node_t *sdb_type_nodes;	/* dev-type binding nodes */
};

#define	SGEN_ESTIMATED_NUM_DEVS	4		/* for soft-state allocation */

/*
 * Time to wait before a retry for commands returning Busy Status
 */
#define	SGEN_BSY_TIMEOUT	(drv_usectohz(5 * 1000000))
#define	SGEN_IO_TIME		60		/* seconds */

/*
 * sgen_callback action codes
 */
#define	COMMAND_DONE		0	/* command completed, biodone it */
#define	COMMAND_DONE_ERROR	1	/* command completed, indicate error */
#define	FETCH_SENSE		2	/* CHECK CONDITION, so initiate sense */
					/* fetch */

#define	SET_BP_ERROR(bp, err)	bioerror(bp, err);

#endif /* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_TARGETS_SGENDEF_H */
