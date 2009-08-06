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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FCP_H
#define	_FCP_H

/*
 * Frame format and protocol definitions for transferring
 * commands and data between a SCSI initiator and target
 * using an FC4 serial link interface.
 *
 * this file originally taken from fc4/fcp.h
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>


/*
 * FCP Device Data Frame Information Categories
 */
#define	FCP_SCSI_DATA		0x01	/* frame contains SCSI data */
#define	FCP_SCSI_CMD		0x02	/* frame contains SCSI command */
#define	FCP_SCSI_RSP		0x03	/* frame contains SCSI response */
#define	FCP_SCSI_XFER_RDY	0x05	/* frame contains xfer rdy block */

/*
 * fcp SCSI control structure
 */
typedef struct fcp_cntl {

	uchar_t	cntl_reserved_0;		/* reserved */

#if	defined(_BIT_FIELDS_HTOL)

	uchar_t	cntl_reserved_1	: 5,		/* reserved */
		cntl_qtype	: 3;		/* tagged queueing type */

	uchar_t	cntl_kill_tsk	: 1,		/* terminate task */
		cntl_clr_aca	: 1,		/* clear aca */
		cntl_reset_tgt	: 1,		/* reset target */
		cntl_reset_lun	: 1,		/* reset lun */
		cntl_reserved_2	: 1,		/* reserved */
		cntl_clr_tsk	: 1,		/* clear task set */
		cntl_abort_tsk	: 1,		/* abort task set */
		cntl_reserved_3	: 1;		/* reserved */

	uchar_t	cntl_reserved_4	: 6,		/* reserved */
		cntl_read_data	: 1,		/* initiator read */
		cntl_write_data	: 1;		/* initiator write */

#elif	defined(_BIT_FIELDS_LTOH)

	uchar_t	cntl_qtype	: 3,		/* tagged queueing type */
		cntl_reserved_1	: 5;		/* reserved */

	uchar_t	cntl_reserved_3	: 1,		/* reserved */
		cntl_abort_tsk	: 1,		/* abort task set */
		cntl_clr_tsk	: 1,		/* clear task set */
		cntl_reserved_2	: 1,		/* reserved */
		cntl_reset_lun	: 1,		/* reset lun */
		cntl_reset_tgt	: 1,		/* reset target */
		cntl_clr_aca	: 1,		/* clear aca */
		cntl_kill_tsk	: 1;		/* terminate task */

	uchar_t	cntl_write_data	: 1,		/* initiator write */
		cntl_read_data	: 1,		/* initiator read */
		cntl_reserved_4	: 6;		/* reserved */

#else
#error	one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif

} fcp_cntl_t;

/*
 * fcp SCSI control tagged queueing types - cntl_qtype
 */
#define	FCP_QTYPE_SIMPLE	0		/* simple queueing */
#define	FCP_QTYPE_HEAD_OF_Q	1		/* head of queue */
#define	FCP_QTYPE_ORDERED	2		/* ordered queueing */
#define	FCP_QTYPE_ACA_Q_TAG	4		/* ACA queueing */
#define	FCP_QTYPE_UNTAGGED	5		/* Untagged */

/*
 * fcp SCSI entity address
 *
 * ent_addr_0 is always the first and highest layer of
 * the hierarchy.  The depth of the hierarchy of addressing,
 * up to a maximum of four layers, is arbitrary and
 * device-dependent.
 */
typedef struct fcp_ent_addr {
	ushort_t ent_addr_0;		/* entity address 0 */
	ushort_t ent_addr_1;		/* entity address 1 */
	ushort_t ent_addr_2;		/* entity address 2 */
	ushort_t ent_addr_3;		/* entity address 3 */
} fcp_ent_addr_t;

/*
 * maximum size of SCSI cdb in fcp SCSI command
 */
#define	FCP_CDB_SIZE		16
#define	FCP_LUN_SIZE		8
#define	FCP_LUN_HEADER		8

/*
 * FCP SCSI command payload
 */
typedef struct fcp_cmd {
	fcp_ent_addr_t	fcp_ent_addr;			/* entity address */
	fcp_cntl_t	fcp_cntl;			/* SCSI options */
	uchar_t		fcp_cdb[FCP_CDB_SIZE];		/* SCSI cdb */
	int		fcp_data_len;			/* data length */
} fcp_cmd_t;

/*
 * fcp SCSI status
 */
typedef struct fcp_status {
	ushort_t reserved_0;			/* reserved */

#if	defined(_BIT_FIELDS_HTOL)

	uchar_t	reserved_1	: 4,		/* reserved */
		resid_under	: 1,		/* resid non-zero */
		resid_over	: 1,		/* resid non-zero */
		sense_len_set	: 1,		/* sense_len non-zero */
		rsp_len_set	: 1;		/* response_len non-zero */

#elif	defined(_BIT_FIELDS_LTOH)

	uchar_t	rsp_len_set	: 1,		/* response_len non-zero */
		sense_len_set	: 1,		/* sense_len non-zero */
		resid_over	: 1,		/* resid non-zero */
		resid_under	: 1,		/* resid non-zero */
		reserved_1	: 4;		/* reserved */

#endif
	uchar_t	scsi_status;			/* status of cmd */
} fcp_status_t;

/*
 * fcp SCSI response payload
 */
typedef struct fcp_rsp {
	uint32_t	reserved_0;			/* reserved */
	uint32_t	reserved_1;			/* reserved */
	union {
		fcp_status_t	fcp_status;		/* command status */
		uint32_t	i_fcp_status;
	} fcp_u;
	uint32_t	fcp_resid;		/* resid of operation */
	uint32_t	fcp_sense_len;		/* sense data length */
	uint32_t	fcp_response_len;	/* response data length */
	/*
	 * 'm' bytes of scsi response info follow
	 * 'n' bytes of scsi sense info follow
	 */
} fcp_rsp_t;

/* MAde 256 for sonoma as it wants to give tons of sense info */
#define	FCP_MAX_RSP_IU_SIZE	256

/*
 * fcp rsp_info field format
 */
struct fcp_rsp_info {
	uchar_t		resvd1;
	uchar_t		resvd2;
	uchar_t		resvd3;
	uchar_t		rsp_code;
	uchar_t		resvd4;
	uchar_t		resvd5;
	uchar_t		resvd6;
	uchar_t		resvd7;
};

/*
 * rsp_code definitions
 */
#define		FCP_NO_FAILURE			0x0
#define		FCP_DL_LEN_MISMATCH		0x1
#define		FCP_CMND_INVALID		0x2
#define		FCP_DATA_RO_MISMATCH		0x3
#define		FCP_TASK_MGMT_NOT_SUPPTD	0x4
#define		FCP_TASK_MGMT_FAILED		0x5

#ifdef	THIS_NEEDED_YET

/*
 * fcp scsi_xfer_rdy payload
 */
typedef struct fcp_xfer_rdy {
	ulong64_t	fcp_seq_offset;		/* relative offset */
	ulong64_t	fcp_burst_len;		/* buffer space */
	ulong64_t	reserved;		/* reserved */
} fcp_xfer_rdy_t;

#endif	/* THIS_NEEDED_YET */

/*
 * fcp PRLI payload
 */
struct fcp_prli {
	uchar_t		type;
	uchar_t		resvd1;			/* rsvd by std */

#if	defined(_BIT_FIELDS_HTOL)

	uint16_t	orig_process_assoc_valid : 1,
			resp_process_assoc_valid : 1,
			establish_image_pair : 1,
			resvd2 : 13;		/* rsvd by std */

#elif	defined(_BIT_FIELDS_LTOH)

	uint16_t	resvd2 : 13,		/* rsvd by std */
			establish_image_pair : 1,
			resp_process_assoc_valid : 1,
			orig_process_assoc_valid : 1;

#endif

	uint32_t	orig_process_associator;
	uint32_t	resp_process_associator;

#if	defined(_BIT_FIELDS_HTOL)

	uint32_t	resvd3 : 23,		/* rsvd by std */
			retry : 1,
			confirmed_compl_allowed : 1,
			data_overlay_allowed : 1,
			initiator_fn : 1,
			target_fn : 1,
			obsolete_2 : 1,
			obsolete_1 : 1,
			read_xfer_rdy_disabled : 1,
			write_xfer_rdy_disabled : 1;

#elif	defined(_BIT_FIELDS_LTOH)

	uint32_t	write_xfer_rdy_disabled : 1,
			read_xfer_rdy_disabled : 1,
			obsolete_1 : 1,
			obsolete_2 : 1,
			target_fn : 1,
			initiator_fn : 1,
			data_overlay_allowed : 1,
			confirmed_compl_allowed : 1,
			retry : 1,
			resvd3 : 23;		/* rsvd by std */

#endif

};

/*
 * fcp PRLI ACC payload
 */
struct fcp_prli_acc {
	uchar_t		type;
	uchar_t		resvd1; /* type code extension */

#if	defined(_BIT_FIELDS_HTOL)
	uint16_t	orig_process_assoc_valid : 1,
			resp_process_assoc_valid : 1,
			image_pair_established : 1,
			resvd2 : 1,
			accept_response_code : 4,
			resvd3 : 8;
#elif	defined(_BIT_FIELDS_LTOH)
	uint16_t	resvd3 : 8,
			accept_response_code : 4,
			resvd2 : 1,
			image_pair_established : 1,
			resp_process_assoc_valid : 1,
			orig_process_assoc_valid : 1;
#endif

	uint32_t	orig_process_associator;
	uint32_t	resp_process_associator;

#if	defined(_BIT_FIELDS_HTOL)
	uint32_t	resvd4 : 26,
			initiator_fn : 1,
			target_fn : 1,
			cmd_data_mixed : 1,
			data_resp_mixed : 1,
			read_xfer_rdy_disabled : 1,
			write_xfer_rdy_disabled : 1;
#elif	defined(_BIT_FIELDS_LTOH)
	uint32_t	write_xfer_rdy_disabled : 1,
			read_xfer_rdy_disabled : 1,
			data_resp_mixed : 1,
			cmd_data_mixed : 1,
			target_fn : 1,
			initiator_fn : 1,
			resvd4 : 26;
#endif
};

#define	FC_UB_FCP_CDB_FLAG	0x0001		/* UB has valid cdb */
#define	FC_UB_FCP_PORT_LOGOUT	0x0002		/* Port logout UB */
#define	FC_UB_FCP_ABORT_TASK	0x0004		/* Abort task UB */
#define	FC_UB_FCP_BUS_RESET	0x0008		/* Bus reset UB */
#define	FC_UB_FCP_CMD_DONE	0x8000		/* Work on this UB is done */

#define	FC_UB_FCP_OOB_CMD	(FC_UB_FCP_PORT_LOGOUT | FC_UB_FCP_ABORT_TASK \
	| FC_UB_FCP_BUS_RESET)			/* Out-of-band traget cmds */


#if !defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("Unshared Data",
    fcp_cmd
    fcp_rsp
    fcp_prli))
#endif /* __lint */

/*
 * FC4 type setttings for Name Server registration.
 */
#define	FC4_TYPE_WORD_POS(x)	((uchar_t)(x) >> 5)
#define	FC4_TYPE_BIT_POS(x)	((uchar_t)(x) & 0x1F)

#ifdef	__cplusplus
}
#endif

#endif	/* _FCP_H */
