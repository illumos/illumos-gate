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
 * Copyright (c) 1995,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_FC4_FCP_H
#define	_SYS_FC4_FCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Frame format and protocol definitions for transferring
 * commands and data between a SCSI initiator and target
 * using an FC4 serial link interface.
 */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * FCP Device Data Frame Information Categories
 */
#define	FCP_SCSI_DATA		0x01	/* frame contains SCSI data */
#define	FCP_SCSI_CMD		0x02	/* frame contains SCSI command */
#define	FCP_SCSI_RSP		0x03	/* frame contains SCSI response */
#define	FCP_SCSI_XFER_RDY	0x05	/* frame contains xfer rdy block */


/*
 * FCP SCSI Control structure
 */
typedef struct fcp_cntl {
	uchar_t	cntl_reserved_0;		/* reserved */
	uchar_t	cntl_reserved_1	: 5,		/* reserved */
		cntl_qtype	: 3;		/* tagged queueing type */
	uchar_t	cntl_kill_tsk	: 1,		/* terminate task */
		cntl_clr_aca	: 1,		/* clear aca */
		cntl_reset	: 1,		/* reset */
		cntl_reserved_2	: 2,		/* reserved */
		cntl_clr_tsk	: 1,		/* clear task set */
		cntl_abort_tsk	: 1,		/* abort task set */
		cntl_reserved_3	: 1;		/* reserved */
	uchar_t	cntl_reserved_4	: 6,		/* reserved */
		cntl_read_data	: 1,		/* initiator read */
		cntl_write_data	: 1;		/* initiator write */
} fcp_cntl_t;

/*
 * FCP SCSI Control Tagged Queueing types - cntl_qtype
 */
#define	FCP_QTYPE_SIMPLE	0		/* simple queueing */
#define	FCP_QTYPE_HEAD_OF_Q	1		/* head of queue */
#define	FCP_QTYPE_ORDERED	2		/* ordered queueing */
#define	FCP_QTYPE_ACA_Q_TAG	4		/* ACA queueing */
#define	FCP_QTYPE_UNTAGGED	5		/* Untagged */


/*
 * FCP SCSI Entity Address
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
 * Maximum size of SCSI cdb in FCP SCSI command
 */
#define	FCP_CDB_SIZE		16
#define	FCP_LUN_SIZE		8

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
 * FCP SCSI status
 */
typedef struct fcp_status {
	ushort_t reserved_0;			/* reserved */
	uchar_t	reserved_1	: 4,		/* reserved */
		resid_under	: 1,		/* resid non-zero */
		resid_over	: 1,		/* resid non-zero */
		sense_len_set	: 1,		/* sense_len non-zero */
		rsp_len_set	: 1;		/* response_len non-zero */
	uchar_t	scsi_status;			/* status of cmd */
} fcp_status_t;

#define	resid_len_set	resid_over		/* for pln */


/*
 * FCP SCSI Response Payload
 */
typedef struct fcp_rsp {
	uint_t	reserved_0;			/* reserved */
	uint_t	reserved_1;			/* reserved */
	union {
		fcp_status_t	fcp_status;		/* command status */
		uint_t		i_fcp_status;
	}fcp_u;
	uint_t		fcp_resid;		/* resid of operation */
	uint_t		fcp_sense_len;		/* sense data length */
	uint_t		fcp_response_len;	/* response data length */
	/*
	 * 'm' bytes of scsi response info follow
	 * 'n' bytes of scsi sense info follow
	 */
} fcp_rsp_t;

#define	FCP_MAX_RSP_IU_SIZE	256

/*
 * FCP RSP_INFO field format
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

/*	RSP_CODE definitions */

#define		FCP_NO_FAILURE			0x0
#define		FCP_DL_LEN_MISMATCH		0x1
#define		FCP_CMND_INVALID		0x2
#define		FCP_DATA_RO_MISMATCH		0x3
#define		FCP_TASK_MGMT_NOT_SUPPTD	0x4
#define		FCP_TASK_MGMT_FAILED		0x5


/*
 * FCP SCSI_ XFER_RDY Payload
 */
typedef struct fcp_xfer_rdy {
	ulong_t		fcp_seq_offset;		/* relative offset */
	ulong_t		fcp_burst_len;		/* buffer space */
	ulong_t		reserved;		/* reserved */
} fcp_xfer_rdy_t;

/*
 * FCP PRLI Payload
 */

struct fcp_prli {
	uchar_t		type;
	uchar_t		resvd1;
	uint_t		orig_process_assoc_valid:1;
	uint_t		resp_process_assoc_valid:1;
	uint_t		establish_image_pair:1;
	uint_t		resvd2:13;
	uint_t		orig_process_associator;
	uint_t		resp_process_associator;
	uint_t		resvd3:25;
	uint_t		data_overlay_allowed:1;
	uint_t		initiator_fn:1;
	uint_t		target_fn:1;
	uint_t		cmd_data_mixed:1;
	uint_t		data_resp_mixed:1;
	uint_t		read_xfer_rdy_disabled:1;
	uint_t		write_xfer_rdy_disabled:1;
};

/*
 * FCP PRLI ACC Payload
 */

struct fcp_prli_acc {
	uchar_t		type;
	uchar_t		resvd1;
	uint_t		orig_process_assoc_valid:1;
	uint_t		resp_process_assoc_valid:1;
	uint_t		image_pair_establsihed:1;
	uint_t		resvd2:1;
	uint_t		accept_response_code:4;
	uint_t		resvd3:8;
	uint_t		orig_process_associator;
	uint_t		resp_process_associator;
	uint_t		resvd4:26;
	uint_t		initiator_fn:1;
	uint_t		target_fn:1;
	uint_t		cmd_data_mixed:1;
	uint_t		data_resp_mixed:1;
	uint_t		read_xfer_rdy_disabled:1;
	uint_t		write_xfer_rdy_disabled:1;
};


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FC4_FCP_H */
