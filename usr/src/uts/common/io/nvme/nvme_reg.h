/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * NVMe hardware interface
 */

#ifndef _NVME_REG_H
#define	_NVME_REG_H

#include <sys/nvme.h>

#pragma pack(1)

#ifdef __cplusplus
extern "C" {
#endif


/*
 * NVMe constants
 */
#define	NVME_MAX_ADMIN_QUEUE_LEN	4096

/*
 * NVMe registers and register fields
 */
#define	NVME_REG_CAP	0x0		/* Controller Capabilities */
#define	NVME_REG_VS	0x8		/* Version */
#define	NVME_REG_INTMS	0xc		/* Interrupt Mask Set */
#define	NVME_REG_INTMC	0x10		/* Interrupt Mask Clear */
#define	NVME_REG_CC	0x14		/* Controller Configuration */
#define	NVME_REG_CSTS	0x1c		/* Controller Status */
#define	NVME_REG_NSSR	0x20		/* NVM Subsystem Reset */
#define	NVME_REG_AQA	0x24		/* Admin Queue Attributes */
#define	NVME_REG_ASQ	0x28		/* Admin Submission Queue */
#define	NVME_REG_ACQ	0x30		/* Admin Completion Qeueu */
#define	NVME_REG_SQTDBL(nvme, n) \
	(0x1000 + ((2 * (n)) * nvme->n_doorbell_stride))
#define	NVME_REG_CQHDBL(nvme, n) \
	(0x1000 + ((2 * (n) + 1) * nvme->n_doorbell_stride))

#define	 NVME_CAP_CSS_NVM	1	/* NVM Command Set */
#define	 NVME_CAP_AMS_WRR	1	/* Weighted Round-Robin */

/* CAP -- Controller Capabilities */
typedef union {
	struct {
		uint16_t cap_mqes;	/* Maximum Queue Entries Supported */
		uint8_t cap_cqr:1;	/* Contiguous Queues Required */
		uint8_t cap_ams:2;	/* Arbitration Mechanisms Supported */
		uint8_t cap_rsvd1:5;
		uint8_t cap_to;		/* Timeout */
		uint16_t cap_dstrd:4;	/* Doorbell Stride */
		uint16_t cap_nssrs:1;	/* NVM Subsystem Reset Supported */
		uint16_t cap_css:8;	/* Command Sets Supported */
		uint16_t cap_rsvd2:3;
		uint8_t cap_mpsmin:4;	/* Memory Page Size Minimum */
		uint8_t cap_mpsmax:4;	/* Memory Page Size Maximum */
		uint8_t cap_rsvd3;
	} b;
	uint64_t r;
} nvme_reg_cap_t;

/* VS -- Version */
typedef union {
	struct {
		uint8_t vs_rsvd;
		uint8_t vs_mnr;		/* Minor Version Number */
		uint16_t vs_mjr;	/* Major Version Number */
	} b;
	uint32_t r;
} nvme_reg_vs_t;

/* CC -- Controller Configuration */
#define	NVME_CC_SHN_NORMAL	1	/* Normal Shutdown Notification */
#define	NVME_CC_SHN_ABRUPT	2	/* Abrupt Shutdown Notification */

typedef union {
	struct {
		uint16_t cc_en:1;	/* Enable */
		uint16_t cc_rsvd1:3;
		uint16_t cc_css:3;	/* I/O Command Set Selected */
		uint16_t cc_mps:4;	/* Memory Page Size */
		uint16_t cc_ams:3;	/* Arbitration Mechanism Selected */
		uint16_t cc_shn:2;	/* Shutdown Notification */
		uint8_t cc_iosqes:4;	/* I/O Submission Queue Entry Size */
		uint8_t cc_iocqes:4;	/* I/O Completion Queue Entry Size */
		uint8_t cc_rsvd2;
	} b;
	uint32_t r;
} nvme_reg_cc_t;

/* CSTS -- Controller Status */
#define	NVME_CSTS_SHN_OCCURING	1	/* Shutdown Processing Occuring */
#define	NVME_CSTS_SHN_COMPLETE	2	/* Shutdown Processing Complete */

typedef union {
	struct {
		uint32_t csts_rdy:1;	/* Ready */
		uint32_t csts_cfs:1;	/* Controller Fatal Status */
		uint32_t csts_shst:2;	/* Shutdown Status */
		uint32_t csts_nssro:1;	/* NVM Subsystem Reset Occured */
		uint32_t csts_rsvd:27;
	} b;
	uint32_t r;
} nvme_reg_csts_t;

/* NSSR -- NVM Subsystem Reset */
#define	NVME_NSSR_NSSRC	0x4e564d65	/* NSSR magic value */
typedef uint32_t nvme_reg_nssr_t;

/* AQA -- Admin Queue Attributes */
typedef union {
	struct {
		uint16_t aqa_asqs:12;	/* Admin Submission Queue Size */
		uint16_t aqa_rsvd1:4;
		uint16_t aqa_acqs:12;	/* Admin Completion Queue Size */
		uint16_t aqa_rsvd2:4;
	} b;
	uint32_t r;
} nvme_reg_aqa_t;

/*
 * The spec specifies the lower 12 bits of ASQ and ACQ as reserved, which is
 * probably a specification bug. The full 64bit regs are used as base address,
 * and the lower bits must be zero to ensure alignment on the page size
 * specified in CC.MPS.
 */
/* ASQ -- Admin Submission Queue Base Address */
typedef uint64_t nvme_reg_asq_t;	/* Admin Submission Queue Base */

/* ACQ -- Admin Completion Queue Base Address */
typedef uint64_t nvme_reg_acq_t;	/* Admin Completion Queue Base */

/* SQyTDBL -- Submission Queue y Tail Doorbell */
typedef union {
	struct {
		uint16_t sqtdbl_sqt;	/* Submission Queue Tail */
		uint16_t sqtdbl_rsvd;
	} b;
	uint32_t r;
} nvme_reg_sqtdbl_t;

/* CQyHDBL -- Completion Queue y Head Doorbell */
typedef union {
	struct {
		uint16_t cqhdbl_cqh;	/* Completion Queue Head */
		uint16_t cqhdbl_rsvd;
	} b;
	uint32_t r;
} nvme_reg_cqhdbl_t;

/*
 * NVMe submission queue entries
 */

/* NVMe scatter/gather list descriptor */
typedef struct {
	uint64_t sgl_addr;		/* Address */
	uint32_t sgl_len;		/* Length */
	uint8_t sgl_rsvd[3];
	uint8_t sgl_zero:4;
	uint8_t sgl_type:4;		/* SGL descriptor type */
} nvme_sgl_t;

/* NVMe SGL descriptor type */
#define	NVME_SGL_DATA_BLOCK	0
#define	NVME_SGL_BIT_BUCKET	1
#define	NVME_SGL_SEGMENT	2
#define	NVME_SGL_LAST_SEGMENT	3
#define	NVME_SGL_VENDOR		0xf

/* NVMe submission queue entry */
typedef struct {
	uint8_t sqe_opc;		/* Opcode */
	uint8_t sqe_fuse:2;		/* Fused Operation */
	uint8_t sqe_rsvd:5;
	uint8_t sqe_psdt:1;		/* PRP or SGL for Data Transfer */
	uint16_t sqe_cid;		/* Command Identifier */
	uint32_t sqe_nsid;		/* Namespace Identifier */
	uint64_t sqe_rsvd1;
	union {
		uint64_t m_ptr;		/* Metadata Pointer */
		uint64_t m_sglp;	/* Metadata SGL Segment Pointer */
	} sqe_m;
	union {
		uint64_t d_prp[2];	/* Physical Page Region Entries 1 & 2 */
		nvme_sgl_t d_sgl;	/* SGL Entry 1 */
	} sqe_dptr;			/* Data Pointer */
	uint32_t sqe_cdw10;		/* Number of Dwords in Data Transfer */
	uint32_t sqe_cdw11;		/* Number of Dwords in Metadata Xfer */
	uint32_t sqe_cdw12;
	uint32_t sqe_cdw13;
	uint32_t sqe_cdw14;
	uint32_t sqe_cdw15;
} nvme_sqe_t;

/* NVMe admin command opcodes */
#define	NVME_OPC_DELETE_SQUEUE	0x0
#define	NVME_OPC_CREATE_SQUEUE	0x1
#define	NVME_OPC_GET_LOG_PAGE	0x2
#define	NVME_OPC_DELETE_CQUEUE	0x4
#define	NVME_OPC_CREATE_CQUEUE	0x5
#define	NVME_OPC_IDENTIFY	0x6
#define	NVME_OPC_ABORT		0x8
#define	NVME_OPC_SET_FEATURES	0x9
#define	NVME_OPC_GET_FEATURES	0xa
#define	NVME_OPC_ASYNC_EVENT	0xc
#define	NVME_OPC_FW_ACTIVATE	0x10
#define	NVME_OPC_FW_IMAGE_LOAD	0x11

/* NVMe NVM command set specific admin command opcodes */
#define	NVME_OPC_NVM_FORMAT	0x80
#define	NVME_OPC_NVM_SEC_SEND	0x81
#define	NVME_OPC_NVM_SEC_RECV	0x82

/* NVMe NVM command opcodes */
#define	NVME_OPC_NVM_FLUSH	0x0
#define	NVME_OPC_NVM_WRITE	0x1
#define	NVME_OPC_NVM_READ	0x2
#define	NVME_OPC_NVM_WRITE_UNC	0x4
#define	NVME_OPC_NVM_COMPARE	0x5
#define	NVME_OPC_NVM_WRITE_ZERO	0x8
#define	NVME_OPC_NVM_DSET_MGMT	0x9
#define	NVME_OPC_NVM_RESV_REG	0xd
#define	NVME_OPC_NVM_RESV_REPRT	0xe
#define	NVME_OPC_NVM_RESV_ACQ	0x11
#define	NVME_OPC_NVM_RESV_REL	0x12

/*
 * NVMe completion queue entry
 */
typedef struct {
	uint32_t cqe_dw0;		/* Command Specific */
	uint32_t cqe_rsvd1;
	uint16_t cqe_sqhd;		/* SQ Head Pointer */
	uint16_t cqe_sqid;		/* SQ Identifier */
	uint16_t cqe_cid;		/* Command Identifier */
	nvme_cqe_sf_t cqe_sf;		/* Status Field */
} nvme_cqe_t;

/* NVMe completion status code type */
#define	NVME_CQE_SCT_GENERIC	0	/* Generic Command Status */
#define	NVME_CQE_SCT_SPECIFIC	1	/* Command Specific Status */
#define	NVME_CQE_SCT_INTEGRITY	2	/* Media and Data Integrity Errors */
#define	NVME_CQE_SCT_VENDOR	7	/* Vendor Specific */

/* NVMe completion status code (generic) */
#define	NVME_CQE_SC_GEN_SUCCESS		0x0	/* Successful Completion */
#define	NVME_CQE_SC_GEN_INV_OPC		0x1	/* Invalid Command Opcode */
#define	NVME_CQE_SC_GEN_INV_FLD		0x2	/* Invalid Field in Command */
#define	NVME_CQE_SC_GEN_ID_CNFL		0x3	/* Command ID Conflict */
#define	NVME_CQE_SC_GEN_DATA_XFR_ERR	0x4	/* Data Transfer Error */
#define	NVME_CQE_SC_GEN_ABORT_PWRLOSS	0x5	/* Cmds Aborted / Pwr Loss */
#define	NVME_CQE_SC_GEN_INTERNAL_ERR	0x6	/* Internal Error */
#define	NVME_CQE_SC_GEN_ABORT_REQUEST	0x7	/* Command Abort Requested */
#define	NVME_CQE_SC_GEN_ABORT_SQ_DEL	0x8	/* Cmd Aborted / SQ deletion */
#define	NVME_CQE_SC_GEN_ABORT_FUSE_FAIL	0x9	/* Cmd Aborted / Failed Fused */
#define	NVME_CQE_SC_GEN_ABORT_FUSE_MISS	0xa	/* Cmd Aborted / Missing Fusd */
#define	NVME_CQE_SC_GEN_INV_NS		0xb	/* Inval Namespace or Format */
#define	NVME_CQE_SC_GEN_CMD_SEQ_ERR	0xc	/* Command Sequence Error */
#define	NVME_CQE_SC_GEN_INV_SGL_LAST	0xd	/* Inval SGL Last Seg Desc */
#define	NVME_CQE_SC_GEN_INV_SGL_NUM	0xe	/* Inval Number of SGL Desc */
#define	NVME_CQE_SC_GEN_INV_DSGL_LEN	0xf	/* Data SGL Length Invalid */
#define	NVME_CQE_SC_GEN_INV_MSGL_LEN	0x10	/* Metadata SGL Length Inval */
#define	NVME_CQE_SC_GEN_INV_SGL_DESC	0x11	/* SGL Descriptor Type Inval */

/* NVMe completion status code (generic NVM commands) */
#define	NVME_CQE_SC_GEN_NVM_LBA_RANGE	0x80	/* LBA Out Of Range */
#define	NVME_CQE_SC_GEN_NVM_CAP_EXC	0x81	/* Capacity Exceeded */
#define	NVME_CQE_SC_GEN_NVM_NS_NOTRDY	0x82	/* Namespace Not Ready */
#define	NVME_CQE_SC_GEN_NVM_RSV_CNFLCT	0x83	/* Reservation Conflict */

/* NVMe completion status code (command specific) */
#define	NVME_CQE_SC_SPC_INV_CQ		0x0	/* Completion Queue Invalid */
#define	NVME_CQE_SC_SPC_INV_QID		0x1	/* Invalid Queue Identifier */
#define	NVME_CQE_SC_SPC_MAX_QSZ_EXC	0x2	/* Max Queue Size Exceeded */
#define	NVME_CQE_SC_SPC_ABRT_CMD_EXC	0x3	/* Abort Cmd Limit Exceeded */
#define	NVME_CQE_SC_SPC_ASYNC_EVREQ_EXC	0x5	/* Async Event Request Limit */
#define	NVME_CQE_SC_SPC_INV_FW_SLOT	0x6	/* Invalid Firmware Slot */
#define	NVME_CQE_SC_SPC_INV_FW_IMG	0x7	/* Invalid Firmware Image */
#define	NVME_CQE_SC_SPC_INV_INT_VECT	0x8	/* Invalid Interrupt Vector */
#define	NVME_CQE_SC_SPC_INV_LOG_PAGE	0x9	/* Invalid Log Page */
#define	NVME_CQE_SC_SPC_INV_FORMAT	0xa	/* Invalid Format */
#define	NVME_CQE_SC_SPC_FW_RESET	0xb	/* FW Application Reset Reqd */
#define	NVME_CQE_SC_SPC_INV_Q_DEL	0xc	/* Invalid Queue Deletion */
#define	NVME_CQE_SC_SPC_FEAT_SAVE	0xd	/* Feature Id Not Saveable */
#define	NVME_CQE_SC_SPC_FEAT_CHG	0xe	/* Feature Not Changeable */
#define	NVME_CQE_SC_SPC_FEAT_NS_SPEC	0xf	/* Feature Not Namespace Spec */
#define	NVME_CQE_SC_SPC_FW_NSSR		0x10	/* FW Application NSSR Reqd */

/* NVMe completion status code (NVM command specific */
#define	NVME_CQE_SC_SPC_NVM_CNFL_ATTR	0x80	/* Conflicting Attributes */
#define	NVME_CQE_SC_SPC_NVM_INV_PROT	0x81	/* Invalid Protection */
#define	NVME_CQE_SC_SPC_NVM_READONLY	0x82	/* Write to Read Only Range */

/* NVMe completion status code (data / metadata integrity) */
#define	NVME_CQE_SC_INT_NVM_WRITE	0x80	/* Write Fault */
#define	NVME_CQE_SC_INT_NVM_READ	0x81	/* Unrecovered Read Error */
#define	NVME_CQE_SC_INT_NVM_GUARD	0x82	/* Guard Check Error */
#define	NVME_CQE_SC_INT_NVM_APPL_TAG	0x83	/* Application Tag Check Err */
#define	NVME_CQE_SC_INT_NVM_REF_TAG	0x84	/* Reference Tag Check Err */
#define	NVME_CQE_SC_INT_NVM_COMPARE	0x85	/* Compare Failure */
#define	NVME_CQE_SC_INT_NVM_ACCESS	0x86	/* Access Denied */

/*
 * NVMe Asynchronous Event Request
 */
#define	NVME_ASYNC_TYPE_ERROR		0x0	/* Error Status */
#define	NVME_ASYNC_TYPE_HEALTH		0x1	/* SMART/Health Status */
#define	NVME_ASYNC_TYPE_VENDOR		0x7	/* vendor specific */

#define	NVME_ASYNC_ERROR_INV_SQ		0x0	/* Invalid Submission Queue */
#define	NVME_ASYNC_ERROR_INV_DBL	0x1	/* Invalid Doorbell Write */
#define	NVME_ASYNC_ERROR_DIAGFAIL	0x2	/* Diagnostic Failure */
#define	NVME_ASYNC_ERROR_PERSISTENT	0x3	/* Persistent Internal Error */
#define	NVME_ASYNC_ERROR_TRANSIENT	0x4	/* Transient Internal Error */
#define	NVME_ASYNC_ERROR_FW_LOAD	0x5	/* Firmware Image Load Error */

#define	NVME_ASYNC_HEALTH_RELIABILITY	0x0	/* Device Reliability */
#define	NVME_ASYNC_HEALTH_TEMPERATURE	0x1	/* Temp. Above Threshold */
#define	NVME_ASYNC_HEALTH_SPARE		0x2	/* Spare Below Threshold */

typedef union {
	struct {
		uint8_t ae_type:3;		/* Asynchronous Event Type */
		uint8_t ae_rsvd1:5;
		uint8_t ae_info;		/* Asynchronous Event Info */
		uint8_t ae_logpage;		/* Associated Log Page */
		uint8_t ae_rsvd2;
	} b;
	uint32_t r;
} nvme_async_event_t;

/*
 * NVMe Create Completion/Submission Queue
 */
typedef union {
	struct {
		uint16_t q_qid;			/* Queue Identifier */
		uint16_t q_qsize; 		/* Queue Size */
	} b;
	uint32_t r;
} nvme_create_queue_dw10_t;

typedef union {
	struct {
		uint16_t cq_pc:1;		/* Physically Contiguous */
		uint16_t cq_ien:1;		/* Interrupts Enabled */
		uint16_t cq_rsvd:14;
		uint16_t cq_iv;			/* Interrupt Vector */
	} b;
	uint32_t r;
} nvme_create_cq_dw11_t;

typedef union {
	struct {
		uint16_t sq_pc:1;		/* Physically Contiguous */
		uint16_t sq_qprio:2;		/* Queue Priority */
		uint16_t sq_rsvd:13;
		uint16_t sq_cqid;		/* Completion Queue ID */
	} b;
	uint32_t r;
} nvme_create_sq_dw11_t;

/*
 * NVMe Identify
 */

/* NVMe Identify parameters (cdw10) */
#define	NVME_IDENTIFY_NSID	0x0	/* Identify Namespace */
#define	NVME_IDENTIFY_CTRL	0x1	/* Identify Controller */
#define	NVME_IDENTIFY_LIST	0x2	/* Identify List Namespaces */


/*
 * NVMe Abort Command
 */
typedef union {
	struct {
		uint16_t ac_sqid;	/* Submission Queue ID */
		uint16_t ac_cid;	/* Command ID */
	} b;
	uint32_t r;
} nvme_abort_cmd_t;


/*
 * NVMe Get Log Page
 */
typedef union {
	struct {
		uint8_t lp_lid;		/* Log Page Identifier */
		uint8_t lp_rsvd1;
		uint16_t lp_numd:12;	/* Number of Dwords */
		uint16_t lp_rsvd2:4;
	} b;
	uint32_t r;
} nvme_getlogpage_t;


#ifdef __cplusplus
}
#endif

#pragma pack() /* pack(1) */

#endif /* _NVME_REG_H */
