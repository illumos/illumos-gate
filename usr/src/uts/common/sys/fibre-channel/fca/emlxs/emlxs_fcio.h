/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_FCIO_H
#define	_EMLXS_FCIO_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * FCIO_REV: 1 - Initial implementation 2 - Added EMLXS_GET_FCIO_REV support
 */
#define	FCIO_REV	2


/* Emulex ULP Diag Codes */
#define	EMLXS_DIAG			('E'<< 8)

#define	EMLXS_DIAG_BIU			(EMLXS_DIAG | 100)
#define	EMLXS_DIAG_POST			(EMLXS_DIAG | 101)
#define	EMLXS_DIAG_ECHO			(EMLXS_DIAG | 102)

#define	EMLXS_PARM_GET_NUM		(EMLXS_DIAG | 200)
#define	EMLXS_PARM_GET_LIST		(EMLXS_DIAG | 201)
#define	EMLXS_PARM_GET			(EMLXS_DIAG | 202)
#define	EMLXS_PARM_SET			(EMLXS_DIAG | 203)
#define	EMLXS_GET_BOOT_REV		(EMLXS_DIAG | 204)
#define	EMLXS_DOWNLOAD_BOOT		(EMLXS_DIAG | 205)
#define	EMLXS_DOWNLOAD_CFL		(EMLXS_DIAG | 206)
#define	EMLXS_VPD_GET   		(EMLXS_DIAG | 207)
#define	EMLXS_GET_FCIO_REV   		(EMLXS_DIAG | 208)
#define	EMLXS_SET_BOOT_STATE_old	(EMLXS_DIAG | 209)
#define	EMLXS_GET_BOOT_STATE_old	(EMLXS_DIAG | 210)
#define	EMLXS_DFC_COMMAND		(EMLXS_DIAG | 211)
#define	EMLXS_SET_BOOT_STATE		(EMLXS_DIAG | 212)
#define	EMLXS_GET_BOOT_STATE		(EMLXS_DIAG | 213)
#define	EMLXS_GET_DFC_REV		(EMLXS_DIAG | 214)
#define	EMLXS_PHY_GET			(EMLXS_DIAG | 215)
#define	EMLXS_SET_THROTTLE		(EMLXS_DIAG | 216)
#define	EMLXS_GET_THROTTLE		(EMLXS_DIAG | 217)
#define	EMLXS_VPD_GET_V2   		(EMLXS_DIAG | 218)

#define	EMLXS_BAR_IO			(EMLXS_DIAG | 253)
#define	EMLXS_TEST_CODE   		(EMLXS_DIAG | 254)
#define	EMLXS_HW_ERROR_TEST   		(EMLXS_DIAG | 255)
#define	EMLXS_MB_TIMEOUT_TEST		(EMLXS_DIAG | 256)

#define	EMLXS_LOG_GET			(EMLXS_DIAG | 300)


/* DUMP file ids */
#define	EMLXS_TXT_FILE_ID			1
#define	EMLXS_DMP_FILE_ID			2
#define	EMLXS_CEE_FILE_ID			3
#define	EMLXS_FAT_FILE_ID			4


/* Emulex specific error codes */
#define	EMLXS_ERRNO_START		0x100
#define	EMLXS_TEST_FAILED		(EMLXS_ERRNO_START + 0)	/* Diagnostic */
								/* test fail */
#define	EMLXS_IMAGE_BAD			(EMLXS_ERRNO_START + 1)	/* Image has */
								/* bad data */
#define	EMLXS_IMAGE_INCOMPATIBLE	(EMLXS_ERRNO_START + 2)	/* Image not */
								/* compatible */
								/* with H/W */
#define	EMLXS_IMAGE_FAILED		(EMLXS_ERRNO_START + 3)	/* Image */
								/* download */
								/* failed */
#define	EMLXS_OFFLINE_FAILED		(EMLXS_ERRNO_START + 4)	/* Unable to */
								/* take HBA */
								/* offline */
#define	EMLXS_NO_BOOT_CODE		(EMLXS_ERRNO_START + 5)	/* No boot */
								/* code image */
#define	EMLXS_OP_NOT_SUP		(EMLXS_ERRNO_START + 6)	/* Operation */
								/* not supp */
#define	EMLXS_REBOOT_REQUIRED		(EMLXS_ERRNO_START + 7)	/* Reboot */
								/* required */
#define	EMLXS_ERRNO_END			(EMLXS_ERRNO_START + 7)


typedef struct emlxs_parm
{
	char		label[32];
	uint32_t	min;
	uint32_t	max;
	uint32_t	def;
	uint32_t	current;
	uint32_t	flags;
	char		help[128];
} emlxs_parm_t;

/* emlxs_parm_t flags */
#define	PARM_DYNAMIC	0x00000001	/* Reboot not required */
#define	PARM_BOOLEAN	0x00000002
#define	PARM_HEX	0x00000004

/* PARM_DYNAMIC subtypes */
#define	PARM_DYNAMIC_RESET	(PARM_DYNAMIC | 0x00000010)	/* Hard reset */
								/* required */
#define	PARM_DYNAMIC_LINK	(PARM_DYNAMIC | 0x00000020)	/* Link reset */
								/* required */

typedef struct emlxs_vpd_desc
{
	char	id[80];
	char	part_num[32];
	char	eng_change[32];
	char	manufacturer[80];
	char	serial_num[32];
	char	model[32];
	char	model_desc[80];
	char	port_num[4];
	char	prog_types[80];
} emlxs_vpd_desc_t;

typedef struct emlxs_vpd_desc_v2
{
	char	id[256];
	char	part_num[256];
	char	eng_change[256];
	char	manufacturer[256];
	char	serial_num[256];
	char	model[256];
	char	model_desc[256];
	char	port_num[256];
	char	prog_types[256];
} emlxs_vpd_desc_v2_t;

typedef struct emlxs_phy_desc
{
	uint32_t phy_type;
	uint32_t interface_type;
	uint32_t misc_params;
	uint32_t rsvd[4];

} emlxs_phy_desc_t;

typedef struct emlxs_throttle_desc
{
	uint8_t wwpn[8];
	uint32_t throttle;

} emlxs_throttle_desc_t;

typedef struct emlxs_log_req
{
	uint32_t	first;	/* First msg id requested */
	uint32_t	count;	/* Maximum number of messages */
				/* capable of receiving */
				/* This value can be set to zero */
				/* to receive just log stats */
} emlxs_log_req_t;


typedef struct emlxs_log_resp
{
	uint32_t	first;	/* Actual starting msg id in resp buffer */
				/* This represents the first available */
				/* msg id >= first id requested */
	uint32_t	last;	/* Current last msg id in log file */
	uint32_t	count;	/* Total number of messages in resp buffer */
				/* This value will be <= the max count */
				/* requested */

				/* If count > 0, then the response buffer */
				/* will immediately follow this structure */
				/* The response buffer will be an array of */
				/* string buffers MAX_MSG_LENGTH in size */
#define	MAX_LOG_MSG_LENGTH	160
} emlxs_log_resp_t;

typedef struct FCIO_EQ_DESC
{
	uint32_t	host_index;
	uint32_t	max_index;
	uint32_t	qid;
	uint32_t	msix_vector;

	uint32_t	phys;	/* specifies physical buffer pointer */
	uint32_t	virt;	/* specifies virtual buffer pointer */
	uint32_t	virt_hi; /* specifies virtual buffer pointer */

	/* Statistics */
	uint32_t	max_proc;
	uint32_t	isr_count;
	uint32_t	num_proc;
} FCIO_EQ_DESC_t;


typedef struct FCIO_CQ_DESC
{
	uint32_t	host_index;
	uint32_t	max_index;
	uint32_t	qid;
	uint32_t	eqid;
	uint32_t	type;

	uint32_t	phys;	/* specifies physical buffer pointer */
	uint32_t	virt;	/* specifies virtual buffer pointer */
	uint32_t	virt_hi; /* specifies virtual buffer pointer */

	/* Statistics */
	uint32_t	max_proc;
	uint32_t	isr_count;
	uint32_t	num_proc;
	uint32_t	rsvd;
} FCIO_CQ_DESC_t;


typedef struct FCIO_WQ_DESC
{
	uint32_t	host_index;
	uint32_t	max_index;
	uint32_t	port_index;
	uint32_t	release_depth;
	uint32_t	qid;
	uint32_t	cqid;

	uint32_t	phys;	/* specifies physical buffer pointer */
	uint32_t	virt;	/* specifies virtual buffer pointer */
	uint32_t	virt_hi; /* specifies virtual buffer pointer */

	/* Statistics */
	uint32_t	num_proc;
	uint32_t	num_busy;
	uint32_t	rsvd;
} FCIO_WQ_DESC_t;


typedef struct FCIO_RQ_DESC
{
	uint32_t	host_index;
	uint32_t	max_index;
	uint32_t	qid;
	uint32_t	cqid;

	uint32_t	phys;	/* specifies physical buffer pointer */
	uint32_t	virt;	/* specifies virtual buffer pointer */
	uint32_t	virt_hi; /* specifies virtual buffer pointer */

	/* Statistics */
	uint32_t	num_proc;
} FCIO_RQ_DESC_t;


#define	FCIO_MSI_MAX_INTRS	8
#define	FCIO_MAX_WQS_PER_EQ	4
#define	FCIO_MAX_EQS	FCIO_MSI_MAX_INTRS
#define	FCIO_MAX_WQS	FCIO_MAX_WQS_PER_EQ * FCIO_MAX_EQS
#define	FCIO_MAX_RQS	2	/* ONLY 1 pair is allowed */

/* One CQ for each WQ & (RQ pair) plus one for the MQ */
#define	FCIO_MAX_CQS	(FCIO_MAX_WQS + (FCIO_MAX_RQS/2) + 1)

typedef struct FCIO_Q_STAT
{
	FCIO_EQ_DESC_t	eq[FCIO_MAX_EQS];
	FCIO_CQ_DESC_t	cq[FCIO_MAX_CQS];
	FCIO_WQ_DESC_t	wq[FCIO_MAX_WQS];
	FCIO_RQ_DESC_t	rq[FCIO_MAX_RQS];
	uint32_t	que_start_timer;
	uint32_t	que_current_timer;
	uint32_t	intr_count;
} FCIO_Q_STAT_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_FCIO_H */
