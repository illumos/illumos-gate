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

#ifndef	_DAPL_TAVOR_HW_H
#define	_DAPL_TAVOR_HW_H

/*
 * dapl_tavor_hw.h
 *    Contains all the structure definitions and #defines for all Tavor
 *    hardware resources and registers.
 *    Most of these definitions have been replicated from the tavor_hw.h
 *    header file used by the tavor device driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"
#include "dapl_tavor_ibtf.h"


/*
 * Ownership flags used to define hardware or software ownership for
 * various Tavor resources
 */
#define	TAVOR_HW_OWNER			0x1U
#define	TAVOR_SW_OWNER			0x0

/*
 * Tavor Completion Queue Entries (CQE)
 *    Each CQE contains enough information for the software to associate the
 *    completion with the Work Queue Element (WQE) to which it corresponds.
 *
 *    Note: The following structure is not #define'd with both little-endian
 *    and big-endian definitions.  This is because each CQE's individual
 *    fields are not directly accessed except through the macros defined below.
 */

/*
 * The following defines are used for Tavor CQ error handling.  Note: For
 * CQEs which correspond to error events, the Tavor device requires some
 * special handling by software.  These defines are used to identify and
 * extract the necessary information from each error CQE, including status
 * code (above), doorbell count, and whether a error completion is for a
 * send or receive work request.
 */
#define	TAVOR_CQE_ERR_STATUS_SHIFT	24
#define	TAVOR_CQE_ERR_STATUS_MASK	0xFF
#define	TAVOR_CQE_ERR_DBDCNT_MASK	0xFFFF
#define	TAVOR_CQE_SEND_ERR_OPCODE	0xFF
#define	TAVOR_CQE_RECV_ERR_OPCODE	0xFE
#define	TAVOR_CQ_SYNC_AND_DB		0
#define	TAVOR_CQ_RECYCLE_ENTRY		1

/*
 * These are the defines for the Tavor CQ entry types.  They are also
 * specified by the Tavor register specification.  They indicate what type
 * of work request is completing (for successful completions).  Note: The
 * "SND" or "RCV" in each define is used to indicate whether the completion
 * work request was from the Send work queue or the Receive work queue on
 * the associated QP.
 */
#define	TAVOR_CQE_SND_RDMAWR		0x8
#define	TAVOR_CQE_SND_RDMAWR_IMM	0x9
#define	TAVOR_CQE_SND_SEND		0xA
#define	TAVOR_CQE_SND_SEND_IMM		0xB
#define	TAVOR_CQE_SND_RDMARD		0x10
#define	TAVOR_CQE_SND_ATOMIC_CS		0x11
#define	TAVOR_CQE_SND_ATOMIC_FA		0x12
#define	TAVOR_CQE_SND_BIND_MW		0x18
#define	TAVOR_CQE_RCV_RECV_IMM		0x3
#define	TAVOR_CQE_RCV_RECV_IMM2		0x5
#define	TAVOR_CQE_RCV_RECV		0x2
#define	TAVOR_CQE_RCV_RECV2		0x4
#define	TAVOR_CQE_RCV_RDMAWR_IMM	0x9
#define	TAVOR_CQE_RCV_RDMAWR_IMM2	0xB

/*
 * These are the defines for the Tavor CQ completion statuses.  They are
 * specified by the Tavor register specification.
 */
#define	TAVOR_CQE_SUCCESS		0x0
#define	TAVOR_CQE_LOC_LEN_ERR		0x1
#define	TAVOR_CQE_LOC_OP_ERR		0x2
#define	TAVOR_CQE_LOC_EEC_ERR		0x3	/* unsupported: RD */
#define	TAVOR_CQE_LOC_PROT_ERR		0x4
#define	TAVOR_CQE_WR_FLUSHED_ERR	0x5
#define	TAVOR_CQE_MW_BIND_ERR		0x6
#define	TAVOR_CQE_BAD_RESPONSE_ERR	0x10
#define	TAVOR_CQE_LOCAL_ACCESS_ERR	0x11
#define	TAVOR_CQE_REM_INV_REQ_ERR	0x12
#define	TAVOR_CQE_REM_ACC_ERR		0x13
#define	TAVOR_CQE_REM_OP_ERR		0x14
#define	TAVOR_CQE_TRANS_TO_ERR		0x15
#define	TAVOR_CQE_RNRNAK_TO_ERR		0x16
#define	TAVOR_CQE_LOCAL_RDD_VIO_ERR	0x20	/* unsupported: RD */
#define	TAVOR_CQE_REM_INV_RD_REQ_ERR	0x21	/* unsupported: RD */
#define	TAVOR_CQE_EEC_REM_ABORTED_ERR	0x22	/* unsupported: RD */
#define	TAVOR_CQE_INV_EEC_NUM_ERR	0x23	/* unsupported: RD */
#define	TAVOR_CQE_INV_EEC_STATE_ERR	0x24	/* unsupported: RD */

typedef struct tavor_hw_cqe_s {
	uint32_t	ver		:4;
	uint32_t			:4;
	uint32_t	my_qpn		:24;
	uint32_t			:8;
	uint32_t	my_ee		:24;
	uint32_t			:8;
	uint32_t	rqpn		:24;
	uint32_t	sl		:4;
	uint32_t			:4;
	uint32_t	grh		:1;
	uint32_t	ml_path		:7;
	uint32_t	rlid		:16;
	uint32_t	imm_eth_pkey_cred;
	uint32_t	byte_cnt;
	uint32_t	wqe_addr	:26;
	uint32_t	wqe_sz		:6;
	uint32_t	opcode		:8;
	uint32_t	send_or_recv	:1;
	uint32_t			:15;
	uint32_t	owner		:1;
	uint32_t	status		:7;
} tavor_hw_cqe_t;
#define	TAVOR_COMPLETION_RECV		0x0
#define	TAVOR_COMPLETION_SEND		0x1

#define	TAVOR_CQE_DEFAULT_VERSION	0x0

/*
 * The following macros are used for extracting (and in some cases filling in)
 * information from CQEs
 */
#define	TAVOR_CQE_QPNUM_MASK		0x00FFFFFF
#define	TAVOR_CQE_QPNUM_SHIFT		0
#define	TAVOR_CQE_DQPN_MASK		0x00FFFFFF
#define	TAVOR_CQE_DQPN_SHIFT		0
#define	TAVOR_CQE_SL_MASK		0xF0000000
#define	TAVOR_CQE_SL_SHIFT		28
#define	TAVOR_CQE_GRH_MASK		0x00800000
#define	TAVOR_CQE_GRH_SHIFT		23
#define	TAVOR_CQE_PATHBITS_MASK		0x007F0000
#define	TAVOR_CQE_PATHBITS_SHIFT	16
#define	TAVOR_CQE_DLID_MASK		0x0000FFFF
#define	TAVOR_CQE_DLID_SHIFT		0
#define	TAVOR_CQE_OPCODE_MASK		0xFF000000
#define	TAVOR_CQE_OPCODE_SHIFT		24
#define	TAVOR_CQE_SENDRECV_MASK		0x00800000
#define	TAVOR_CQE_SENDRECV_SHIFT	23
#define	TAVOR_CQE_OWNER_MASK		0x00000080
#define	TAVOR_CQE_OWNER_SHIFT		7

#define	TAVOR_CQE_QPNUM_GET(cqe)					\
	((BETOH_32(((uint32_t *)(cqe))[0]) & TAVOR_CQE_QPNUM_MASK) >>	\
	    TAVOR_CQE_QPNUM_SHIFT)
#define	TAVOR_CQE_DQPN_GET(cqe)						\
	((BETOH_32(((uint32_t *)(cqe))[2]) & TAVOR_CQE_DQPN_MASK) >>	\
	    TAVOR_CQE_DQPN_SHIFT)
#define	TAVOR_CQE_SL_GET(cqe)						\
	((BETOH_32(((uint32_t *)(cqe))[3]) & TAVOR_CQE_SL_MASK) >>	\
	    TAVOR_CQE_SL_SHIFT)
#define	TAVOR_CQE_GRH_GET(cqe)						\
	((BETOH_32(((uint32_t *)(cqe))[3]) & TAVOR_CQE_GRH_MASK) >>	\
	    TAVOR_CQE_GRH_SHIFT)
#define	TAVOR_CQE_PATHBITS_GET(cqe)					\
	((BETOH_32(((uint32_t *)(cqe))[3]) & TAVOR_CQE_PATHBITS_MASK) >>\
	    TAVOR_CQE_PATHBITS_SHIFT)
#define	TAVOR_CQE_DLID_GET(cqe)						\
	((BETOH_32(((uint32_t *)(cqe))[3]) & TAVOR_CQE_DLID_MASK) >>	\
	    TAVOR_CQE_DLID_SHIFT)
#define	TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cqe)				\
	(BETOH_32(((uint32_t *)(cqe))[4]))
#define	TAVOR_CQE_IMM_ETH_PKEY_CRED_SET(cqe, arg)			\
	(((uint32_t *)(cqe))[4] = HTOBE_32((arg)))
#define	TAVOR_CQE_BYTECNT_GET(cqe)					\
	(BETOH_32(((uint32_t *)(cqe))[5]))
#define	TAVOR_CQE_WQEADDRSZ_GET(cqe)					\
	(BETOH_32(((uint32_t *)(cqe))[6]))
#define	TAVOR_CQE_WQEADDRSZ_SET(cqe, arg)				\
	(((uint32_t *)(cqe))[6] = HTOBE_32((arg)))
#define	TAVOR_CQE_OPCODE_GET(cqe)					\
	((BETOH_32(((uint32_t *)(cqe))[7]) & TAVOR_CQE_OPCODE_MASK) >>	\
	    TAVOR_CQE_OPCODE_SHIFT)
#define	TAVOR_CQE_SENDRECV_GET(cqe)					\
	((BETOH_32(((uint32_t *)(cqe))[7]) & TAVOR_CQE_SENDRECV_MASK) >>\
	    TAVOR_CQE_SENDRECV_SHIFT)
#define	TAVOR_CQE_OWNER_IS_SW(cqe)					\
	(((BETOH_32(((uint32_t *)(cqe))[7]) & TAVOR_CQE_OWNER_MASK) >>	\
	    TAVOR_CQE_OWNER_SHIFT) == TAVOR_SW_OWNER)
#define	TAVOR_CQE_OWNER_SET_HW(cqe)					\
	(((uint32_t *)(cqe))[7] =					\
	    BETOH_32((TAVOR_HW_OWNER << TAVOR_CQE_OWNER_SHIFT) &	\
	    TAVOR_CQE_OWNER_MASK))

/*
 * Tavor User Access Region (UAR)
 *    Tavor doorbells are each rung by writing to the doorbell registers that
 *    form a User Access Region (UAR).  A doorbell is a write-only hardware
 *    register which enables passing information from software to hardware
 *    with minimum software latency. A write operation from the host software
 *    to these doorbell registers passes information about the HCA resources
 *    and initiates processing of the doorbell data.  There are 6 types of
 *    doorbells in Tavor.
 *
 *    "Send Doorbell" for synchronizing the attachment of a WQE (or a chain
 *        of WQEs) to the send queue.
 *    "RD Send Doorbell" (Same as above, except for RD QPs) is not supported.
 *    "Receive Doorbell" for synchronizing the attachment of a WQE (or a chain
 *        of WQEs) to the receive queue.
 *    "CQ Doorbell" for updating the CQ consumer index and requesting
 *        completion notifications.
 *    "EQ Doorbell" for updating the EQ consumer index, arming interrupt
 *        triggering, and disarming CQ notification requests.
 *    "InfiniBlast" (which would have enabled access to the "InfiniBlast
 *        buffer") is not supported.
 *
 *    Note: The tavor_hw_uar_t below is the container for all of the various
 *    doorbell types.  Below we first define several structures which make up
 *    the contents of those doorbell types.
 *
 *    Note also: The following structures are not #define'd with both little-
 *    endian and big-endian definitions.  This is because each doorbell type
 *    is not directly accessed except through a single ddi_put64() operation
 *    (see tavor_qp_send_doorbell, tavor_qp_recv_doorbell, tavor_cq_doorbell,
 *    or tavor_eq_doorbell)
 */
typedef struct tavor_hw_uar_send_s {
	uint32_t	nda		:26;
	uint32_t	fence		:1;
	uint32_t	nopcode		:5;
	uint32_t	qpn		:24;
	uint32_t			:2;
	uint32_t	nds		:6;
} tavor_hw_uar_send_t;
#define	TAVOR_QPSNDDB_NDA_MASK		0xFFFFFFC0
#define	TAVOR_QPSNDDB_NDA_SHIFT		0x20
#define	TAVOR_QPSNDDB_F_SHIFT		0x25
#define	TAVOR_QPSNDDB_NOPCODE_SHIFT	0x20
#define	TAVOR_QPSNDDB_QPN_SHIFT		0x8

typedef struct tavor_hw_uar_recv_s {
	uint32_t	nda		:26;
	uint32_t	nds		:6;
	uint32_t	qpn		:24;
	uint32_t	credits		:8;
} tavor_hw_uar_recv_t;
#define	TAVOR_QPRCVDB_NDA_MASK		0xFFFFFFC0
#define	TAVOR_QPRCVDB_NDA_SHIFT		0x20
#define	TAVOR_QPRCVDB_NDS_SHIFT		0x20
#define	TAVOR_QPRCVDB_QPN_SHIFT		0x8
/* Max descriptors per Tavor doorbell */
#define	TAVOR_QP_MAXDESC_PER_DB		256

typedef struct tavor_hw_uar_cq_s {
	uint32_t	cmd		:8;
	uint32_t	cqn		:24;
	uint32_t	param;
} tavor_hw_uar_cq_t;
#define	TAVOR_CQDB_CMD_SHIFT		0x38
#define	TAVOR_CQDB_CQN_SHIFT		0x20

#define	TAVOR_CQDB_INCR_CONSINDX	0x01
#define	TAVOR_CQDB_NOTIFY_CQ		0x02
#define	TAVOR_CQDB_NOTIFY_CQ_SOLICIT	0x03
#define	TAVOR_CQDB_SET_CONSINDX		0x04
#define	TAVOR_CQDB_NOTIFY_NCQ		0x05
/* Default value for use in NOTIFY_CQ doorbell */
#define	TAVOR_CQDB_DEFAULT_PARAM	0xFFFFFFFF

typedef struct tavor_hw_uar_eq_s {
	uint32_t	cmd		:8;
	uint32_t			:18;
	uint32_t	eqn		:6;
	uint32_t	param;
} tavor_hw_uar_eq_t;

typedef struct tavor_hw_uar_s {
	uint32_t		rsrv0[4];	/* "RD Send" unsupported */
	uint64_t		send;		/* tavor_hw_uar_send_t */
	uint64_t		recv;		/* tavor_hw_uar_recv_t */
	uint64_t		cq;		/* tavor_hw_uar_cq_t   */
	uint64_t		eq;		/* tavor_hw_uar_eq_t   */
	uint32_t		rsrv1[244];
	uint32_t		iblast[256];	/* "InfiniBlast" unsupported */
} tavor_hw_uar_t;

typedef struct tavor_hw_uar32_s {
	uint32_t		rsrv0[4];	/* "RD Send" unsupported */
	uint32_t		send[2];	/* tavor_hw_uar_send_t */
	uint32_t		recv[2];	/* tavor_hw_uar_recv_t */
	uint32_t		cq[2];		/* tavor_hw_uar_cq_t   */
	uint32_t		eq[2];		/* tavor_hw_uar_eq_t   */
	uint32_t		rsrv1[244];
	uint32_t		iblast[256];	/* "InfiniBlast" unsupported */
} tavor_hw_uar32_t;


/*
 * Tavor Send Work Queue Element (WQE)
 *    A Tavor Send WQE is built of the following segments, each of which is a
 *    multiple of 16 bytes.  Note: Each individual WQE may contain only a
 *    subset of these segments described below (according to the operation type
 *    and transport type of the QP).
 *
 *    The first 16 bytes of ever WQE are formed from the "Next/Ctrl" segment.
 *    This segment contains the address of the next WQE to be executed and the
 *    information required in order to allocate the resources to execute the
 *    next WQE.  The "Ctrl" part of this segment contains the control
 *    information required to execute the WQE, including the opcode and other
 *    control information.
 *    The "Datagram" segment contains address information required in order to
 *    form a UD message.
 *    The "Bind" segment contains the parameters required for a Bind Memory
 *    Window operation.
 *    The "Remote Address" segment is present only in RDMA or Atomic WQEs and
 *    specifies remote virtual addresses and RKey, respectively.  Length of
 *    the remote access is calculated from the scatter/gather list (for
 *    RDMA-write/RDMA-read) or set to eight (for Atomic).
 *    The "Atomic" segment is present only in Atomic WQEs and specifies
 *    Swap/Add and Compare data.
 *
 *    Note: The following structures are not #define'd with both little-endian
 *    and big-endian definitions.  This is because their individual fields are
 *    not directly accessed except through macros defined below.
 */
typedef struct tavor_hw_snd_wqe_nextctrl_s {
	uint32_t	next_wqe_addr	:26;
	uint32_t			:1;
	uint32_t	nopcode		:5;
	uint32_t	next_eec	:24;
	uint32_t	dbd		:1;
	uint32_t	fence		:1;
	uint32_t	nds		:6;

	uint32_t			:28;
	uint32_t	c		:1;
	uint32_t	e		:1;
	uint32_t	s		:1;
	uint32_t	i		:1;
	uint32_t	immediate	:32;
} tavor_hw_snd_wqe_nextctrl_t;

#define	TAVOR_WQE_NDA_MASK		0x00000000FFFFFFC0
#define	TAVOR_WQE_NDS_MASK		0x3F
#define	TAVOR_WQE_DBD_MASK		0x80

#define	TAVOR_WQE_SEND_FENCE_MASK	0x40
#define	TAVOR_WQE_SEND_NOPCODE_RDMAW	0x8
#define	TAVOR_WQE_SEND_NOPCODE_RDMAWI	0x9
#define	TAVOR_WQE_SEND_NOPCODE_SEND	0xA
#define	TAVOR_WQE_SEND_NOPCODE_SENDI	0xB
#define	TAVOR_WQE_SEND_NOPCODE_RDMAR	0x10
#define	TAVOR_WQE_SEND_NOPCODE_ATMCS	0x11
#define	TAVOR_WQE_SEND_NOPCODE_ATMFA	0x12
#define	TAVOR_WQE_SEND_NOPCODE_BIND	0x18

#define	TAVOR_WQE_SEND_SIGNALED_MASK	0x800000000ULL
#define	TAVOR_WQE_SEND_EVENT_MASK	0x400000000ULL
#define	TAVOR_WQE_SEND_SOLICIT_MASK	0x200000000ULL
#define	TAVOR_WQE_SEND_IMMEDIATE_MASK	0x100000000ULL

#define	TAVOR_WQE_SENDHDR_UD_AV_MASK	0xFFFFFFFFFFFFFFE0
#define	TAVOR_WQE_SENDHDR_UD_DQPN_MASK	0xFFFFFF

typedef struct tavor_hw_snd_wqe_bind_s {
	uint32_t	ae		:1;
	uint32_t	rw		:1;
	uint32_t	rr		:1;
	uint32_t			:29;
	uint32_t			:32;
	uint32_t	new_rkey;
	uint32_t	reg_lkey;
	uint64_t	addr;
	uint64_t	len;
} tavor_hw_snd_wqe_bind_t;
#define	TAVOR_WQE_SENDHDR_BIND_ATOM	0x8000000000000000ULL
#define	TAVOR_WQE_SENDHDR_BIND_WR	0x4000000000000000ULL
#define	TAVOR_WQE_SENDHDR_BIND_RD	0x2000000000000000ULL

typedef struct tavor_hw_snd_wqe_remaddr_s {
	uint64_t	vaddr;
	uint32_t	rkey;
	uint32_t			:32;
} tavor_hw_snd_wqe_remaddr_t;

/*
 * Tavor Receive Work Queue Element (WQE)
 *    Like the Send WQE, the Receive WQE is built of 16-byte segments. The
 *    segment is the "Next/Ctrl" segment (defined below).  It is followed by
 *    some number of scatter list entries for the incoming message.
 *
 *    The format of the scatter-gather list entries is also shown below.  For
 *    Receive WQEs the "inline_data" field must be cleared (i.e. data segments
 *    cannot contain inline data).
 */
typedef struct tavor_hw_rcv_wqe_nextctrl_s {
	uint32_t	next_wqe_addr	:26;
	uint32_t			:5;
	uint32_t	one		:1;
	uint32_t			:24;
	uint32_t	dbd		:1;
	uint32_t			:1;
	uint32_t	nds		:6;

	uint32_t			:28;
	uint32_t	c		:1;
	uint32_t	e		:1;
	uint32_t			:2;
	uint32_t			:32;
} tavor_hw_rcv_wqe_nextctrl_t;

/*
 * This bit must be set in the next/ctrl field of all Receive WQEs
 * as a workaround to a Tavor hardware erratum related to having
 * the first 32-bits in the WQE set to zero.
 */
#define	TAVOR_RCV_WQE_NDA0_WA_MASK	0x0000000100000000ULL
#define	TAVOR_WQE_RCV_SIGNALED_MASK	0x800000000ULL
#define	TAVOR_WQE_RCV_EVENT_MASK	0x400000000ULL

typedef struct tavor_hw_wqe_sgl_s {
	uint32_t	inline_data	:1;
	uint32_t	byte_cnt	:31;
	uint32_t	lkey;
	uint64_t	addr;
} tavor_hw_wqe_sgl_t;
#define	TAVOR_WQE_SGL_BYTE_CNT_MASK	0x7FFFFFFF
#define	TAVOR_WQE_SGL_INLINE_MASK	0x80000000
/*
 * The tavor_sw_wqe_dbinfo_t structure is used internally by the Tavor
 * driver to return information (from the tavor_wqe_mlx_build_nextctl() and
 * tavor_wqe_send_build_nextctl() routines) regarding the type of Tavor
 * doorbell necessary.
 */
typedef struct tavor_sw_wqe_dbinfo_s {
	uint_t  db_nopcode;
	uint_t  db_fence;
} tavor_sw_wqe_dbinfo_t;


/*
 * The following macros are used for building each of the individual
 * segments that can make up a Tavor WQE.  Note: We try not to use the
 * structures (with their associated bitfields) here, instead opting to
 * build and put 64-bit or 32-bit chunks to the WQEs as appropriate,
 * primarily because using the bitfields appears to force more read-modify-
 * write operations.
 *
 *    TAVOR_WQE_BUILD_REMADDR		- Builds Remote Address Segment using
 *					    RDMA info from the work request
 *    TAVOR_WQE_BUILD_BIND		- Builds the Bind Memory Window
 *					    Segment using bind info from the
 *					    work request
 *    TAVOR_WQE_LINKNEXT		- Links the current WQE to the
 *					    previous one
 *    TAVOR_WQE_LINKFIRST		- Links the first WQE on the current
 *					    chain to the previous WQE
 */

#define	TAVOR_WQE_BUILD_REMADDR(ra,  wr_rdma)				\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ra);					\
	tmp[0] = HTOBE_64((wr_rdma)->rdma_raddr);			\
	tmp[1] = HTOBE_64((uint64_t)(wr_rdma)->rdma_rkey << 32);	\
}
#define	TAVOR_WQE_BUILD_BIND(bn, wr_bind)				\
{									\
	uint64_t		*tmp;					\
	uint64_t		bn0_tmp;				\
	ibt_bind_flags_t	bind_flags;				\
									\
	tmp	   = (uint64_t *)(bn);					\
	bind_flags = (wr_bind)->bind_flags;				\
	bn0_tmp	   = (bind_flags & IBT_WR_BIND_ATOMIC) ?		\
	    TAVOR_WQE_SENDHDR_BIND_ATOM : 0;				\
	bn0_tmp	  |= (bind_flags & IBT_WR_BIND_WRITE) ?			\
	    TAVOR_WQE_SENDHDR_BIND_WR : 0;				\
	bn0_tmp	  |= (bind_flags & IBT_WR_BIND_READ) ?			\
	    TAVOR_WQE_SENDHDR_BIND_RD : 0;				\
	tmp[0] = HTOBE_64(bn0_tmp);					\
	tmp[1] = HTOBE_64(((uint64_t)(wr_bind)->bind_rkey_out << 32) |	\
			(wr_bind)->bind_lkey);				\
	tmp[2] = HTOBE_64((wr_bind)->bind_va);				\
	tmp[3] = HTOBE_64((wr_bind)->bind_len);				\
}

#define	TAVOR_WQE_BUILD_DATA_SEG(ds, sgl)				\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ds);					\
	tmp[0]	= HTOBE_64(((uint64_t)((sgl)->ds_len &			\
		TAVOR_WQE_SGL_BYTE_CNT_MASK) << 32) | (sgl)->ds_key);	\
	tmp[1]	= HTOBE_64((sgl)->ds_va);				\
}

#define	TAVOR_WQE_LINKNEXT(prev, ctrl, next)				\
{									\
	((uint64_t *)(prev))[1] = HTOBE_64((ctrl));			\
	((uint64_t *)(prev))[0] = HTOBE_64((next));			\
}

#define	TAVOR_WQE_LINKFIRST(prev, next)					\
{									\
	((uint64_t *)(prev))[0] = HTOBE_64((next));			\
}

/*
 * The following macro is used to convert WQE address and size into the
 * "wqeaddrsz" value needed in the tavor_wrid_entry_t (see below).
 */
#define	TAVOR_QP_WQEADDRSZ(addr, size)                                  \
	((((uintptr_t)(addr)) & ~TAVOR_WQE_NDS_MASK) |                   \
	((size) & TAVOR_WQE_NDS_MASK))

/*
 * The following macros are used to calculate pointers to the Send or Receive
 * WQEs on a given QP, respectively
 */
#define	TAVOR_QP_SQ_ENTRY(qp, tail)                                     \
	((uint64_t *)((uintptr_t)((qp)->qp_sq_buf) +			\
	((tail) * (qp)->qp_sq_wqesz)))
#define	TAVOR_QP_SQ_DESC(qp, tail)					\
	((uint32_t)((qp)->qp_sq_desc_addr +				\
	((tail) * (qp)->qp_sq_wqesz)))
#define	TAVOR_QP_RQ_ENTRY(qp, tail)                                     \
	((uint64_t *)((uintptr_t)((qp)->qp_rq_buf) +		 	\
	((tail) * (qp)->qp_rq_wqesz)))
#define	TAVOR_QP_RQ_DESC(qp, tail)					\
	((uint32_t)((qp)->qp_rq_desc_addr +				\
	((tail) * (qp)->qp_rq_wqesz)))
#define	TAVOR_SRQ_RQ_ENTRY(srq, tail)					\
	((uint64_t *)((uintptr_t)((srq)->srq_wq_buf) +		 	\
	((tail) * (srq)->srq_wq_wqesz)))
#define	TAVOR_SRQ_RQ_DESC(srq, tail)					\
	((uint32_t)((srq)->srq_wq_desc_addr +				\
	((tail) * (srq)->srq_wq_wqesz)))
#define	TAVOR_SRQ_WQ_INDEX(srq_wq_desc_addr, desc_addr, wqesz)		\
	((uint32_t)(((desc_addr) - (srq_wq_desc_addr)) / (wqesz)))
#define	TAVOR_SRQ_WQ_ENTRY(srq, index)					\
	((uint64_t *)(((uintptr_t)(srq)->srq_addr) +			\
	((index) * (srq)->srq_wq_wqesz)))

/*
 * Maximum header before the data bytes when inlining data.
 * "Header" includes the link (nextctrl) struct, a remote address struct
 * (only for RDMA Write, not for Send) and the 32-bit byte count field.
 */
#define	TAVOR_INLINE_HEADER_SIZE_MAX	0x40	/* from tavor driver */
#define	TAVOR_INLINE_HEADER_SIZE_RDMAW	\
	(sizeof (tavor_hw_snd_wqe_nextctrl_t) + \
	sizeof (tavor_hw_snd_wqe_remaddr_t) + \
	sizeof (uint32_t))
#define	TAVOR_INLINE_HEADER_SIZE_SEND \
	(sizeof (tavor_hw_snd_wqe_nextctrl_t) + \
	sizeof (uint32_t))

/*
 * Function signatures
 */
extern int dapls_tavor_max_inline(void);

#ifdef __cplusplus
}
#endif

#endif	/* _DAPL_TAVOR_HW_H */
