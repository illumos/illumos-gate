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

#ifndef	_SYS_IB_ADAPTERS_TAVOR_CMD_H
#define	_SYS_IB_ADAPTERS_TAVOR_CMD_H

/*
 * tavor_cmd.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Tavor Firmware Command routines.
 *    Specifically it contains the command types, command statuses and flags,
 *    structures used for managing Tavor mailboxes and outstanding commands,
 *    and prototypes for most of the functions consumed by other parts of
 *    the Tavor driver.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/mgt/sm_attr.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Defines used tavor_write_hcr() to determine the duration and number of
 * times (at maximum) to poll while waiting for a Tavor firmware command to
 * release the HCR resource (i.e. waiting for the command to complete)
 */
#define	TAVOR_CMD_POLL_DELAY		1
#define	TAVOR_CMD_POLL_MAX		3000000

/*
 * The following defines specify the default number of mailboxes (log 2) of
 * each type and their size and alignment restrictions.  By default the number
 * of both "In" and "Out" mailboxes is set to eight (with each mailbox being
 * 512 bytes in size), but both the number and sizes of each are controllable
 * through the "tavor_log_num_inmbox", "tavor_log_num_outmbox",
 * "tavor_log_inmbox_size" and "tavor_log_outmbox_size" configuration
 * variables.
 */
#define	TAVOR_NUM_MAILBOXES_SHIFT	8
#define	TAVOR_NUM_INTR_MAILBOXES_SHIFT	0
#define	TAVOR_MBOX_SIZE_SHIFT		0x9
#define	TAVOR_MBOX_SIZE			(1 << TAVOR_MBOX_SIZE_SHIFT)
#define	TAVOR_MBOX_ALIGN		TAVOR_MBOX_SIZE

/*
 * The following macro determines whether the contents of given mailbox
 * type need to be sync'd (with ddi_dma_sync()).  This decision is based
 * on whether the mailbox is in DDR memory (no sync) or system memory
 * (sync required).  And it also supports the possibility that if a CQ in
 * system memory is mapped DDI_DMA_CONSISTENT, it can be configured to not be
 * sync'd because of the "sync override" parameter in the config profile.
 */
#define	TAVOR_MBOX_IS_SYNC_REQ(state, type)				\
	((((((state)->ts_cfg_profile->cp_streaming_consistent) &&	\
	((state)->ts_cfg_profile->cp_consistent_syncoverride))) ||      \
	((&((state)->ts_rsrc_hdl[(type)]))->rsrc_loc == TAVOR_IN_DDR))	\
	? 0 : 1)

/*
 * These are the defines for the Tavor command type (opcodes).  They are
 * specified by the Tavor register specification
 */
#define	SYS_EN				0x1
#define	SYS_DIS				0x2
#define	QUERY_DEV_LIM			0x3
#define	QUERY_FW			0x4
#define	QUERY_DDR			0x5
#define	QUERY_ADAPTER			0x6
#define	INIT_HCA			0x7
#define	CLOSE_HCA			0x8
#define	INIT_IB				0x9
#define	CLOSE_IB			0xA
#define	QUERY_HCA			0xB
#define	SET_IB				0xC
#define	ACCESS_DDR			0x2E
#define	SW2HW_MPT			0xD
#define	QUERY_MPT			0xE
#define	HW2SW_MPT			0xF
#define	READ_MTT			0x10
#define	WRITE_MTT			0x11
#define	SYNC_TPT			0x2F
#define	MAP_EQ				0x12
#define	SW2HW_EQ			0x13
#define	HW2SW_EQ			0x14
#define	QUERY_EQ			0x15
#define	SW2HW_CQ			0x16
#define	HW2SW_CQ			0x17
#define	QUERY_CQ			0x18
#define	RESIZE_CQ			0x2C
#define	RST2INIT_QP			0x19
#define	INIT2INIT_QP			0x2D
#define	INIT2RTR_QP			0x1A
#define	RTR2RTS_QP			0x1B
#define	RTS2RTS_QP			0x1C
#define	SQERR2RTS_QP			0x1D
#define	TOERR_QP			0x1E
#define	RTS2SQD_QP			0x1F
#define	SQD2RTS_QP			0x20
#define	TORST_QP			0x21
#define	QUERY_QP			0x22
#define	CONF_SPECIAL_QP			0x23
#define	MAD_IFC				0x24
#define	READ_MGM			0x25
#define	WRITE_MGM			0x26
#define	MGID_HASH			0x27
#define	CONF_NTU			0x28
#define	QUERY_NTU			0x29
#define	QUERY_DEBUG_MSG			0x2A
#define	SET_DEBUG_MSG			0x2B
#define	DIAG_RPRT			0x30
#define	MOD_STAT_CFG			0x34
#define	SW2HW_SRQ			0x35
#define	HW2SW_SRQ			0x36
#define	QUERY_SRQ			0x37
#define	SQD2SQD_QP			0x38
#define	MODIFY_MPT			0x39

/*
 * These are the defines for the Tavor command completion statuses.  They are
 * also specified (in part) by the Tavor register specification.  However,
 * the TAVOR_CMD_INSUFF_RSRC, TAVOR_CMD_TIMEOUT and TAVOR_CMD_INVALID_STATUS
 * codes were added for this driver specifically to indicate the conditions
 * when insufficient resources are available for a command, when a command has
 * timed out (failure in the Tavor firmware) or when some other invalid result
 * was received.
 */
#define	TAVOR_CMD_INSUFF_RSRC		0xFFFD
#define	TAVOR_CMD_TIMEOUT		0xFFFE
#define	TAVOR_CMD_INVALID_STATUS	0xFFFF
#define	TAVOR_CMD_SUCCESS		0x00
#define	TAVOR_CMD_INTERNAL_ERR		0x01
#define	TAVOR_CMD_BAD_OP		0x02
#define	TAVOR_CMD_BAD_PARAM		0x03
#define	TAVOR_CMD_BAD_SYS_STATE		0x04
#define	TAVOR_CMD_BAD_RESOURCE		0x05
#define	TAVOR_CMD_RESOURCE_BUSY		0x06
#define	TAVOR_CMD_DDR_MEM_ERR		0x07
#define	TAVOR_CMD_EXCEED_LIM		0x08
#define	TAVOR_CMD_BAD_RES_STATE		0x09
#define	TAVOR_CMD_BAD_INDEX		0x0A
#define	TAVOR_CMD_BAD_NVMEM		0x0B
#define	TAVOR_CMD_BAD_QP_STATE		0x10
#define	TAVOR_CMD_BAD_SEG_PARAM		0x20
#define	TAVOR_CMD_REG_BOUND		0x21
#define	TAVOR_CMD_BAD_PKT		0x30
#define	TAVOR_CMD_BAD_SIZE		0x40

/*
 * These defines are used in the "special QP" allocation to indicate the type
 * of special QP (SMI, GSI, or one of the raw types).  These values are
 * specified by the Tavor register specification
 */
#define	TAVOR_CMD_QP_SMI		0
#define	TAVOR_CMD_QP_GSI		1
#define	TAVOR_CMD_QP_RAW_IPV6		2
#define	TAVOR_CMD_QP_RAW_ETH		3

/*
 * For certain Tavor QP state transition commands some optional flags are
 * allowed.  These "opmask" flags are defined by the Tavor register
 * specification as a bitmask.
 */
#define	TAVOR_CMD_OP_ALT_PATH		(1 << 0)
#define	TAVOR_CMD_OP_RRE		(1 << 1)
#define	TAVOR_CMD_OP_RAE		(1 << 2)
#define	TAVOR_CMD_OP_RWE		(1 << 3)
#define	TAVOR_CMD_OP_PKEYINDX		(1 << 4)
#define	TAVOR_CMD_OP_QKEY		(1 << 5)
#define	TAVOR_CMD_OP_MINRNRNAK		(1 << 6)
#define	TAVOR_CMD_OP_PRIM_PATH		(1 << 7)
#define	TAVOR_CMD_OP_SRA_SET		(1 << 8)
#define	TAVOR_CMD_OP_RRA_SET		(1 << 9)
#define	TAVOR_CMD_OP_PM_STATE		(1 << 10)
#define	TAVOR_CMD_OP_PRIM_PORT		(1 << 11)
#define	TAVOR_CMD_OP_RETRYCNT		(1 << 12)
#define	TAVOR_CMD_OP_ALT_RNRRETRY	(1 << 13)
#define	TAVOR_CMD_OP_ACKTIMEOUT		(1 << 14)
#define	TAVOR_CMD_OP_PRIM_RNRRETRY	(1 << 15)
#define	TAVOR_CMD_OP_SCHEDQUEUE		(1 << 16)


/*
 * The Tavor RTS2SQD command can take the following flag as part of its
 * input modifier to request the Send Queue Drained event
 */
#define	TAVOR_CMD_REQ_SQD_EVENT		0x80000000

/*
 * The Tavor TORST command can take the following flag (as part of a bitmask)
 * in its opcode modifier to request that the transition to reset should
 * not go through the Error state (and, hence, should not generate "flushed-
 * in-error" completions
 */
#define	TAVOR_CMD_DIRECT_TO_RESET	(1 << 1)

/*
 * Some Tavor commands write an OUT mailbox entry, depending on the value of
 * the 'opmod' parameter.  These defines provide the correct opmod value to
 * write depending on whether to write an entry or not.
 */
#define	TAVOR_CMD_DO_OUTMBOX		(0)
#define	TAVOR_CMD_NO_OUTMBOX		(1 << 0)

/*
 * The Tavor SYS_EN command can take the following opcode modifier options
 * to specify whether certain DDR checks should be performed.
 */
#define	TAVOR_CMD_SYS_EN_NORMAL		0
#define	TAVOR_CMD_SYS_EN_DDR_MEMCHECK	2
#define	TAVOR_CMD_SYS_EN_DDR_PRESERVE	3

/*
 * The Tavor MAP_EQ command can take the following flags (and use the
 * TAVOR_CMD_UNMAP_EQ_MASK input modifier) to indicate whether the given
 * event queue should mapped to or unmapped from the given event type.
 */
#define	TAVOR_CMD_MAP_EQ_EVT_MAP	0
#define	TAVOR_CMD_MAP_EQ_EVT_UNMAP	1
#define	TAVOR_CMD_UNMAP_EQ_MASK		0x80000000

/*
 * The following defines are used by the MAD_IFC command and the helper
 * routines that get PortInfo, NodeInfo, GUIDInfo, and PKeyTable entries.
 *
 * The first indicates whether of not MKey checking should be enforced.
 * This is passed in the opcode modifier field for MAD_IFC commands.
 *
 * The next set are used to define certain hardcoded management datagram (MAD)
 * sizes, offsets, and header formats for each of the helper operations.
 */
#define	TAVOR_CMD_MKEY_CHECK		0
#define	TAVOR_CMD_MKEY_DONTCHECK	1
#define	TAVOR_CMD_BKEY_DONTCHECK	2

#define	TAVOR_CMD_MAD_IFC_SIZE		0x100
#define	TAVOR_CMD_MADDATA_OFFSET	0x40
#define	TAVOR_CMD_MADHDR0		0x01010101
#define	TAVOR_CMD_MADHDR1		0x00000000
#define	TAVOR_CMD_MADHDR2		0x00000000
#define	TAVOR_CMD_MADHDR3		0x00000000
#define	TAVOR_CMD_PORTINFO		0x00150000
#define	TAVOR_CMD_NODEINFO		0x00110000
#define	TAVOR_CMD_NODEDESC		0x00100000
#define	TAVOR_CMD_GUIDINFO		0x00140000
#define	TAVOR_CMD_PKEYTBLE		0x00160000

#define	TAVOR_CMD_PERF_GET		0x01040101
#define	TAVOR_CMD_PERF_SET		0x01040102
#define	TAVOR_CMD_PERFCNTRS		0x00120000
#define	TAVOR_CMD_PERFATTR		0x00000000

/*
 * The next few defines are used to indicate the size of the "reserved" area
 * in the WRITE_MTT command, and the respective sizes of the SET_IB and
 * MGID_HASH commands
 */
#define	TAVOR_CMD_WRITEMTT_RSVD_SZ	0x10
#define	TAVOR_CMD_SETIB_SZ		0x8
#define	TAVOR_CMD_MGIDHASH_SZ		0x10

/*
 * This last define is used by tavor_cmn_ownership_cmd_post() to keep track
 * of the direction (from hardware ownership to software, or vice versa) of
 * the requested operation
 */
#define	TAVOR_CMD_RSRC_HW2SW		0
#define	TAVOR_CMD_RSRC_SW2HW		1

/*
 * The following macros are used for handling any endianness related issues
 * that might arise from the Tavor driver's internal use of MADs.
 *
 *    TAVOR_GETPORTINFO_SWAP	- All the necessary swapping to handle the
 *				    response to a GetPortInfo MAD
 *    TAVOR_GETNODEINFO_SWAP	- All the necessary swapping to handle the
 *				    response to a GetNodeInfo MAD
 *    TAVOR_GETGUIDINFO_SWAP	- All the necessary swapping to handle the
 *				    response to a GetGUIDInfo MAD
 *    TAVOR_GETPKEYTABLE_SWAP	- All the necessary swapping to handle the
 *				    response to a GetPKeyTable MAD
 */
#ifdef	_LITTLE_ENDIAN
#define	TAVOR_GETPORTINFO_SWAP(portinfo)				\
{									\
	(portinfo)->M_Key = ddi_swap64((portinfo)->M_Key);		\
	(portinfo)->GidPrefix = ddi_swap64((portinfo)->GidPrefix);	\
	(portinfo)->LID = ddi_swap16((portinfo)->LID);			\
	(portinfo)->MasterSMLID = ddi_swap16((portinfo)->MasterSMLID);	\
	(portinfo)->CapabilityMask =					\
	    ddi_swap32((portinfo)->CapabilityMask);			\
	(portinfo)->DiagCode = ddi_swap16((portinfo)->DiagCode);	\
	(portinfo)->M_KeyLeasePeriod =					\
	    ddi_swap16((portinfo)->M_KeyLeasePeriod);			\
	(portinfo)->M_KeyViolations =					\
	    ddi_swap16((portinfo)->M_KeyViolations);			\
	(portinfo)->P_KeyViolations =					\
	    ddi_swap16((portinfo)->P_KeyViolations);			\
	(portinfo)->Q_KeyViolations =					\
	    ddi_swap16((portinfo)->Q_KeyViolations);			\
}
#else
#define	TAVOR_GETPORTINFO_SWAP(portinfo)
#endif

#ifdef	_LITTLE_ENDIAN
#define	TAVOR_GETNODEINFO_SWAP(nodeinfo)				\
{									\
	uint32_t	tmp;						\
									\
	tmp = ddi_swap32(((uint32_t *)nodeinfo)[9]);			\
	(nodeinfo)->VendorID	 = tmp & 0xFFFFFF;			\
	(nodeinfo)->LocalPortNum = tmp >> 24;				\
	(nodeinfo)->Revision	 =					\
	    ddi_swap32(((uint32_t *)nodeinfo)[8]);			\
	tmp = ddi_swap32(((uint32_t *)nodeinfo)[7]);			\
	(nodeinfo)->PartitionCap = tmp >> 16;				\
	(nodeinfo)->DeviceID	 = tmp & 0xFFFF;			\
	(nodeinfo)->PortGUID = ddi_swap64((((uint64_t)			\
	    (((uint32_t *)nodeinfo)[6]) << 32) |			\
	    ((uint32_t *)nodeinfo)[5]));				\
	(nodeinfo)->NodeGUID = ddi_swap64((((uint64_t)			\
	    (((uint32_t *)nodeinfo)[4]) << 32) |			\
	    ((uint32_t *)nodeinfo)[3]));				\
	(nodeinfo)->SystemImageGUID = ddi_swap64((((uint64_t)		\
	    (((uint32_t *)nodeinfo)[2]) << 32) |			\
	    ((uint32_t *)nodeinfo)[1]));				\
}
#else
#define	TAVOR_GETNODEINFO_SWAP(nodeinfo)				\
{									\
	uint32_t	tmp;						\
									\
	tmp = ((uint32_t *)nodeinfo)[9];				\
	(nodeinfo)->VendorID	 = tmp & 0xFFFFFF;			\
	(nodeinfo)->LocalPortNum = tmp >> 24;				\
	(nodeinfo)->Revision	 = ((uint32_t *)nodeinfo)[8];		\
	tmp = ((uint32_t *)nodeinfo)[7];				\
	(nodeinfo)->PartitionCap = tmp >> 16;				\
	(nodeinfo)->DeviceID	 = tmp & 0xFFFF;			\
	(nodeinfo)->PortGUID = (((uint64_t)				\
	    (((uint32_t *)nodeinfo)[5]) << 32) |			\
	    ((uint32_t *)nodeinfo)[6]);					\
	(nodeinfo)->NodeGUID = (((uint64_t)				\
	    (((uint32_t *)nodeinfo)[3]) << 32) |			\
	    ((uint32_t *)nodeinfo)[4]);					\
	(nodeinfo)->SystemImageGUID = (((uint64_t)			\
	    (((uint32_t *)nodeinfo)[1]) << 32) |			\
	    ((uint32_t *)nodeinfo)[2]);					\
}
#endif

#ifdef	_LITTLE_ENDIAN
#define	TAVOR_GETGUIDINFO_SWAP(guidinfo)				\
{									\
	int	i;							\
									\
	for (i = 0; i < 8; i++) {					\
		(guidinfo)->GUIDBlocks[i] =				\
		    ddi_swap64((guidinfo)->GUIDBlocks[i]);		\
	}								\
}
#else
#define	TAVOR_GETGUIDINFO_SWAP(guidinfo)
#endif

#ifdef	_LITTLE_ENDIAN
#define	TAVOR_GETPKEYTABLE_SWAP(pkeytable)				\
{									\
	int	i;							\
									\
	for (i = 0; i < 32; i++) {					\
		(pkeytable)->P_KeyTableBlocks[i] =			\
		    ddi_swap16((pkeytable)->P_KeyTableBlocks[i]);	\
	}								\
}
#else
#define	TAVOR_GETPKEYTABLE_SWAP(pkeytable)
#endif

/*
 * The Tavor MODIFY_MPT command can take the following opcode modifier
 * options to specify whether to modify for ResizeSRQ() or to swap the
 * full MPT entry.
 */
#define	TAVOR_CMD_MODIFY_MPT_RESIZESRQ	3
#define	TAVOR_CMD_MODIFY_MPT_SWAPFULL	5


/*
 * The tavor_mbox_t structure is used internally by the Tavor driver to track
 * all the information necessary to manage mailboxes for the Tavor command
 * interface.  Specifically, by containing a pointer to the buffer, the
 * PCI mapped address, the access handle, and a back pointer to the
 * tavor_rsrc_t structure used to track this resource, it provides enough
 * information allocate, use, and free any type of mailbox.
 *
 * The mb_indx, mb_next, and mb_prev fields are used only by the mailbox
 * alloc/free routines (see tavor_impl_mbox_alloc/free() for more details)
 * and are not read or modified by any mailbox consumers.  They are used
 * to implement a fast allocation mechanism.
 */
typedef struct tavor_mbox_s {
	void			*mb_addr;
	uint64_t		mb_mapaddr;
	ddi_acc_handle_t	mb_acchdl;
	tavor_rsrc_t		*mb_rsrcptr;
	uint_t			mb_sync;
	uint_t			mb_indx;
	uint_t			mb_next;
	uint_t			mb_prev;
} tavor_mbox_t;

/*
 * The tavor_mboxlist_t structure is used to track all the information
 * relevant to the pools of Tavor mailboxes.  Specifically, it has a pointer
 * to an array of tavor_mbox_t structures, a lock and cv used for blocking
 * on alloc when mailboxes are not available, and a head, tail, and entries
 * free counter to keep track of which (if any) mailboxes are currently free.
 * This is used (along with the mb_indx, mb_next, and mb_prev fields in the
 * tavor_mbox_t) to implement the fast allocation mechanism.
 */
typedef struct tavor_mboxlist_s {
	kmutex_t		mbl_lock;
	kcondvar_t		mbl_cv;
	tavor_mbox_t		*mbl_mbox;
	uint_t			mbl_list_sz;
	uint_t			mbl_num_alloc;
	uint_t			mbl_head_indx;
	uint_t			mbl_tail_indx;
	uint_t			mbl_entries_free;
	uint_t			mbl_waiters;
	uint_t			mbl_pollers;
	uint_t			mbl_signal;
} tavor_mboxlist_t;
_NOTE(MUTEX_PROTECTS_DATA(tavor_mboxlist_t::mbl_lock,
    tavor_mboxlist_t::mbl_mbox
    tavor_mboxlist_t::mbl_list_sz
    tavor_mboxlist_t::mbl_num_alloc
    tavor_mboxlist_t::mbl_cv
    tavor_mboxlist_t::mbl_head_indx
    tavor_mboxlist_t::mbl_tail_indx
    tavor_mboxlist_t::mbl_entries_free
    tavor_mboxlist_t::mbl_waiters
    tavor_mboxlist_t::mbl_pollers
    tavor_mboxlist_t::mbl_signal
    tavor_mbox_t::mb_next
    tavor_mbox_t::mb_prev))

/*
 * The tavor_mbox_info_t structure is used by mailbox allocators to specify
 * the type of mailbox(es) being requested.  On a call to tavor_mbox_alloc()
 * the mbi_alloc_flags may be set to TAVOR_ALLOC_INMBOX, TAVOR_ALLOC_OUTMBOX,
 * or both.  If it is able to allocate the request type(s) of mailboxes,
 * tavor_mbox_alloc() will fill in the "mbi_in" and/or "mbi_out" pointers
 * to point to valid tavor_mbox_t structures from the appropriate
 * tavor_mboxlist_t (see above).
 * This same structure is also passed to tavor_mbox_free().  It is the
 * responsibility of the caller to tavor_mbox_alloc() to return this exact
 * structure (unmodified) to tavor_mbox_free().
 *
 * Note: If both "In" and "Out" mailboxes are requested, it is assured that
 * no deadlock can result (from holding one mailbox while attempting to get
 * the other).  This is assured by the fact that the "In" mailbox will always
 * be allocated first before attempting to allocate the "Out"
 */
typedef struct tavor_mbox_info_s {
	uint_t			mbi_alloc_flags;
	uint_t			mbi_sleep_context;
	tavor_mbox_t		*mbi_in;
	tavor_mbox_t		*mbi_out;
} tavor_mbox_info_t;
#define	TAVOR_ALLOC_INMBOX	(1 << 0)
#define	TAVOR_ALLOC_OUTMBOX	(1 << 1)


/*
 * The tavor_cmd_t structure is used internally by the Tavor driver to track
 * all the information necessary to manage outstanding firmware commands on
 * the Tavor command interface.
 *
 * Each tavor_cmd_t structure contains a cv and lock which are used by the
 * posting thread to block for completion (with cmd_status being overloaded
 * to indicate the condition variable).  The cmd_outparam field is used to
 * return additional status from those Tavor commands that specifically
 * require it.
 *
 * The cmd_indx, cmd_next, and cmd_prev fields are used by the outstanding
 * command alloc/free routines (see tavor_outstanding_cmd_alloc/free() for
 * more details).  They are used (in much the same way as the mb_indx,
 * mb_next, and mb_prev fields in tavor_mbox_t above) to implement a fast
 * allocation mechanism.
 */
typedef struct tavor_cmd_s {
	kmutex_t		cmd_comp_lock;
	kcondvar_t		cmd_comp_cv;
	uint64_t		cmd_outparm;
	uint_t			cmd_status;
	uint_t			cmd_indx;
	uint_t			cmd_next;
	uint_t			cmd_prev;
} tavor_cmd_t;
_NOTE(MUTEX_PROTECTS_DATA(tavor_cmd_t::cmd_comp_lock,
    tavor_cmd_t::cmd_comp_cv
    tavor_cmd_t::cmd_status))

/*
 * The tavor_cmdlist_t structure is used in almost exactly the same way as
 * the tavor_mboxlist_t above, but instead to track all the information
 * relevant to the pool of outstanding Tavor commands.  Specifically, it has
 * a pointer to an array of tavor_cmd_t structures, a lock and cv used for
 * blocking on alloc when outstanding command slots are not available, and a
 * head, tail, and entries free counter to keep track of which (if any)
 * command slots are currently free.  This is used (along with the cmd_indx,
 * cmd_next, and cmd_prev fields in the tavor_cmd_t) to implement the fast
 * allocation mechanism.
 */
typedef struct tavor_cmdlist_s {
	kmutex_t		cml_lock;
	kcondvar_t		cml_cv;
	tavor_cmd_t		*cml_cmd;
	uint_t			cml_list_sz;
	uint_t			cml_num_alloc;
	uint_t			cml_head_indx;
	uint_t			cml_tail_indx;
	uint_t			cml_entries_free;
	uint_t			cml_waiters;
} tavor_cmdlist_t;
_NOTE(MUTEX_PROTECTS_DATA(tavor_cmdlist_t::cml_lock,
    tavor_cmdlist_t::cml_cv
    tavor_cmdlist_t::cml_cmd
    tavor_cmdlist_t::cml_list_sz
    tavor_cmdlist_t::cml_num_alloc
    tavor_cmdlist_t::cml_head_indx
    tavor_cmdlist_t::cml_tail_indx
    tavor_cmdlist_t::cml_entries_free
    tavor_cmdlist_t::cml_waiters
    tavor_cmd_t::cmd_next
    tavor_cmd_t::cmd_prev))
_NOTE(LOCK_ORDER(tavor_cmdlist_t::cml_lock
    tavor_cmd_t::cmd_comp_lock))

/*
 * The tavor_cmd_post_t structure is used by all the Tavor Firmware Command
 * routines to post to Tavor firmware.  The fields almost exactly mimic
 * the fields in the Tavor HCR registers.  The notable exception is the
 * addition of the "cp_flags" field (which can be set to TAVOR_CMD_SPIN or
 * TAVOR_CMD_NOSPIN).  This flag really controls the value of the "e" bit
 * in the HCR (i.e. the bit to indicate whether command should complete
 * "in place" - in the HCR - or whether they should have their completions
 * written to the command completion event queue.  TAVOR_CMD_SPIN means
 * to allow commands to complete "in place" and to poll the "go" bit in
 * the HCR to determine completion.
 *
 * We use TAVOR_SLEEP and TAVOR_NOSLEEP for our TAVOR_CMD_ #defines.  This is
 * to maintain consistency with the rest of the SLEEP flags.  Additionally,
 * because TAVOR_SLEEPFLAG_FOR_CONTEXT() in tavor_rsrc.h returns TAVOR_SLEEP or
 * NOSLEEP we must be compatible with this macro.
 */
typedef struct tavor_cmd_post_s {
	uint64_t		cp_inparm;
	uint64_t		cp_outparm;
	uint32_t		cp_inmod;
	uint16_t		cp_opcode;
	uint16_t		cp_opmod;
	uint32_t		cp_flags;
} tavor_cmd_post_t;
#define	TAVOR_CMD_SLEEP_NOSPIN		TAVOR_SLEEP
#define	TAVOR_CMD_NOSLEEP_SPIN		TAVOR_NOSLEEP


/*
 * The following are the Tavor Firmware Command routines that accessible
 * externally (i.e. throughout the rest of the Tavor driver software).
 * These include the all the alloc/free routines, some initialization
 * and cleanup routines, and the various specific Tavor firmware commands.
 */
int tavor_cmd_post(tavor_state_t *state, tavor_cmd_post_t *cmdpost);
int tavor_mbox_alloc(tavor_state_t *state, tavor_mbox_info_t *mbox_info,
    uint_t mbox_wait);
void tavor_mbox_free(tavor_state_t *state, tavor_mbox_info_t *mbox_info);
int tavor_cmd_complete_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe);
int tavor_inmbox_list_init(tavor_state_t *state);
int tavor_intr_inmbox_list_init(tavor_state_t *state);
int tavor_outmbox_list_init(tavor_state_t *state);
int tavor_intr_outmbox_list_init(tavor_state_t *state);
void tavor_inmbox_list_fini(tavor_state_t *state);
void tavor_intr_inmbox_list_fini(tavor_state_t *state);
void tavor_outmbox_list_fini(tavor_state_t *state);
void tavor_intr_outmbox_list_fini(tavor_state_t *state);
int tavor_outstanding_cmdlist_init(tavor_state_t *state);
void tavor_outstanding_cmdlist_fini(tavor_state_t *state);

/*
 * SYS_EN and SYS_DIS - used for startup and shutdown of Tavor device
 */
int tavor_sys_en_cmd_post(tavor_state_t *state, uint_t flags,
    uint64_t *errorcode, uint_t sleepflag);
int tavor_sys_dis_cmd_post(tavor_state_t *state, uint_t sleepflag);

/*
 * INIT_HCA and CLOSE_HCA - used for initialization and teardown of Tavor
 * device configuration
 */
int tavor_init_hca_cmd_post(tavor_state_t *state,
    tavor_hw_initqueryhca_t *inithca, uint_t sleepflag);
int tavor_close_hca_cmd_post(tavor_state_t *state, uint_t sleepflag);

/*
 * INIT_IB, CLOSE_IB, and SET_IB - used for bring Tavor ports up and down,
 * and to set properties of each port (e.g. PortInfo capability mask)
 */
int tavor_init_ib_cmd_post(tavor_state_t *state,
    tavor_hw_initib_t *initib, uint_t port, uint_t sleepflag);
int tavor_close_ib_cmd_post(tavor_state_t *state, uint_t port,
    uint_t sleepflag);
int tavor_set_ib_cmd_post(tavor_state_t *state, uint32_t capmask,
    uint_t port, uint_t reset_qkey, uint_t sleepflag);

/*
 * This common function is used to post the following Tavor QP state
 * transition firmware commands:
 * RTS2SQD, TOERR, TORST, RST2INIT, INIT2INIT, INIT2RTR, RTR2RTS, RTS2RTS,
 * SQD2SQD, SQD2RTS, and SQERR2RTS.
 */
int tavor_cmn_qp_cmd_post(tavor_state_t *state, uint_t opcode,
    tavor_hw_qpc_t *qp, uint_t qpindx, uint32_t opmask, uint_t sleepflag);

/*
 * This common function is used to post the following Tavor query firmware
 * commands:
 * QUERY_DEV_LIM, QUERY_FW, QUERY_DDR, QUERY_ADAPTER, QUERY_HCA, QUERY_MPT,
 * QUERY_EQ, QUERY_CQ, and QUERY_QP.
 */
int tavor_cmn_query_cmd_post(tavor_state_t *state, uint_t opcode,
    uint_t queryindx, void *query, uint_t size, uint_t sleepflag);

/*
 * This common function is used to post the following Tavor resource ownership
 * firmware commands:
 * HW2SW_MPT, HW2SW_EQ, HW2SW_CQ, SW2HW_MPT, SW2HW_EQ, and SW2HW_CQ
 */
int tavor_cmn_ownership_cmd_post(tavor_state_t *state, uint_t opcode,
    void *hwrsrc, uint_t size, uint_t hwrsrcindx, uint_t sleepflag);

/*
 * MAD_IFC and helper functions - used for posting IB MADs to Tavor firmware.
 * The helper functions are for the MADs most frequently used by the Tavor
 * driver (internally).
 */
int tavor_mad_ifc_cmd_post(tavor_state_t *state, uint_t port,
    uint_t sleepflag, uint32_t *mad, uint32_t *resp);
int tavor_getportinfo_cmd_post(tavor_state_t *state, uint_t port,
    uint_t sleepflag, sm_portinfo_t *portinfo);
int tavor_getnodeinfo_cmd_post(tavor_state_t *state, uint_t sleepflag,
    sm_nodeinfo_t *nodeinfo);
int tavor_getnodedesc_cmd_post(tavor_state_t *state, uint_t sleepflag,
    sm_nodedesc_t *nodedesc);
int tavor_getguidinfo_cmd_post(tavor_state_t *state, uint_t port,
    uint_t guidblock, uint_t sleepflag, sm_guidinfo_t *guidinfo);
int tavor_getpkeytable_cmd_post(tavor_state_t *state, uint_t port,
    uint_t pkeyblock, uint_t sleepflag, sm_pkey_table_t *pkeytable);
int tavor_getperfcntr_cmd_post(tavor_state_t *state, uint_t port,
    uint_t sleepflag, tavor_hw_sm_perfcntr_t *perfinfo, int reset);

/*
 * WRITE_MTT - used for write MTT entries to the Tavor MTT table
 */
int tavor_write_mtt_cmd_post(tavor_state_t *state,
    tavor_mbox_info_t *mbox_info, uint_t num_mtt, uint_t sleepflag);

/*
 * SYNC_TPT - used to sync Tavor TPT caches
 */
int tavor_sync_tpt_cmd_post(tavor_state_t *state, uint_t sleepflag);

/*
 * MAP_EQ - used for map classes of events to Tavor event queues (EQ)
 */
int tavor_map_eq_cmd_post(tavor_state_t *state, uint_t map,
    uint_t eqcindx, uint64_t eqmapmask, uint_t sleepflag);

/*
 * RESIZE_CQ - used for resize completion queue (CQ)
 */
int tavor_resize_cq_cmd_post(tavor_state_t *state, tavor_hw_cqc_t *cqc,
    uint_t cqcindx, uint32_t *prod_indx, uint_t sleepflag);

/*
 * CONF_SPECIAL_QP - used to configure a pair of queue pairs for use as
 * special QP.  Necessary to enable full QP0 and/or QP1 operation.
 */
int tavor_conf_special_qp_cmd_post(tavor_state_t *state, uint_t qpindx,
    uint_t qptype, uint_t sleepflag);

/*
 * MGID_HASH, READ_MGM, and WRITE_MGM - used for manipulation of the
 * hardware resource tables for multicast groups.
 */
int tavor_mgid_hash_cmd_post(tavor_state_t *state, uint64_t mgid_h,
    uint64_t mgid_l, uint64_t *mgid_hash, uint_t sleepflag);
int tavor_read_mgm_cmd_post(tavor_state_t *state, tavor_hw_mcg_t *mcg,
    uint_t mcgindx, uint_t sleepflag);
int tavor_write_mgm_cmd_post(tavor_state_t *state, tavor_hw_mcg_t *mcg,
    uint_t mcgindx, uint_t sleepflag);

/*
 * MOD_STAT_CFG - used to configure (override) settings set in NVRAM before
 * a call to QUERY_DEV_LIM.  This is primarily used for SRQ settings in
 * the firmware.
 */
int tavor_mod_stat_cfg_cmd_post(tavor_state_t *state);

/*
 * MODIFY_MPT - used to change MPT attributes of a memory region.  This
 * is primarily used for Resizing SRQs.
 */
int tavor_modify_mpt_cmd_post(tavor_state_t *state, tavor_hw_mpt_t *mpt,
    uint_t mptindx, uint_t flags, uint_t sleepflag);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_CMD_H */
