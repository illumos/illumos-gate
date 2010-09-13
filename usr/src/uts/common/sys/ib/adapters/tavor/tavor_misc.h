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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_MISC_H
#define	_SYS_IB_ADAPTERS_TAVOR_MISC_H

/*
 * tavor_misc.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Tavor Miscellaneous routines - Address Handle, Multicast,
 *    Protection Domain, port-related, statistics (kstat) routines, and
 *    extra VTS related routines.
 *    Many of these functions are called by other parts of the Tavor driver
 *    (and several routines are directly exposed through the IBTF CI
 *    interface and/or kstat interface).
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/adapters/tavor/tavor_ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following defines specify the default number of Address Handles (AH)
 * and their size (in the hardware).  By default the maximum number of address
 * handles is set to 32K.  This value is controllable through the
 * "tavor_log_num_ah" configuration variable.  Note:  Tavor Address Handles
 * are also referred to as UD Address Vectors (UDAV).
 */
#define	TAVOR_NUM_AH_SHIFT		0xF
#define	TAVOR_NUM_AH			(1 << TAVOR_NUM_AH_SHIFT)
#define	TAVOR_UDAV_SIZE_SHIFT		0x5
#define	TAVOR_UDAV_SIZE			(1 << TAVOR_UDAV_SIZE_SHIFT)

/*
 * Minimal configuration value.
 */
#define	TAVOR_NUM_AH_SHIFT_MIN		0xA

/*
 * The following macro determines whether the contents of a UDAV need to be
 * sync'd (with ddi_dma_sync()).  This decision is based on whether the
 * UDAV is in DDR memory (no sync) or system memory (sync required).
 */
#define	TAVOR_UDAV_IS_SYNC_REQ(state)					\
	(((&((state)->ts_rsrc_hdl[TAVOR_UDAV]))->rsrc_loc ==		\
	TAVOR_IN_DDR) ? 0 : 1)

/*
 * These defines are used by tavor_get_addr_path() and tavor_set_addr_path()
 * below.  They indicate the type of hardware context being passed in the
 * "path" argument.  Because the Tavor hardware formats for the QP address
 * path and UDAV address path structures is so similar, but not exactly the
 * same, we use these flags to indicate which type of structure is being
 * read from or written to.
 */
#define	TAVOR_ADDRPATH_QP		0x0
#define	TAVOR_ADDRPATH_UDAV		0x1


/*
 * The following defines specify the default number of Multicast Groups (MCG)
 * and the maximum number of QP which can be associated with each.  By default
 * the maximum number of multicast groups is set to 256, and the maximum number
 * of QP per multicast group is set to 8.  These values are controllable
 * through the "tavor_log_num_mcg" and "tavor_num_qp_per_mcg" configuration
 * variables.
 * We also define a macro below that is used to determine the size of each
 * individual MCG entry (in hardware) based on the number of QP to be
 * supported per multicast group.
 */
#define	TAVOR_NUM_MCG_SHIFT		0x8
#define	TAVOR_NUM_MCG			(1 << TAVOR_NUM_MCG_SHIFT)
#define	TAVOR_NUM_QP_PER_MCG		8

/*
 * Minimal configuration values.
 */
#define	TAVOR_NUM_MCG_SHIFT_MIN		0x4
#define	TAVOR_NUM_QP_PER_MCG_MIN	0x1

/*
 * Macro to compute the offset of the QP list in a given MCG entry.
 */
#define	TAVOR_MCGMEM_SZ(state)						\
	((((state)->ts_cfg_profile->cp_num_qp_per_mcg) + 8) << 2)
#define	TAVOR_MCG_GET_QPLIST_PTR(mcg)					\
	((tavor_hw_mcg_qp_list_t *)((uintptr_t)(mcg) +			\
	sizeof (tavor_hw_mcg_t)))

/*
 * The following defines specify the characteristics of the Tavor multicast
 * group hash table.  The TAVOR_NUM_MCG_HASH_SHIFT defines the size of the
 * hash table (as a power-of-2), which is set to 16 by default.  This value
 * is controllable through the "tavor_log_num_mcg_hash" configuration variable,
 * but serious consideration should be taken before changing this value.  Note:
 * its appropriate size should be a function of the entire table size (as
 * defined by "tavor_log_num_mcg" and TAVOR_NUM_MCG_SHIFT above).
 */
#define	TAVOR_NUM_MCG_HASH_SHIFT	0x4

/*
 * Minimal configuration value.
 */
#define	TAVOR_NUM_MCG_HASH_SHIFT_MIN	0x2

/*
 * The following defines are used by the multicast routines to determine
 * if a given "multicast GID" is valid or not (see tavor_mcg_is_mgid_valid
 * for more details.  These values are pulled from the IBA specification,
 * rev. 1.1
 */
#define	TAVOR_MCG_TOPBITS_SHIFT		56
#define	TAVOR_MCG_TOPBITS_MASK		0xFF
#define	TAVOR_MCG_TOPBITS		0xFF

#define	TAVOR_MCG_FLAGS_SHIFT		52
#define	TAVOR_MCG_FLAGS_MASK		0xF
#define	TAVOR_MCG_FLAGS_PERM		0x0
#define	TAVOR_MCG_FLAGS_NONPERM		0x1

#define	TAVOR_MCG_SCOPE_SHIFT		48
#define	TAVOR_MCG_SCOPE_MASK		0xF
#define	TAVOR_MCG_SCOPE_LINKLOC		0x2
#define	TAVOR_MCG_SCOPE_SITELOC		0x5
#define	TAVOR_MCG_SCOPE_ORGLOC		0x8
#define	TAVOR_MCG_SCOPE_GLOBAL		0xE


/*
 * The following defines specify the default number of Protection Domains (PD).
 * By default the maximum number of protection domains is set to 64K.  This
 * value is controllable through the "tavor_log_num_pd" configuration variable.
 */
#define	TAVOR_NUM_PD_SHIFT		0x10
#define	TAVOR_NUM_PD			(1 << TAVOR_NUM_PD_SHIFT)

/*
 * The following defines specify the default number of Partition Keys (PKey)
 * per port.  By default the maximum number of PKeys is set to 32 per port, for
 * a total of 64 (assuming two ports) .  This value is controllable through the
 * "tavor_log_max_pkeytbl" configuration variable.
 */
#define	TAVOR_NUM_PKEYTBL_SHIFT		0x5
#define	TAVOR_NUM_PKEYTBL		(1 << TAVOR_NUM_PKEYTBL_SHIFT)

/*
 * The following defines specify the default number of SGIDs per port.  By
 * default the maximum number of GIDS per port is set to 16.  This value
 * is controllable through the "tavor_log_max_gidtbl" configuration variable.
 */
#define	TAVOR_NUM_GIDTBL_SHIFT		0x4
#define	TAVOR_NUM_GIDTBL		(1 << TAVOR_NUM_GIDTBL_SHIFT)

/*
 * The following defines specify the default number of UAR pages.  By
 * default the maximum number of UAR pages is set to 1024.  This value
 * is controllable through the "tavor_log_num_uar" configuration variable.
 * NOTE: This value should not be set larger than 15 (0xF) because the
 * UAR index number is used as part of the minor number calculation (see
 * tavor_open() for details) and the minor numbers should not be larger
 * than eighteen bits (i.e. 15 bits of UAR index, 3 bits of driver instance
 * number).  This is especially true for 32-bit kernels.
 */
#define	TAVOR_NUM_UAR_SHIFT		0xA
#define	TAVOR_NUM_UAR			(1 << TAVOR_NUM_UAR_SHIFT)

/*
 * Minimal configuration value.
 */
#define	TAVOR_NUM_UAR_SHIFT_MIN		0x4

/*
 * These defines specify some miscellaneous port-related configuration
 * information.  Specifically, TAVOR_MAX_MTU is used to define the maximum
 * MTU supported for each Tavor port, TAVOR_MAX_PORT_WIDTH is used to define
 * the maximum supported port width, and the TAVOR_MAX_VLCAP define is used
 * to specify the maximum number of VLs supported, excluding VL15.  Both
 * of these values are controllable and get be set using the "tavor_max_mtu"
 * and "tavor_max_vlcap" configuration variables.  Note: as with many of the
 * configurable variables, caution should be exercised when changing these
 * values.  These values, specifically, should not be set any larger than
 * they are defined here as these are set to the current Tavor device
 * maximums.
 */
#define	TAVOR_MAX_MTU			0x4
#define	TAVOR_MAX_PORT_WIDTH		0x3
#define	TAVOR_MAX_VLCAP			0x8

/*
 * These last defines are used by the statistics counting routines (kstats)
 * for initialization of the structures associated with the IB statistics
 * access routines.  The TAVOR_CNTR_MASK and TAVOR_CNTR_SIZE defines are
 * used to divide the "pcr" register into two 32-bit counters (one for "pic0"
 * and the other for "pic1")
 */
#define	TAVOR_CNTR_MASK		0xFFFFFFFF
#define	TAVOR_CNTR_SIZE		32
#define	TAVOR_CNTR_NUMENTRIES	17

/*
 * The following defines are used by tavor_queue_alloc() to specify whether
 * a given QP/CQ/EQ queue memory should be allocated from kernel system memory
 * (TAVOR_QUEUE_LOCATION_NORMAL), from user-mappable system memory
 * (TAVOR_QUEUE_LOCATION_USERLAND), or from local-attached DDR memory
 * (TAVOR_QUEUE_LOCATION_INDDR).
 */
#define	TAVOR_QUEUE_LOCATION_NORMAL	0x1
#define	TAVOR_QUEUE_LOCATION_USERLAND	0x2
#define	TAVOR_QUEUE_LOCATION_INDDR	0x3

/*
 * Minimum number of ticks to delay between successive polls of the CQ in
 * VTS ioctl loopback test
 */
#define	TAVOR_VTS_LOOPBACK_MIN_WAIT_DUR	50


/*
 * The tavor_sw_ah_s structure is also referred to using the "tavor_ahhdl_t"
 * typedef (see tavor_typedef.h).  It encodes all the information necessary
 * to track the various resources (e.g. the UDAV hardware resource) needed to
 * allocate, query, modify, and (later) free an address handle.
 *
 * In specific, it has a lock to ensure single-threaded access, it stores a
 * pointer to the associated MR handle (for the mapped UDAV memory) and a
 * pointer to the associated PD handle.  And it also contains a copy of the
 * GUID stored into the address handle.  The reason for this extra copy of
 * the GUID info has to do with Tavor PRM compliance and is fully explained
 * in tavor_misc.c
 *
 * It also has the always necessary backpointer to the resource for the AH
 * handle structure itself.
 */
struct tavor_sw_ah_s {
	kmutex_t	ah_lock;
	tavor_pdhdl_t	ah_pdhdl;
	tavor_mrhdl_t	ah_mrhdl;
	tavor_rsrc_t	*ah_udavrsrcp;
	tavor_rsrc_t	*ah_rsrcp;
	uint64_t	ah_save_guid;
	ibt_srate_t	ah_save_srate;
	uint_t		ah_sync;
};
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_ah_s::ah_lock,
    tavor_sw_ah_s::ah_pdhdl
    tavor_sw_ah_s::ah_mrhdl
    tavor_sw_ah_s::ah_udavrsrcp
    tavor_sw_ah_s::ah_rsrcp
    tavor_sw_ah_s::ah_save_guid
    tavor_sw_ah_s::ah_sync))

/*
 * The tavor_sw_mcg_list_s structure is also referred to using the
 * "tavor_mcghdl_t" typedef (see tavor_typedef.h).  It encodes all the
 * information necessary to track the various resources needed to for attaching
 * and detaching QP from multicast groups.
 *
 * The Tavor driver keeps an array of these and uses them as a shadow for
 * the real HW-based MCG table.  They hold all the necessary information
 * to track the resources and to allow fast access to the MCG table.  First,
 * it had a 128-bit multicast GID (stored in "mcg_mgid_h" and "mcg_mgid_l".
 * next if has a field to indicate the index of the next tavor_mcghdl_t in
 * the current hash chain (zero is the end of the chain).  Note: this very
 * closely mimics what the hardware MCG entry has. Then it has a field to
 * indicate how many QP are currently attached to the given MCG.  And, lastly,
 * it has the obligatory backpointer to the resource for the MCH handle
 * structure itself.
 */
struct tavor_sw_mcg_list_s {
	uint64_t	mcg_mgid_h;
	uint64_t	mcg_mgid_l;
	uint_t		mcg_next_indx;
	uint_t		mcg_num_qps;
	tavor_rsrc_t	*mcg_rsrcp;
};

/*
 * The tavor_sw_pd_s structure is also referred to using the "tavor_pdhdl_t"
 * typedef (see tavor_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to allocate and free protection
 * domains
 *
 * Specifically, it has reference count and a lock to ensure single threaded
 * access to it.  It has a field for the protection domain number ("pd_pdnum").
 * And it also has the obligatory backpointer to the resource for the PD
 * handle structure itself.
 */
struct tavor_sw_pd_s {
	kmutex_t	pd_lock;
	uint32_t	pd_pdnum;
	uint32_t	pd_refcnt;
	tavor_rsrc_t	*pd_rsrcp;
};
_NOTE(READ_ONLY_DATA(tavor_sw_pd_s::pd_pdnum
    tavor_sw_pd_s::pd_rsrcp))
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_pd_s::pd_lock,
    tavor_sw_pd_s::pd_refcnt))

/*
 * The tavor_qalloc_info_s structure is also referred to using the
 * "tavor_qalloc_info_t" typedef (see tavor_typedef.h).  It holds all the
 * information necessary to track the resources for each of the various Tavor
 * queue types (i.e. Event Queue, Completion Queue, Work Queue).
 *
 * Specifically, it has the size, alignment restrictions, and location (in DDR
 * or in system memory).  And depending on the location, it also has the
 * ddi_dma_handle_t, ddi_acc_handle_t, and pointers used for reading/writing to
 * the queue's memory.
 */
struct tavor_qalloc_info_s {
	uint64_t		qa_size;
	uint64_t		qa_alloc_align;
	uint64_t		qa_bind_align;
	uint32_t		*qa_buf_real;
	uint32_t		*qa_buf_aligned;
	uint64_t		qa_buf_realsz;
	uint_t			qa_location;
	ddi_dma_handle_t	qa_dmahdl;
	ddi_acc_handle_t	qa_acchdl;
	ddi_umem_cookie_t	qa_umemcookie;
};

/*
 * The tavor_ks_mask_t structure encodes all the information necessary for
 * the individual kstat entries.  The "ks_reg_offset" field contains the
 * hardware offset for the corresponding counter, and "ks_reg_shift" and
 * "ks_reg_mask" contain shift and mask registers used by the access routines.
 * Also the "ks_old_pic0" and "ks_old_pic1" fields contain the most recently
 * read value for the corresponding port ("pic").  Note:  An array of these
 * structures is part of the "tavor_ks_info_t" structure below.
 */
typedef struct tavor_ks_mask_s {
	char		*ks_evt_name;
	uint64_t	ks_reg_offset;
	uint32_t	ks_reg_shift;
	uint32_t	ks_reg_mask;
	uint32_t	ks_old_pic0;
	uint32_t	ks_old_pic1;
} tavor_ks_mask_t;

/*
 * Index into the named data components of 64 bit "perf_counters" kstat.
 */
enum {
	TAVOR_PERFCNTR64_ENABLE_IDX = 0,
	TAVOR_PERFCNTR64_XMIT_DATA_IDX,
	TAVOR_PERFCNTR64_RECV_DATA_IDX,
	TAVOR_PERFCNTR64_XMIT_PKTS_IDX,
	TAVOR_PERFCNTR64_RECV_PKTS_IDX,
	TAVOR_PERFCNTR64_NUM_COUNTERS
};

/*
 * Data associated with the 64 bit "perf_counters" kstat. One for each port.
 */
typedef struct tavor_perfcntr64_ks_info_s {
	struct kstat	*tki64_ksp;
	int		tki64_enabled;
	uint64_t	tki64_counters[TAVOR_PERFCNTR64_NUM_COUNTERS];
	uint32_t	tki64_last_read[TAVOR_PERFCNTR64_NUM_COUNTERS];
	uint_t		tki64_port_num;
	tavor_state_t	*tki64_state;
} tavor_perfcntr64_ks_info_t;


/*
 * The tavor_ks_info_t structure stores all the information necessary for
 * tracking the resources associated with each of the various kstats.  In
 * addition to containing pointers to each of the counter and pic kstats,
 * this structure also contains "tki_pcr" which is the control register that
 * determines which of the countable entries (from the "tki_ib_perfcnt[]"
 * array) is being currently accessed.
 */
typedef struct tavor_ks_info_s {
	struct kstat	*tki_cntr_ksp;
	struct kstat	*tki_picN_ksp[TAVOR_NUM_PORTS];
	uint64_t	tki_pcr;
	uint64_t	tki_pic0;
	uint64_t	tki_pic1;
	tavor_ks_mask_t	tki_ib_perfcnt[TAVOR_CNTR_NUMENTRIES];
	kt_did_t	tki_perfcntr64_thread_id;
	kmutex_t	tki_perfcntr64_lock;
	kcondvar_t	tki_perfcntr64_cv;
	uint_t		tki_perfcntr64_flags;	/* see below */
	tavor_perfcntr64_ks_info_t	tki_perfcntr64[TAVOR_NUM_PORTS];
} tavor_ks_info_t;

/* tki_perfcntr64_flags */
#define	TAVOR_PERFCNTR64_THREAD_CREATED		0x0001
#define	TAVOR_PERFCNTR64_THREAD_EXIT		0x0002

/*
 * The tavor_ports_ioctl32_t, tavor_loopback_ioctl32_t, and
 * tavor_flash_ioctl32_s structures are used internally by the Tavor
 * driver to accomodate 32-bit applications which need to access the
 * Tavor ioctls.  They are 32-bit versions of externally available
 * structures defined in tavor_ioctl.h
 */
typedef struct tavor_ports_ioctl32_s {
	uint_t			tp_revision;
	caddr32_t		tp_ports;
	uint8_t			tp_num_ports;
} tavor_ports_ioctl32_t;

typedef struct tavor_loopback_ioctl32_s {
	uint_t			tlb_revision;
	caddr32_t		tlb_send_buf;
	caddr32_t		tlb_fail_buf;
	uint_t			tlb_buf_sz;
	uint_t			tlb_num_iter;
	uint_t			tlb_pass_done;
	uint_t			tlb_timeout;
	tavor_loopback_error_t	tlb_error_type;
	uint8_t			tlb_port_num;
	uint8_t			tlb_num_retry;
} tavor_loopback_ioctl32_t;

typedef struct tavor_flash_ioctl32_s {
	uint32_t	tf_type;
	caddr32_t	tf_sector;
	uint32_t	tf_sector_num;
	uint32_t	tf_addr;
	uint32_t	tf_quadlet;
	uint8_t		tf_byte;
} tavor_flash_ioctl32_t;

/*
 * The tavor_loopback_comm_t and tavor_loopback_state_t structures below
 * are used to store all of the relevant state information needed to keep
 * track of a single VTS ioctl loopback test run.
 */
typedef struct tavor_loopback_comm_s {
	uint8_t			*tlc_buf;
	size_t			tlc_buf_sz;
	ibt_mr_desc_t		tlc_mrdesc;

	tavor_mrhdl_t		tlc_mrhdl;
	tavor_cqhdl_t		tlc_cqhdl[2];
	tavor_qphdl_t		tlc_qp_hdl;

	ibt_mr_attr_t		tlc_memattr;
	uint_t			tlc_qp_num;
	ibt_cq_attr_t		tlc_cq_attr;
	ibt_qp_alloc_attr_t	tlc_qp_attr;
	ibt_chan_sizes_t	tlc_chan_sizes;
	ibt_qp_info_t		tlc_qp_info;
	ibt_queue_sizes_t	tlc_queue_sizes;
	ibt_send_wr_t		tlc_wr;
	ibt_wr_ds_t		tlc_sgl;
	ibt_wc_t		tlc_wc;
	uint_t			tlc_num_polled;
	ibt_status_t		tlc_status;
	int			tlc_complete;
	int			tlc_wrid;
} tavor_loopback_comm_t;

typedef struct tavor_loopback_state_s {
	uint8_t			tls_port;
	uint_t			tls_lid;
	uint8_t			tls_retry;
	tavor_state_t		*tls_state;
	ibc_hca_hdl_t		tls_hca_hdl;
	tavor_pdhdl_t		tls_pd_hdl;
	tavor_loopback_comm_t	tls_tx;
	tavor_loopback_comm_t	tls_rx;
	ibt_status_t		tls_status;
	int			tls_err;
	int			tls_pkey_ix;
	int			tls_timeout;
} tavor_loopback_state_t;

/* Tavor Address Handle routines */
int tavor_ah_alloc(tavor_state_t *state, tavor_pdhdl_t pd,
    ibt_adds_vect_t *attr_p, tavor_ahhdl_t *ahhdl, uint_t sleepflag);
int tavor_ah_free(tavor_state_t *state, tavor_ahhdl_t *ahhdl,
    uint_t sleepflag);
int tavor_ah_query(tavor_state_t *state, tavor_ahhdl_t ahhdl,
    tavor_pdhdl_t *pdhdl, ibt_adds_vect_t *attr_p);
int tavor_ah_modify(tavor_state_t *state, tavor_ahhdl_t ahhdl,
    ibt_adds_vect_t *attr_p);

/* Tavor Multicast Group routines */
int tavor_mcg_attach(tavor_state_t *state, tavor_qphdl_t qphdl, ib_gid_t gid,
    ib_lid_t lid);
int tavor_mcg_detach(tavor_state_t *state, tavor_qphdl_t qphdl, ib_gid_t gid,
    ib_lid_t lid);

/* Tavor Protection Domain routines */
int tavor_pd_alloc(tavor_state_t *state, tavor_pdhdl_t *pdhdl,
    uint_t sleepflag);
int tavor_pd_free(tavor_state_t *state, tavor_pdhdl_t *pdhdl);
void tavor_pd_refcnt_inc(tavor_pdhdl_t pd);
void tavor_pd_refcnt_dec(tavor_pdhdl_t pd);

/* Tavor port-related routines */
int tavor_port_query(tavor_state_t *state, uint_t port,
    ibt_hca_portinfo_t *pi);
int tavor_port_modify(tavor_state_t *state, uint8_t port,
    ibt_port_modify_flags_t flags, uint8_t init_type);

/* Tavor statistics (kstat) routines */
int tavor_kstat_init(tavor_state_t *state);
void tavor_kstat_fini(tavor_state_t *state);

/* Miscellaneous routines */
int tavor_set_addr_path(tavor_state_t *state, ibt_adds_vect_t *av,
    tavor_hw_addr_path_t *path, uint_t type, tavor_qphdl_t qp);
void tavor_get_addr_path(tavor_state_t *state, tavor_hw_addr_path_t *path,
    ibt_adds_vect_t *av, uint_t type, tavor_qphdl_t qp);
int tavor_portnum_is_valid(tavor_state_t *state, uint_t portnum);
int tavor_pkeyindex_is_valid(tavor_state_t *state, uint_t pkeyindx);
int tavor_queue_alloc(tavor_state_t *state, tavor_qalloc_info_t *qa_info,
    uint_t sleepflag);
void tavor_queue_free(tavor_state_t *state, tavor_qalloc_info_t *qa_info);
void tavor_dma_attr_init(ddi_dma_attr_t *dma_attr);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_MISC_H */
