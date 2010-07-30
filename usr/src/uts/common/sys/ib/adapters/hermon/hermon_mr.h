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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_ADAPTERS_HERMON_MR_H
#define	_SYS_IB_ADAPTERS_HERMON_MR_H

/*
 * hermon_mr.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Hermon Memory Region/Window routines.
 *    Specifically it contains #defines, macros, and prototypes for each of
 *    the required memory region/window verbs that can be accessed through
 *    the IBTF's CI interfaces.  In particular each of the prototypes defined
 *    below is called from a corresponding CI interface routine (as specified
 *    in the hermon_ci.c file).
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following defines specify the default number of MPT entries to
 * configure. This value is controllable through the "hermon_log_num_mpt"
 * configuration variable.
 */
#define	HERMON_NUM_DMPT_SHIFT		0x16

/*
 * The following defines specify the default number of MPT entries to
 * configure. This value is controllable through the "hermon_log_num_mtt"
 * configuration variable. This default value expects an averages of 8
 * MTTs per MPT. We also define a log MTT size, since it's not likely
 * to change.
 */
#define	HERMON_NUM_MTT_SHIFT		0x1d
#define	HERMON_MTT_SIZE_SHIFT		0x3

/*
 * This define is the maximum size of a memory region or window (log 2), which
 * is used to initialize the "hermon_log_max_mrw_sz" configuration variable.
 */
#define	HERMON_MAX_MEM_MPT_SHIFT			0x24

/*
 * Defines used by hermon_mr_deregister() to specify how much/to what extent
 * a given memory regions resources should be freed up.  HERMON_MR_DEREG_ALL
 * says what it means, free up all the resources associated with the region.
 * HERMON_MR_DEREG_NO_HW2SW_MPT indicates that it is unnecessary to attempt
 * the ownership transfer (from hardware to software) for the given MPT entry.
 * And HERMON_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND indicates that it is not only
 * unnecessary to attempt the ownership transfer for MPT, but it is also
 * unnecessary to attempt to unbind the memory.
 * In general, these last two are specified when hermon_mr_deregister() is
 * called from hermon_mr_reregister(), where the MPT ownership transfer or
 * memory unbinding may have already been successfully performed.
 */
#define	HERMON_MR_DEREG_ALL			3
#define	HERMON_MR_DEREG_NO_HW2SW_MPT		2
#define	HERMON_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND	1

/*
 * The following define is used by hermon_mr_rereg_xlat_helper() to determine
 * whether or not a given DMA handle can be reused.  If the DMA handle was
 * previously initialized for IOMMU bypass mapping, then it can not be reused
 * to reregister a region for DDI_DMA_STREAMING access.
 */
#define	HERMON_MR_REUSE_DMAHDL(mr, flags)				\
	(((mr)->mr_bindinfo.bi_bypass != HERMON_BINDMEM_BYPASS) ||	\
	    !((flags) & IBT_MR_NONCOHERENT))

/*
 * The hermon_sw_refcnt_t structure is used internally by the Hermon driver to
 * track all the information necessary to manage shared memory regions.  Since
 * a shared memory region _will_ have its own distinct MPT entry, but will
 * _share_ its MTT entries with another region, it is necessary to track the
 * number of times a given MTT structure is shared.  This ensures that it will
 * not be prematurely freed up and that can be destroyed only when it is
 * appropriate to do so.
 *
 * Each hermon_sw_refcnt_t structure contains a lock and a reference count
 * variable which are used to track the necessary information.
 *
 * The following macros (below) are used to manipulate and query the MTT
 * reference count parameters.  HERMON_MTT_REFCNT_INIT() is used to initialize
 * a newly allocated hermon_sw_refcnt_t struct (setting the "swrc_refcnt" to 1).
 * And the HERMON_MTT_IS_NOT_SHARED() and HERMON_MTT_IS_SHARED() macros are
 * used to query the current status of hermon_sw_refcnt_t struct to determine
 * if its "swrc_refcnt" is one or not.
 */
typedef struct hermon_sw_refcnt_s {
	kmutex_t		swrc_lock;
	uint_t			swrc_refcnt;
} hermon_sw_refcnt_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(hermon_sw_refcnt_t::swrc_refcnt))
_NOTE(MUTEX_PROTECTS_DATA(hermon_sw_refcnt_t::swrc_lock,
    hermon_sw_refcnt_t::swrc_refcnt))
#define	HERMON_MTT_REFCNT_INIT(swrc_tmp)	((swrc_tmp)->swrc_refcnt = 1)
#define	HERMON_MTT_IS_NOT_SHARED(swrc_tmp)	((swrc_tmp)->swrc_refcnt == 1)
#define	HERMON_MTT_IS_SHARED(swrc_tmp)		((swrc_tmp)->swrc_refcnt != 1)


/*
 * The hermon_bind_info_t structure is used internally by the Hermon driver to
 * track all the information necessary to perform the DMA mappings necessary
 * for memory registration.  It is specifically passed into both the
 * hermon_mr_mem_bind() and hermon_mr_mtt_write() functions which perform most
 * of the necessary operations for Hermon memory registration.
 *
 * This structure is used to pass all the information necessary for a call
 * to either ddi_dma_addr_bind_handle() or ddi_dma_buf_bind_handle().  Note:
 * the fields which need to be valid for each type of binding are slightly
 * different and that it indicated by the value in the "bi_type" field.  The
 * "bi_type" field may be set to either of the following defined values:
 * HERMON_BINDHDL_VADDR (to indicate an "addr" bind) or HERMON_BINDHDL_BUF (to
 * indicate a "buf" bind).
 *
 * Upon return from hermon_mr_mem_bind(), the hermon_bind_info_t struct will
 * have its "bi_dmahdl", "bi_dmacookie", and "bi_cookiecnt" fields filled in.
 * It is these values which are of particular interest to the
 * hermon_mr_mtt_write() routine (they hold the PCI mapped addresses).
 *
 * Once initialized and used in this way, the hermon_bind_info_t will not to be
 * modified in anyway until it is subsequently passed to hermon_mr_mem_unbind()
 * where the memory and resources will be unbound and reclaimed.  Note:  the
 * "bi_free_dmahdl" flag indicated whether the ddi_dma_handle_t should be
 * freed as part of the hermon_mr_mem_unbind() operation or whether it will
 * be freed later elsewhere.
 */
typedef struct hermon_bind_info_s {
	uint64_t		bi_addr;
	uint64_t		bi_len;
	struct as		*bi_as;
	struct buf		*bi_buf;
	ddi_dma_handle_t	bi_dmahdl;
	ddi_dma_cookie_t	bi_dmacookie;
	uint_t			bi_cookiecnt;
	uint_t			bi_type;
	uint_t			bi_flags;
	uint_t			bi_bypass;
	uint_t			bi_free_dmahdl;
} hermon_bind_info_t;
#define	HERMON_BINDHDL_NONE		0
#define	HERMON_BINDHDL_VADDR		1
#define	HERMON_BINDHDL_BUF		2
#define	HERMON_BINDHDL_UBUF		3
#define	HERMON_BINDHDL_LKEY		4

/*
 * The hermon_sw_mr_s structure is also referred to using the "hermon_mrhdl_t"
 * typedef (see hermon_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to register, reregister, deregister,
 * and perform all the myriad other operations on both memory regions _and_
 * memory windows.
 *
 * A pointer to this structure is returned from many of the IBTF's CI verbs
 * interfaces for memory registration.
 *
 * It contains pointers to the various resources allocated for a memory
 * region, i.e. MPT resource, MTT resource, and MTT reference count resource.
 * In addition it contains the hermon_bind_info_t struct used for the memory
 * bind operation on a given memory region.
 *
 * It also has a pointers to the associated PD handle, placeholders for access
 * flags, memory keys, and suggested page size for the region.  It also has
 * the necessary backpointer to the resource that corresponds to the structure
 * itself.  And lastly, it contains a placeholder for a callback which should
 * be called on memory region unpinning.
 */
struct hermon_sw_mr_s {
	kmutex_t		mr_lock;
	hermon_rsrc_t		*mr_mptrsrcp;
	hermon_rsrc_t		*mr_mttrsrcp;
	hermon_rsrc_t		*mr_mttrefcntp;
	hermon_pdhdl_t		mr_pdhdl;
	hermon_bind_info_t	mr_bindinfo;
	ibt_mr_attr_flags_t	mr_accflag;
	uint32_t		mr_lkey;
	uint32_t		mr_rkey;
	uint32_t		mr_logmttpgsz;
	hermon_mpt_rsrc_type_t	mr_mpt_type;
	uint64_t		mr_mttaddr;	/* for cMPTs */
	uint64_t		mr_log2_pgsz;
				/* entity_size (in bytes), for cMPTS */
	hermon_rsrc_t		*mr_rsrcp;
	uint_t			mr_is_fmr;
	uint8_t			mr_fmr_key;	/* per FMR 8-bit key */
	hermon_fmr_list_t	*mr_fmr;
	uint_t			mr_is_umem;
	ddi_umem_cookie_t	mr_umemcookie;
	void 			(*mr_umem_cbfunc)(void *, void *);
	void			*mr_umem_cbarg1;
	void			*mr_umem_cbarg2;
};
_NOTE(DATA_READABLE_WITHOUT_LOCK(hermon_sw_mr_s::mr_bindinfo
    hermon_sw_mr_s::mr_lkey
    hermon_sw_mr_s::mr_mttaddr
    hermon_sw_mr_s::mr_is_umem
    hermon_sw_mr_s::mr_is_fmr
    hermon_sw_mr_s::mr_fmr))
_NOTE(MUTEX_PROTECTS_DATA(hermon_sw_mr_s::mr_lock,
    hermon_sw_mr_s::mr_mptrsrcp
    hermon_sw_mr_s::mr_mttrsrcp
    hermon_sw_mr_s::mr_mttrefcntp
    hermon_sw_mr_s::mr_bindinfo
    hermon_sw_mr_s::mr_lkey
    hermon_sw_mr_s::mr_rkey
    hermon_sw_mr_s::mr_logmttpgsz
    hermon_sw_mr_s::mr_rsrcp
    hermon_sw_mr_s::mr_is_umem
    hermon_sw_mr_s::mr_umemcookie
    hermon_sw_mr_s::mr_umem_cbfunc
    hermon_sw_mr_s::mr_umem_cbarg1
    hermon_sw_mr_s::mr_umem_cbarg2))

/*
 * The hermon_mr_options_t structure is used in several of the Hermon memory
 * registration routines to provide additional option functionality.  When
 * a NULL pointer is passed in place of a pointer to this struct, it is a
 * way of specifying the "default" behavior.  Using this structure, however,
 * is a way of controlling any extended behavior.
 *
 * Currently, the only defined "extended" behaviors are for specifying whether
 * a given memory region should bypass the PCI IOMMU (HERMON_BINDMEM_BYPASS)
 * or be mapped into the IOMMU (HERMON_BINDMEM_NORMAL), for specifying whether
 * a given ddi_dma_handle_t should be used in the bind operation, and for
 * specifying whether a memory registration should attempt to return an IB
 * vaddr which is "zero-based" (aids in alignment contraints for QPs).
 *
 * This defaults today to always bypassing the IOMMU (can be changed by using
 * the "hermon_iommu_bypass" configuration variable), to always allocating
 * a new dma handle, and to using the virtual address passed in (i.e. not
 * "zero-based").
 */
typedef struct hermon_mr_options_s {
	ddi_dma_handle_t	mro_bind_dmahdl;
	uint_t			mro_bind_type;
	uint_t			mro_bind_override_addr;
} hermon_mr_options_t;
#define	HERMON_BINDMEM_NORMAL		1
#define	HERMON_BINDMEM_BYPASS		0

#define	HERMON_NO_MPT_OWNERSHIP		0	/* for cMPTs */
#define	HERMON_PASS_MPT_OWNERSHIP	1

/*
 * Memory Allocation/Deallocation
 *
 * Although this is not strictly related to "memory regions", this is
 * the most logical place to define the struct used for the memory
 * allocation/deallocation CI entry points.
 *
 * ibc_mem_alloc_s structure is used to store DMA handles for
 * for these allocations.
 */
struct ibc_mem_alloc_s {
	ddi_dma_handle_t ibc_dma_hdl;
	ddi_acc_handle_t ibc_acc_hdl;
};
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
    ibc_mem_alloc_s::ibc_dma_hdl
    ibc_mem_alloc_s::ibc_acc_hdl))

int hermon_dma_mr_register(hermon_state_t *state, hermon_pdhdl_t pdhdl,
    ibt_dmr_attr_t *attr_p, hermon_mrhdl_t *mrhdl);
int hermon_mr_register(hermon_state_t *state, hermon_pdhdl_t pdhdl,
    ibt_mr_attr_t *attr_p, hermon_mrhdl_t *mrhdl, hermon_mr_options_t *op,
    hermon_mpt_rsrc_type_t mpt_type);
int hermon_mr_register_buf(hermon_state_t *state, hermon_pdhdl_t pdhdl,
    ibt_smr_attr_t *attrp, struct buf *buf, hermon_mrhdl_t *mrhdl,
    hermon_mr_options_t *op, hermon_mpt_rsrc_type_t mpt_type);
int hermon_mr_mtt_bind(hermon_state_t *state, hermon_bind_info_t *bind,
    ddi_dma_handle_t bind_dmahdl, hermon_rsrc_t **mtt, uint_t *mtt_pgsz_bits,
    uint_t is_buffer);
int hermon_mr_mtt_unbind(hermon_state_t *state, hermon_bind_info_t *bind,
    hermon_rsrc_t *mtt);
int hermon_mr_register_shared(hermon_state_t *state, hermon_mrhdl_t mrhdl,
    hermon_pdhdl_t pdhdl, ibt_smr_attr_t *attr_p, hermon_mrhdl_t *mrhdl_new);
int hermon_mr_deregister(hermon_state_t *state, hermon_mrhdl_t *mrhdl,
    uint_t level, uint_t sleep);
int hermon_mr_query(hermon_state_t *state, hermon_mrhdl_t mrhdl,
    ibt_mr_query_attr_t *attr);
int hermon_mr_reregister(hermon_state_t *state, hermon_mrhdl_t mrhdl,
    hermon_pdhdl_t pdhdl, ibt_mr_attr_t *attr_p, hermon_mrhdl_t *mrhdl_new,
    hermon_mr_options_t *op);
int hermon_mr_reregister_buf(hermon_state_t *state, hermon_mrhdl_t mr,
    hermon_pdhdl_t pd, ibt_smr_attr_t *mr_attr, struct buf *buf,
    hermon_mrhdl_t *mrhdl_new, hermon_mr_options_t *op);
int hermon_mr_sync(hermon_state_t *state, ibt_mr_sync_t *mr_segs,
    size_t num_segs);
int hermon_mw_alloc(hermon_state_t *state, hermon_pdhdl_t pdhdl,
    ibt_mw_flags_t flags, hermon_mwhdl_t *mwhdl);
int hermon_mw_free(hermon_state_t *state, hermon_mwhdl_t *mwhdl, uint_t sleep);
uint32_t hermon_mr_keycalc(uint32_t indx);
uint32_t hermon_mr_key_swap(uint32_t indx);
uint32_t hermon_index_to_mkey(uint32_t indx);
int hermon_mr_alloc_fmr(hermon_state_t *state, hermon_pdhdl_t pd,
    hermon_fmrhdl_t fmr_pool, hermon_mrhdl_t *mrhdl);
int hermon_mr_dealloc_fmr(hermon_state_t *state, hermon_mrhdl_t *mrhdl);
int hermon_mr_register_physical_fmr(hermon_state_t *state,
    ibt_pmr_attr_t *mem_pattr_p, hermon_mrhdl_t mr, ibt_pmr_desc_t *mem_desc_p);
int hermon_mr_alloc_lkey(hermon_state_t *state, hermon_pdhdl_t pd,
    ibt_lkey_flags_t flags, uint_t sz, hermon_mrhdl_t *mr);
int hermon_mr_fexch_mpt_init(hermon_state_t *state, hermon_pdhdl_t pd,
    uint32_t mpt_indx, uint_t nummtt, uint64_t mtt_addr, uint_t sleep);
int hermon_mr_fexch_mpt_fini(hermon_state_t *state, hermon_pdhdl_t pd,
    uint32_t mpt_indx, uint_t sleep);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_MR_H */
