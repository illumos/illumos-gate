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

#ifndef	_SYS_IB_ADAPTERS_TAVOR_MR_H
#define	_SYS_IB_ADAPTERS_TAVOR_MR_H

/*
 * tavor_mr.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Tavor Memory Region/Window routines.
 *    Specifically it contains #defines, macros, and prototypes for each of
 *    the required memory region/window verbs that can be accessed through
 *    the IBTF's CI interfaces.  In particular each of the prototypes defined
 *    below is called from a corresponding CI interface routine (as specified
 *    in the tavor_ci.c file).
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following defines specify the default number of MPT entries and their
 * individual entry size.  Settings exist for the supported DDR DIMM sizes of
 * 128MB and 256MB.  If a DIMM greater than 256 is found, then the 256MB
 * profile is used.  See tavor_cfg.c for more discussion on config profiles.
 *
 * For manual configuration (not using config profiles), this value is
 * controllable through the "tavor_log_num_mpt" configuration variable.  To
 * override config profile settings the 'tavor_alt_config_enable' configuration
 * variable must first be set.
 */
#define	TAVOR_NUM_MPT_SHIFT_128		0x14
#define	TAVOR_NUM_MPT_SHIFT_256		0x15
#define	TAVOR_MPT_SIZE_SHIFT		0x6
#define	TAVOR_MPT_SIZE			(1 << TAVOR_MPT_SIZE_SHIFT)

/*
 * Minimal configuration value.
 */
#define	TAVOR_NUM_MPT_SHIFT_MIN		0xD

/*
 * The following defines specify the size of each individual MTT entry and
 * the number of MTT entries that make up an MTT segment (TAVOR_MTTSEG_SIZE)
 */
#define	TAVOR_MTT_SIZE_SHIFT		0x3
#define	TAVOR_MTT_SIZE			(1 << TAVOR_MTT_SIZE_SHIFT)
#define	TAVOR_MTTSEG_SIZE_SHIFT		0x0
#define	TAVOR_MTTSEG_SIZE		(8 << TAVOR_MTTSEG_SIZE_SHIFT)

/*
 * These define the total number of MTT segments.  By default we are setting
 * this number of MTT segments (the MTT table size) to 2M segments.  This
 * default value is used to initialize the "tavor_log_num_mttseg" config
 * variable.
 * Note: Each segment is currently set to 8 MTT entries (TAVOR_MTTSEG_SIZE).
 * This means that we can support up to 16M MTT entries (i.e. "pages").
 */
#define	TAVOR_NUM_MTTSEG_SHIFT		0x15
#define	TAVOR_NUM_MTTSEG		(1 << TAVOR_NUM_MTTSEG_SHIFT)

/*
 * Minimal configuration value.
 */
#define	TAVOR_NUM_MTTSEG_SHIFT_MIN	0x11

/*
 * Macro to round a number of MTT entries to the number of MTT segments.
 */
#define	TAVOR_NUMMTT_TO_MTTSEG(num)		\
	(((num) + TAVOR_MTTSEG_SIZE - 1) >>	\
	(TAVOR_MTTSEG_SIZE_SHIFT + TAVOR_MTT_SIZE_SHIFT))

/*
 * This define is used to specify the "MTT page walk version" in the Tavor
 * INIT_HCA command.
 */
#define	TAVOR_MTT_PG_WALK_VER		0

/*
 * This define is the maximum size of a memory region or window (log 2).  It is
 * set depending on size of the DDR being either 128MB or 256MB.  These defines
 * are used to initialize the "tavor_log_max_mrw_sz" configuration variable,
 * and are proportional to the max MPT size set above.
 */
#define	TAVOR_MAX_MEM_MPT_SHIFT_128		0x23
#define	TAVOR_MAX_MEM_MPT_SHIFT_256		0x24

/*
 * Minimal configuration value.
 */
#define	TAVOR_MAX_MEM_MPT_SHIFT_MIN		0x1E

/*
 * Defines used by tavor_mr_deregister() to specify how much/to what extent
 * a given memory regions resources should be freed up.  TAVOR_MR_DEREG_ALL
 * says what it means, free up all the resources associated with the region.
 * TAVOR_MR_DEREG_NO_HW2SW_MPT indicates that it is unnecessary to attempt
 * the ownership transfer (from hardware to software) for the given MPT entry.
 * And TAVOR_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND indicates that it is not only
 * unnecessary to attempt the ownership transfer for MPT, but it is also
 * unnecessary to attempt to unbind the memory.
 * In general, these last two are specified when tavor_mr_deregister() is
 * called from tavor_mr_reregister(), where the MPT ownership transfer or
 * memory unbinding may have already been successfully performed.
 */
#define	TAVOR_MR_DEREG_ALL			3
#define	TAVOR_MR_DEREG_NO_HW2SW_MPT		2
#define	TAVOR_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND	1

/*
 * The following define is used by tavor_mr_rereg_xlat_helper() to determine
 * whether or not a given DMA handle can be reused.  If the DMA handle was
 * previously initialized for IOMMU bypass mapping, then it can not be reused
 * to reregister a region for DDI_DMA_STREAMING access.
 */
#define	TAVOR_MR_REUSE_DMAHDL(mr, flags)				\
	(((mr)->mr_bindinfo.bi_bypass != TAVOR_BINDMEM_BYPASS) ||	\
	    !((flags) & IBT_MR_NONCOHERENT))

/*
 * The tavor_sw_refcnt_t structure is used internally by the Tavor driver to
 * track all the information necessary to manage shared memory regions.  Since
 * a shared memory region _will_ have its own distinct MPT entry, but will
 * _share_ its MTT entries with another region, it is necessary to track the
 * number of times a given MTT structure is shared.  This ensures that it will
 * not be prematurely freed up and that can be destroyed only when it is
 * appropriate to do so.
 *
 * Each tavor_sw_refcnt_t structure contains a lock and a reference count
 * variable which are used to track the necessary information.
 *
 * The following macros (below) are used to manipulate and query the MTT
 * reference count parameters.  TAVOR_MTT_REFCNT_INIT() is used to initialize
 * a newly allocated tavor_sw_refcnt_t struct (setting the "swrc_refcnt" to 1).
 * And the TAVOR_MTT_IS_NOT_SHARED() and TAVOR_MTT_IS_SHARED() macros are
 * used to query the current status of tavor_sw_refcnt_t struct to determine
 * if its "swrc_refcnt" is one or not.
 */
typedef struct tavor_sw_refcnt_s {
	kmutex_t		swrc_lock;
	uint_t			swrc_refcnt;
} tavor_sw_refcnt_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(tavor_sw_refcnt_t::swrc_refcnt))
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_refcnt_t::swrc_lock,
    tavor_sw_refcnt_t::swrc_refcnt))
#define	TAVOR_MTT_REFCNT_INIT(swrc_tmp)		((swrc_tmp)->swrc_refcnt = 1)
#define	TAVOR_MTT_IS_NOT_SHARED(swrc_tmp)	((swrc_tmp)->swrc_refcnt == 1)
#define	TAVOR_MTT_IS_SHARED(swrc_tmp)		((swrc_tmp)->swrc_refcnt != 1)


/*
 * The tavor_bind_info_t structure is used internally by the Tavor driver to
 * track all the information necessary to perform the DMA mappings necessary
 * for memory registration.  It is specifically passed into both the
 * tavor_mr_mem_bind() and tavor_mr_mtt_write() functions which perform most
 * of the necessary operations for Tavor memory registration.
 *
 * This structure is used to pass all the information necessary for a call
 * to either ddi_dma_addr_bind_handle() or ddi_dma_buf_bind_handle().  Note:
 * the fields which need to be valid for each type of binding are slightly
 * different and that it indicated by the value in the "bi_type" field.  The
 * "bi_type" field may be set to either of the following defined values:
 * TAVOR_BINDHDL_VADDR (to indicate an "addr" bind) or TAVOR_BINDHDL_BUF (to
 * indicate a "buf" bind).
 *
 * Upon return from tavor_mr_mem_bind(), the tavor_bind_info_t struct will
 * have its "bi_dmahdl", "bi_dmacookie", and "bi_cookiecnt" fields filled in.
 * It is these values which are of particular interest to the
 * tavor_mr_mtt_write() routine (they hold the PCI mapped addresses).
 *
 * Once initialized and used in this way, the tavor_bind_info_t will not to be
 * modified in anyway until it is subsequently passed to tavor_mr_mem_unbind()
 * where the memory and resources will be unbound and reclaimed.  Note:  the
 * "bi_free_dmahdl" flag indicated whether the ddi_dma_handle_t should be
 * freed as part of the tavor_mr_mem_unbind() operation or whether it will
 * be freed later elsewhere.
 */
typedef struct tavor_bind_info_s {
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
} tavor_bind_info_t;
#define	TAVOR_BINDHDL_NONE		0
#define	TAVOR_BINDHDL_VADDR		1
#define	TAVOR_BINDHDL_BUF		2
#define	TAVOR_BINDHDL_UBUF		3

/*
 * The tavor_sw_mr_s structure is also referred to using the "tavor_mrhdl_t"
 * typedef (see tavor_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to register, reregister, deregister,
 * and perform all the myriad other operations on both memory regions _and_
 * memory windows.
 *
 * A pointer to this structure is returned from many of the IBTF's CI verbs
 * interfaces for memory registration.
 *
 * It contains pointers to the various resources allocated for a memory
 * region, i.e. MPT resource, MTT resource, and MTT reference count resource.
 * In addition it contains the tavor_bind_info_t struct used for the memory
 * bind operation on a given memory region.
 *
 * It also has a pointers to the associated PD handle, placeholders for access
 * flags, memory keys, and suggested page size for the region.  It also has
 * the necessary backpointer to the resource that corresponds to the structure
 * itself.  And lastly, it contains a placeholder for a callback which should
 * be called on memory region unpinning.
 */
struct tavor_sw_mr_s {
	kmutex_t		mr_lock;
	tavor_rsrc_t		*mr_mptrsrcp;
	tavor_rsrc_t		*mr_mttrsrcp;
	tavor_rsrc_t		*mr_mttrefcntp;
	tavor_pdhdl_t		mr_pdhdl;
	tavor_bind_info_t	mr_bindinfo;
	ibt_mr_attr_flags_t	mr_accflag;
	uint32_t		mr_lkey;
	uint32_t		mr_rkey;
	uint32_t		mr_logmttpgsz;
	tavor_rsrc_t		*mr_rsrcp;
	uint_t			mr_is_umem;
	ddi_umem_cookie_t	mr_umemcookie;
	void 			(*mr_umem_cbfunc)(void *, void *);
	void			*mr_umem_cbarg1;
	void			*mr_umem_cbarg2;
};
_NOTE(DATA_READABLE_WITHOUT_LOCK(tavor_sw_mr_s::mr_bindinfo
    tavor_sw_mr_s::mr_lkey
    tavor_sw_mr_s::mr_is_umem))
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_mr_s::mr_lock,
    tavor_sw_mr_s::mr_mptrsrcp
    tavor_sw_mr_s::mr_mttrsrcp
    tavor_sw_mr_s::mr_mttrefcntp
    tavor_sw_mr_s::mr_bindinfo
    tavor_sw_mr_s::mr_lkey
    tavor_sw_mr_s::mr_rkey
    tavor_sw_mr_s::mr_logmttpgsz
    tavor_sw_mr_s::mr_rsrcp
    tavor_sw_mr_s::mr_is_umem
    tavor_sw_mr_s::mr_umemcookie
    tavor_sw_mr_s::mr_umem_cbfunc
    tavor_sw_mr_s::mr_umem_cbarg1
    tavor_sw_mr_s::mr_umem_cbarg2))

/*
 * The tavor_mr_options_t structure is used in several of the Tavor memory
 * registration routines to provide additional option functionality.  When
 * a NULL pointer is passed in place of a pointer to this struct, it is a
 * way of specifying the "default" behavior.  Using this structure, however,
 * is a way of controlling any extended behavior.
 *
 * Currently, the only defined "extended" behaviors are for specifying whether
 * a given memory region should bypass the PCI IOMMU (TAVOR_BINDMEM_BYPASS)
 * or be mapped into the IOMMU (TAVOR_BINDMEM_NORMAL), for specifying whether
 * a given ddi_dma_handle_t should be used in the bind operation, and for
 * specifying whether a memory registration should attempt to return an IB
 * vaddr which is "zero-based" (aids in alignment contraints for QPs).
 *
 * This defaults today to always bypassing the IOMMU (can be changed by using
 * the "tavor_iommu_bypass" configuration variable), to always allocating
 * a new dma handle, and to using the virtual address passed in (i.e. not
 * "zero-based").
 */
typedef struct tavor_mr_options_s {
	ddi_dma_handle_t	mro_bind_dmahdl;
	uint_t			mro_bind_type;
	uint_t			mro_bind_override_addr;
} tavor_mr_options_t;
#define	TAVOR_BINDMEM_NORMAL		1
#define	TAVOR_BINDMEM_BYPASS		0

int tavor_dma_mr_register(tavor_state_t *state, tavor_pdhdl_t pdhdl,
    ibt_dmr_attr_t *attr_p, tavor_mrhdl_t *mrhdl);
int tavor_mr_register(tavor_state_t *state, tavor_pdhdl_t pdhdl,
    ibt_mr_attr_t *attr_p, tavor_mrhdl_t *mrhdl, tavor_mr_options_t *op);
int tavor_mr_register_buf(tavor_state_t *state, tavor_pdhdl_t pdhdl,
    ibt_smr_attr_t *attrp, struct buf *buf, tavor_mrhdl_t *mrhdl,
    tavor_mr_options_t *op);
int tavor_mr_mtt_bind(tavor_state_t *state, tavor_bind_info_t *bind,
    ddi_dma_handle_t bind_dmahdl, tavor_rsrc_t **mtt, uint_t *mtt_pgsz_bits);
int tavor_mr_mtt_unbind(tavor_state_t *state, tavor_bind_info_t *bind,
    tavor_rsrc_t *mtt);
int tavor_mr_register_shared(tavor_state_t *state, tavor_mrhdl_t mrhdl,
    tavor_pdhdl_t pdhdl, ibt_smr_attr_t *attr_p, tavor_mrhdl_t *mrhdl_new);
int tavor_mr_deregister(tavor_state_t *state, tavor_mrhdl_t *mrhdl,
    uint_t level, uint_t sleep);
int tavor_mr_query(tavor_state_t *state, tavor_mrhdl_t mrhdl,
    ibt_mr_query_attr_t *attr);
int tavor_mr_reregister(tavor_state_t *state, tavor_mrhdl_t mrhdl,
    tavor_pdhdl_t pdhdl, ibt_mr_attr_t *attr_p, tavor_mrhdl_t *mrhdl_new,
    tavor_mr_options_t *op);
int tavor_mr_reregister_buf(tavor_state_t *state, tavor_mrhdl_t mr,
    tavor_pdhdl_t pd, ibt_smr_attr_t *mr_attr, struct buf *buf,
    tavor_mrhdl_t *mrhdl_new, tavor_mr_options_t *op);
int tavor_mr_sync(tavor_state_t *state, ibt_mr_sync_t *mr_segs,
    size_t num_segs);
int tavor_mw_alloc(tavor_state_t *state, tavor_pdhdl_t pdhdl,
    ibt_mw_flags_t flags, tavor_mwhdl_t *mwhdl);
int tavor_mw_free(tavor_state_t *state, tavor_mwhdl_t *mwhdl, uint_t sleep);
void tavor_mr_keycalc(tavor_state_t *state, uint32_t indx, uint32_t *key);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_MR_H */
