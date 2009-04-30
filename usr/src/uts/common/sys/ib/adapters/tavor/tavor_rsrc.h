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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_RSRC_H
#define	_SYS_IB_ADAPTERS_TAVOR_RSRC_H

/*
 * tavor_rsrc.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Tavor Resource Management routines.
 *    Specifically it contains the resource names, resource types, and
 *    structures used for enabling both init/fini and alloc/free operations.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/disp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The above extern and the following #defines and macro are used to determine
 * the current context for purposes of setting the sleepflag.  If the calling
 * thread is running in the interrupt context, then macro will return
 * TAVOR_NOSLEEP (indicating that it is not appropriate to sleep in the current
 * context.  In all other cases, this macro will return TAVOR_SLEEP.
 *
 * The TAVOR_CMD_SLEEP_NOSPIN and TAVOR_CMD_NOSLEEP_SPIN #defines from
 * tavor_cmd.h are set to use and be compatible with the following SLEEP
 * variables.  It is important that these remain in sync so that the
 * TAVOR_SLEEPFLAG_FOR_CONTEXT() macro will work in all cases.
 */
#define	TAVOR_SLEEP			0
#define	TAVOR_NOSLEEP			1
#define	TAVOR_SLEEPFLAG_FOR_CONTEXT()					\
	((servicing_interrupt() || ddi_in_panic()) ? TAVOR_NOSLEEP :	\
	    TAVOR_SLEEP)

/*
 * The following #defines are used as the names for various resource pools.
 * They represent the kmem_cache and vmem_arena names, respectively.  In
 * order to provide for unique naming when multiple Tavor drivers are present,
 * the TAVOR_RSRC_NAME macro below is used to append the driver's instance
 * number to the provided string.  Note: resource names should not be longer
 * than TAVOR_RSRC_NAME_MAXLEN.
 */
#define	TAVOR_RSRC_CACHE		"tavor_rsrc_cache"
#define	TAVOR_PDHDL_CACHE		"tavor_pdhdl_cache"
#define	TAVOR_MRHDL_CACHE		"tavor_mrhdl_cache"
#define	TAVOR_EQHDL_CACHE		"tavor_eqhdl_cache"
#define	TAVOR_CQHDL_CACHE		"tavor_cqhdl_cache"
#define	TAVOR_SRQHDL_CACHE		"tavor_srqhdl_cache"
#define	TAVOR_AHHDL_CACHE		"tavor_ahhdl_cache"
#define	TAVOR_QPHDL_CACHE		"tavor_qphdl_cache"
#define	TAVOR_REFCNT_CACHE		"tavor_refcnt_cache"

#define	TAVOR_DDR_VMEM			"tavor_ddr_vmem"
#define	TAVOR_DDR_INMBOX_VMEM		"tavor_ddr_inmbox_vmem"
#define	TAVOR_DDR_OUTMBOX_VMEM		"tavor_ddr_outmbox_vmem"
#define	TAVOR_DDR_INTR_INMBOX_VMEM	"tavor_ddr_intr_inmbox_vmem"
#define	TAVOR_DDR_INTR_OUTMBOX_VMEM	"tavor_ddr_intr_outmbox_vmem"
#define	TAVOR_DDR_QPC_VMEM		"tavor_ddr_qpc_vmem"
#define	TAVOR_DDR_CQC_VMEM		"tavor_ddr_cqc_vmem"
#define	TAVOR_DDR_SRQC_VMEM		"tavor_ddr_srqc_vmem"
#define	TAVOR_DDR_EQC_VMEM		"tavor_ddr_eqc_vmem"
#define	TAVOR_DDR_EQPC_VMEM		"tavor_ddr_eqpc_vmem"
#define	TAVOR_DDR_RDB_VMEM		"tavor_ddr_rdb_vmem"
#define	TAVOR_DDR_MCG_VMEM		"tavor_ddr_mcg_vmem"
#define	TAVOR_DDR_MPT_VMEM		"tavor_ddr_mpt_vmem"
#define	TAVOR_DDR_MTT_VMEM		"tavor_ddr_mtt_vmem"
#define	TAVOR_DDR_UARSCR_VMEM		"tavor_ddr_uarscr_vmem"
#define	TAVOR_DDR_UDAV_VMEM		"tavor_ddr_udav_vmem"
#define	TAVOR_UAR_VMEM			"tavor_uar_vmem"
#define	TAVOR_PDHDL_VMEM		"tavor_pd_vmem"

/* Macro provided for building unique naming for multiple instance  */
#define	TAVOR_RSRC_NAME(rsrc_name, string)		\
	(void) sprintf((rsrc_name), string"%08X",	\
	    state->ts_instance)
#define	TAVOR_RSRC_NAME_MAXLEN		0x80

/*
 * The following enumerated type is used to capture all the various types
 * of Tavor resources.  Note: The TAVOR_NUM_RESOURCES type is used as a
 * marker for the end of the resource types.  No additional resources should
 * be added after TAVOR_NUM_RESOURCES.  Any addition resources should be
 * added before it.
 */
typedef enum {
	TAVOR_QPC,
	TAVOR_CQC,
	TAVOR_SRQC,
	TAVOR_EQC,
	TAVOR_EQPC,
	TAVOR_RDB,
	TAVOR_MCG,
	TAVOR_MPT,
	TAVOR_MTT,
	TAVOR_UAR_SCR,
	TAVOR_UDAV,
	TAVOR_IN_MBOX,
	TAVOR_OUT_MBOX,
	TAVOR_PDHDL,
	TAVOR_MRHDL,
	TAVOR_EQHDL,
	TAVOR_CQHDL,
	TAVOR_SRQHDL,
	TAVOR_AHHDL,
	TAVOR_QPHDL,
	TAVOR_REFCNT,
	TAVOR_UARPG,
	TAVOR_INTR_IN_MBOX,
	TAVOR_INTR_OUT_MBOX,
	/* No more resources types below this point! */
	TAVOR_NUM_RESOURCES
} tavor_rsrc_type_t;


/*
 * The following enumerated type and structures are used during resource
 * initialization.  Note: The TAVOR_RSRC_CLEANUP_ALL type is used as a marker
 * for end of the cleanup steps.  No cleanup steps should be added after
 * TAVOR_RSRC_CLEANUP_ALL.  Any addition steps should be added before it.
 */
typedef enum {
	TAVOR_RSRC_CLEANUP_LEVEL0,
	TAVOR_RSRC_CLEANUP_LEVEL1,
	TAVOR_RSRC_CLEANUP_LEVEL2,
	TAVOR_RSRC_CLEANUP_LEVEL3,
	TAVOR_RSRC_CLEANUP_PHASE1_COMPLETE,
	TAVOR_RSRC_CLEANUP_LEVEL5,
	TAVOR_RSRC_CLEANUP_LEVEL6,
	TAVOR_RSRC_CLEANUP_LEVEL7,
	TAVOR_RSRC_CLEANUP_LEVEL8,
	TAVOR_RSRC_CLEANUP_LEVEL9,
	TAVOR_RSRC_CLEANUP_LEVEL10,
	TAVOR_RSRC_CLEANUP_LEVEL11,
	TAVOR_RSRC_CLEANUP_LEVEL12,
	TAVOR_RSRC_CLEANUP_LEVEL13,
	TAVOR_RSRC_CLEANUP_LEVEL14,
	TAVOR_RSRC_CLEANUP_LEVEL15,
	TAVOR_RSRC_CLEANUP_LEVEL16,
	TAVOR_RSRC_CLEANUP_LEVEL17,
	TAVOR_RSRC_CLEANUP_LEVEL18,
	TAVOR_RSRC_CLEANUP_LEVEL19,
	TAVOR_RSRC_CLEANUP_LEVEL20,
	TAVOR_RSRC_CLEANUP_LEVEL21,
	TAVOR_RSRC_CLEANUP_LEVEL22,
	TAVOR_RSRC_CLEANUP_LEVEL23,
	TAVOR_RSRC_CLEANUP_LEVEL24,
	TAVOR_RSRC_CLEANUP_LEVEL25,
	TAVOR_RSRC_CLEANUP_LEVEL26,
	TAVOR_RSRC_CLEANUP_LEVEL27,
	TAVOR_RSRC_CLEANUP_LEVEL28,
	TAVOR_RSRC_CLEANUP_LEVEL29,
	TAVOR_RSRC_CLEANUP_LEVEL30,
	/* No more cleanup steps below this point! */
	TAVOR_RSRC_CLEANUP_ALL
} tavor_rsrc_cleanup_level_t;

/*
 * The tavor_rsrc_mbox_info_t structure is used when initializing the two
 * Tavor mailbox types ("In" and "Out").  This structure contains the
 * requested number and size of the mailboxes, the resource pool from which
 * the other relevant properties will come, and the name of the resource
 */
typedef struct tavor_rsrc_mbox_info_s {
	uint64_t		mbi_num;
	uint64_t		mbi_size;
	tavor_rsrc_pool_info_t 	*mbi_rsrcpool;
	char			*mbi_rsrcname;
} tavor_rsrc_mbox_info_t;

/*
 * The tavor_rsrc_hw_entry_info_t structure is used when initializing the
 * Tavor HW entry types.  This structure contains the requested number of
 * entries for the resource.  That value is compared against the maximum
 * number (usually determined as a result of the Tavor QUERY_DEV_LIM command).
 * In addition is contains a number of requested entries to be "pre-allocated"
 * (this is generally because the Tavor hardware requires a certain number
 * for its own purposes).  Lastly the resource pool and resource name
 * information.
 */
typedef struct tavor_rsrc_hw_entry_info_s {
	uint64_t		hwi_num;
	uint64_t		hwi_max;
	uint64_t		hwi_prealloc;
	tavor_rsrc_pool_info_t 	*hwi_rsrcpool;
	char			*hwi_rsrcname;
} tavor_rsrc_hw_entry_info_t;

/*
 * The tavor_rsrc_sw_hdl_info_t structure is used when initializing the
 * Tavor software handle types.  This structure also contains the requested
 * number of handles for the resource.  That value is compared against a
 * maximum number passed in.  Because many of the software handle resource
 * types are managed through the use of kmem_cache, fields are provided for
 * specifying cache constructor and destructor methods.  Just like above,
 * there is space for resource pool and resource name information.  And,
 * somewhat like above, there is space to provide information (size, type,
 * pointer to table, etc). about any "pre-allocated" resources that need to
 * be set aside.
 * Note specifically that the "swi_flags" field may contain any of the flags
 * #define'd below.  The TAVOR_SWHDL_KMEMCACHE_INIT flag indicates that the
 * given resource should have a kmem_cache setup for it, and the
 * TAVOR_SWHDL_TABLE_INIT flag indicates that some preallocation (as defined
 * by the "swi_num" and "swi_prealloc_sz" fields) should be done, with the
 * resulting table pointer passed back in "swi_table_ptr".
 */
typedef struct tavor_rsrc_sw_hdl_info_s {
	uint64_t		swi_num;
	uint64_t		swi_max;
	uint64_t		swi_prealloc_sz;
	tavor_rsrc_pool_info_t 	*swi_rsrcpool;
	int (*swi_constructor)(void *, void *, int);
	void (*swi_destructor)(void *, void *);
	char			*swi_rsrcname;
	uint_t			swi_flags;
	void			*swi_table_ptr;
} tavor_rsrc_sw_hdl_info_t;
#define	TAVOR_SWHDL_NOFLAGS		0
#define	TAVOR_SWHDL_KMEMCACHE_INIT	(1 << 0)
#define	TAVOR_SWHDL_TABLE_INIT		(1 << 1)


/*
 * The following structure is used to specify (at init time) and to track
 * (during allocation and freeing) all the useful information regarding a
 * particular resource type.  An array of these resources (indexed by
 * resource type) is allocated at driver startup time.  It is available
 * through the driver's soft state structure.
 * Each resource has an indication of its type and its location.  Resources
 * may be located in one of three possible places - in Tavor DDR memory,
 * in system memory, or in Tavor UAR memory.
 * Each resource pool also has properties associated with it and the object
 * that make up the pool.  These include the pool's size, the size of the
 * individual objects (rsrc_quantum), any alignment restrictions placed on
 * the pool of objects, and the shift size (log2) of each object.
 * In addition (depending on object type) the "rsrc_ddr_offset" field may
 * indicate where in DDR memory a given resource pool is located (e.g. a
 * QP context table).  It may have a pointer to a vmem_arena for that table
 * and/or it may point to some other private information (rsrc_private)
 * specific to the given object type.
 * Always, though, the resource pool pointer provides a pointer back to the
 * soft state structure of the Tavor driver instance with which it is
 * associated.
 */
struct tavor_rsrc_pool_info_s {
	tavor_rsrc_type_t	rsrc_type;
	uint_t			rsrc_loc;
	uint64_t		rsrc_pool_size;
	uint64_t		rsrc_align;
	uint_t			rsrc_shift;
	uint_t			rsrc_quantum;
	void			*rsrc_start;
	void			*rsrc_ddr_offset;
	vmem_t			*rsrc_vmp;
	tavor_state_t		*rsrc_state;
	void			*rsrc_private;
};
#define	TAVOR_IN_DDR			0x0
#define	TAVOR_IN_SYSMEM			0x1
#define	TAVOR_IN_UAR			0x2

/*
 * The tavor_rsrc_priv_mbox_t structure is used to pass along additional
 * information about the mailbox types.  Specifically, by containing the
 * DMA attributes, access handle, dev access handle, etc., it provides enough
 * information that each mailbox can be later by bound/unbound/etc. for
 * DMA access by the hardware.  Note: we can also specify (using the
 * "pmb_xfer_mode" field), whether a given mailbox type should be bound for
 * DDI_DMA_STREAMING or DDI_DMA_CONSISTENT operations.
 */
typedef struct tavor_rsrc_priv_mbox_s {
	dev_info_t		*pmb_dip;
	ddi_dma_attr_t		pmb_dmaattr;
	ddi_acc_handle_t	pmb_acchdl;
	ddi_device_acc_attr_t	pmb_devaccattr;
	uint_t			pmb_xfer_mode;
} tavor_rsrc_priv_mbox_t;

/*
 * The tavor_rsrc_t structure is the structure returned by the Tavor resource
 * allocation routines.  It contains all the necessary information about the
 * allocated object.  Specifically, it provides an address where the object
 * can be accessed.  It also provides the length and index (specifically, for
 * those resources that are accessed from tables).  In addition it can provide
 * an access handles and DMA handle to be used when accessing or setting DMA
 * to a specific object.  Note: not all of this information is valid for all
 * object types.  See the consumers of each object for more explanation of
 * which fields are used (and for what purpose).
 */
struct tavor_rsrc_s {
	tavor_rsrc_type_t	rsrc_type;
	void			*tr_addr;
	uint32_t		tr_len;
	uint32_t		tr_indx;
	ddi_acc_handle_t	tr_acchdl;
	ddi_dma_handle_t	tr_dmahdl;
};


/*
 * The following are the Tavor Resource Management routines that accessible
 * externally (i.e. throughout the rest of the Tavor driver software).
 * These include the alloc/free routines, the initialization routines, which
 * are broken into two phases (see tavor_rsrc.c for further explanation),
 * and the Tavor resource cleanup routines (which are used at driver detach()
 * time.
 */
int tavor_rsrc_alloc(tavor_state_t *state, tavor_rsrc_type_t rsrc,
    uint_t num, uint_t sleepflag, tavor_rsrc_t **hdl);
void tavor_rsrc_free(tavor_state_t *state, tavor_rsrc_t **hdl);
int tavor_rsrc_init_phase1(tavor_state_t *state);
int tavor_rsrc_init_phase2(tavor_state_t *state);
void tavor_rsrc_fini(tavor_state_t *state,
    tavor_rsrc_cleanup_level_t clean);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_RSRC_H */
