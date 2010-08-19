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

#ifndef	_SYS_IB_ADAPTERS_HERMON_RSRC_H
#define	_SYS_IB_ADAPTERS_HERMON_RSRC_H

/*
 * hermon_rsrc.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Hermon Resource Management routines.
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
 * HERMON_NOSLEEP (indicating that it is not appropriate to sleep in the current
 * context.  In all other cases, this macro will return HERMON_SLEEP.
 *
 * The HERMON_CMD_SLEEP_NOSPIN and HERMON_CMD_NOSLEEP_SPIN #defines from
 * hermon_cmd.h are set to use and be compatible with the following SLEEP
 * variables.  It is important that these remain in sync so that the
 * HERMON_SLEEPFLAG_FOR_CONTEXT() macro will work in all cases.
 */
#define	HERMON_SLEEP			0
#define	HERMON_NOSLEEP			1
#define	HERMON_SLEEPFLAG_FOR_CONTEXT()					\
	((servicing_interrupt() || ddi_in_panic()) ? HERMON_NOSLEEP :	\
	    HERMON_SLEEP)

/*
 * The following #defines are used as the names for various resource pools.
 * They represent the kmem_cache and vmem_arena names, respectively.  In
 * order to provide for unique naming when multiple Hermon drivers are present,
 * the HERMON_RSRC_NAME macro below is used to append the driver's instance
 * number to the provided string.  Note: resource names should not be longer
 * than HERMON_RSRC_NAME_MAXLEN.
 */


#define	HERMON_RSRC_CACHE		"hermon_rsrc_cache"
#define	HERMON_PDHDL_CACHE		"hermon_pdhdl_cache"
#define	HERMON_MRHDL_CACHE		"hermon_mrhdl_cache"
#define	HERMON_EQHDL_CACHE		"hermon_eqhdl_cache"
#define	HERMON_CQHDL_CACHE		"hermon_cqhdl_cache"
#define	HERMON_SRQHDL_CACHE		"hermon_srqhdl_cache"
#define	HERMON_AHHDL_CACHE		"hermon_ahhdl_cache"
#define	HERMON_QPHDL_CACHE		"hermon_qphdl_cache"
#define	HERMON_REFCNT_CACHE		"hermon_refcnt_cache"

#define	HERMON_ICM_VMEM			"hermon_icm_vmem"
#define	HERMON_INMBOX_VMEM		"hermon_inmbox_vmem"
#define	HERMON_OUTMBOX_VMEM		"hermon_outmbox_vmem"
#define	HERMON_INTR_INMBOX_VMEM		"hermon_intr_inmbox_vmem"
#define	HERMON_INTR_OUTMBOX_VMEM	"hermon_intr_outmbox_vmem"
/* ICM based vmem */
#define	HERMON_CMPT_VMEM		"hermon_cmpt_vmem"
#define	HERMON_CMPT_QPC_VMEM		"hermon_cmpt_qpc_vmem"
#define	HERMON_CMPT_SRQ_VMEM		"hermon_cmpt_srq_vmem"
#define	HERMON_CMPT_CQC_VMEM		"hermon_cmpt_cqc_vmem"
#define	HERMON_CMPT_EQC_VMEM		"hermon_cmpt_eqc_vmem"
#define	HERMON_DMPT_VMEM		"hermon_dmpt_vmem"
#define	HERMON_MTT_VMEM			"hermon_mtt_vmem"
#define	HERMON_QPC_VMEM			"hermon_qpc_vmem"
#define	HERMON_SRQC_VMEM		"hermon_srqc_vmem"
#define	HERMON_RDB_VMEM			"hermon_rdb_vmem"
#define	HERMON_CQC_VMEM			"hermon_cqc_vmem"
#define	HERMON_ALTC_VMEM		"hermon_altc_vmem"
#define	HERMON_AUXC_VMEM		"hermon_auxc_vmem"
#define	HERMON_EQC_VMEM			"hermon_eqc_vmem"
#define	HERMON_MCG_VMEM			"hermon_mcg_vmem"
/* Add'd vmem arenas */
#define	HERMON_UAR_PAGE_VMEM_ATTCH	"hermon_uar_pg_vmem:a"
#define	HERMON_UAR_PAGE_VMEM_RUNTM	"hermon_uar_pg_vmem:r"
#define	HERMON_BLUEFLAME_VMEM		"hermon_blueflame_vmem"
#define	HERMON_PDHDL_VMEM		"hermon_pd_vmem"

/* Macro provided for building unique naming for multiple instance  */
#define	HERMON_RSRC_NAME(rsrc_name, string)		\
	(void) sprintf((rsrc_name), string"%08X",	\
	    state->hs_instance)
#define	HERMON_RSRC_NAME_MAXLEN		0x80

/* various cMPT types - need to concatenate w/ index to find it in ICM */
typedef enum {
	HERMON_QP_CMPT	= 0,
	HERMON_SRQ_CMPT	= 1,
	HERMON_CQ_CMPT	= 2,
	HERMON_EQ_CMPT	= 3,
	HERMON_MPT_DMPT	= 4
} hermon_mpt_rsrc_type_t;


/*
 * The following enumerated type is used to capture all the various types
 * of Hermon resources.  Note the HERMON_NUM_RESOURCES type is used as a marker
 * for the end of the resource types.  No additional resources should be
 * added after this. Note also that HERMON_NUM_ICM_RESOURCES is used similarly,
 * indicating the number of ICM resource types. If additional ICM types are
 * added, they should be added before MERMON_NUM_ICM_RESOURCES.
 */

typedef enum {
	HERMON_CMPT,		/* for sizing ICM space for control MPTs */
	HERMON_QPC,
	HERMON_SRQC,
	HERMON_CQC,
	HERMON_EQC,
	HERMON_DMPT,
	HERMON_MTT,
	HERMON_ALTC,		/* for allocation of ICM backing memory */
	HERMON_AUXC,		/* for allocation of ICM backing memory */
	HERMON_RDB,		/* for allocation of ICM backing memory */
	HERMON_CMPT_QPC,	/* for allocation of ICM backing memory */
	HERMON_CMPT_SRQC,	/* for allocation of ICM backing memory */
	HERMON_CMPT_CQC,	/* for allocation of ICM backing memory */
	HERMON_CMPT_EQC,	/* for allocation of ICM backing memory */
	HERMON_MCG,		/* type 0x0E */
	/* all types above are in ICM, all below are in non-ICM */
	HERMON_NUM_ICM_RESOURCES,
	HERMON_IN_MBOX = HERMON_NUM_ICM_RESOURCES,
	HERMON_OUT_MBOX,	/* type 0x10 */
	HERMON_PDHDL,
	HERMON_MRHDL,
	HERMON_EQHDL,
	HERMON_CQHDL,
	HERMON_QPHDL,
	HERMON_SRQHDL,
	HERMON_AHHDL,
	HERMON_REFCNT,
	HERMON_UARPG,
	HERMON_INTR_IN_MBOX,
	HERMON_INTR_OUT_MBOX,	/* type 0x1B */
	HERMON_QPC_FEXCH_PORT1,
	HERMON_QPC_FEXCH_PORT2,
	HERMON_QPC_RFCI_PORT1,
	HERMON_QPC_RFCI_PORT2,
	HERMON_NUM_RESOURCES
} hermon_rsrc_type_t;

/*
 * The following enumerated type and structures are used during resource
 * initialization.  Note: The HERMON_RSRC_CLEANUP_ALL type is used as a marker
 * for end of the cleanup steps.  No cleanup steps should be added after
 * HERMON_RSRC_CLEANUP_ALL.  Any addition steps should be added before it.
 */
typedef enum {
	HERMON_RSRC_CLEANUP_LEVEL0,
	HERMON_RSRC_CLEANUP_LEVEL1,
	HERMON_RSRC_CLEANUP_LEVEL2,
	HERMON_RSRC_CLEANUP_LEVEL3,
	HERMON_RSRC_CLEANUP_LEVEL4,
	HERMON_RSRC_CLEANUP_LEVEL5,
	HERMON_RSRC_CLEANUP_LEVEL6,
	HERMON_RSRC_CLEANUP_LEVEL7,
	HERMON_RSRC_CLEANUP_PHASE1_COMPLETE,
	HERMON_RSRC_CLEANUP_LEVEL8,
	HERMON_RSRC_CLEANUP_LEVEL9,
	HERMON_RSRC_CLEANUP_LEVEL10,
	HERMON_RSRC_CLEANUP_LEVEL10QP,
	HERMON_RSRC_CLEANUP_LEVEL10SRQ,
	HERMON_RSRC_CLEANUP_LEVEL10CQ,
	HERMON_RSRC_CLEANUP_LEVEL10EQ,
	HERMON_RSRC_CLEANUP_LEVEL11,
	HERMON_RSRC_CLEANUP_LEVEL12,
	HERMON_RSRC_CLEANUP_LEVEL13,
	HERMON_RSRC_CLEANUP_LEVEL14,
	HERMON_RSRC_CLEANUP_LEVEL15,
	HERMON_RSRC_CLEANUP_LEVEL16,
	HERMON_RSRC_CLEANUP_LEVEL17,
	HERMON_RSRC_CLEANUP_LEVEL18,
	HERMON_RSRC_CLEANUP_LEVEL19,
	HERMON_RSRC_CLEANUP_LEVEL20,
	HERMON_RSRC_CLEANUP_LEVEL21,
	HERMON_RSRC_CLEANUP_LEVEL22,
	HERMON_RSRC_CLEANUP_LEVEL23,
	HERMON_RSRC_CLEANUP_LEVEL24,
	HERMON_RSRC_CLEANUP_LEVEL25,
	HERMON_RSRC_CLEANUP_LEVEL26,
	HERMON_RSRC_CLEANUP_LEVEL27,
	HERMON_RSRC_CLEANUP_LEVEL28,
	HERMON_RSRC_CLEANUP_LEVEL29,
	HERMON_RSRC_CLEANUP_LEVEL30,
	HERMON_RSRC_CLEANUP_LEVEL31,
	/* No more cleanup steps below this point! */
	HERMON_RSRC_CLEANUP_ALL
} hermon_rsrc_cleanup_level_t;

/*
 * The hermon_rsrc_mbox_info_t structure is used when initializing the two
 * Hermon mailbox types ("In" and "Out").  This structure contains the
 * requested number and size of the mailboxes, and the resource pool from
 * which the other relevant properties will come.
 */
typedef struct hermon_rsrc_mbox_info_s {
	uint64_t		mbi_num;
	uint64_t		mbi_size;
	hermon_rsrc_pool_info_t *mbi_rsrcpool;
} hermon_rsrc_mbox_info_t;

/*
 * The hermon_rsrc_hw_entry_info_t structure is used when initializing the
 * Hermon HW entry types.  This structure contains the requested number of
 * entries for the resource.  That value is compared against the maximum
 * number (usually determined as a result of the Hermon QUERY_DEV_CAP command).
 * In addition it contains a number of requested entries to be "pre-allocated"
 * (this is generally because the Hermon hardware requires a certain number
 * for its own purposes).  Lastly the resource pool and resource name
 * information.
 */
typedef struct hermon_rsrc_hw_entry_info_s {
	uint64_t		hwi_num;
	uint64_t		hwi_max;
	uint64_t		hwi_prealloc;
	hermon_rsrc_pool_info_t *hwi_rsrcpool;
	char			*hwi_rsrcname;
} hermon_rsrc_hw_entry_info_t;

/*
 * The hermon_rsrc_sw_hdl_info_t structure is used when initializing the
 * Hermon software handle types.  This structure also contains the requested
 * number of handles for the resource.  That value is compared against a
 * maximum number passed in.  Because many of the software handle resource
 * types are managed through the use of kmem_cache, fields are provided for
 * specifying cache constructor and destructor methods.  Just like above,
 * there is space for resource pool and resource name information.  And,
 * somewhat like above, there is space to provide information (size, type,
 * pointer to table, etc). about any "pre-allocated" resources that need to
 * be set aside.
 * Note specifically that the "swi_flags" field may contain any of the flags
 * #define'd below.  The HERMON_SWHDL_KMEMCACHE_INIT flag indicates that the
 * given resource should have a kmem_cache setup for it, and the
 * HERMON_SWHDL_TABLE_INIT flag indicates that some preallocation (as defined
 * by the "swi_num" and "swi_prealloc_sz" fields) should be done, with the
 * resulting table pointer passed back in "swi_table_ptr".
 */
typedef struct hermon_rsrc_sw_hdl_info_s {
	uint64_t		swi_num;
	uint64_t		swi_max;
	uint64_t		swi_prealloc_sz;
	hermon_rsrc_pool_info_t 	*swi_rsrcpool;
	int (*swi_constructor)(void *, void *, int);
	void (*swi_destructor)(void *, void *);
	char			*swi_rsrcname;
	uint_t			swi_flags;
	void			*swi_table_ptr;
} hermon_rsrc_sw_hdl_info_t;
#define	HERMON_SWHDL_NOFLAGS		0
#define	HERMON_SWHDL_KMEMCACHE_INIT	(1 << 0)
#define	HERMON_SWHDL_TABLE_INIT		(1 << 1)


/*
 * The following structure is used to specify (at init time) and to track
 * (during allocation and freeing) all the useful information regarding a
 * particular resource type.  An array of these resources (indexed by
 * resource type) is allocated at driver startup time.  It is available
 * through the driver's soft state structure.
 * Each resource has an indication of its type and its location.  Resources
 * may be located in one of three possible places - in the Hermon ICM memory
 * (device virtual, backed by system memory),in system memory, or in
 * Hermon UAR memory (residing behind BAR2).
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
 * soft state structure of the Hermon driver instance with which it is
 * associated.
 */
struct hermon_rsrc_pool_info_s {
	hermon_rsrc_type_t	rsrc_type;
	uint_t			rsrc_loc;
	uint64_t		rsrc_pool_size; /* table size (num x size) */
	uint64_t		rsrc_align;
	uint_t			rsrc_shift;
	uint_t			rsrc_quantum; /* size of each content */
	void			*rsrc_start; /* phys start addr of table */
	vmem_t			*rsrc_vmp; /* vmem arena for table */
	hermon_state_t		*rsrc_state;
	void			*rsrc_private;
};
#define	HERMON_IN_ICM			0x0
#define	HERMON_IN_SYSMEM		0x1
#define	HERMON_IN_UAR			0x2

/*
 * The hermon_rsrc_priv_mbox_t structure is used to pass along additional
 * information about the mailbox types.  Specifically, by containing the
 * DMA attributes, access handle, dev access handle, etc., it provides enough
 * information that each mailbox can be later by bound/unbound/etc. for
 * DMA access by the hardware.  Note: we can also specify (using the
 * "pmb_xfer_mode" field), whether a given mailbox type should be bound for
 * DDI_DMA_STREAMING or DDI_DMA_CONSISTENT operations.
 */
typedef struct hermon_rsrc_priv_mbox_s {
	dev_info_t		*pmb_dip;
	ddi_dma_attr_t		pmb_dmaattr;
	/* JBDB what is this handle for? */
	ddi_acc_handle_t	pmb_acchdl;
	ddi_device_acc_attr_t	pmb_devaccattr;
	uint_t			pmb_xfer_mode;
} hermon_rsrc_priv_mbox_t;

/*
 * The hermon_rsrc_t structure is the structure returned by the Hermon resource
 * allocation routines.  It contains all the necessary information about the
 * allocated object.  Specifically, it provides an address where the object
 * can be accessed.  It also provides the length and index (specifically, for
 * those resources that are accessed from tables).  In addition it can provide
 * an access handles and DMA handle to be used when accessing or setting DMA
 * to a specific object.  Note: not all of this information is valid for all
 * object types.  See the consumers of each object for more explanation of
 * which fields are used (and for what purpose).
 */
struct hermon_rsrc_s {
	hermon_rsrc_type_t	rsrc_type;
	void			*hr_addr;
	uint32_t		hr_len;
	uint32_t		hr_indx;
	ddi_acc_handle_t	hr_acchdl;
	ddi_dma_handle_t	hr_dmahdl;
};

/*
 * The following are the Hermon Resource Management routines that accessible
 * externally (i.e. throughout the rest of the Hermon driver software).
 * These include the alloc/free routines, the initialization routines, which
 * are broken into two phases (see hermon_rsrc.c for further explanation),
 * and the Hermon resource cleanup routines (which are used at driver detach()
 * time.
 */
int hermon_rsrc_alloc(hermon_state_t *state, hermon_rsrc_type_t rsrc,
    uint_t num, uint_t sleepflag, hermon_rsrc_t **hdl);
void hermon_rsrc_free(hermon_state_t *state, hermon_rsrc_t **hdl);
int hermon_rsrc_init_phase1(hermon_state_t *state);
int hermon_rsrc_init_phase2(hermon_state_t *state);
void hermon_rsrc_fini(hermon_state_t *state,
    hermon_rsrc_cleanup_level_t clean);

/* Exporting resource reservation capabilitity to FCoIB */
int hermon_rsrc_reserve(hermon_state_t *state, hermon_rsrc_type_t rsrc,
    uint_t num, uint_t sleepflag, hermon_rsrc_t **hdl);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_RSRC_H */
