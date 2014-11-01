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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tavor_rsrc.c
 *    Tavor Resource Management Routines
 *
 *    Implements all the routines necessary for setup, teardown, and
 *    alloc/free of all Tavor resources, including those that are managed
 *    by Tavor hardware or which live in Tavor's direct attached DDR memory.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/vmem.h>
#include <sys/bitmap.h>

#include <sys/ib/adapters/tavor/tavor.h>

/*
 * The following routines are used for initializing and destroying
 * the resource pools used by the Tavor resource allocation routines.
 * They consist of four classes of object:
 *
 * Mailboxes:  The "In" and "Out" mailbox types are used by the Tavor
 *    command interface routines.  Mailboxes are used to pass information
 *    back and forth to the Tavor firmware.  Either type of mailbox may
 *    be allocated from Tavor's direct attached DDR memory or from system
 *    memory (although currently all "In" mailboxes are in DDR and all "out"
 *    mailboxes come from system memory.
 *
 * HW entry objects:  These objects represent resources required by the Tavor
 *    hardware.  These objects include things like Queue Pair contexts (QPC),
 *    Completion Queue contexts (CQC), Event Queue contexts (EQC), RDB (for
 *    supporting RDMA Read/Atomic), Multicast Group entries (MCG), Memory
 *    Protection Table entries (MPT), Memory Translation Table entries (MTT).
 *
 *    What these objects all have in common is that they are each required
 *    to come from DDR memory, they are always allocated from tables, and
 *    they are not to be directly accessed (read or written) by driver
 *    software.
 *    One notable exceptions to this rule are the Extended QP contexts (EQPC),
 *    and the UAR scratch area (UAR_SCR), both of which are not directly
 *    accessible through the Tavor resource allocation routines, but both
 *    of which are also required to reside in DDR memory and are not to be
 *    manipulated by driver software (they are privately managed by Tavor
 *    hardware).
 *    The other notable exceptions are the UAR pages (UAR_PG) which are
 *    allocated from the UAR address space rather than DDR, and the UD
 *    address vectors (UDAV) which are similar to the common object types
 *    with the major difference being that UDAVs _are_ directly read and
 *    written by driver software.
 *
 * SW handle objects: These objects represent resources required by Tavor
 *    driver software.  They are primarily software tracking structures,
 *    which are allocated from system memory (using kmem_cache).  Several of
 *    the objects have both a "constructor" and "destructor" method
 *    associated with them (see below).
 *
 * Protection Domain (PD) handle objects:  These objects are very much like
 *    a SW handle object with the notable difference that all PD handle
 *    objects have an actual Protection Domain number (PD) associated with
 *    them (and the PD number is allocated/managed through a separate
 *    vmem_arena specifically set aside for this purpose.
 */

static int tavor_rsrc_mbox_init(tavor_state_t *state,
    tavor_rsrc_mbox_info_t *info);
static void tavor_rsrc_mbox_fini(tavor_state_t *state,
    tavor_rsrc_mbox_info_t *info);

static int tavor_rsrc_hw_entries_init(tavor_state_t *state,
    tavor_rsrc_hw_entry_info_t *info);
static void tavor_rsrc_hw_entries_fini(tavor_state_t *state,
    tavor_rsrc_hw_entry_info_t *info);

static int tavor_rsrc_sw_handles_init(tavor_state_t *state,
    tavor_rsrc_sw_hdl_info_t *info);
static void tavor_rsrc_sw_handles_fini(tavor_state_t *state,
    tavor_rsrc_sw_hdl_info_t *info);

static int tavor_rsrc_pd_handles_init(tavor_state_t *state,
    tavor_rsrc_sw_hdl_info_t *info);
static void tavor_rsrc_pd_handles_fini(tavor_state_t *state,
    tavor_rsrc_sw_hdl_info_t *info);

/*
 * The following routines are used for allocating and freeing the specific
 * types of objects described above from their associated resource pools.
 */
static int tavor_rsrc_mbox_alloc(tavor_rsrc_pool_info_t *pool_info,
    uint_t num, tavor_rsrc_t *hdl);
static void tavor_rsrc_mbox_free(tavor_rsrc_pool_info_t *pool_info,
    tavor_rsrc_t *hdl);

static int tavor_rsrc_hw_entry_alloc(tavor_rsrc_pool_info_t *pool_info,
    uint_t num, uint_t num_align, ddi_acc_handle_t acc_handle,
    uint_t sleepflag, tavor_rsrc_t *hdl);
static void tavor_rsrc_hw_entry_free(tavor_rsrc_pool_info_t *pool_info,
    tavor_rsrc_t *hdl);

static int tavor_rsrc_swhdl_alloc(tavor_rsrc_pool_info_t *pool_info,
    uint_t sleepflag, tavor_rsrc_t *hdl);
static void tavor_rsrc_swhdl_free(tavor_rsrc_pool_info_t *pool_info,
    tavor_rsrc_t *hdl);

static int tavor_rsrc_pdhdl_alloc(tavor_rsrc_pool_info_t *pool_info,
    uint_t sleepflag, tavor_rsrc_t *hdl);
static void tavor_rsrc_pdhdl_free(tavor_rsrc_pool_info_t *pool_info,
    tavor_rsrc_t *hdl);

/*
 * The following routines are the constructors and destructors for several
 * of the SW handle type objects.  For certain types of SW handles objects
 * (all of which are implemented using kmem_cache), we need to do some
 * special field initialization (specifically, mutex_init/destroy).  These
 * routines enable that init and teardown.
 */
static int tavor_rsrc_pdhdl_constructor(void *pd, void *priv, int flags);
static void tavor_rsrc_pdhdl_destructor(void *pd, void *state);
static int tavor_rsrc_cqhdl_constructor(void *cq, void *priv, int flags);
static void tavor_rsrc_cqhdl_destructor(void *cq, void *state);
static int tavor_rsrc_qphdl_constructor(void *cq, void *priv, int flags);
static void tavor_rsrc_qphdl_destructor(void *cq, void *state);
static int tavor_rsrc_srqhdl_constructor(void *srq, void *priv, int flags);
static void tavor_rsrc_srqhdl_destructor(void *srq, void *state);
static int tavor_rsrc_refcnt_constructor(void *rc, void *priv, int flags);
static void tavor_rsrc_refcnt_destructor(void *rc, void *state);
static int tavor_rsrc_ahhdl_constructor(void *ah, void *priv, int flags);
static void tavor_rsrc_ahhdl_destructor(void *ah, void *state);
static int tavor_rsrc_mrhdl_constructor(void *mr, void *priv, int flags);
static void tavor_rsrc_mrhdl_destructor(void *mr, void *state);

/*
 * Special routine to calculate and return the size of a MCG object based
 * on current driver configuration (specifically, the number of QP per MCG
 * that has been configured.
 */
static int tavor_rsrc_mcg_entry_get_size(tavor_state_t *state,
    uint_t *mcg_size_shift);


/*
 * tavor_rsrc_alloc()
 *
 *    Context: Can be called from interrupt or base context.
 *    The "sleepflag" parameter is used by all object allocators to
 *    determine whether to SLEEP for resources or not.
 */
int
tavor_rsrc_alloc(tavor_state_t *state, tavor_rsrc_type_t rsrc, uint_t num,
    uint_t sleepflag, tavor_rsrc_t **hdl)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_rsrc_t		*tmp_rsrc_hdl;
	int			flag, status = DDI_FAILURE;

	TAVOR_TNF_ENTER(tavor_rsrc_alloc);

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	rsrc_pool = &state->ts_rsrc_hdl[rsrc];
	ASSERT(rsrc_pool != NULL);

	/*
	 * Allocate space for the object used to track the resource handle
	 */
	flag = (sleepflag == TAVOR_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	tmp_rsrc_hdl = (tavor_rsrc_t *)kmem_cache_alloc(state->ts_rsrc_cache,
	    flag);
	if (tmp_rsrc_hdl == NULL) {
		TNF_PROBE_0(tavor_rsrc_alloc_kmca_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_rsrc_alloc);
		return (DDI_FAILURE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*tmp_rsrc_hdl))

	/*
	 * Set rsrc_hdl type.  This is later used by the tavor_rsrc_free call
	 * to know what type of resource is being freed.
	 */
	tmp_rsrc_hdl->rsrc_type = rsrc;

	/*
	 * Depending on resource type, call the appropriate alloc routine
	 */
	switch (rsrc_pool->rsrc_type) {
	case TAVOR_IN_MBOX:
	case TAVOR_OUT_MBOX:
	case TAVOR_INTR_IN_MBOX:
	case TAVOR_INTR_OUT_MBOX:
		status = tavor_rsrc_mbox_alloc(rsrc_pool, num, tmp_rsrc_hdl);
		break;

	case TAVOR_QPC:
	case TAVOR_CQC:
	case TAVOR_SRQC:
	case TAVOR_EQC:
	case TAVOR_RDB:
		/*
		 * Because these objects are NOT accessed by Tavor driver
		 * software, we set the acc_handle parameter to zero.  But
		 * if they are allocated in multiples, we specify here that
		 * they must be aligned on a more restrictive boundary.
		 */
		status = tavor_rsrc_hw_entry_alloc(rsrc_pool, num, num, 0,
		    sleepflag, tmp_rsrc_hdl);
		break;

	case TAVOR_MPT:
		/*
		 * Because these MPT objects are sometimes accessed by Tavor
		 * driver software (FMR), we set the acc_handle parameter.  But
		 * if they are allocated in multiples, we specify here that
		 * they must be aligned on a more restrictive boundary.
		 */
		status = tavor_rsrc_hw_entry_alloc(rsrc_pool, num, num,
		    state->ts_reg_ddrhdl, sleepflag, tmp_rsrc_hdl);
		break;

	case TAVOR_MCG:
		/*
		 * Tavor MCG entries are also NOT accessed by Tavor driver
		 * software, but because MCG entries do not have the same
		 * alignnment restrictions we loosen the constraint here.
		 */
		status = tavor_rsrc_hw_entry_alloc(rsrc_pool, num, 1, 0,
		    sleepflag, tmp_rsrc_hdl);
		break;

	case TAVOR_MTT:
	case TAVOR_UDAV:
		/*
		 * Because MTT segments are among the few HW resources that
		 * may be allocated in odd numbers, we specify a less
		 * restrictive alignment than for the above resources.
		 *
		 * Also because both UDAV and MTT segment objects are read
		 * and/or written by Tavor driver software, we set the
		 * acc_handle parameter to point to the ddi_acc_handle_t for
		 * the Tavor DDR memory.
		 */
		status = tavor_rsrc_hw_entry_alloc(rsrc_pool, num, 1,
		    state->ts_reg_ddrhdl, sleepflag, tmp_rsrc_hdl);
		break;

	case TAVOR_UARPG:
		/*
		 * Because UAR pages are written by Tavor driver software (for
		 * doorbells), we set the acc_handle parameter to point to
		 * the ddi_acc_handle_t for the Tavor UAR memory.
		 */
		status = tavor_rsrc_hw_entry_alloc(rsrc_pool, num, 1,
		    state->ts_reg_uarhdl, sleepflag, tmp_rsrc_hdl);
		break;

	case TAVOR_MRHDL:
	case TAVOR_EQHDL:
	case TAVOR_CQHDL:
	case TAVOR_SRQHDL:
	case TAVOR_AHHDL:
	case TAVOR_QPHDL:
	case TAVOR_REFCNT:
		status = tavor_rsrc_swhdl_alloc(rsrc_pool, sleepflag,
		    tmp_rsrc_hdl);
		break;

	case TAVOR_PDHDL:
		status = tavor_rsrc_pdhdl_alloc(rsrc_pool, sleepflag,
		    tmp_rsrc_hdl);
		break;

	default:
		TAVOR_WARNING(state, "unexpected resource type in alloc");
		TNF_PROBE_0(tavor_rsrc_alloc_inv_rsrctype_fail,
		    TAVOR_TNF_ERROR, "");
		break;
	}

	/*
	 * If the resource allocation failed, then free the special resource
	 * tracking structure and return failure.  Otherwise return the
	 * handle for the resource tracking structure.
	 */
	if (status != DDI_SUCCESS) {
		kmem_cache_free(state->ts_rsrc_cache, tmp_rsrc_hdl);
		tmp_rsrc_hdl = NULL;
		TNF_PROBE_1(tavor_rsrc_alloc_fail, TAVOR_TNF_ERROR, "",
		    tnf_uint, rsrc_type, rsrc_pool->rsrc_type);
		TAVOR_TNF_EXIT(tavor_rsrc_alloc);
		return (DDI_FAILURE);
	} else {
		*hdl = tmp_rsrc_hdl;
		TAVOR_TNF_EXIT(tavor_rsrc_alloc);
		return (DDI_SUCCESS);
	}
}


/*
 * tavor_rsrc_free()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_rsrc_free(tavor_state_t *state, tavor_rsrc_t **hdl)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;

	TAVOR_TNF_ENTER(tavor_rsrc_free);

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	rsrc_pool = &state->ts_rsrc_hdl[(*hdl)->rsrc_type];
	ASSERT(rsrc_pool != NULL);

	/*
	 * Depending on resource type, call the appropriate free routine
	 */
	switch (rsrc_pool->rsrc_type) {
	case TAVOR_IN_MBOX:
	case TAVOR_OUT_MBOX:
	case TAVOR_INTR_IN_MBOX:
	case TAVOR_INTR_OUT_MBOX:
		tavor_rsrc_mbox_free(rsrc_pool, *hdl);
		break;

	case TAVOR_QPC:
	case TAVOR_CQC:
	case TAVOR_SRQC:
	case TAVOR_EQC:
	case TAVOR_RDB:
	case TAVOR_MCG:
	case TAVOR_MPT:
	case TAVOR_MTT:
	case TAVOR_UDAV:
	case TAVOR_UARPG:
		tavor_rsrc_hw_entry_free(rsrc_pool, *hdl);
		break;

	case TAVOR_MRHDL:
	case TAVOR_EQHDL:
	case TAVOR_CQHDL:
	case TAVOR_SRQHDL:
	case TAVOR_AHHDL:
	case TAVOR_QPHDL:
	case TAVOR_REFCNT:
		tavor_rsrc_swhdl_free(rsrc_pool, *hdl);
		break;

	case TAVOR_PDHDL:
		tavor_rsrc_pdhdl_free(rsrc_pool, *hdl);
		break;

	default:
		TAVOR_WARNING(state, "unexpected resource type in free");
		TNF_PROBE_0(tavor_rsrc_free_inv_rsrctype_fail,
		    TAVOR_TNF_ERROR, "");
		break;
	}

	/*
	 * Free the special resource tracking structure, set the handle to
	 * NULL, and return.
	 */
	kmem_cache_free(state->ts_rsrc_cache, *hdl);
	*hdl = NULL;

	TAVOR_TNF_EXIT(tavor_rsrc_free);
}


/*
 * tavor_rsrc_init_phase1()
 *
 *    Completes the first phase of Tavor resource/configuration init.
 *    This involves creating the kmem_cache for the "tavor_rsrc_t"
 *    structs, allocating the space for the resource pool handles,
 *    and setting up the "Out" mailboxes.
 *
 *    When this function completes, the Tavor driver is ready to
 *    post the following commands which return information only in the
 *    "Out" mailbox: QUERY_DDR, QUERY_FW, QUERY_DEV_LIM, and QUERY_ADAPTER
 *    If any of these commands are to be posted at this time, they must be
 *    done so only when "spinning" (as the outstanding command list and
 *    EQ setup code has not yet run)
 *
 *    Context: Only called from attach() path context
 */
int
tavor_rsrc_init_phase1(tavor_state_t *state)
{
	tavor_rsrc_pool_info_t		*rsrc_pool;
	tavor_rsrc_mbox_info_t 		mbox_info;
	tavor_rsrc_cleanup_level_t	cleanup;
	tavor_cfg_profile_t		*cfgprof;
	uint64_t			num, size;
	int				status;
	char				*errormsg, *rsrc_name;

	TAVOR_TNF_ENTER(tavor_rsrc_init_phase1);

	ASSERT(state != NULL);

	/* This is where Phase 1 of resource initialization begins */
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL0;

	/* Build kmem cache name from Tavor instance */
	rsrc_name = (char *)kmem_zalloc(TAVOR_RSRC_NAME_MAXLEN, KM_SLEEP);
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_RSRC_CACHE);

	/*
	 * Create the kmem_cache for "tavor_rsrc_t" structures
	 * (kmem_cache_create will SLEEP until successful)
	 */
	state->ts_rsrc_cache = kmem_cache_create(rsrc_name,
	    sizeof (tavor_rsrc_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * Allocate an array of tavor_rsrc_pool_info_t's (used in all
	 * subsequent resource allocations)
	 */
	state->ts_rsrc_hdl = kmem_zalloc(TAVOR_NUM_RESOURCES *
	    sizeof (tavor_rsrc_pool_info_t), KM_SLEEP);

	cfgprof = state->ts_cfg_profile;

	/*
	 * Initialize the resource pool for "Out" mailboxes.  Notice that
	 * the number of "Out" mailboxes, their size, and their location
	 * (DDR or system memory) is configurable.  By default, however,
	 * all "Out" mailboxes are located in system memory only (because
	 * they are primarily read from and never written to)
	 */
	num  =  ((uint64_t)1 << cfgprof->cp_log_num_outmbox);
	size =  ((uint64_t)1 << cfgprof->cp_log_outmbox_size);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_OUT_MBOX];
	rsrc_pool->rsrc_type	  = TAVOR_OUT_MBOX;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_pool_size = (size * num);
	rsrc_pool->rsrc_shift	  = cfgprof->cp_log_outmbox_size;
	rsrc_pool->rsrc_quantum	  = size;
	rsrc_pool->rsrc_align	  = TAVOR_MBOX_ALIGN;
	rsrc_pool->rsrc_state	  = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_OUTMBOX_VMEM);
	mbox_info.mbi_num	  = num;
	mbox_info.mbi_size	  = size;
	mbox_info.mbi_rsrcpool	  = rsrc_pool;
	mbox_info.mbi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_mbox_init(state, &mbox_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "out mailboxes");
		goto rsrcinitp1_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL1;

	/*
	 * Initialize the Tavor "Out" mailbox list.  This step actually uses
	 * the tavor_rsrc_alloc() for TAVOR_OUT_MBOX to preallocate the
	 * "Out" mailboxes, bind them for DMA access, and arrange them into
	 * an easily accessed fast-allocation mechanism (see tavor_cmd.c
	 * for more details)
	 */
	status = tavor_outmbox_list_init(state);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "out mailbox list");
		goto rsrcinitp1_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL2;

	/*
	 * Initialize the resource pool for interrupt "Out" mailboxes.  Notice
	 * that the number of interrupt "Out" mailboxes, their size, and their
	 * location (DDR or system memory) is configurable.  By default,
	 * however, all interrupt "Out" mailboxes are located in system memory
	 * only (because they are primarily read from and never written to)
	 */
	num  =  ((uint64_t)1 << cfgprof->cp_log_num_intr_outmbox);
	size =  ((uint64_t)1 << cfgprof->cp_log_outmbox_size);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_INTR_OUT_MBOX];
	rsrc_pool->rsrc_type	  = TAVOR_INTR_OUT_MBOX;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_pool_size = (size * num);
	rsrc_pool->rsrc_shift	  = cfgprof->cp_log_outmbox_size;
	rsrc_pool->rsrc_quantum	  = size;
	rsrc_pool->rsrc_align	  = TAVOR_MBOX_ALIGN;
	rsrc_pool->rsrc_state	  = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_INTR_OUTMBOX_VMEM);
	mbox_info.mbi_num	  = num;
	mbox_info.mbi_size	  = size;
	mbox_info.mbi_rsrcpool	  = rsrc_pool;
	mbox_info.mbi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_mbox_init(state, &mbox_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "out intr mailboxes");
		goto rsrcinitp1_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL3;

	/*
	 * Initialize the Tavor "Out" mailbox list.  This step actually uses
	 * the tavor_rsrc_alloc() for TAVOR_OUT_MBOX to preallocate the
	 * "Out" mailboxes, bind them for DMA access, and arrange them into
	 * an easily accessed fast-allocation mechanism (see tavor_cmd.c
	 * for more details)
	 */
	status = tavor_intr_outmbox_list_init(state);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "out intr mailbox list");
		goto rsrcinitp1_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_PHASE1_COMPLETE;

	kmem_free(rsrc_name, TAVOR_RSRC_NAME_MAXLEN);
	TAVOR_TNF_EXIT(tavor_rsrc_init_phase1);
	return (DDI_SUCCESS);

rsrcinitp1_fail:
	kmem_free(rsrc_name, TAVOR_RSRC_NAME_MAXLEN);
	TNF_PROBE_1(tavor_rsrc_init_phase1_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_rsrc_init_phase1);
	return (status);
}


/*
 * tavor_rsrc_init_phase2()
 *    Context: Only called from attach() path context
 */
int
tavor_rsrc_init_phase2(tavor_state_t *state)
{
	tavor_rsrc_sw_hdl_info_t	hdl_info;
	tavor_rsrc_hw_entry_info_t	entry_info;
	tavor_rsrc_mbox_info_t		mbox_info;
	tavor_rsrc_pool_info_t		*rsrc_pool;
	tavor_rsrc_cleanup_level_t	cleanup;
	tavor_cfg_profile_t		*cfgprof;
	uint64_t			num, max, size, num_prealloc;
	uint64_t			ddr_size, fw_size;
	uint_t				mcg_size, mcg_size_shift;
	uint_t				uarscr_size, mttsegment_sz;
	int				status;
	char				*errormsg, *rsrc_name;

	TAVOR_TNF_ENTER(tavor_rsrc_init_phase2);

	ASSERT(state != NULL);

	/* Phase 2 initialization begins where Phase 1 left off */
	cleanup = TAVOR_RSRC_CLEANUP_PHASE1_COMPLETE;

	/*
	 * Calculate the extent of the DDR size and portion of which that
	 * is already reserved for Tavor firmware.  (Note: this information
	 * is available because the QUERY_DDR and QUERY_FW commands have
	 * been posted to Tavor firmware prior to calling this routine)
	 */
	ddr_size = state->ts_ddr.ddr_endaddr - state->ts_ddr.ddr_baseaddr + 1;
	fw_size  = state->ts_fw.fw_endaddr - state->ts_fw.fw_baseaddr + 1;

	/* Build the DDR vmem arena name from Tavor instance */
	rsrc_name = (char *)kmem_zalloc(TAVOR_RSRC_NAME_MAXLEN, KM_SLEEP);
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_VMEM);

	/*
	 * Do a vmem_create for the entire DDR range (not including the
	 * portion consumed by Tavor firmware).  This creates the vmem arena
	 * from which all other DDR objects (specifically, tables of HW
	 * entries) will be allocated.
	 */
	state->ts_ddrvmem = vmem_create(rsrc_name,
	    (void *)(uintptr_t)state->ts_ddr.ddr_baseaddr, (ddr_size - fw_size),
	    sizeof (uint64_t), NULL, NULL, NULL, 0, VM_SLEEP);
	if (state->ts_ddrvmem == NULL) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "DDR vmem");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL5;

	/*
	 * Initialize the resource pools for all objects that exist in
	 * Tavor DDR memory.  This includes ("In") mailboxes, context tables
	 * (QPC, CQC, EQC, etc...), and other miscellaneous HW objects.
	 */
	cfgprof = state->ts_cfg_profile;

	/*
	 * Initialize the resource pool for the MPT table entries.  Notice
	 * that the number of MPTs is configurable.  The configured value must
	 * be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that a certain
	 * number of MPTs must be set aside for Tavor firmware use.
	 */
	num = ((uint64_t)1 << cfgprof->cp_log_num_mpt);
	max = ((uint64_t)1 << state->ts_devlim.log_max_mpt);
	num_prealloc = ((uint64_t)1 << state->ts_devlim.log_rsvd_mpt);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MPT];
	rsrc_pool->rsrc_type	  = TAVOR_MPT;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_MPT_SIZE * num);
	rsrc_pool->rsrc_shift	  = TAVOR_MPT_SIZE_SHIFT;
	rsrc_pool->rsrc_quantum	  = TAVOR_MPT_SIZE;
	rsrc_pool->rsrc_align	  = (TAVOR_MPT_SIZE * num);
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_MPT_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "MPT table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL6;

	/*
	 * Initialize the resource pool for the MTT table entries.  Notice
	 * that the number of MTTs is configurable.  The configured value must
	 * be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that a certain
	 * number of MTT segments must be set aside for Tavor firmware use.
	 */
	mttsegment_sz = (TAVOR_MTTSEG_SIZE << TAVOR_MTT_SIZE_SHIFT);
	num = ((uint64_t)1 << cfgprof->cp_log_num_mttseg);
	max = ((uint64_t)1 << state->ts_devlim.log_max_mttseg);
	num_prealloc = ((uint64_t)1 << state->ts_devlim.log_rsvd_mttseg);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MTT];
	rsrc_pool->rsrc_type	  = TAVOR_MTT;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_MTT_SIZE * num);
	rsrc_pool->rsrc_shift	  = TAVOR_MTT_SIZE_SHIFT;
	rsrc_pool->rsrc_quantum	  = mttsegment_sz;
	rsrc_pool->rsrc_align	  = (TAVOR_MTT_SIZE * num);
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_MTT_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "MTT table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL7;

	/*
	 * Initialize the resource pool for the QPC table entries.  Notice
	 * that the number of QPs is configurable.  The configured value must
	 * be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that a certain
	 * number of QP contexts must be set aside for Tavor firmware use.
	 */
	num = ((uint64_t)1 << cfgprof->cp_log_num_qp);
	max = ((uint64_t)1 << state->ts_devlim.log_max_qp);
	num_prealloc = ((uint64_t)1 << state->ts_devlim.log_rsvd_qp);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_QPC];
	rsrc_pool->rsrc_type	  = TAVOR_QPC;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_QPC_SIZE * num);
	rsrc_pool->rsrc_shift	  = TAVOR_QPC_SIZE_SHIFT;
	rsrc_pool->rsrc_quantum	  = TAVOR_QPC_SIZE;
	rsrc_pool->rsrc_align	  = (TAVOR_QPC_SIZE * num);
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_QPC_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "QPC table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL8;

	/*
	 * Initialize the resource pool for the RDB table entries.  Notice
	 * that the number of RDBs is configurable.  The configured value must
	 * be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.
	 */
	num = ((uint64_t)1 << cfgprof->cp_log_num_rdb);
	max = ((uint64_t)1 << state->ts_devlim.log_max_ra_glob);
	num_prealloc = 0;
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_RDB];
	rsrc_pool->rsrc_type	  = TAVOR_RDB;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_RDB_SIZE * num);
	rsrc_pool->rsrc_shift	  = TAVOR_RDB_SIZE_SHIFT;
	rsrc_pool->rsrc_quantum	  = TAVOR_RDB_SIZE;
	rsrc_pool->rsrc_align	  = (TAVOR_RDB_SIZE * num);
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_RDB_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "RDB table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL9;

	/*
	 * Initialize the resource pool for the CQC table entries.  Notice
	 * that the number of CQs is configurable.  The configured value must
	 * be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that a certain
	 * number of CQ contexts must be set aside for Tavor firmware use.
	 */
	num = ((uint64_t)1 << cfgprof->cp_log_num_cq);
	max = ((uint64_t)1 << state->ts_devlim.log_max_cq);
	num_prealloc = ((uint64_t)1 << state->ts_devlim.log_rsvd_cq);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_CQC];
	rsrc_pool->rsrc_type	  = TAVOR_CQC;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_CQC_SIZE * num);
	rsrc_pool->rsrc_shift	  = TAVOR_CQC_SIZE_SHIFT;
	rsrc_pool->rsrc_quantum	  = TAVOR_CQC_SIZE;
	rsrc_pool->rsrc_align	  = (TAVOR_CQC_SIZE * num);
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_CQC_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "CQC table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL10;

	/*
	 * Initialize the resource pool for the Extended QPC table entries.
	 * Notice that the number of EQPCs must be the same as the number
	 * of QP contexts.  So the initialization is constructed in a
	 * similar way as above (for TAVOR_QPC).  One notable difference
	 * here, however, is that by setting the rsrc_quantum field to
	 * zero (indicating a zero-sized object) we indicate that the
	 * object is not allocatable.  The EQPC table is, in fact, managed
	 * internally by the hardware and it is, therefore, unnecessary to
	 * initialize an additional vmem_arena for this type of object.
	 */
	num = ((uint64_t)1 << cfgprof->cp_log_num_qp);
	max = ((uint64_t)1 << state->ts_devlim.log_max_qp);
	num_prealloc = 0;
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_EQPC];
	rsrc_pool->rsrc_type	  = TAVOR_EQPC;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_EQPC_SIZE * num);
	rsrc_pool->rsrc_shift	  = 0;
	rsrc_pool->rsrc_quantum	  = 0;
	rsrc_pool->rsrc_align	  = TAVOR_EQPC_SIZE;
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_EQPC_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "Extended QPC table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL11;

	/*
	 * Initialize the resource pool for the UD address vector table
	 * entries.  Notice that the number of UDAVs is configurable.  The
	 * configured value must be less that the maximum value (obtained
	 * from the QUERY_DEV_LIM command) or the initialization will fail.
	 */
	num = ((uint64_t)1 << cfgprof->cp_log_num_ah);
	max = ((uint64_t)1 << state->ts_devlim.log_max_av);
	num_prealloc = 0;
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_UDAV];
	rsrc_pool->rsrc_type	  = TAVOR_UDAV;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_UDAV_SIZE * num);
	rsrc_pool->rsrc_shift	  = TAVOR_UDAV_SIZE_SHIFT;
	rsrc_pool->rsrc_quantum	  = TAVOR_UDAV_SIZE;
	rsrc_pool->rsrc_align	  = TAVOR_UDAV_SIZE;
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_UDAV_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "UDAV table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL12;

	/*
	 * Initialize the resource pool for the UAR scratch table entries.
	 * Notice that the number of UARSCRs is configurable.  The configured
	 * value must be less that the maximum value (obtained from the
	 * QUERY_DEV_LIM command) or the initialization will fail.
	 * Like the EQPCs above, UARSCR objects are not allocatable.  The
	 * UARSCR table is also managed internally by the hardware and it
	 * is, therefore, unnecessary to initialize an additional vmem_arena
	 * for this type of object.  We indicate this by setting the
	 * rsrc_quantum field to zero (indicating a zero-sized object).
	 */
	uarscr_size = state->ts_devlim.uarscr_entry_sz;
	num = ((uint64_t)1 << cfgprof->cp_log_num_uar);
	max = ((uint64_t)1 << (state->ts_devlim.log_max_uar_sz + 20 -
	    PAGESHIFT));
	num_prealloc = 0;
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_UAR_SCR];
	rsrc_pool->rsrc_type	  = TAVOR_UAR_SCR;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (uarscr_size * num);
	rsrc_pool->rsrc_shift	  = 0;
	rsrc_pool->rsrc_quantum	  = 0;
	rsrc_pool->rsrc_align	  = uarscr_size;
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_UARSCR_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "UAR scratch table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL13;

	/*
	 * Initialize the resource pool for the SRQC table entries.  Notice
	 * that the number of SRQs is configurable.  The configured value must
	 * be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that a certain
	 * number of SRQ contexts must be set aside for Tavor firmware use.
	 *
	 * Note: We only allocate these resources if SRQ is enabled in the
	 * config profile; see below.
	 */
	num = ((uint64_t)1 << cfgprof->cp_log_num_srq);
	max = ((uint64_t)1 << state->ts_devlim.log_max_srq);
	num_prealloc = ((uint64_t)1 << state->ts_devlim.log_rsvd_srq);

	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_SRQC];
	rsrc_pool->rsrc_type	  = TAVOR_SRQC;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_SRQC_SIZE * num);
	rsrc_pool->rsrc_shift	  = TAVOR_SRQC_SIZE_SHIFT;
	rsrc_pool->rsrc_quantum	  = TAVOR_SRQC_SIZE;
	rsrc_pool->rsrc_align	  = (TAVOR_SRQC_SIZE * num);
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_SRQC_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;

	/*
	 * SRQ support is configurable.  Only if SRQ is enabled (the default)
	 * do we actually try to configure these resources.  Otherwise, we
	 * simply set the cleanup level and continue on to the next resource
	 */
	if (state->ts_cfg_profile->cp_srq_enable != 0) {
		status = tavor_rsrc_hw_entries_init(state, &entry_info);
		if (status != DDI_SUCCESS) {
			tavor_rsrc_fini(state, cleanup);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(DDI_FAILURE, "SRQC table");
			goto rsrcinitp2_fail;
		}
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL14;

	/*
	 * Initialize the resource pool for "In" mailboxes.  Notice that
	 * the number of "In" mailboxes, their size, and their location
	 * (DDR or system memory) is configurable.  By default, however,
	 * all "In" mailboxes are located in system memory only (because
	 * they are primarily written to and rarely read from)
	 */
	num  =  ((uint64_t)1 << cfgprof->cp_log_num_inmbox);
	size =  ((uint64_t)1 << cfgprof->cp_log_inmbox_size);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_IN_MBOX];
	rsrc_pool->rsrc_type	  = TAVOR_IN_MBOX;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (size * num);
	rsrc_pool->rsrc_shift	  = cfgprof->cp_log_inmbox_size;
	rsrc_pool->rsrc_quantum	  = size;
	rsrc_pool->rsrc_align	  = TAVOR_MBOX_ALIGN;
	rsrc_pool->rsrc_state	  = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_INMBOX_VMEM);
	mbox_info.mbi_num	  = num;
	mbox_info.mbi_size	  = size;
	mbox_info.mbi_rsrcpool	  = rsrc_pool;
	mbox_info.mbi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_mbox_init(state, &mbox_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "in mailboxes");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL15;

	/*
	 * Initialize the Tavor "In" mailbox list.  This step actually uses
	 * the tavor_rsrc_alloc() for TAVOR_IN_MBOX to preallocate the
	 * "In" mailboxes, bind them for DMA access, and arrange them into
	 * an easily accessed fast-allocation mechanism (see tavor_cmd.c
	 * for more details)
	 */
	status = tavor_inmbox_list_init(state);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "in mailbox list");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL16;

	/*
	 * Initialize the resource pool for interrupt "In" mailboxes.  Notice
	 * that the number of interrupt "In" mailboxes, their size, and their
	 * location (DDR or system memory) is configurable.  By default,
	 * however, all interrupt "In" mailboxes are located in system memory
	 * only (because they are primarily written to and rarely read from)
	 */
	num  =  ((uint64_t)1 << cfgprof->cp_log_num_intr_inmbox);
	size =  ((uint64_t)1 << cfgprof->cp_log_inmbox_size);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_INTR_IN_MBOX];
	rsrc_pool->rsrc_type	  = TAVOR_INTR_IN_MBOX;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (size * num);
	rsrc_pool->rsrc_shift	  = cfgprof->cp_log_inmbox_size;
	rsrc_pool->rsrc_quantum	  = size;
	rsrc_pool->rsrc_align	  = TAVOR_MBOX_ALIGN;
	rsrc_pool->rsrc_state	  = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_INTR_INMBOX_VMEM);
	mbox_info.mbi_num	  = num;
	mbox_info.mbi_size	  = size;
	mbox_info.mbi_rsrcpool	  = rsrc_pool;
	mbox_info.mbi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_mbox_init(state, &mbox_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "in intr mailboxes");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL17;

	/*
	 * Initialize the Tavor interrupt "In" mailbox list.  This step
	 * actually uses the tavor_rsrc_alloc() for TAVOR_IN_MBOX to
	 * preallocate the interrupt "In" mailboxes, bind them for DMA access,
	 * and arrange them into an easily accessed fast-allocation mechanism
	 * (see tavor_cmd.c for more details)
	 */
	status = tavor_intr_inmbox_list_init(state);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "in intr mailbox list");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL18;

	/*
	 * Initialize the Tavor command handling interfaces.  This step
	 * sets up the outstanding command tracking mechanism for easy access
	 * and fast allocation (see tavor_cmd.c for more details).
	 */
	status = tavor_outstanding_cmdlist_init(state);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "outstanding cmd list");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL19;

	/*
	 * Calculate (and validate) the size of Multicast Group (MCG) entries
	 */
	status = tavor_rsrc_mcg_entry_get_size(state, &mcg_size_shift);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "failed get MCG size");
		goto rsrcinitp2_fail;
	}
	mcg_size = TAVOR_MCGMEM_SZ(state);

	/*
	 * Initialize the resource pool for the MCG table entries.  Notice
	 * that the number of MCGs is configurable.  The configured value must
	 * be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that a certain
	 * number of MCGs must be set aside for Tavor firmware use (they
	 * correspond to the number of MCGs used by the internal hash
	 * function.
	 */
	num = ((uint64_t)1 << cfgprof->cp_log_num_mcg);
	max = ((uint64_t)1 << state->ts_devlim.log_max_mcg);
	num_prealloc = ((uint64_t)1 << cfgprof->cp_log_num_mcg_hash);
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MCG];
	rsrc_pool->rsrc_type	  = TAVOR_MCG;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (mcg_size * num);
	rsrc_pool->rsrc_shift	  = mcg_size_shift;
	rsrc_pool->rsrc_quantum	  = mcg_size;
	rsrc_pool->rsrc_align	  = mcg_size;
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_MCG_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "MCG table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL20;

	/*
	 * Initialize the resource pool for the EQC table entries.  Notice
	 * that the number of EQs is hardcoded.  The hardcoded value should
	 * be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.
	 */
	num = TAVOR_NUM_EQ;
	max = ((uint64_t)1 << state->ts_devlim.log_max_eq);
	num_prealloc = 0;
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_EQC];
	rsrc_pool->rsrc_type	  = TAVOR_EQC;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_DDR;
	rsrc_pool->rsrc_pool_size = (TAVOR_EQC_SIZE * num);
	rsrc_pool->rsrc_shift	  = TAVOR_EQC_SIZE_SHIFT;
	rsrc_pool->rsrc_quantum	  = TAVOR_EQC_SIZE;
	rsrc_pool->rsrc_align	  = (TAVOR_EQC_SIZE * num);
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = NULL;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_DDR_EQC_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "EQC table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL21;

	/*
	 * Initialize the resource pools for all objects that exist in
	 * system memory.  This includes PD handles, MR handle, EQ handles,
	 * QP handles, etc.  These objects are almost entirely managed using
	 * kmem_cache routines.  (See comment above for more detail)
	 */

	/*
	 * Initialize the resource pool for the PD handles.  Notice
	 * that the number of PDHDLs is configurable.  The configured value
	 * must be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that the PD
	 * handle has constructor and destructor methods associated with it.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_PDHDL];
	rsrc_pool->rsrc_type	 = TAVOR_PDHDL;
	rsrc_pool->rsrc_loc	 = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (struct tavor_sw_pd_s);
	rsrc_pool->rsrc_state	 = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_PDHDL_CACHE);
	hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_pd);
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_pd);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = tavor_rsrc_pdhdl_constructor;
	hdl_info.swi_destructor	 = tavor_rsrc_pdhdl_destructor;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = TAVOR_SWHDL_KMEMCACHE_INIT;
	status = tavor_rsrc_pd_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "PD handle");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL22;

	/*
	 * Initialize the resource pool for the MR handles.  Notice
	 * that the number of MRHDLs is configurable.  The configured value
	 * must be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MRHDL];
	rsrc_pool->rsrc_type	 = TAVOR_MRHDL;
	rsrc_pool->rsrc_loc	 = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (struct tavor_sw_mr_s);
	rsrc_pool->rsrc_state	 = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_MRHDL_CACHE);
	hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_mpt);
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_mpt);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = tavor_rsrc_mrhdl_constructor;
	hdl_info.swi_destructor	 = tavor_rsrc_mrhdl_destructor;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = TAVOR_SWHDL_KMEMCACHE_INIT;
	status = tavor_rsrc_sw_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "MR handle");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL23;

	/*
	 * Initialize the resource pool for the EQ handles.  Notice
	 * that the number of EQHDLs is hardcoded.  The hardcoded value
	 * should be less that the maximum value (obtained from the
	 * QUERY_DEV_LIM command) or the initialization will fail.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_EQHDL];
	rsrc_pool->rsrc_type	 = TAVOR_EQHDL;
	rsrc_pool->rsrc_loc	 = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (struct tavor_sw_eq_s);
	rsrc_pool->rsrc_state	 = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_EQHDL_CACHE);
	hdl_info.swi_num = TAVOR_NUM_EQ;
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_eq);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = NULL;
	hdl_info.swi_destructor	 = NULL;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = TAVOR_SWHDL_KMEMCACHE_INIT;
	status = tavor_rsrc_sw_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "EQ handle");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL24;

	/*
	 * Initialize the resource pool for the CQ handles.  Notice
	 * that the number of CQHDLs is configurable.  The configured value
	 * must be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that the CQ
	 * handle has constructor and destructor methods associated with it.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_CQHDL];
	rsrc_pool->rsrc_type	 = TAVOR_CQHDL;
	rsrc_pool->rsrc_loc	 = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (struct tavor_sw_cq_s);
	rsrc_pool->rsrc_state	 = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_CQHDL_CACHE);
	hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_cq);
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_cq);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = tavor_rsrc_cqhdl_constructor;
	hdl_info.swi_destructor	 = tavor_rsrc_cqhdl_destructor;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = (TAVOR_SWHDL_KMEMCACHE_INIT |
	    TAVOR_SWHDL_TABLE_INIT);
	hdl_info.swi_prealloc_sz = sizeof (tavor_cqhdl_t);
	status = tavor_rsrc_sw_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "CQ handle");
		goto rsrcinitp2_fail;
	}

	/*
	 * Save away the pointer to the central list of CQ handle pointers
	 * This this is used as a mechanism to enable fast CQnumber-to-CQhandle
	 * lookup during EQ event processing.  The table is a list of
	 * tavor_cqhdl_t allocated by the above routine because of the
	 * TAVOR_SWHDL_TABLE_INIT flag.  The table has as many tavor_cqhdl_t
	 * as the number of CQs.
	 */
	state->ts_cqhdl = hdl_info.swi_table_ptr;
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL25;

	/*
	 * Initialize the resource pool for the SRQ handles.  Notice
	 * that the number of SRQHDLs is configurable.  The configured value
	 * must be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that the SRQ
	 * handle has constructor and destructor methods associated with it.
	 *
	 * Note: We only allocate these resources if SRQ is enabled in the
	 * config profile; see below.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_SRQHDL];
	rsrc_pool->rsrc_type	 = TAVOR_SRQHDL;
	rsrc_pool->rsrc_loc	 = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (struct tavor_sw_srq_s);
	rsrc_pool->rsrc_state	 = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_SRQHDL_CACHE);
	hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_srq);
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_srq);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = tavor_rsrc_srqhdl_constructor;
	hdl_info.swi_destructor	 = tavor_rsrc_srqhdl_destructor;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = (TAVOR_SWHDL_KMEMCACHE_INIT |
	    TAVOR_SWHDL_TABLE_INIT);
	hdl_info.swi_prealloc_sz = sizeof (tavor_srqhdl_t);

	/*
	 * SRQ support is configurable.  Only if SRQ is enabled (the default)
	 * do we actually try to configure these resources.  Otherwise, we
	 * simply set the cleanup level and continue on to the next resource
	 */
	if (state->ts_cfg_profile->cp_srq_enable != 0) {
		status = tavor_rsrc_sw_handles_init(state, &hdl_info);
		if (status != DDI_SUCCESS) {
			tavor_rsrc_fini(state, cleanup);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(DDI_FAILURE, "SRQ handle");
			goto rsrcinitp2_fail;
		}

		/*
		 * Save away the pointer to the central list of SRQ handle
		 * pointers This this is used as a mechanism to enable fast
		 * SRQnumber-to-SRQhandle lookup.  The table is a list of
		 * tavor_srqhdl_t allocated by the above routine because of the
		 * TAVOR_SWHDL_TABLE_INIT flag.  The table has as many
		 * tavor_srqhdl_t as the number of SRQs.
		 */
		state->ts_srqhdl = hdl_info.swi_table_ptr;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL26;

	/*
	 * Initialize the resource pool for the address handles.  Notice
	 * that the number of AHHDLs is configurable.  The configured value
	 * must be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_AHHDL];
	rsrc_pool->rsrc_type	 = TAVOR_AHHDL;
	rsrc_pool->rsrc_loc	 = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (struct tavor_sw_ah_s);
	rsrc_pool->rsrc_state	 = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_AHHDL_CACHE);
	hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_ah);
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_av);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = tavor_rsrc_ahhdl_constructor;
	hdl_info.swi_destructor	 = tavor_rsrc_ahhdl_destructor;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = TAVOR_SWHDL_KMEMCACHE_INIT;
	status = tavor_rsrc_sw_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "AH handle");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL27;

	/*
	 * Initialize the resource pool for the QP handles.  Notice
	 * that the number of QPHDLs is configurable.  The configured value
	 * must be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that the QP
	 * handle has constructor and destructor methods associated with it.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_QPHDL];
	rsrc_pool->rsrc_type	 = TAVOR_QPHDL;
	rsrc_pool->rsrc_loc	 = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (struct tavor_sw_qp_s);
	rsrc_pool->rsrc_state	 = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_QPHDL_CACHE);
	hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_qp);
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_qp);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = tavor_rsrc_qphdl_constructor;
	hdl_info.swi_destructor	 = tavor_rsrc_qphdl_destructor;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = (TAVOR_SWHDL_KMEMCACHE_INIT |
	    TAVOR_SWHDL_TABLE_INIT);
	hdl_info.swi_prealloc_sz = sizeof (tavor_qphdl_t);
	status = tavor_rsrc_sw_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "QP handle");
		goto rsrcinitp2_fail;
	}

	/*
	 * Save away the pointer to the central list of QP handle pointers
	 * This this is used as a mechanism to enable fast QPnumber-to-QPhandle
	 * lookup during CQ event processing.  The table is a list of
	 * tavor_qphdl_t allocated by the above routine because of the
	 * TAVOR_SWHDL_TABLE_INIT flag.  The table has as many tavor_qphdl_t
	 * as the number of QPs.
	 */
	state->ts_qphdl = hdl_info.swi_table_ptr;
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL28;

	/*
	 * Initialize the resource pool for the reference count handles.
	 * Notice that the number of REFCNTs is configurable, but it's value
	 * is set to the number of MPTs.  Since REFCNTs are used to support
	 * shared memory regions, it is possible that we might require as
	 * one REFCNT for every MPT.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_REFCNT];
	rsrc_pool->rsrc_type	 = TAVOR_REFCNT;
	rsrc_pool->rsrc_loc	 = TAVOR_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (tavor_sw_refcnt_t);
	rsrc_pool->rsrc_state	 = state;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_REFCNT_CACHE);
	hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_mpt);
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_mpt);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = tavor_rsrc_refcnt_constructor;
	hdl_info.swi_destructor	 = tavor_rsrc_refcnt_destructor;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = TAVOR_SWHDL_KMEMCACHE_INIT;
	status = tavor_rsrc_sw_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "reference count handle");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL29;

	/*
	 * Initialize the resource pool for the MCG handles.  Notice that for
	 * these MCG handles, we are allocating a table of structures (used to
	 * keep track of the MCG entries that are being written to hardware
	 * and to speed up multicast attach/detach operations).
	 */
	hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_mcg);
	hdl_info.swi_max = ((uint64_t)1 << state->ts_devlim.log_max_mcg);
	hdl_info.swi_flags = TAVOR_SWHDL_TABLE_INIT;
	hdl_info.swi_prealloc_sz = sizeof (struct tavor_sw_mcg_list_s);
	status = tavor_rsrc_sw_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "MCG handle");
		goto rsrcinitp2_fail;
	}
	state->ts_mcghdl = hdl_info.swi_table_ptr;
	cleanup = TAVOR_RSRC_CLEANUP_LEVEL30;

	/*
	 * Initialize the resource pools for all objects that exist in
	 * UAR memory.  The only objects that are allocated from UAR memory
	 * are the UAR pages which are used for holding Tavor hardware's
	 * doorbell registers.
	 */

	/*
	 * Initialize the resource pool for the UAR pages.  Notice
	 * that the number of UARPGs is configurable.  The configured value
	 * must be less that the maximum value (obtained from the QUERY_DEV_LIM
	 * command) or the initialization will fail.  Note also that by
	 * specifying the rsrc_start parameter in advance, we direct the
	 * initialization routine not to attempt to allocated space from the
	 * Tavor DDR vmem_arena.
	 */
	num  = ((uint64_t)1 << cfgprof->cp_log_num_uar);
	max  = ((uint64_t)1 << (state->ts_devlim.log_max_uar_sz + 20 -
	    PAGESHIFT));
	num_prealloc = 0;
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_UARPG];
	rsrc_pool->rsrc_type	  = TAVOR_UARPG;
	rsrc_pool->rsrc_loc	  = TAVOR_IN_UAR;
	rsrc_pool->rsrc_pool_size = (num << PAGESHIFT);
	rsrc_pool->rsrc_shift	  = PAGESHIFT;
	rsrc_pool->rsrc_quantum	  = PAGESIZE;
	rsrc_pool->rsrc_align	  = PAGESIZE;
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = (void *)state->ts_reg_uar_baseaddr;
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_UAR_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = tavor_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_fini(state, cleanup);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(DDI_FAILURE, "UAR page table");
		goto rsrcinitp2_fail;
	}
	cleanup = TAVOR_RSRC_CLEANUP_ALL;

	kmem_free(rsrc_name, TAVOR_RSRC_NAME_MAXLEN);
	TAVOR_TNF_EXIT(tavor_rsrc_init_phase2);
	return (DDI_SUCCESS);

rsrcinitp2_fail:
	kmem_free(rsrc_name, TAVOR_RSRC_NAME_MAXLEN);
	TNF_PROBE_1(tavor_rsrc_init_phase2_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_rsrc_init_phase2);
	return (status);
}


/*
 * tavor_rsrc_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_rsrc_fini(tavor_state_t *state, tavor_rsrc_cleanup_level_t clean)
{
	tavor_rsrc_sw_hdl_info_t	hdl_info;
	tavor_rsrc_hw_entry_info_t	entry_info;
	tavor_rsrc_mbox_info_t		mbox_info;
	tavor_cfg_profile_t		*cfgprof;

	TAVOR_TNF_ENTER(tavor_rsrc_fini);

	ASSERT(state != NULL);

	cfgprof = state->ts_cfg_profile;

	switch (clean) {
	/*
	 * If we add more resources that need to be cleaned up here, we should
	 * ensure that TAVOR_RSRC_CLEANUP_ALL is still the first entry (i.e.
	 * corresponds to the last resource allocated).
	 */
	case TAVOR_RSRC_CLEANUP_ALL:
		/* Cleanup the UAR page resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_UARPG];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL30:
		/* Cleanup the central MCG handle pointers list */
		hdl_info.swi_rsrcpool  = NULL;
		hdl_info.swi_table_ptr = state->ts_mcghdl;
		hdl_info.swi_num =
		    ((uint64_t)1 << cfgprof->cp_log_num_mcg);
		hdl_info.swi_prealloc_sz = sizeof (struct tavor_sw_mcg_list_s);
		tavor_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL29:
		/* Cleanup the reference count resource pool */
		hdl_info.swi_rsrcpool  = &state->ts_rsrc_hdl[TAVOR_REFCNT];
		hdl_info.swi_table_ptr = NULL;
		tavor_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL28:
		/* Cleanup the QP handle resource pool */
		hdl_info.swi_rsrcpool  = &state->ts_rsrc_hdl[TAVOR_QPHDL];
		hdl_info.swi_table_ptr = state->ts_qphdl;
		hdl_info.swi_num =
		    ((uint64_t)1 << cfgprof->cp_log_num_qp);
		hdl_info.swi_prealloc_sz = sizeof (tavor_qphdl_t);
		tavor_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL27:
		/* Cleanup the address handle resource pool */
		hdl_info.swi_rsrcpool  = &state->ts_rsrc_hdl[TAVOR_AHHDL];
		hdl_info.swi_table_ptr = NULL;
		tavor_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL26:
		/*
		 * Cleanup the SRQ handle resource pool.
		 *
		 * Note: We only clean up if SRQ is enabled.  Otherwise we
		 * simply fallthrough to the next resource cleanup.
		 */
		if (state->ts_cfg_profile->cp_srq_enable != 0) {
			hdl_info.swi_rsrcpool  =
			    &state->ts_rsrc_hdl[TAVOR_SRQHDL];
			hdl_info.swi_table_ptr = state->ts_srqhdl;
			hdl_info.swi_num =
			    ((uint64_t)1 << cfgprof->cp_log_num_srq);
			hdl_info.swi_prealloc_sz = sizeof (tavor_srqhdl_t);
			tavor_rsrc_sw_handles_fini(state, &hdl_info);
		}
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL25:
		/* Cleanup the CQ handle resource pool */
		hdl_info.swi_rsrcpool  = &state->ts_rsrc_hdl[TAVOR_CQHDL];
		hdl_info.swi_table_ptr = state->ts_cqhdl;
		hdl_info.swi_num =
		    ((uint64_t)1 << cfgprof->cp_log_num_cq);
		hdl_info.swi_prealloc_sz = sizeof (tavor_cqhdl_t);
		tavor_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL24:
		/* Cleanup the EQ handle resource pool */
		hdl_info.swi_rsrcpool  = &state->ts_rsrc_hdl[TAVOR_EQHDL];
		hdl_info.swi_table_ptr = NULL;
		tavor_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL23:
		/* Cleanup the MR handle resource pool */
		hdl_info.swi_rsrcpool  = &state->ts_rsrc_hdl[TAVOR_MRHDL];
		hdl_info.swi_table_ptr = NULL;
		tavor_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL22:
		/* Cleanup the PD handle resource pool */
		hdl_info.swi_rsrcpool  = &state->ts_rsrc_hdl[TAVOR_PDHDL];
		hdl_info.swi_table_ptr = NULL;
		tavor_rsrc_pd_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL21:
		/* Cleanup the EQC table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_EQC];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL20:
		/* Cleanup the MCG table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_MCG];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL19:
		/* Cleanup the outstanding command list  */
		tavor_outstanding_cmdlist_fini(state);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL18:
		/* Cleanup the "In" mailbox list  */
		tavor_intr_inmbox_list_fini(state);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL17:
		/* Cleanup the interrupt "In" mailbox resource pool */
		mbox_info.mbi_rsrcpool = &state->ts_rsrc_hdl[
		    TAVOR_INTR_IN_MBOX];
		tavor_rsrc_mbox_fini(state, &mbox_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL16:
		/* Cleanup the "In" mailbox list  */
		tavor_inmbox_list_fini(state);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL15:
		/* Cleanup the "In" mailbox resource pool */
		mbox_info.mbi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_IN_MBOX];
		tavor_rsrc_mbox_fini(state, &mbox_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL14:
		/*
		 * Cleanup the SRQC table resource pool.
		 *
		 * Note: We only clean up if SRQ is enabled.  Otherwise we
		 * simply fallthrough to the next resource cleanup.
		 */
		if (state->ts_cfg_profile->cp_srq_enable != 0) {
			entry_info.hwi_rsrcpool =
			    &state->ts_rsrc_hdl[TAVOR_SRQC];
			tavor_rsrc_hw_entries_fini(state, &entry_info);
		}
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL13:
		/* Cleanup the UAR scratch table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_UAR_SCR];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL12:
		/* Cleanup the UDAV table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_UDAV];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL11:
		/* Cleanup the EQPC table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_EQPC];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL10:
		/* Cleanup the CQC table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_CQC];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL9:
		/* Cleanup the RDB table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_RDB];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL8:
		/* Cleanup the QPC table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_QPC];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL7:
		/* Cleanup the MTT table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_MTT];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL6:
		/* Cleanup the MPT table resource pool */
		entry_info.hwi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_MPT];
		tavor_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL5:
		/* Destroy the vmem arena for DDR memory */
		vmem_destroy(state->ts_ddrvmem);
		break;

	/*
	 * The cleanup below comes from the "Phase 1" initialization step.
	 * (see tavor_rsrc_init_phase1() above)
	 */
	case TAVOR_RSRC_CLEANUP_PHASE1_COMPLETE:
		/* Cleanup the interrupt "Out" mailbox list  */
		tavor_intr_outmbox_list_fini(state);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL3:
		/* Cleanup the "Out" mailbox resource pool */
		mbox_info.mbi_rsrcpool = &state->ts_rsrc_hdl[
		    TAVOR_INTR_OUT_MBOX];
		tavor_rsrc_mbox_fini(state, &mbox_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL2:
		/* Cleanup the "Out" mailbox list  */
		tavor_outmbox_list_fini(state);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL1:
		/* Cleanup the "Out" mailbox resource pool */
		mbox_info.mbi_rsrcpool = &state->ts_rsrc_hdl[TAVOR_OUT_MBOX];
		tavor_rsrc_mbox_fini(state, &mbox_info);
		/* FALLTHROUGH */

	case TAVOR_RSRC_CLEANUP_LEVEL0:
		/* Free the array of tavor_rsrc_pool_info_t's */
		kmem_free(state->ts_rsrc_hdl, TAVOR_NUM_RESOURCES *
		    sizeof (tavor_rsrc_pool_info_t));
		kmem_cache_destroy(state->ts_rsrc_cache);
		break;

	default:
		TAVOR_WARNING(state, "unexpected resource cleanup level");
		TNF_PROBE_0(tavor_rsrc_fini_default_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_rsrc_fini);
		return;
	}

	TAVOR_TNF_EXIT(tavor_rsrc_fini);
}


/*
 * tavor_rsrc_mbox_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_rsrc_mbox_init(tavor_state_t *state, tavor_rsrc_mbox_info_t *info)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_rsrc_priv_mbox_t	*priv;
	vmem_t			*vmp;
	uint64_t		offset;
	uint_t			dma_xfer_mode;

	TAVOR_TNF_ENTER(tavor_rsrc_mbox_init);

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->mbi_rsrcpool;
	ASSERT(rsrc_pool != NULL);

	dma_xfer_mode = state->ts_cfg_profile->cp_streaming_consistent;

	/* Allocate and initialize mailbox private structure */
	priv = kmem_zalloc(sizeof (tavor_rsrc_priv_mbox_t), KM_SLEEP);
	priv->pmb_dip		= state->ts_dip;
	priv->pmb_acchdl	= state->ts_reg_ddrhdl;
	priv->pmb_devaccattr	= state->ts_reg_accattr;
	priv->pmb_xfer_mode	= dma_xfer_mode;

	/*
	 * Initialize many of the default DMA attributes.  Then set alignment
	 * and scatter-gather restrictions specific for mailbox memory.
	 */
	tavor_dma_attr_init(&priv->pmb_dmaattr);
	priv->pmb_dmaattr.dma_attr_align  = TAVOR_MBOX_ALIGN;
	priv->pmb_dmaattr.dma_attr_sgllen = 1;

	rsrc_pool->rsrc_private = priv;

	/* Is object in DDR memory or system memory? */
	if (rsrc_pool->rsrc_loc == TAVOR_IN_DDR) {
		rsrc_pool->rsrc_ddr_offset = vmem_xalloc(state->ts_ddrvmem,
		    rsrc_pool->rsrc_pool_size, rsrc_pool->rsrc_align,
		    0, 0, NULL, NULL, VM_SLEEP);
		if (rsrc_pool->rsrc_ddr_offset == NULL) {
			/* Unable to alloc space for mailboxes */
			kmem_free(priv, sizeof (tavor_rsrc_priv_mbox_t));
			TNF_PROBE_0(tavor_rsrc_mbox_init_vma_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_rsrc_mbox_init);
			return (DDI_FAILURE);
		}

		/* Calculate offset and starting point (in DDR) */
		offset = ((uintptr_t)rsrc_pool->rsrc_ddr_offset -
		    state->ts_ddr.ddr_baseaddr);
		rsrc_pool->rsrc_start =
		    (void *)(uintptr_t)((uintptr_t)state->ts_reg_ddr_baseaddr +
		    offset);

		/* Create new vmem arena for the mailboxes */
		vmp = vmem_create(info->mbi_rsrcname,
		    rsrc_pool->rsrc_ddr_offset, rsrc_pool->rsrc_pool_size,
		    rsrc_pool->rsrc_quantum, NULL, NULL, NULL, 0, VM_SLEEP);
		if (vmp == NULL) {
			/* Unable to create vmem arena */
			vmem_xfree(state->ts_ddrvmem,
			    rsrc_pool->rsrc_ddr_offset,
			    rsrc_pool->rsrc_pool_size);
			kmem_free(priv, sizeof (tavor_rsrc_priv_mbox_t));
			TNF_PROBE_0(tavor_rsrc_mbox_init_vmem_create_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_rsrc_mbox_init);
			return (DDI_FAILURE);
		}
		rsrc_pool->rsrc_vmp = vmp;
	} else {
		rsrc_pool->rsrc_ddr_offset = NULL;
		rsrc_pool->rsrc_start = NULL;
		rsrc_pool->rsrc_vmp = NULL;
	}

	TAVOR_TNF_EXIT(tavor_rsrc_mbox_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_mbox_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_rsrc_mbox_fini(tavor_state_t *state, tavor_rsrc_mbox_info_t *info)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;

	TAVOR_TNF_ENTER(tavor_rsrc_mbox_fini);

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->mbi_rsrcpool;
	ASSERT(rsrc_pool != NULL);

	/* If mailboxes are DDR memory, then destroy and free up vmem */
	if (rsrc_pool->rsrc_loc == TAVOR_IN_DDR) {

		/* Destroy the specially created mbox vmem arena */
		vmem_destroy(rsrc_pool->rsrc_vmp);

		/* Free up the region from the ddr_vmem arena */
		vmem_xfree(state->ts_ddrvmem, rsrc_pool->rsrc_ddr_offset,
		    rsrc_pool->rsrc_pool_size);
	}

	/* Free up the private struct */
	kmem_free(rsrc_pool->rsrc_private, sizeof (tavor_rsrc_priv_mbox_t));

	TAVOR_TNF_EXIT(tavor_rsrc_mbox_fini);
}


/*
 * tavor_rsrc_hw_entries_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_rsrc_hw_entries_init(tavor_state_t *state,
    tavor_rsrc_hw_entry_info_t *info)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_rsrc_t		*rsvd_rsrc = NULL;
	vmem_t			*vmp;
	uint64_t		num_hwentry, max_hwentry, num_prealloc;
	uint64_t		offset;
	int			status;

	TAVOR_TNF_ENTER(tavor_rsrc_hw_entries_init);

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool	= info->hwi_rsrcpool;
	ASSERT(rsrc_pool != NULL);
	num_hwentry	= info->hwi_num;
	max_hwentry	= info->hwi_max;
	num_prealloc	= info->hwi_prealloc;

	/* Make sure number of HW entries makes sense */
	if (num_hwentry > max_hwentry) {
		TNF_PROBE_2(tavor_rsrc_hw_entries_init_toomany_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "number of HW "
		    "entries exceeds device maximum", tnf_uint, maxhw,
		    max_hwentry);
		TAVOR_TNF_EXIT(tavor_rsrc_hw_entries_init);
		return (DDI_FAILURE);
	}

	/*
	 * Determine if we need to allocate DDR space to set up the
	 * "rsrc_start" pointer.  Not necessary if "rsrc_start" has already
	 * been initialized (as is the case for the UAR page init).
	 */
	if (rsrc_pool->rsrc_start == NULL) {
		/* Make sure HW entries table is aligned as specified */
		rsrc_pool->rsrc_ddr_offset = vmem_xalloc(state->ts_ddrvmem,
		    rsrc_pool->rsrc_pool_size, rsrc_pool->rsrc_align,
		    0, 0, NULL, NULL, VM_NOSLEEP | VM_FIRSTFIT);
		if (rsrc_pool->rsrc_ddr_offset == NULL) {
			/* Unable to alloc space for aligned HW table */
			TNF_PROBE_0(tavor_rsrc_hw_entry_table_vmxalloc_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_rsrc_hw_entries_init);
			return (DDI_FAILURE);
		}

		/* Calculate offset and starting point (in DDR) */
		offset = ((uintptr_t)rsrc_pool->rsrc_ddr_offset -
		    state->ts_ddr.ddr_baseaddr);
		rsrc_pool->rsrc_start =
		    (void *)(uintptr_t)((uintptr_t)state->ts_reg_ddr_baseaddr +
		    offset);
	} else {
		rsrc_pool->rsrc_ddr_offset = rsrc_pool->rsrc_start;
	}

	/*
	 * Create new vmem arena for the HW entries table (if rsrc_quantum
	 * is non-zero).  Otherwise if rsrc_quantum is zero, then these HW
	 * entries are not going to be dynamically allocatable (i.e. they
	 * won't be allocated/freed through tavor_rsrc_alloc/free).  This
	 * latter option is used for EQPC and UARSCR resource which are, in
	 * fact, managed by the Tavor hardware.
	 */
	if (rsrc_pool->rsrc_quantum != 0) {
		vmp = vmem_create(info->hwi_rsrcname,
		    rsrc_pool->rsrc_ddr_offset, rsrc_pool->rsrc_pool_size,
		    rsrc_pool->rsrc_quantum, NULL, NULL, NULL, 0, VM_SLEEP);
		if (vmp == NULL) {
			/* Unable to create vmem arena */
			if (rsrc_pool->rsrc_ddr_offset !=
			    rsrc_pool->rsrc_start) {
				vmem_xfree(state->ts_ddrvmem,
				    rsrc_pool->rsrc_ddr_offset,
				    rsrc_pool->rsrc_pool_size);
			}
			TNF_PROBE_0(tavor_rsrc_hw_entries_init_vmemcreate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_rsrc_hw_entries_init);
			return (DDI_FAILURE);
		}
		rsrc_pool->rsrc_vmp = vmp;
	} else {
		rsrc_pool->rsrc_vmp = NULL;
	}

	/* The first HW entries may be reserved by Tavor firmware */
	if (num_prealloc != 0) {
		status = tavor_rsrc_alloc(state, rsrc_pool->rsrc_type,
		    num_prealloc, TAVOR_SLEEP, &rsvd_rsrc);
		if (status != DDI_SUCCESS) {
			/* Unable to preallocate the reserved HW entries */
			if (rsrc_pool->rsrc_vmp != NULL) {
				vmem_destroy(rsrc_pool->rsrc_vmp);
			}
			if (rsrc_pool->rsrc_ddr_offset !=
			    rsrc_pool->rsrc_start) {
				vmem_xfree(state->ts_ddrvmem,
				    rsrc_pool->rsrc_ddr_offset,
				    rsrc_pool->rsrc_pool_size);
			}
			TNF_PROBE_0(tavor_rsrc_hw_entries_init_pre_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_rsrc_hw_entries_init);
			return (DDI_FAILURE);
		}
	}
	rsrc_pool->rsrc_private = rsvd_rsrc;

	TAVOR_TNF_EXIT(tavor_rsrc_hw_entries_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_hw_entries_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_rsrc_hw_entries_fini(tavor_state_t *state,
    tavor_rsrc_hw_entry_info_t *info)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_rsrc_t		*rsvd_rsrc;

	TAVOR_TNF_ENTER(tavor_rsrc_hw_entries_fini);

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->hwi_rsrcpool;
	ASSERT(rsrc_pool != NULL);

	/* Free up any "reserved" (i.e. preallocated) HW entries */
	rsvd_rsrc = (tavor_rsrc_t *)rsrc_pool->rsrc_private;
	if (rsvd_rsrc != NULL) {
		tavor_rsrc_free(state, &rsvd_rsrc);
	}

	/*
	 * If we've actually setup a vmem arena for the HW entries, then
	 * destroy it now
	 */
	if (rsrc_pool->rsrc_vmp != NULL) {
		vmem_destroy(rsrc_pool->rsrc_vmp);
	}

	/*
	 * Determine if a region was allocated from the tavor_ddr_vmem
	 * arena (and free it up if necessary)
	 */
	if (rsrc_pool->rsrc_ddr_offset != rsrc_pool->rsrc_start) {
		vmem_xfree(state->ts_ddrvmem, rsrc_pool->rsrc_ddr_offset,
		    rsrc_pool->rsrc_pool_size);
	}

	TAVOR_TNF_EXIT(tavor_rsrc_hw_entries_fini);
}


/*
 * tavor_rsrc_sw_handles_init()
 *    Context: Only called from attach() path context
 */
/* ARGSUSED */
static int
tavor_rsrc_sw_handles_init(tavor_state_t *state, tavor_rsrc_sw_hdl_info_t *info)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	uint64_t		num_swhdl, max_swhdl, prealloc_sz;

	TAVOR_TNF_ENTER(tavor_rsrc_sw_handles_init);

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool	= info->swi_rsrcpool;
	ASSERT(rsrc_pool != NULL);
	num_swhdl	= info->swi_num;
	max_swhdl	= info->swi_max;
	prealloc_sz	= info->swi_prealloc_sz;

	/* Make sure number of SW handles makes sense */
	if (num_swhdl > max_swhdl) {
		TNF_PROBE_2(tavor_rsrc_sw_handles_init_toomany_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "number of SW "
		    "handles exceeds maximum", tnf_uint, maxsw, max_swhdl);
		TAVOR_TNF_EXIT(tavor_rsrc_sw_handles_init);
		return (DDI_FAILURE);
	}

	/*
	 * Depending on the flags parameter, create a kmem_cache for some
	 * number of software handle structures.  Note: kmem_cache_create()
	 * will SLEEP until successful.
	 */
	if (info->swi_flags & TAVOR_SWHDL_KMEMCACHE_INIT) {
		rsrc_pool->rsrc_private = kmem_cache_create(
		    info->swi_rsrcname, rsrc_pool->rsrc_quantum, 0,
		    info->swi_constructor, info->swi_destructor, NULL,
		    rsrc_pool->rsrc_state, NULL, 0);
	}

	/* Allocate the central list of SW handle pointers */
	if (info->swi_flags & TAVOR_SWHDL_TABLE_INIT) {
		info->swi_table_ptr = kmem_zalloc(num_swhdl * prealloc_sz,
		    KM_SLEEP);
	}

	TAVOR_TNF_EXIT(tavor_rsrc_sw_handles_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_sw_handles_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
/* ARGSUSED */
static void
tavor_rsrc_sw_handles_fini(tavor_state_t *state, tavor_rsrc_sw_hdl_info_t *info)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	uint64_t		num_swhdl, prealloc_sz;

	TAVOR_TNF_ENTER(tavor_rsrc_sw_handles_fini);

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool	= info->swi_rsrcpool;
	num_swhdl	= info->swi_num;
	prealloc_sz	= info->swi_prealloc_sz;

	/*
	 * If a "software handle" kmem_cache exists for this resource, then
	 * destroy it now
	 */
	if (rsrc_pool != NULL) {
		kmem_cache_destroy(rsrc_pool->rsrc_private);
	}

	/* Free up this central list of SW handle pointers */
	if (info->swi_table_ptr != NULL) {
		kmem_free(info->swi_table_ptr, num_swhdl * prealloc_sz);
	}

	TAVOR_TNF_EXIT(tavor_rsrc_sw_handles_fini);
}


/*
 * tavor_rsrc_pd_handles_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_rsrc_pd_handles_init(tavor_state_t *state, tavor_rsrc_sw_hdl_info_t *info)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	vmem_t			*vmp;
	char			vmem_name[TAVOR_RSRC_NAME_MAXLEN];
	int			status;

	TAVOR_TNF_ENTER(tavor_rsrc_pd_handles_init);

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->swi_rsrcpool;
	ASSERT(rsrc_pool != NULL);

	/* Initialize the resource pool for software handle table */
	status = tavor_rsrc_sw_handles_init(state, info);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_rsrc_pdhdl_alloc_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_rsrc_pdhdl_alloc);
		return (DDI_FAILURE);
	}

	/* Build vmem arena name from Tavor instance */
	TAVOR_RSRC_NAME(vmem_name, TAVOR_PDHDL_VMEM);

	/* Create new vmem arena for PD numbers */
	vmp = vmem_create(vmem_name, (caddr_t)1, info->swi_num, 1, NULL,
	    NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);
	if (vmp == NULL) {
		/* Unable to create vmem arena */
		info->swi_table_ptr = NULL;
		tavor_rsrc_sw_handles_fini(state, info);
		TNF_PROBE_0(tavor_rsrc_pd_handles_init_vmem_create_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_rsrc_pd_handles_init);
		return (DDI_FAILURE);
	}
	rsrc_pool->rsrc_vmp = vmp;

	TAVOR_TNF_EXIT(tavor_rsrc_pd_handles_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_pd_handles_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_rsrc_pd_handles_fini(tavor_state_t *state, tavor_rsrc_sw_hdl_info_t *info)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;

	TAVOR_TNF_ENTER(tavor_rsrc_pd_handles_fini);

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->swi_rsrcpool;

	/* Destroy the specially created UAR scratch table vmem arena */
	vmem_destroy(rsrc_pool->rsrc_vmp);

	/* Destroy the "tavor_sw_pd_t" kmem_cache */
	tavor_rsrc_sw_handles_fini(state, info);

	TAVOR_TNF_EXIT(tavor_rsrc_pd_handles_fini);
}


/*
 * tavor_rsrc_mbox_alloc()
 *    Context: Only called from attach() path context
 */
static int
tavor_rsrc_mbox_alloc(tavor_rsrc_pool_info_t *pool_info, uint_t num,
    tavor_rsrc_t *hdl)
{
	tavor_rsrc_priv_mbox_t	*priv;
	void			*addr;
	caddr_t			kaddr;
	uint64_t		offset;
	size_t			real_len, temp_len;
	int			status;

	TAVOR_TNF_ENTER(tavor_rsrc_mbox_alloc);

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Get the private pointer for the mailboxes */
	priv = pool_info->rsrc_private;
	ASSERT(priv != NULL);

	/*
	 * Allocate a DMA handle for the mailbox.  This will be used for
	 * two purposes (potentially).  First, it could be used below in
	 * the call to ddi_dma_mem_alloc() - if the mailbox is to come from
	 * system memory.  Second, it is definitely used later to bind
	 * the mailbox for DMA access from/by the hardware.
	 */
	status = ddi_dma_alloc_handle(priv->pmb_dip, &priv->pmb_dmaattr,
	    DDI_DMA_SLEEP, NULL, &hdl->tr_dmahdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_1(tavor_rsrc_mbox_alloc_dmahdl_fail, TAVOR_TNF_ERROR,
		    "", tnf_uint, status, status);
		TAVOR_TNF_EXIT(tavor_rsrc_mbox_alloc);
		return (DDI_FAILURE);
	}

	/* Is mailbox in DDR memory or system memory? */
	if (pool_info->rsrc_loc == TAVOR_IN_DDR) {
		/* Use vmem_alloc() to get DDR address of mbox */
		hdl->tr_len = (num * pool_info->rsrc_quantum);
		addr = vmem_alloc(pool_info->rsrc_vmp, hdl->tr_len,
		    VM_SLEEP);
		if (addr == NULL) {
			/* No more DDR available for mailbox entries */
			ddi_dma_free_handle(&hdl->tr_dmahdl);
			TNF_PROBE_0(tavor_rsrc_mbox_alloc_vma_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_rsrc_mbox_alloc);
			return (DDI_FAILURE);
		}
		hdl->tr_acchdl = priv->pmb_acchdl;

		/* Calculate kernel virtual address (from the DDR offset) */
		offset = ((uintptr_t)addr -
		    (uintptr_t)pool_info->rsrc_ddr_offset);
		hdl->tr_addr = (void *)(uintptr_t)(offset +
		    (uintptr_t)pool_info->rsrc_start);

	} else { /* TAVOR_IN_SYSMEM */

		/* Use ddi_dma_mem_alloc() to get memory for mailbox */
		temp_len = (num * pool_info->rsrc_quantum);
		status = ddi_dma_mem_alloc(hdl->tr_dmahdl, temp_len,
		    &priv->pmb_devaccattr, priv->pmb_xfer_mode, DDI_DMA_SLEEP,
		    NULL, &kaddr, &real_len, &hdl->tr_acchdl);
		if (status != DDI_SUCCESS) {
			/* No more sys memory available for mailbox entries */
			ddi_dma_free_handle(&hdl->tr_dmahdl);
			TNF_PROBE_0(tavor_rsrc_mbox_alloc_dma_memalloc_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_rsrc_mbox_alloc);
			return (DDI_FAILURE);
		}
		hdl->tr_addr = (void *)kaddr;
		hdl->tr_len  = real_len;
	}

	TAVOR_TNF_EXIT(tavor_rsrc_mbox_alloc);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_mbox_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_rsrc_mbox_free(tavor_rsrc_pool_info_t *pool_info, tavor_rsrc_t *hdl)
{
	void		*addr;
	uint64_t	offset;

	TAVOR_TNF_ENTER(tavor_rsrc_mbox_free);

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Is mailbox in DDR memory or system memory? */
	if (pool_info->rsrc_loc == TAVOR_IN_DDR) {

		/* Calculate the allocated address (the mbox's DDR offset) */
		offset = ((uintptr_t)hdl->tr_addr -
		    (uintptr_t)pool_info->rsrc_start);
		addr = (void *)(uintptr_t)(offset +
		    (uintptr_t)pool_info->rsrc_ddr_offset);

		/* Use vmem_free() to free up DDR memory for mailbox */
		vmem_free(pool_info->rsrc_vmp, addr, hdl->tr_len);

	} else { /* TAVOR_IN_SYSMEM */

		/* Use ddi_dma_mem_free() to free up sys memory for mailbox */
		ddi_dma_mem_free(&hdl->tr_acchdl);
	}

	/* Free the DMA handle for the mailbox */
	ddi_dma_free_handle(&hdl->tr_dmahdl);

	TAVOR_TNF_EXIT(tavor_rsrc_mbox_free);
}


/*
 * tavor_rsrc_hw_entry_alloc()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_rsrc_hw_entry_alloc(tavor_rsrc_pool_info_t *pool_info, uint_t num,
    uint_t num_align, ddi_acc_handle_t acc_handle, uint_t sleepflag,
    tavor_rsrc_t *hdl)
{
	void		*addr;
	uint64_t	offset;
	uint32_t	align;
	int		flag;

	TAVOR_TNF_ENTER(tavor_rsrc_hw_entry_alloc);

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/*
	 * Tavor hardware entries (QPC, CQC, EQC, MPT, MTT, etc.) do not
	 * use dma_handle (because they are in Tavor locally attached DDR
	 * memory) and, generally, don't use the acc_handle (because the
	 * entries are not directly accessed by software).  The exceptions
	 * to this rule are the UARPG and UDAV entries.
	 */

	/*
	 * Use vmem_xalloc() to get a properly aligned pointer (based on
	 * the number requested) to the HW entry(ies).  This handles the
	 * cases (for special QPCs and for RDB entries) where we need more
	 * than one and need to ensure that they are properly aligned.
	 */
	flag = (sleepflag == TAVOR_SLEEP) ? VM_SLEEP : VM_NOSLEEP;
	hdl->tr_len = (num * pool_info->rsrc_quantum);
	align	    = (num_align * pool_info->rsrc_quantum);
	addr = vmem_xalloc(pool_info->rsrc_vmp, hdl->tr_len,
	    align, 0, 0, NULL, NULL, flag | VM_FIRSTFIT);
	if (addr == NULL) {
		/* No more HW entries available */
		TNF_PROBE_0(tavor_rsrc_hw_entry_alloc_vmxa_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_rsrc_hw_entry_alloc);
		return (DDI_FAILURE);
	}

	/* If an access handle was provided, fill it in */
	if (acc_handle != 0) {
		hdl->tr_acchdl = acc_handle;
	}

	/* Calculate vaddr and HW table index (from the DDR offset) */
	offset = ((uintptr_t)addr - (uintptr_t)pool_info->rsrc_ddr_offset);
	hdl->tr_addr = (void *)(uintptr_t)(offset +
	    (uintptr_t)pool_info->rsrc_start);
	hdl->tr_indx = (offset >> pool_info->rsrc_shift);

	TAVOR_TNF_EXIT(tavor_rsrc_hw_entry_alloc);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_hw_entry_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_rsrc_hw_entry_free(tavor_rsrc_pool_info_t *pool_info, tavor_rsrc_t *hdl)
{
	void		*addr;
	uint64_t	offset;

	TAVOR_TNF_ENTER(tavor_rsrc_hw_entry_free);

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Calculate the allocated address (the entry's DDR offset) */
	offset = ((uintptr_t)hdl->tr_addr - (uintptr_t)pool_info->rsrc_start);
	addr   = (void *)(uintptr_t)(offset +
	    (uintptr_t)pool_info->rsrc_ddr_offset);

	/* Use vmem_xfree() to free up the HW table entry */
	vmem_xfree(pool_info->rsrc_vmp, addr, hdl->tr_len);

	TAVOR_TNF_EXIT(tavor_rsrc_hw_entry_free);
}


/*
 * tavor_rsrc_swhdl_alloc()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_rsrc_swhdl_alloc(tavor_rsrc_pool_info_t *pool_info, uint_t sleepflag,
    tavor_rsrc_t *hdl)
{
	void	*addr;
	int	flag;

	TAVOR_TNF_ENTER(tavor_rsrc_swhdl_alloc);

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Allocate the software handle structure */
	flag = (sleepflag == TAVOR_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	addr = kmem_cache_alloc(pool_info->rsrc_private, flag);
	if (addr == NULL) {
		TNF_PROBE_0(tavor_rsrc_swhdl_alloc_kmca_fail, TAVOR_TNF_ERROR,
		    "");
		TAVOR_TNF_EXIT(tavor_rsrc_swhdl_alloc);
		return (DDI_FAILURE);
	}
	hdl->tr_len  = pool_info->rsrc_quantum;
	hdl->tr_addr = addr;

	TAVOR_TNF_EXIT(tavor_rsrc_swhdl_alloc);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_swhdl_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_rsrc_swhdl_free(tavor_rsrc_pool_info_t *pool_info, tavor_rsrc_t *hdl)
{
	TAVOR_TNF_ENTER(tavor_rsrc_swhdl_free);

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Free the software handle structure */
	kmem_cache_free(pool_info->rsrc_private, hdl->tr_addr);

	TAVOR_TNF_EXIT(tavor_rsrc_swhdl_free);
}


/*
 * tavor_rsrc_pdhdl_alloc()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_rsrc_pdhdl_alloc(tavor_rsrc_pool_info_t *pool_info, uint_t sleepflag,
    tavor_rsrc_t *hdl)
{
	tavor_pdhdl_t	addr;
	void		*tmpaddr;
	int		flag, status;

	TAVOR_TNF_ENTER(tavor_rsrc_pdhdl_alloc);

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Allocate the software handle */
	status = tavor_rsrc_swhdl_alloc(pool_info, sleepflag, hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_rsrc_pdhdl_alloc_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_rsrc_pdhdl_alloc);
		return (DDI_FAILURE);
	}
	addr = (tavor_pdhdl_t)hdl->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*addr))

	/* Allocate a PD number for the handle */
	flag = (sleepflag == TAVOR_SLEEP) ? VM_SLEEP : VM_NOSLEEP;
	tmpaddr = vmem_alloc(pool_info->rsrc_vmp, 1, flag);
	if (tmpaddr == NULL) {
		/* No more PD number entries available */
		tavor_rsrc_swhdl_free(pool_info, hdl);
		TNF_PROBE_0(tavor_rsrc_pdhdl_alloc_vma_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_rsrc_pdhdl_alloc);
		return (DDI_FAILURE);
	}
	addr->pd_pdnum = (uint32_t)(uintptr_t)tmpaddr;
	addr->pd_rsrcp = hdl;
	hdl->tr_indx   = addr->pd_pdnum;

	TAVOR_TNF_EXIT(tavor_rsrc_pdhdl_alloc);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_pdhdl_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_rsrc_pdhdl_free(tavor_rsrc_pool_info_t *pool_info, tavor_rsrc_t *hdl)
{
	TAVOR_TNF_ENTER(tavor_rsrc_pdhdl_free);

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Use vmem_free() to free up the PD number */
	vmem_free(pool_info->rsrc_vmp, (void *)(uintptr_t)hdl->tr_indx, 1);

	/* Free the software handle structure */
	tavor_rsrc_swhdl_free(pool_info, hdl);

	TAVOR_TNF_EXIT(tavor_rsrc_pdhdl_free);
}


/*
 * tavor_rsrc_pdhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_rsrc_pdhdl_constructor(void *pd, void *priv, int flags)
{
	tavor_pdhdl_t	pdhdl;
	tavor_state_t	*state;

	TAVOR_TNF_ENTER(tavor_rsrc_pdhdl_constructor);

	pdhdl = (tavor_pdhdl_t)pd;
	state = (tavor_state_t *)priv;

	mutex_init(&pdhdl->pd_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	TAVOR_TNF_EXIT(tavor_rsrc_pdhdl_constructor);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_pdhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
tavor_rsrc_pdhdl_destructor(void *pd, void *priv)
{
	tavor_pdhdl_t	pdhdl;

	TAVOR_TNF_ENTER(tavor_rsrc_pdhdl_destructor);

	pdhdl = (tavor_pdhdl_t)pd;

	mutex_destroy(&pdhdl->pd_lock);

	TAVOR_TNF_EXIT(tavor_rsrc_pdhdl_destructor);
}


/*
 * tavor_rsrc_cqhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_rsrc_cqhdl_constructor(void *cq, void *priv, int flags)
{
	tavor_cqhdl_t	cqhdl;
	tavor_state_t	*state;

	TAVOR_TNF_ENTER(tavor_rsrc_cqhdl_constructor);

	cqhdl = (tavor_cqhdl_t)cq;
	state = (tavor_state_t *)priv;

	mutex_init(&cqhdl->cq_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));
	mutex_init(&cqhdl->cq_wrid_wqhdr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	TAVOR_TNF_EXIT(tavor_rsrc_cqhdl_constructor);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_cqhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
tavor_rsrc_cqhdl_destructor(void *cq, void *priv)
{
	tavor_cqhdl_t	cqhdl;

	TAVOR_TNF_ENTER(tavor_rsrc_cqhdl_destructor);

	cqhdl = (tavor_cqhdl_t)cq;

	mutex_destroy(&cqhdl->cq_wrid_wqhdr_lock);
	mutex_destroy(&cqhdl->cq_lock);

	TAVOR_TNF_EXIT(tavor_rsrc_cqhdl_destructor);
}


/*
 * tavor_rsrc_qphdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_rsrc_qphdl_constructor(void *qp, void *priv, int flags)
{
	tavor_qphdl_t	qphdl;
	tavor_state_t	*state;

	TAVOR_TNF_ENTER(tavor_rsrc_qphdl_constructor);

	qphdl = (tavor_qphdl_t)qp;
	state = (tavor_state_t *)priv;

	mutex_init(&qphdl->qp_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	TAVOR_TNF_EXIT(tavor_rsrc_qphdl_constructor);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_qphdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
tavor_rsrc_qphdl_destructor(void *qp, void *priv)
{
	tavor_qphdl_t	qphdl;

	TAVOR_TNF_ENTER(tavor_rsrc_qphdl_destructor);

	qphdl = (tavor_qphdl_t)qp;

	mutex_destroy(&qphdl->qp_lock);

	TAVOR_TNF_ENTER(tavor_rsrc_qphdl_destructor);
}


/*
 * tavor_rsrc_srqhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_rsrc_srqhdl_constructor(void *srq, void *priv, int flags)
{
	tavor_srqhdl_t	srqhdl;
	tavor_state_t	*state;

	TAVOR_TNF_ENTER(tavor_rsrc_srqhdl_constructor);

	srqhdl = (tavor_srqhdl_t)srq;
	state = (tavor_state_t *)priv;

	mutex_init(&srqhdl->srq_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	TAVOR_TNF_EXIT(tavor_rsrc_srqhdl_constructor);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_srqhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
tavor_rsrc_srqhdl_destructor(void *srq, void *priv)
{
	tavor_srqhdl_t	srqhdl;

	TAVOR_TNF_ENTER(tavor_rsrc_srqhdl_destructor);

	srqhdl = (tavor_srqhdl_t)srq;

	mutex_destroy(&srqhdl->srq_lock);

	TAVOR_TNF_EXIT(tavor_rsrc_srqhdl_destructor);
}


/*
 * tavor_rsrc_refcnt_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_rsrc_refcnt_constructor(void *rc, void *priv, int flags)
{
	tavor_sw_refcnt_t	*refcnt;
	tavor_state_t		*state;

	TAVOR_TNF_ENTER(tavor_rsrc_refcnt_constructor);

	refcnt = (tavor_sw_refcnt_t *)rc;
	state  = (tavor_state_t *)priv;

	mutex_init(&refcnt->swrc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	TAVOR_TNF_EXIT(tavor_rsrc_refcnt_constructor);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_refcnt_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
tavor_rsrc_refcnt_destructor(void *rc, void *priv)
{
	tavor_sw_refcnt_t	*refcnt;

	TAVOR_TNF_ENTER(tavor_rsrc_refcnt_destructor);

	refcnt = (tavor_sw_refcnt_t *)rc;

	mutex_destroy(&refcnt->swrc_lock);

	TAVOR_TNF_ENTER(tavor_rsrc_refcnt_destructor);
}


/*
 * tavor_rsrc_ahhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_rsrc_ahhdl_constructor(void *ah, void *priv, int flags)
{
	tavor_ahhdl_t	ahhdl;
	tavor_state_t	*state;

	TAVOR_TNF_ENTER(tavor_rsrc_ahhdl_constructor);

	ahhdl = (tavor_ahhdl_t)ah;
	state = (tavor_state_t *)priv;

	mutex_init(&ahhdl->ah_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	TAVOR_TNF_EXIT(tavor_rsrc_ahhdl_constructor);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_ahhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
tavor_rsrc_ahhdl_destructor(void *ah, void *priv)
{
	tavor_ahhdl_t	ahhdl;

	TAVOR_TNF_ENTER(tavor_rsrc_ahhdl_destructor);

	ahhdl = (tavor_ahhdl_t)ah;

	mutex_destroy(&ahhdl->ah_lock);

	TAVOR_TNF_ENTER(tavor_rsrc_ahhdl_destructor);
}


/*
 * tavor_rsrc_mrhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_rsrc_mrhdl_constructor(void *mr, void *priv, int flags)
{
	tavor_mrhdl_t	mrhdl;
	tavor_state_t	*state;

	TAVOR_TNF_ENTER(tavor_rsrc_mrhdl_constructor);

	mrhdl = (tavor_mrhdl_t)mr;
	state = (tavor_state_t *)priv;

	mutex_init(&mrhdl->mr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	TAVOR_TNF_EXIT(tavor_rsrc_mrhdl_constructor);
	return (DDI_SUCCESS);
}


/*
 * tavor_rsrc_mrhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
tavor_rsrc_mrhdl_destructor(void *mr, void *priv)
{
	tavor_mrhdl_t	mrhdl;

	TAVOR_TNF_ENTER(tavor_rsrc_mrhdl_destructor);

	mrhdl = (tavor_mrhdl_t)mr;

	mutex_destroy(&mrhdl->mr_lock);

	TAVOR_TNF_ENTER(tavor_rsrc_mrhdl_destructor);
}


/*
 * tavor_rsrc_mcg_entry_get_size()
 */
static int
tavor_rsrc_mcg_entry_get_size(tavor_state_t *state, uint_t *mcg_size_shift)
{
	uint_t	num_qp_per_mcg, max_qp_per_mcg, log2;

	TAVOR_TNF_ENTER(tavor_rsrc_mcg_entry_get_size);

	/*
	 * Round the configured number of QP per MCG to next larger
	 * power-of-2 size and update.
	 */
	num_qp_per_mcg = state->ts_cfg_profile->cp_num_qp_per_mcg + 8;
	log2 = highbit(num_qp_per_mcg);
	if (ISP2(num_qp_per_mcg)) {
		log2 = log2 - 1;
	}
	state->ts_cfg_profile->cp_num_qp_per_mcg = (1 << log2) - 8;

	/* Now make sure number of QP per MCG makes sense */
	num_qp_per_mcg = state->ts_cfg_profile->cp_num_qp_per_mcg;
	max_qp_per_mcg = (1 << state->ts_devlim.log_max_qp_mcg);
	if (num_qp_per_mcg > max_qp_per_mcg) {
		TNF_PROBE_1(tavor_rsrc_mcg_getsz_toomany_qppermcg_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, maxqpmcg, max_qp_per_mcg);
		TAVOR_TNF_EXIT(tavor_rsrc_mcg_entry_get_size);
		return (DDI_FAILURE);
	}

	/* Return the (shift) size of an individual MCG HW entry */
	*mcg_size_shift = log2 + 2;

	TAVOR_TNF_EXIT(tavor_rsrc_mcg_entry_get_size);
	return (DDI_SUCCESS);
}
