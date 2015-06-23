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

/*
 * hermon_rsrc.c
 *    Hermon Resource Management Routines
 *
 *    Implements all the routines necessary for setup, teardown, and
 *    alloc/free of all Hermon resources, including those that are managed
 *    by Hermon hardware or which live in Hermon's direct attached DDR memory.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/vmem.h>
#include <sys/bitmap.h>

#include <sys/ib/adapters/hermon/hermon.h>

int hermon_rsrc_verbose = 0;

/*
 * The following routines are used for initializing and destroying
 * the resource pools used by the Hermon resource allocation routines.
 * They consist of four classes of object:
 *
 * Mailboxes:  The "In" and "Out" mailbox types are used by the Hermon
 *    command interface routines.  Mailboxes are used to pass information
 *    back and forth to the Hermon firmware.  Either type of mailbox may
 *    be allocated from Hermon's direct attached DDR memory or from system
 *    memory (although currently all "In" mailboxes are in DDR and all "out"
 *    mailboxes come from system memory.
 *
 * HW entry objects:  These objects represent resources required by the Hermon
 *    hardware.  These objects include things like Queue Pair contexts (QPC),
 *    Completion Queue contexts (CQC), Event Queue contexts (EQC), RDB (for
 *    supporting RDMA Read/Atomic), Multicast Group entries (MCG), Memory
 *    Protection Table entries (MPT), Memory Translation Table entries (MTT).
 *
 *    What these objects all have in common is that they are each required
 *    to come from ICM memory, they are always allocated from tables, and
 *    they are not to be directly accessed (read or written) by driver
 *    software (Mellanox FMR access to MPT is an exception).
 *    The other notable exceptions are the UAR pages (UAR_PG) which are
 *    allocated from the UAR address space rather than DDR, and the UD
 *    address vectors (UDAV) which are similar to the common object types
 *    with the major difference being that UDAVs _are_ directly read and
 *    written by driver software.
 *
 * SW handle objects: These objects represent resources required by Hermon
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

static int hermon_rsrc_mbox_init(hermon_state_t *state,
    hermon_rsrc_mbox_info_t *info);
static void hermon_rsrc_mbox_fini(hermon_state_t *state,
    hermon_rsrc_mbox_info_t *info);

static int hermon_rsrc_sw_handles_init(hermon_state_t *state,
    hermon_rsrc_sw_hdl_info_t *info);
static void hermon_rsrc_sw_handles_fini(hermon_state_t *state,
    hermon_rsrc_sw_hdl_info_t *info);

static int hermon_rsrc_pd_handles_init(hermon_state_t *state,
    hermon_rsrc_sw_hdl_info_t *info);
static void hermon_rsrc_pd_handles_fini(hermon_state_t *state,
    hermon_rsrc_sw_hdl_info_t *info);

/*
 * The following routines are used for allocating and freeing the specific
 * types of objects described above from their associated resource pools.
 */
static int hermon_rsrc_mbox_alloc(hermon_rsrc_pool_info_t *pool_info,
    uint_t num, hermon_rsrc_t *hdl);
static void hermon_rsrc_mbox_free(hermon_rsrc_t *hdl);

static int hermon_rsrc_hw_entry_alloc(hermon_rsrc_pool_info_t *pool_info,
    uint_t num, uint_t num_align, uint_t sleepflag, hermon_rsrc_t *hdl);
static void hermon_rsrc_hw_entry_free(hermon_rsrc_pool_info_t *pool_info,
    hermon_rsrc_t *hdl);
static int hermon_rsrc_hw_entry_reserve(hermon_rsrc_pool_info_t *pool_info,
    uint_t num, uint_t num_align, uint_t sleepflag, hermon_rsrc_t *hdl);

static int hermon_rsrc_hw_entry_icm_confirm(hermon_rsrc_pool_info_t *pool_info,
    uint_t num, hermon_rsrc_t *hdl, int num_to_hdl);
static int hermon_rsrc_hw_entry_icm_free(hermon_rsrc_pool_info_t *pool_info,
    hermon_rsrc_t *hdl, int num_to_hdl);

static int hermon_rsrc_swhdl_alloc(hermon_rsrc_pool_info_t *pool_info,
    uint_t sleepflag, hermon_rsrc_t *hdl);
static void hermon_rsrc_swhdl_free(hermon_rsrc_pool_info_t *pool_info,
    hermon_rsrc_t *hdl);

static int hermon_rsrc_pdhdl_alloc(hermon_rsrc_pool_info_t *pool_info,
    uint_t sleepflag, hermon_rsrc_t *hdl);
static void hermon_rsrc_pdhdl_free(hermon_rsrc_pool_info_t *pool_info,
    hermon_rsrc_t *hdl);

static int hermon_rsrc_fexch_alloc(hermon_state_t *state,
    hermon_rsrc_type_t rsrc, uint_t num, uint_t sleepflag, hermon_rsrc_t *hdl);
static void hermon_rsrc_fexch_free(hermon_state_t *state, hermon_rsrc_t *hdl);
static int hermon_rsrc_rfci_alloc(hermon_state_t *state,
    hermon_rsrc_type_t rsrc, uint_t num, uint_t sleepflag, hermon_rsrc_t *hdl);
static void hermon_rsrc_rfci_free(hermon_state_t *state, hermon_rsrc_t *hdl);

/*
 * The following routines are the constructors and destructors for several
 * of the SW handle type objects.  For certain types of SW handles objects
 * (all of which are implemented using kmem_cache), we need to do some
 * special field initialization (specifically, mutex_init/destroy).  These
 * routines enable that init and teardown.
 */
static int hermon_rsrc_pdhdl_constructor(void *pd, void *priv, int flags);
static void hermon_rsrc_pdhdl_destructor(void *pd, void *state);
static int hermon_rsrc_cqhdl_constructor(void *cq, void *priv, int flags);
static void hermon_rsrc_cqhdl_destructor(void *cq, void *state);
static int hermon_rsrc_qphdl_constructor(void *cq, void *priv, int flags);
static void hermon_rsrc_qphdl_destructor(void *cq, void *state);
static int hermon_rsrc_srqhdl_constructor(void *srq, void *priv, int flags);
static void hermon_rsrc_srqhdl_destructor(void *srq, void *state);
static int hermon_rsrc_refcnt_constructor(void *rc, void *priv, int flags);
static void hermon_rsrc_refcnt_destructor(void *rc, void *state);
static int hermon_rsrc_ahhdl_constructor(void *ah, void *priv, int flags);
static void hermon_rsrc_ahhdl_destructor(void *ah, void *state);
static int hermon_rsrc_mrhdl_constructor(void *mr, void *priv, int flags);
static void hermon_rsrc_mrhdl_destructor(void *mr, void *state);

/*
 * Special routine to calculate and return the size of a MCG object based
 * on current driver configuration (specifically, the number of QP per MCG
 * that has been configured.
 */
static int hermon_rsrc_mcg_entry_get_size(hermon_state_t *state,
    uint_t *mcg_size_shift);


/*
 * hermon_rsrc_alloc()
 *
 *    Context: Can be called from interrupt or base context.
 *    The "sleepflag" parameter is used by all object allocators to
 *    determine whether to SLEEP for resources or not.
 */
int
hermon_rsrc_alloc(hermon_state_t *state, hermon_rsrc_type_t rsrc, uint_t num,
    uint_t sleepflag, hermon_rsrc_t **hdl)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;
	hermon_rsrc_t		*tmp_rsrc_hdl;
	int			flag, status = DDI_FAILURE;

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	rsrc_pool = &state->hs_rsrc_hdl[rsrc];
	ASSERT(rsrc_pool != NULL);

	/*
	 * Allocate space for the object used to track the resource handle
	 */
	flag = (sleepflag == HERMON_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	tmp_rsrc_hdl = kmem_cache_alloc(state->hs_rsrc_cache, flag);
	if (tmp_rsrc_hdl == NULL) {
		return (DDI_FAILURE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*tmp_rsrc_hdl))

	/*
	 * Set rsrc_hdl type.  This is later used by the hermon_rsrc_free call
	 * to know what type of resource is being freed.
	 */
	tmp_rsrc_hdl->rsrc_type = rsrc;

	/*
	 * Depending on resource type, call the appropriate alloc routine
	 */
	switch (rsrc) {
	case HERMON_IN_MBOX:
	case HERMON_OUT_MBOX:
	case HERMON_INTR_IN_MBOX:
	case HERMON_INTR_OUT_MBOX:
		status = hermon_rsrc_mbox_alloc(rsrc_pool, num, tmp_rsrc_hdl);
		break;

	case HERMON_DMPT:
		/* Allocate "num" (contiguous/aligned for FEXCH) DMPTs */
	case HERMON_QPC:
		/* Allocate "num" (contiguous/aligned for RSS) QPCs */
		status = hermon_rsrc_hw_entry_alloc(rsrc_pool, num, num,
		    sleepflag, tmp_rsrc_hdl);
		break;

	case HERMON_QPC_FEXCH_PORT1:
	case HERMON_QPC_FEXCH_PORT2:
		/* Allocate "num" contiguous/aligned QPCs for FEXCH */
		status = hermon_rsrc_fexch_alloc(state, rsrc, num,
		    sleepflag, tmp_rsrc_hdl);
		break;

	case HERMON_QPC_RFCI_PORT1:
	case HERMON_QPC_RFCI_PORT2:
		/* Allocate "num" contiguous/aligned QPCs for RFCI */
		status = hermon_rsrc_rfci_alloc(state, rsrc, num,
		    sleepflag, tmp_rsrc_hdl);
		break;

	case HERMON_MTT:
	case HERMON_CQC:
	case HERMON_SRQC:
	case HERMON_EQC:
	case HERMON_MCG:
	case HERMON_UARPG:
		/* Allocate "num" unaligned resources */
		status = hermon_rsrc_hw_entry_alloc(rsrc_pool, num, 1,
		    sleepflag, tmp_rsrc_hdl);
		break;

	case HERMON_MRHDL:
	case HERMON_EQHDL:
	case HERMON_CQHDL:
	case HERMON_SRQHDL:
	case HERMON_AHHDL:
	case HERMON_QPHDL:
	case HERMON_REFCNT:
		status = hermon_rsrc_swhdl_alloc(rsrc_pool, sleepflag,
		    tmp_rsrc_hdl);
		break;

	case HERMON_PDHDL:
		status = hermon_rsrc_pdhdl_alloc(rsrc_pool, sleepflag,
		    tmp_rsrc_hdl);
		break;

	case HERMON_RDB:	/* handled during HERMON_QPC */
	case HERMON_ALTC:	/* handled during HERMON_QPC */
	case HERMON_AUXC:	/* handled during HERMON_QPC */
	case HERMON_CMPT_QPC:	/* handled during HERMON_QPC */
	case HERMON_CMPT_SRQC:	/* handled during HERMON_SRQC */
	case HERMON_CMPT_CQC:	/* handled during HERMON_CPC */
	case HERMON_CMPT_EQC:	/* handled during HERMON_EPC */
	default:
		HERMON_WARNING(state, "unexpected resource type in alloc ");
		cmn_err(CE_WARN, "Resource type %x \n", rsrc_pool->rsrc_type);
		break;
	}

	/*
	 * If the resource allocation failed, then free the special resource
	 * tracking structure and return failure.  Otherwise return the
	 * handle for the resource tracking structure.
	 */
	if (status != DDI_SUCCESS) {
		kmem_cache_free(state->hs_rsrc_cache, tmp_rsrc_hdl);
		return (DDI_FAILURE);
	} else {
		*hdl = tmp_rsrc_hdl;
		return (DDI_SUCCESS);
	}
}


/*
 * hermon_rsrc_reserve()
 *
 *    Context: Can only be called from attach.
 *    The "sleepflag" parameter is used by all object allocators to
 *    determine whether to SLEEP for resources or not.
 */
int
hermon_rsrc_reserve(hermon_state_t *state, hermon_rsrc_type_t rsrc, uint_t num,
    uint_t sleepflag, hermon_rsrc_t **hdl)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;
	hermon_rsrc_t		*tmp_rsrc_hdl;
	int			flag, status = DDI_FAILURE;

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	rsrc_pool = &state->hs_rsrc_hdl[rsrc];
	ASSERT(rsrc_pool != NULL);

	/*
	 * Allocate space for the object used to track the resource handle
	 */
	flag = (sleepflag == HERMON_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	tmp_rsrc_hdl = kmem_cache_alloc(state->hs_rsrc_cache, flag);
	if (tmp_rsrc_hdl == NULL) {
		return (DDI_FAILURE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*tmp_rsrc_hdl))

	/*
	 * Set rsrc_hdl type.  This is later used by the hermon_rsrc_free call
	 * to know what type of resource is being freed.
	 */
	tmp_rsrc_hdl->rsrc_type = rsrc;

	switch (rsrc) {
	case HERMON_QPC:
	case HERMON_DMPT:
	case HERMON_MTT:
		/*
		 * Reserve num resources, naturally aligned (N * num).
		 */
		status = hermon_rsrc_hw_entry_reserve(rsrc_pool, num, num,
		    sleepflag, tmp_rsrc_hdl);
		break;

	default:
		HERMON_WARNING(state, "unexpected resource type in reserve ");
		cmn_err(CE_WARN, "Resource type %x \n", rsrc);
		break;
	}

	/*
	 * If the resource allocation failed, then free the special resource
	 * tracking structure and return failure.  Otherwise return the
	 * handle for the resource tracking structure.
	 */
	if (status != DDI_SUCCESS) {
		kmem_cache_free(state->hs_rsrc_cache, tmp_rsrc_hdl);
		return (DDI_FAILURE);
	} else {
		*hdl = tmp_rsrc_hdl;
		return (DDI_SUCCESS);
	}
}


/*
 * hermon_rsrc_fexch_alloc()
 *
 *    Context: Can only be called from base context.
 *    The "sleepflag" parameter is used by all object allocators to
 *    determine whether to SLEEP for resources or not.
 */
static int
hermon_rsrc_fexch_alloc(hermon_state_t *state, hermon_rsrc_type_t rsrc,
    uint_t num, uint_t sleepflag, hermon_rsrc_t *hdl)
{
	hermon_fcoib_t		*fcoib;
	void			*addr;
	uint32_t		fexch_qpn_base;
	hermon_rsrc_pool_info_t	*qpc_pool, *mpt_pool, *mtt_pool;
	int			flag, status;
	hermon_rsrc_t		mpt_hdl; /* temporary, just for icm_confirm */
	hermon_rsrc_t		mtt_hdl; /* temporary, just for icm_confirm */
	uint_t			portm1;	/* hca_port_number - 1 */
	uint_t			nummtt;
	vmem_t			*vmp;

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	if ((state->hs_ibtfinfo.hca_attr->hca_flags2 & IBT_HCA2_FC) == 0)
		return (DDI_FAILURE);

	portm1 = rsrc - HERMON_QPC_FEXCH_PORT1;
	fcoib = &state->hs_fcoib;
	flag = (sleepflag == HERMON_SLEEP) ? VM_SLEEP : VM_NOSLEEP;

	/* Allocate from the FEXCH QP range */
	vmp = fcoib->hfc_fexch_vmemp[portm1];
	addr = vmem_xalloc(vmp, num, num, 0, 0, NULL, NULL, flag | VM_FIRSTFIT);
	if (addr == NULL) {
		return (DDI_FAILURE);
	}
	fexch_qpn_base = (uint32_t)((uintptr_t)addr -
	    fcoib->hfc_vmemstart + fcoib->hfc_fexch_base[portm1]);

	/* ICM confirm for the FEXCH QP range */
	qpc_pool = &state->hs_rsrc_hdl[HERMON_QPC];
	hdl->hr_len = num << qpc_pool->rsrc_shift;
	hdl->hr_addr = addr;	/* used only for vmem_xfree */
	hdl->hr_indx = fexch_qpn_base;

	status = hermon_rsrc_hw_entry_icm_confirm(qpc_pool, num, hdl, 1);
	if (status != DDI_SUCCESS) {
		vmem_xfree(vmp, addr, num);
		return (DDI_FAILURE);
	}

	/* ICM confirm for the Primary MKEYs (client side only) */
	mpt_pool = &state->hs_rsrc_hdl[HERMON_DMPT];
	mpt_hdl.hr_len = num << mpt_pool->rsrc_shift;
	mpt_hdl.hr_addr = NULL;
	mpt_hdl.hr_indx = fcoib->hfc_mpt_base[portm1] +
	    (fexch_qpn_base - fcoib->hfc_fexch_base[portm1]);

	status = hermon_rsrc_hw_entry_icm_confirm(mpt_pool, num, &mpt_hdl, 0);
	if (status != DDI_SUCCESS) {
		status = hermon_rsrc_hw_entry_icm_free(qpc_pool, hdl, 1);
		vmem_xfree(vmp, addr, num);
		return (DDI_FAILURE);
	}

	/* ICM confirm for the MTTs of the Primary MKEYs (client side only) */
	nummtt = fcoib->hfc_mtts_per_mpt;
	num *= nummtt;
	mtt_pool = &state->hs_rsrc_hdl[HERMON_MTT];
	mtt_hdl.hr_len = num << mtt_pool->rsrc_shift;
	mtt_hdl.hr_addr = NULL;
	mtt_hdl.hr_indx = fcoib->hfc_mtt_base[portm1] +
	    (fexch_qpn_base - fcoib->hfc_fexch_base[portm1]) *
	    nummtt;

	status = hermon_rsrc_hw_entry_icm_confirm(mtt_pool, num, &mtt_hdl, 0);
	if (status != DDI_SUCCESS) {
		vmem_xfree(vmp, addr, num);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static void
hermon_rsrc_fexch_free(hermon_state_t *state, hermon_rsrc_t *hdl)
{
	hermon_fcoib_t		*fcoib;
	uint_t			portm1; /* hca_port_number - 1 */

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	portm1 = hdl->rsrc_type - HERMON_QPC_FEXCH_PORT1;
	fcoib = &state->hs_fcoib;
	vmem_xfree(fcoib->hfc_fexch_vmemp[portm1], hdl->hr_addr,
	    hdl->hr_len >> state->hs_rsrc_hdl[HERMON_QPC].rsrc_shift);
}

/*
 * hermon_rsrc_rfci_alloc()
 *
 *    Context: Can only be called from base context.
 *    The "sleepflag" parameter is used by all object allocators to
 *    determine whether to SLEEP for resources or not.
 */
static int
hermon_rsrc_rfci_alloc(hermon_state_t *state, hermon_rsrc_type_t rsrc,
    uint_t num, uint_t sleepflag, hermon_rsrc_t *hdl)
{
	hermon_fcoib_t		*fcoib;
	void			*addr;
	uint32_t		rfci_qpn_base;
	hermon_rsrc_pool_info_t	*qpc_pool;
	int			flag, status;
	uint_t			portm1;	/* hca_port_number - 1 */
	vmem_t			*vmp;

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	if ((state->hs_ibtfinfo.hca_attr->hca_flags2 & IBT_HCA2_FC) == 0)
		return (DDI_FAILURE);

	portm1 = rsrc - HERMON_QPC_RFCI_PORT1;
	fcoib = &state->hs_fcoib;
	flag = (sleepflag == HERMON_SLEEP) ? VM_SLEEP : VM_NOSLEEP;

	/* Allocate from the RFCI QP range */
	vmp = fcoib->hfc_rfci_vmemp[portm1];
	addr = vmem_xalloc(vmp, num, num, 0, 0, NULL, NULL, flag | VM_FIRSTFIT);
	if (addr == NULL) {
		return (DDI_FAILURE);
	}
	rfci_qpn_base = (uint32_t)((uintptr_t)addr -
	    fcoib->hfc_vmemstart + fcoib->hfc_rfci_base[portm1]);

	/* ICM confirm for the RFCI QP */
	qpc_pool = &state->hs_rsrc_hdl[HERMON_QPC];
	hdl->hr_len = num << qpc_pool->rsrc_shift;
	hdl->hr_addr = addr;	/* used only for vmem_xfree */
	hdl->hr_indx = rfci_qpn_base;

	status = hermon_rsrc_hw_entry_icm_confirm(qpc_pool, num, hdl, 1);
	if (status != DDI_SUCCESS) {
		vmem_xfree(vmp, addr, num);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static void
hermon_rsrc_rfci_free(hermon_state_t *state, hermon_rsrc_t *hdl)
{
	hermon_fcoib_t		*fcoib;
	uint_t			portm1; /* hca_port_number - 1 */

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	portm1 = hdl->rsrc_type - HERMON_QPC_RFCI_PORT1;
	fcoib = &state->hs_fcoib;
	vmem_xfree(fcoib->hfc_rfci_vmemp[portm1], hdl->hr_addr,
	    hdl->hr_len >> state->hs_rsrc_hdl[HERMON_QPC].rsrc_shift);
}


/*
 * hermon_rsrc_free()
 *    Context: Can be called from interrupt or base context.
 */
void
hermon_rsrc_free(hermon_state_t *state, hermon_rsrc_t **hdl)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;

	ASSERT(state != NULL);
	ASSERT(hdl != NULL);

	rsrc_pool = &state->hs_rsrc_hdl[(*hdl)->rsrc_type];
	ASSERT(rsrc_pool != NULL);

	/*
	 * Depending on resource type, call the appropriate free routine
	 */
	switch (rsrc_pool->rsrc_type) {
	case HERMON_IN_MBOX:
	case HERMON_OUT_MBOX:
	case HERMON_INTR_IN_MBOX:
	case HERMON_INTR_OUT_MBOX:
		hermon_rsrc_mbox_free(*hdl);
		break;

	case HERMON_QPC_FEXCH_PORT1:
	case HERMON_QPC_FEXCH_PORT2:
		hermon_rsrc_fexch_free(state, *hdl);
		break;

	case HERMON_QPC_RFCI_PORT1:
	case HERMON_QPC_RFCI_PORT2:
		hermon_rsrc_rfci_free(state, *hdl);
		break;

	case HERMON_QPC:
	case HERMON_CQC:
	case HERMON_SRQC:
	case HERMON_EQC:
	case HERMON_DMPT:
	case HERMON_MCG:
	case HERMON_MTT:
	case HERMON_UARPG:
		hermon_rsrc_hw_entry_free(rsrc_pool, *hdl);
		break;

	case HERMON_MRHDL:
	case HERMON_EQHDL:
	case HERMON_CQHDL:
	case HERMON_SRQHDL:
	case HERMON_AHHDL:
	case HERMON_QPHDL:
	case HERMON_REFCNT:
		hermon_rsrc_swhdl_free(rsrc_pool, *hdl);
		break;

	case HERMON_PDHDL:
		hermon_rsrc_pdhdl_free(rsrc_pool, *hdl);
		break;

	case HERMON_RDB:
	case HERMON_ALTC:
	case HERMON_AUXC:
	case HERMON_CMPT_QPC:
	case HERMON_CMPT_SRQC:
	case HERMON_CMPT_CQC:
	case HERMON_CMPT_EQC:
	default:
		cmn_err(CE_CONT, "!rsrc_type = 0x%x\n", rsrc_pool->rsrc_type);
		break;
	}

	/*
	 * Free the special resource tracking structure, set the handle to
	 * NULL, and return.
	 */
	kmem_cache_free(state->hs_rsrc_cache, *hdl);
	*hdl = NULL;
}


/*
 * hermon_rsrc_init_phase1()
 *
 *    Completes the first phase of Hermon resource/configuration init.
 *    This involves creating the kmem_cache for the "hermon_rsrc_t"
 *    structs, allocating the space for the resource pool handles,
 *    and setting up the "Out" mailboxes.
 *
 *    When this function completes, the Hermon driver is ready to
 *    post the following commands which return information only in the
 *    "Out" mailbox: QUERY_DDR, QUERY_FW, QUERY_DEV_LIM, and QUERY_ADAPTER
 *    If any of these commands are to be posted at this time, they must be
 *    done so only when "spinning" (as the outstanding command list and
 *    EQ setup code has not yet run)
 *
 *    Context: Only called from attach() path context
 */
int
hermon_rsrc_init_phase1(hermon_state_t *state)
{
	hermon_rsrc_pool_info_t		*rsrc_pool;
	hermon_rsrc_mbox_info_t 		mbox_info;
	hermon_rsrc_cleanup_level_t	cleanup;
	hermon_cfg_profile_t		*cfgprof;
	uint64_t			num, size;
	int				status;
	char				*rsrc_name;

	ASSERT(state != NULL);

	/* This is where Phase 1 of resource initialization begins */
	cleanup = HERMON_RSRC_CLEANUP_LEVEL0;

	/* Build kmem cache name from Hermon instance */
	rsrc_name = kmem_zalloc(HERMON_RSRC_NAME_MAXLEN, KM_SLEEP);
	HERMON_RSRC_NAME(rsrc_name, HERMON_RSRC_CACHE);

	/*
	 * Create the kmem_cache for "hermon_rsrc_t" structures
	 * (kmem_cache_create will SLEEP until successful)
	 */
	state->hs_rsrc_cache = kmem_cache_create(rsrc_name,
	    sizeof (hermon_rsrc_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * Allocate an array of hermon_rsrc_pool_info_t's (used in all
	 * subsequent resource allocations)
	 */
	state->hs_rsrc_hdl = kmem_zalloc(HERMON_NUM_RESOURCES *
	    sizeof (hermon_rsrc_pool_info_t), KM_SLEEP);

	/* Pull in the configuration profile */
	cfgprof = state->hs_cfg_profile;

	/* Initialize the resource pool for "out" mailboxes */
	num  =  ((uint64_t)1 << cfgprof->cp_log_num_outmbox);
	size =  ((uint64_t)1 << cfgprof->cp_log_outmbox_size);
	rsrc_pool = &state->hs_rsrc_hdl[HERMON_OUT_MBOX];
	rsrc_pool->rsrc_loc	  = HERMON_IN_SYSMEM;
	rsrc_pool->rsrc_pool_size = (size * num);
	rsrc_pool->rsrc_shift	  = cfgprof->cp_log_outmbox_size;
	rsrc_pool->rsrc_quantum	  = (uint_t)size;
	rsrc_pool->rsrc_align	  = HERMON_MBOX_ALIGN;
	rsrc_pool->rsrc_state	  = state;
	mbox_info.mbi_num	  = num;
	mbox_info.mbi_size	  = size;
	mbox_info.mbi_rsrcpool	  = rsrc_pool;
	status = hermon_rsrc_mbox_init(state, &mbox_info);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp1_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL1;

	/* Initialize the mailbox list */
	status = hermon_outmbox_list_init(state);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp1_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL2;

	/* Initialize the resource pool for "interrupt out" mailboxes */
	num  =  ((uint64_t)1 << cfgprof->cp_log_num_intr_outmbox);
	size =  ((uint64_t)1 << cfgprof->cp_log_outmbox_size);
	rsrc_pool = &state->hs_rsrc_hdl[HERMON_INTR_OUT_MBOX];
	rsrc_pool->rsrc_loc	  = HERMON_IN_SYSMEM;
	rsrc_pool->rsrc_pool_size = (size * num);
	rsrc_pool->rsrc_shift	  = cfgprof->cp_log_outmbox_size;
	rsrc_pool->rsrc_quantum	  = (uint_t)size;
	rsrc_pool->rsrc_align	  = HERMON_MBOX_ALIGN;
	rsrc_pool->rsrc_state	  = state;
	mbox_info.mbi_num	  = num;
	mbox_info.mbi_size	  = size;
	mbox_info.mbi_rsrcpool	  = rsrc_pool;
	status = hermon_rsrc_mbox_init(state, &mbox_info);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp1_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL3;

	/* Initialize the mailbox list */
	status = hermon_intr_outmbox_list_init(state);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp1_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL4;

	/* Initialize the resource pool for "in" mailboxes */
	num  =  ((uint64_t)1 << cfgprof->cp_log_num_inmbox);
	size =  ((uint64_t)1 << cfgprof->cp_log_inmbox_size);
	rsrc_pool = &state->hs_rsrc_hdl[HERMON_IN_MBOX];
	rsrc_pool->rsrc_loc	  = HERMON_IN_SYSMEM;
	rsrc_pool->rsrc_pool_size = (size * num);
	rsrc_pool->rsrc_shift	  = cfgprof->cp_log_inmbox_size;
	rsrc_pool->rsrc_quantum	  = (uint_t)size;
	rsrc_pool->rsrc_align	  = HERMON_MBOX_ALIGN;
	rsrc_pool->rsrc_state	  = state;
	mbox_info.mbi_num	  = num;
	mbox_info.mbi_size	  = size;
	mbox_info.mbi_rsrcpool	  = rsrc_pool;
	status = hermon_rsrc_mbox_init(state, &mbox_info);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp1_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL5;

	/* Initialize the mailbox list */
	status = hermon_inmbox_list_init(state);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp1_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL6;

	/* Initialize the resource pool for "interrupt in" mailboxes */
	num  =  ((uint64_t)1 << cfgprof->cp_log_num_intr_inmbox);
	size =  ((uint64_t)1 << cfgprof->cp_log_inmbox_size);
	rsrc_pool = &state->hs_rsrc_hdl[HERMON_INTR_IN_MBOX];
	rsrc_pool->rsrc_loc	  = HERMON_IN_SYSMEM;
	rsrc_pool->rsrc_pool_size = (size * num);
	rsrc_pool->rsrc_shift	  = cfgprof->cp_log_inmbox_size;
	rsrc_pool->rsrc_quantum	  = (uint_t)size;
	rsrc_pool->rsrc_align	  = HERMON_MBOX_ALIGN;
	rsrc_pool->rsrc_state	  = state;
	mbox_info.mbi_num	  = num;
	mbox_info.mbi_size	  = size;
	mbox_info.mbi_rsrcpool	  = rsrc_pool;
	status = hermon_rsrc_mbox_init(state, &mbox_info);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp1_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL7;

	/* Initialize the mailbox list */
	status = hermon_intr_inmbox_list_init(state);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp1_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_PHASE1_COMPLETE;
	kmem_free(rsrc_name, HERMON_RSRC_NAME_MAXLEN);
	return (DDI_SUCCESS);

rsrcinitp1_fail:
	kmem_free(rsrc_name, HERMON_RSRC_NAME_MAXLEN);
	return (status);
}


/*
 * hermon_rsrc_init_phase2()
 *    Context: Only called from attach() path context
 */
int
hermon_rsrc_init_phase2(hermon_state_t *state)
{
	hermon_rsrc_sw_hdl_info_t	hdl_info;
	hermon_rsrc_hw_entry_info_t	entry_info;
	hermon_rsrc_pool_info_t		*rsrc_pool;
	hermon_rsrc_cleanup_level_t	cleanup, ncleanup;
	hermon_cfg_profile_t		*cfgprof;
	hermon_hw_querydevlim_t		*devlim;
	uint64_t			num, max, num_prealloc;
	uint_t				mcg_size, mcg_size_shift;
	int				i, status;
	char				*rsrc_name;

	ASSERT(state != NULL);

	/* Phase 2 initialization begins where Phase 1 left off */
	cleanup = HERMON_RSRC_CLEANUP_PHASE1_COMPLETE;

	/* Allocate the ICM resource name space */

	/* Build the ICM vmem arena names from Hermon instance */
	rsrc_name = kmem_zalloc(HERMON_RSRC_NAME_MAXLEN, KM_SLEEP);

	/*
	 * Initialize the resource pools for all objects that exist in
	 * context memory (ICM). The ICM consists of context tables, each
	 * type of resource (QP, CQ, EQ, etc) having it's own context table
	 * (QPC, CQC, EQC, etc...).
	 */
	cfgprof = state->hs_cfg_profile;
	devlim	= &state->hs_devlim;

	/*
	 * Initialize the resource pools for each of the driver resources.
	 * With a few exceptions, these resources fall into the two cateogories
	 * of either hw_entries or sw_entries.
	 */

	/*
	 * Initialize the resource pools for ICM (hardware) types first.
	 * These resources are managed through vmem arenas, which are
	 * created via the rsrc pool initialization routine. Note that,
	 * due to further calculations, the MCG resource pool is
	 * initialized seperately.
	 */
	for (i = 0; i < HERMON_NUM_ICM_RESOURCES; i++) {

		rsrc_pool = &state->hs_rsrc_hdl[i];
		rsrc_pool->rsrc_type = i;
		rsrc_pool->rsrc_state = state;

		/* Set the resource-specific attributes */
		switch (i) {
		case HERMON_MTT:
			max = ((uint64_t)1 << devlim->log_max_mtt);
			num_prealloc = ((uint64_t)1 << devlim->log_rsvd_mtt);
			HERMON_RSRC_NAME(rsrc_name, HERMON_MTT_VMEM);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL9;
			break;

		case HERMON_DMPT:
			max = ((uint64_t)1 << devlim->log_max_dmpt);
			num_prealloc = ((uint64_t)1 << devlim->log_rsvd_dmpt);
			HERMON_RSRC_NAME(rsrc_name, HERMON_DMPT_VMEM);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL10;
			break;

		case HERMON_QPC:
			max = ((uint64_t)1 << devlim->log_max_qp);
			num_prealloc = ((uint64_t)1 << devlim->log_rsvd_qp);
			HERMON_RSRC_NAME(rsrc_name, HERMON_QPC_VMEM);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL11;
			break;

		case HERMON_CQC:
			max = ((uint64_t)1 << devlim->log_max_cq);
			num_prealloc = ((uint64_t)1 << devlim->log_rsvd_cq);
			HERMON_RSRC_NAME(rsrc_name, HERMON_CQC_VMEM);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL13;
			break;

		case HERMON_SRQC:
			max = ((uint64_t)1 << devlim->log_max_srq);
			num_prealloc = ((uint64_t)1 << devlim->log_rsvd_srq);
			HERMON_RSRC_NAME(rsrc_name, HERMON_SRQC_VMEM);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL16;
			break;

		case HERMON_EQC:
			max = ((uint64_t)1 << devlim->log_max_eq);
			num_prealloc = state->hs_rsvd_eqs;
			HERMON_RSRC_NAME(rsrc_name, HERMON_EQC_VMEM);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL18;
			break;

		case HERMON_MCG:	/* handled below */
		case HERMON_AUXC:
		case HERMON_ALTC:
		case HERMON_RDB:
		case HERMON_CMPT_QPC:
		case HERMON_CMPT_SRQC:
		case HERMON_CMPT_CQC:
		case HERMON_CMPT_EQC:
		default:
			/* We don't need to initialize this rsrc here. */
			continue;
		}

		/* Set the common values for all resource pools */
		rsrc_pool->rsrc_state	  = state;
		rsrc_pool->rsrc_loc	  = HERMON_IN_ICM;
		rsrc_pool->rsrc_pool_size = state->hs_icm[i].table_size;
		rsrc_pool->rsrc_align	  = state->hs_icm[i].table_size;
		rsrc_pool->rsrc_shift	  = state->hs_icm[i].log_object_size;
		rsrc_pool->rsrc_quantum	  = state->hs_icm[i].object_size;

		/* Now, initialize the entry_info and call the init routine */
		entry_info.hwi_num	  = state->hs_icm[i].num_entries;
		entry_info.hwi_max	  = max;
		entry_info.hwi_prealloc	  = num_prealloc;
		entry_info.hwi_rsrcpool	  = rsrc_pool;
		entry_info.hwi_rsrcname	  = rsrc_name;
		status = hermon_rsrc_hw_entries_init(state, &entry_info);
		if (status != DDI_SUCCESS) {
			hermon_rsrc_fini(state, cleanup);
			status = DDI_FAILURE;
			goto rsrcinitp2_fail;
		}
		cleanup = ncleanup;
	}

	/*
	 * Initialize the Multicast Group (MCG) entries. First, calculate
	 * (and validate) the size of the MCGs.
	 */
	status = hermon_rsrc_mcg_entry_get_size(state, &mcg_size_shift);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp2_fail;
	}
	mcg_size = HERMON_MCGMEM_SZ(state);

	/*
	 * Initialize the resource pool for the MCG table entries.  Notice
	 * that the number of MCGs is configurable. Note also that a certain
	 * number of MCGs must be set aside for Hermon firmware use (they
	 * correspond to the number of MCGs used by the internal hash
	 * function).
	 */
	num			  = ((uint64_t)1 << cfgprof->cp_log_num_mcg);
	max			  = ((uint64_t)1 << devlim->log_max_mcg);
	num_prealloc	  = ((uint64_t)1 << cfgprof->cp_log_num_mcg_hash);
	rsrc_pool		  = &state->hs_rsrc_hdl[HERMON_MCG];
	rsrc_pool->rsrc_loc	  = HERMON_IN_ICM;
	rsrc_pool->rsrc_pool_size = (mcg_size * num);
	rsrc_pool->rsrc_shift	  = mcg_size_shift;
	rsrc_pool->rsrc_quantum	  = mcg_size;
	rsrc_pool->rsrc_align	  = (mcg_size * num);
	rsrc_pool->rsrc_state	  = state;
	HERMON_RSRC_NAME(rsrc_name, HERMON_MCG_VMEM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = hermon_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp2_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL19;

	/*
	 * Initialize the full range of ICM for the AUXC resource.
	 * This is done because its size is so small, about 1 byte per QP.
	 */

	/*
	 * Initialize the Hermon command handling interfaces.  This step
	 * sets up the outstanding command tracking mechanism for easy access
	 * and fast allocation (see hermon_cmd.c for more details).
	 */
	status = hermon_outstanding_cmdlist_init(state);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp2_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL20;

	/* Initialize the resource pool and vmem arena for the PD handles */
	rsrc_pool		 = &state->hs_rsrc_hdl[HERMON_PDHDL];
	rsrc_pool->rsrc_loc	 = HERMON_IN_SYSMEM;
	rsrc_pool->rsrc_quantum	 = sizeof (struct hermon_sw_pd_s);
	rsrc_pool->rsrc_state	 = state;
	HERMON_RSRC_NAME(rsrc_name, HERMON_PDHDL_CACHE);
	hdl_info.swi_num	 = ((uint64_t)1 << cfgprof->cp_log_num_pd);
	hdl_info.swi_max	 = ((uint64_t)1 << devlim->log_max_pd);
	hdl_info.swi_rsrcpool	 = rsrc_pool;
	hdl_info.swi_constructor = hermon_rsrc_pdhdl_constructor;
	hdl_info.swi_destructor	 = hermon_rsrc_pdhdl_destructor;
	hdl_info.swi_rsrcname	 = rsrc_name;
	hdl_info.swi_flags	 = HERMON_SWHDL_KMEMCACHE_INIT;
	status = hermon_rsrc_pd_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp2_fail;
	}
	cleanup = HERMON_RSRC_CLEANUP_LEVEL21;

	/*
	 * Initialize the resource pools for the rest of the software handles.
	 * This includes MR handles, EQ handles, QP handles, etc.  These
	 * objects are almost entirely managed using kmem_cache routines,
	 * and do not utilize a vmem arena.
	 */
	for (i = HERMON_NUM_ICM_RESOURCES; i < HERMON_NUM_RESOURCES; i++) {
		rsrc_pool = &state->hs_rsrc_hdl[i];
		rsrc_pool->rsrc_type = i;

		/* Set the resource-specific attributes */
		switch (i) {
		case HERMON_MRHDL:
			rsrc_pool->rsrc_quantum =
			    sizeof (struct hermon_sw_mr_s);
			HERMON_RSRC_NAME(rsrc_name, HERMON_MRHDL_CACHE);
			hdl_info.swi_num =
			    ((uint64_t)1 << cfgprof->cp_log_num_dmpt) +
			    ((uint64_t)1 << cfgprof->cp_log_num_cmpt);
			hdl_info.swi_max =
			    ((uint64_t)1 << cfgprof->cp_log_num_dmpt) +
			    ((uint64_t)1 << cfgprof->cp_log_num_cmpt);
			hdl_info.swi_constructor =
			    hermon_rsrc_mrhdl_constructor;
			hdl_info.swi_destructor	 = hermon_rsrc_mrhdl_destructor;
			hdl_info.swi_flags	 = HERMON_SWHDL_KMEMCACHE_INIT;
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL22;
			break;

		case HERMON_EQHDL:
			rsrc_pool->rsrc_quantum =
			    sizeof (struct hermon_sw_eq_s);
			HERMON_RSRC_NAME(rsrc_name, HERMON_EQHDL_CACHE);
			hdl_info.swi_num = HERMON_NUM_EQ;
			hdl_info.swi_max = ((uint64_t)1 << devlim->log_max_eq);
			hdl_info.swi_constructor = NULL;
			hdl_info.swi_destructor	 = NULL;
			hdl_info.swi_flags	 = HERMON_SWHDL_KMEMCACHE_INIT;
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL23;
			break;

		case HERMON_CQHDL:
			rsrc_pool->rsrc_quantum =
			    sizeof (struct hermon_sw_cq_s);
			HERMON_RSRC_NAME(rsrc_name, HERMON_CQHDL_CACHE);
			hdl_info.swi_num =
			    (uint64_t)1 << cfgprof->cp_log_num_cq;
			hdl_info.swi_max = (uint64_t)1 << devlim->log_max_cq;
			hdl_info.swi_constructor =
			    hermon_rsrc_cqhdl_constructor;
			hdl_info.swi_destructor	 = hermon_rsrc_cqhdl_destructor;
			hdl_info.swi_flags	 = HERMON_SWHDL_KMEMCACHE_INIT;
			hdl_info.swi_prealloc_sz = sizeof (hermon_cqhdl_t);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL24;
			break;

		case HERMON_SRQHDL:
			rsrc_pool->rsrc_quantum =
			    sizeof (struct hermon_sw_srq_s);
			HERMON_RSRC_NAME(rsrc_name, HERMON_SRQHDL_CACHE);
			hdl_info.swi_num =
			    (uint64_t)1 << cfgprof->cp_log_num_srq;
			hdl_info.swi_max = (uint64_t)1 << devlim->log_max_srq;
			hdl_info.swi_constructor =
			    hermon_rsrc_srqhdl_constructor;
			hdl_info.swi_destructor = hermon_rsrc_srqhdl_destructor;
			hdl_info.swi_flags	 = HERMON_SWHDL_KMEMCACHE_INIT;
			hdl_info.swi_prealloc_sz = sizeof (hermon_srqhdl_t);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL25;
			break;

		case HERMON_AHHDL:
			rsrc_pool->rsrc_quantum	=
			    sizeof (struct hermon_sw_ah_s);
			HERMON_RSRC_NAME(rsrc_name, HERMON_AHHDL_CACHE);
			hdl_info.swi_num =
			    (uint64_t)1 << cfgprof->cp_log_num_ah;
			hdl_info.swi_max = HERMON_NUM_AH;
			hdl_info.swi_constructor =
			    hermon_rsrc_ahhdl_constructor;
			hdl_info.swi_destructor	 = hermon_rsrc_ahhdl_destructor;
			hdl_info.swi_flags	 = HERMON_SWHDL_KMEMCACHE_INIT;
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL26;
			break;

		case HERMON_QPHDL:
			rsrc_pool->rsrc_quantum =
			    sizeof (struct hermon_sw_qp_s);
			HERMON_RSRC_NAME(rsrc_name, HERMON_QPHDL_CACHE);
			hdl_info.swi_num =
			    (uint64_t)1 << cfgprof->cp_log_num_qp;
			hdl_info.swi_max = (uint64_t)1 << devlim->log_max_qp;
			hdl_info.swi_constructor =
			    hermon_rsrc_qphdl_constructor;
			hdl_info.swi_destructor	= hermon_rsrc_qphdl_destructor;
			hdl_info.swi_flags	 = HERMON_SWHDL_KMEMCACHE_INIT;
			hdl_info.swi_prealloc_sz = sizeof (hermon_qphdl_t);
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL27;
			break;

		case HERMON_REFCNT:
			rsrc_pool->rsrc_quantum	 = sizeof (hermon_sw_refcnt_t);
			HERMON_RSRC_NAME(rsrc_name, HERMON_REFCNT_CACHE);
			hdl_info.swi_num =
			    (uint64_t)1 << cfgprof->cp_log_num_dmpt;
			hdl_info.swi_max = (uint64_t)1 << devlim->log_max_dmpt;
			hdl_info.swi_constructor =
			    hermon_rsrc_refcnt_constructor;
			hdl_info.swi_destructor = hermon_rsrc_refcnt_destructor;
			hdl_info.swi_flags	 = HERMON_SWHDL_KMEMCACHE_INIT;
			ncleanup = HERMON_RSRC_CLEANUP_LEVEL28;
			break;

		default:
			continue;
		}

		/* Set the common values and call the init routine */
		rsrc_pool->rsrc_loc	 = HERMON_IN_SYSMEM;
		rsrc_pool->rsrc_state    = state;
		hdl_info.swi_rsrcpool    = rsrc_pool;
		hdl_info.swi_rsrcname    = rsrc_name;
		status = hermon_rsrc_sw_handles_init(state, &hdl_info);
		if (status != DDI_SUCCESS) {
			hermon_rsrc_fini(state, cleanup);
			status = DDI_FAILURE;
			goto rsrcinitp2_fail;
		}
		cleanup = ncleanup;
	}

	/*
	 * Initialize a resource pool for the MCG handles.  Notice that for
	 * these MCG handles, we are allocating a table of structures (used to
	 * keep track of the MCG entries that are being written to hardware
	 * and to speed up multicast attach/detach operations).
	 */
	hdl_info.swi_num	 = ((uint64_t)1 << cfgprof->cp_log_num_mcg);
	hdl_info.swi_max	 = ((uint64_t)1 << devlim->log_max_mcg);
	hdl_info.swi_flags	 = HERMON_SWHDL_TABLE_INIT;
	hdl_info.swi_prealloc_sz = sizeof (struct hermon_sw_mcg_list_s);
	status = hermon_rsrc_sw_handles_init(state, &hdl_info);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp2_fail;
	}
	state->hs_mcghdl = hdl_info.swi_table_ptr;
	cleanup = HERMON_RSRC_CLEANUP_LEVEL29;

	/*
	 * Last, initialize the resource pool for the UAR pages, which contain
	 * the hardware's doorbell registers. Each process supported in User
	 * Mode is assigned a UAR page. Also coming from this pool are the
	 * kernel-assigned UAR page, and any hardware-reserved pages. Note
	 * that the number of UAR pages is configurable, the value must be less
	 * than the maximum value (obtained from the QUERY_DEV_LIM command) or
	 * the initialization will fail.  Note also that we assign the base
	 * address of the UAR BAR to the rsrc_start parameter.
	 */
	num			  = ((uint64_t)1 << cfgprof->cp_log_num_uar);
	max			  = num;
	num_prealloc		  = max(devlim->num_rsvd_uar, 128);
	rsrc_pool		  = &state->hs_rsrc_hdl[HERMON_UARPG];
	rsrc_pool->rsrc_loc	  = HERMON_IN_UAR;
	rsrc_pool->rsrc_pool_size = (num << PAGESHIFT);
	rsrc_pool->rsrc_shift	  = PAGESHIFT;
	rsrc_pool->rsrc_quantum	  = (uint_t)PAGESIZE;
	rsrc_pool->rsrc_align	  = PAGESIZE;
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = (void *)state->hs_reg_uar_baseaddr;
	HERMON_RSRC_NAME(rsrc_name, HERMON_UAR_PAGE_VMEM_ATTCH);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	status = hermon_rsrc_hw_entries_init(state, &entry_info);
	if (status != DDI_SUCCESS) {
		hermon_rsrc_fini(state, cleanup);
		status = DDI_FAILURE;
		goto rsrcinitp2_fail;
	}

	cleanup = HERMON_RSRC_CLEANUP_ALL;

	kmem_free(rsrc_name, HERMON_RSRC_NAME_MAXLEN);
	return (DDI_SUCCESS);

rsrcinitp2_fail:
	kmem_free(rsrc_name, HERMON_RSRC_NAME_MAXLEN);
	return (status);
}


/*
 * hermon_rsrc_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_rsrc_fini(hermon_state_t *state, hermon_rsrc_cleanup_level_t clean)
{
	hermon_rsrc_sw_hdl_info_t	hdl_info;
	hermon_rsrc_hw_entry_info_t	entry_info;
	hermon_rsrc_mbox_info_t		mbox_info;
	hermon_cfg_profile_t		*cfgprof;

	ASSERT(state != NULL);

	cfgprof = state->hs_cfg_profile;

	/*
	 * If init code above is shortened up (see comments), then we
	 * need to establish how to safely and simply clean up from any
	 * given failure point. Flags, maybe...
	 */

	switch (clean) {
	/*
	 * If we add more resources that need to be cleaned up here, we should
	 * ensure that HERMON_RSRC_CLEANUP_ALL is still the first entry (i.e.
	 * corresponds to the last resource allocated).
	 */

	case HERMON_RSRC_CLEANUP_ALL:
	case HERMON_RSRC_CLEANUP_LEVEL31:
		/* Cleanup the UAR page resource pool, first the dbr pages */
		if (state->hs_kern_dbr) {
			hermon_dbr_kern_free(state);
			state->hs_kern_dbr = NULL;
		}

		/* NS then, the pool itself */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_UARPG];
		hermon_rsrc_hw_entries_fini(state, &entry_info);

		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL30:
		/* Cleanup the central MCG handle pointers list */
		hdl_info.swi_rsrcpool  = NULL;
		hdl_info.swi_table_ptr = state->hs_mcghdl;
		hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_mcg);
		hdl_info.swi_prealloc_sz = sizeof (struct hermon_sw_mcg_list_s);
		hermon_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL29:
		/* Cleanup the reference count resource pool */
		hdl_info.swi_rsrcpool  = &state->hs_rsrc_hdl[HERMON_REFCNT];
		hdl_info.swi_table_ptr = NULL;
		hermon_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL28:
		/* Cleanup the QP handle resource pool */
		hdl_info.swi_rsrcpool  = &state->hs_rsrc_hdl[HERMON_QPHDL];
		hdl_info.swi_table_ptr = NULL;
		hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_qp);
		hdl_info.swi_prealloc_sz = sizeof (hermon_qphdl_t);
		hermon_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */
	case HERMON_RSRC_CLEANUP_LEVEL27:
		/* Cleanup the address handle resrouce pool */
		hdl_info.swi_rsrcpool  = &state->hs_rsrc_hdl[HERMON_AHHDL];
		hdl_info.swi_table_ptr = NULL;
		hermon_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL26:
		/* Cleanup the SRQ handle resource pool. */
		hdl_info.swi_rsrcpool  = &state->hs_rsrc_hdl[HERMON_SRQHDL];
		hdl_info.swi_table_ptr = NULL;
		hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_srq);
		hdl_info.swi_prealloc_sz = sizeof (hermon_srqhdl_t);
		hermon_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL25:
		/* Cleanup the CQ handle resource pool */
		hdl_info.swi_rsrcpool  = &state->hs_rsrc_hdl[HERMON_CQHDL];
		hdl_info.swi_table_ptr = NULL;
		hdl_info.swi_num = ((uint64_t)1 << cfgprof->cp_log_num_cq);
		hdl_info.swi_prealloc_sz = sizeof (hermon_cqhdl_t);
		hermon_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL24:
		/* Cleanup the EQ handle resource pool */
		hdl_info.swi_rsrcpool  = &state->hs_rsrc_hdl[HERMON_EQHDL];
		hdl_info.swi_table_ptr = NULL;
		hermon_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL23:
		/* Cleanup the MR handle resource pool */
		hdl_info.swi_rsrcpool  = &state->hs_rsrc_hdl[HERMON_MRHDL];
		hdl_info.swi_table_ptr = NULL;
		hermon_rsrc_sw_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL22:
		/* Cleanup the PD handle resource pool */
		hdl_info.swi_rsrcpool  = &state->hs_rsrc_hdl[HERMON_PDHDL];
		hdl_info.swi_table_ptr = NULL;
		hermon_rsrc_pd_handles_fini(state, &hdl_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL21:
		/* Currently unused - FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL20:
		/* Cleanup the outstanding command list  */
		hermon_outstanding_cmdlist_fini(state);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL19:
		/* Cleanup the EQC table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_EQC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL18:
		/* Cleanup the MCG table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_MCG];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL17:
		/* Currently Unused - fallthrough */
	case HERMON_RSRC_CLEANUP_LEVEL16:
		/* Cleanup the SRQC table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_SRQC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL15:
		/* Cleanup the AUXC table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_AUXC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL14:
		/* Cleanup the ALTCF table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_ALTC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL13:
		/* Cleanup the CQC table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_CQC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL12:
		/* Cleanup the RDB table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_RDB];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL11:
		/* Cleanup the QPC table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_QPC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL10EQ:
		/* Cleanup the cMPTs for the EQs, CQs, SRQs, and QPs */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_CMPT_EQC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL10CQ:
		/* Cleanup the cMPTs for the EQs, CQs, SRQs, and QPs */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_CMPT_CQC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL10SRQ:
		/* Cleanup the cMPTs for the EQs, CQs, SRQs, and QPs */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_CMPT_SRQC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL10QP:
		/* Cleanup the cMPTs for the EQs, CQs, SRQs, and QPs */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_CMPT_QPC];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL10:
		/* Cleanup the dMPT table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_DMPT];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL9:
		/* Cleanup the MTT table resource pool */
		entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_MTT];
		hermon_rsrc_hw_entries_fini(state, &entry_info);
		break;

	/*
	 * The cleanup below comes from the "Phase 1" initialization step.
	 * (see hermon_rsrc_init_phase1() above)
	 */
	case HERMON_RSRC_CLEANUP_PHASE1_COMPLETE:
		/* Cleanup the "In" mailbox list  */
		hermon_intr_inmbox_list_fini(state);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL7:
		/* Cleanup the interrupt "In" mailbox resource pool */
		mbox_info.mbi_rsrcpool =
		    &state->hs_rsrc_hdl[HERMON_INTR_IN_MBOX];
		hermon_rsrc_mbox_fini(state, &mbox_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL6:
		/* Cleanup the "In" mailbox list  */
		hermon_inmbox_list_fini(state);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL5:
		/* Cleanup the "In" mailbox resource pool */
		mbox_info.mbi_rsrcpool = &state->hs_rsrc_hdl[HERMON_IN_MBOX];
		hermon_rsrc_mbox_fini(state, &mbox_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL4:
		/* Cleanup the interrupt "Out" mailbox list  */
		hermon_intr_outmbox_list_fini(state);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL3:
		/* Cleanup the "Out" mailbox resource pool */
		mbox_info.mbi_rsrcpool =
		    &state->hs_rsrc_hdl[HERMON_INTR_OUT_MBOX];
		hermon_rsrc_mbox_fini(state, &mbox_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL2:
		/* Cleanup the "Out" mailbox list  */
		hermon_outmbox_list_fini(state);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL1:
		/* Cleanup the "Out" mailbox resource pool */
		mbox_info.mbi_rsrcpool = &state->hs_rsrc_hdl[HERMON_OUT_MBOX];
		hermon_rsrc_mbox_fini(state, &mbox_info);
		/* FALLTHROUGH */

	case HERMON_RSRC_CLEANUP_LEVEL0:
		/* Free the array of hermon_rsrc_pool_info_t's */

		kmem_free(state->hs_rsrc_hdl, HERMON_NUM_RESOURCES *
		    sizeof (hermon_rsrc_pool_info_t));

		kmem_cache_destroy(state->hs_rsrc_cache);
		break;

	default:
		HERMON_WARNING(state, "unexpected resource cleanup level");
		break;
	}
}


/*
 * hermon_rsrc_mbox_init()
 *    Context: Only called from attach() path context
 */
static int
hermon_rsrc_mbox_init(hermon_state_t *state, hermon_rsrc_mbox_info_t *info)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;
	hermon_rsrc_priv_mbox_t	*priv;

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->mbi_rsrcpool;
	ASSERT(rsrc_pool != NULL);

	/* Allocate and initialize mailbox private structure */
	priv = kmem_zalloc(sizeof (hermon_rsrc_priv_mbox_t), KM_SLEEP);
	priv->pmb_dip		= state->hs_dip;
	priv->pmb_devaccattr	= state->hs_reg_accattr;
	priv->pmb_xfer_mode	= DDI_DMA_CONSISTENT;

	/*
	 * Initialize many of the default DMA attributes.  Then set alignment
	 * and scatter-gather restrictions specific for mailbox memory.
	 */
	hermon_dma_attr_init(state, &priv->pmb_dmaattr);
	priv->pmb_dmaattr.dma_attr_align  = HERMON_MBOX_ALIGN;
	priv->pmb_dmaattr.dma_attr_sgllen = 1;
	priv->pmb_dmaattr.dma_attr_flags = 0;
	rsrc_pool->rsrc_private = priv;

	ASSERT(rsrc_pool->rsrc_loc == HERMON_IN_SYSMEM);

	rsrc_pool->rsrc_start = NULL;
	rsrc_pool->rsrc_vmp = NULL;

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_mbox_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
/* ARGSUSED */
static void
hermon_rsrc_mbox_fini(hermon_state_t *state, hermon_rsrc_mbox_info_t *info)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->mbi_rsrcpool;
	ASSERT(rsrc_pool != NULL);

	/* Free up the private struct */
	kmem_free(rsrc_pool->rsrc_private, sizeof (hermon_rsrc_priv_mbox_t));
}


/*
 * hermon_rsrc_hw_entries_init()
 *    Context: Only called from attach() path context
 */
int
hermon_rsrc_hw_entries_init(hermon_state_t *state,
    hermon_rsrc_hw_entry_info_t *info)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;
	hermon_rsrc_t		*rsvd_rsrc = NULL;
	vmem_t			*vmp;
	uint64_t		num_hwentry, max_hwentry, num_prealloc;
	int			status;

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool	= info->hwi_rsrcpool;
	ASSERT(rsrc_pool != NULL);
	num_hwentry	= info->hwi_num;
	max_hwentry	= info->hwi_max;
	num_prealloc	= info->hwi_prealloc;

	if (hermon_rsrc_verbose) {
		IBTF_DPRINTF_L2("hermon", "hermon_rsrc_hw_entries_init: "
		    "rsrc_type (0x%x) num (%llx) max (0x%llx) prealloc "
		    "(0x%llx)", rsrc_pool->rsrc_type, (longlong_t)num_hwentry,
		    (longlong_t)max_hwentry, (longlong_t)num_prealloc);
	}

	/* Make sure number of HW entries makes sense */
	if (num_hwentry > max_hwentry) {
		return (DDI_FAILURE);
	}

	/* Set this pool's rsrc_start from the initial ICM allocation */
	if (rsrc_pool->rsrc_start == 0) {

		/* use a ROUND value that works on both 32 and 64-bit kernels */
		rsrc_pool->rsrc_start = (void *)(uintptr_t)0x10000000;

		if (hermon_rsrc_verbose) {
			IBTF_DPRINTF_L2("hermon", "hermon_rsrc_hw_entries_init:"
			    " rsrc_type (0x%x) rsrc_start set (0x%lx)",
			    rsrc_pool->rsrc_type, rsrc_pool->rsrc_start);
		}
	}

	/*
	 * Create new vmem arena for the HW entries table if rsrc_quantum
	 * is non-zero.  Otherwise if rsrc_quantum is zero, then these HW
	 * entries are not going to be dynamically allocatable (i.e. they
	 * won't be allocated/freed through hermon_rsrc_alloc/free).  This
	 * latter option is used for both ALTC and CMPT resources which
	 * are managed by hardware.
	 */
	if (rsrc_pool->rsrc_quantum != 0) {
		vmp = vmem_create(info->hwi_rsrcname,
		    (void *)(uintptr_t)rsrc_pool->rsrc_start,
		    rsrc_pool->rsrc_pool_size, rsrc_pool->rsrc_quantum,
		    NULL, NULL, NULL, 0, VM_SLEEP);
		if (vmp == NULL) {
			/* failed to create vmem arena */
			return (DDI_FAILURE);
		}
		rsrc_pool->rsrc_vmp = vmp;
		if (hermon_rsrc_verbose) {
			IBTF_DPRINTF_L2("hermon", "hermon_rsrc_hw_entries_init:"
			    " rsrc_type (0x%x) created vmem arena for rsrc",
			    rsrc_pool->rsrc_type);
		}
	} else {
		/* we do not require a vmem arena */
		rsrc_pool->rsrc_vmp = NULL;
		if (hermon_rsrc_verbose) {
			IBTF_DPRINTF_L2("hermon", "hermon_rsrc_hw_entries_init:"
			    " rsrc_type (0x%x) vmem arena not required",
			    rsrc_pool->rsrc_type);
		}
	}

	/* Allocate hardware reserved resources, if any */
	if (num_prealloc != 0) {
		status = hermon_rsrc_alloc(state, rsrc_pool->rsrc_type,
		    num_prealloc, HERMON_SLEEP, &rsvd_rsrc);
		if (status != DDI_SUCCESS) {
			/* unable to preallocate the reserved entries */
			if (rsrc_pool->rsrc_vmp != NULL) {
				vmem_destroy(rsrc_pool->rsrc_vmp);
			}
			return (DDI_FAILURE);
		}
	}
	rsrc_pool->rsrc_private = rsvd_rsrc;

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_hw_entries_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_rsrc_hw_entries_fini(hermon_state_t *state,
    hermon_rsrc_hw_entry_info_t *info)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;
	hermon_rsrc_t		*rsvd_rsrc;

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->hwi_rsrcpool;
	ASSERT(rsrc_pool != NULL);

	/* Free up any "reserved" (i.e. preallocated) HW entries */
	rsvd_rsrc = (hermon_rsrc_t *)rsrc_pool->rsrc_private;
	if (rsvd_rsrc != NULL) {
		hermon_rsrc_free(state, &rsvd_rsrc);
	}

	/*
	 * If we've actually setup a vmem arena for the HW entries, then
	 * destroy it now
	 */
	if (rsrc_pool->rsrc_vmp != NULL) {
		vmem_destroy(rsrc_pool->rsrc_vmp);
	}
}


/*
 * hermon_rsrc_sw_handles_init()
 *    Context: Only called from attach() path context
 */
/* ARGSUSED */
static int
hermon_rsrc_sw_handles_init(hermon_state_t *state,
    hermon_rsrc_sw_hdl_info_t *info)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;
	uint64_t		num_swhdl, max_swhdl, prealloc_sz;

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool	= info->swi_rsrcpool;
	ASSERT(rsrc_pool != NULL);
	num_swhdl	= info->swi_num;
	max_swhdl	= info->swi_max;
	prealloc_sz	= info->swi_prealloc_sz;


	/* Make sure number of SW handles makes sense */
	if (num_swhdl > max_swhdl) {
		return (DDI_FAILURE);
	}

	/*
	 * Depending on the flags parameter, create a kmem_cache for some
	 * number of software handle structures.  Note: kmem_cache_create()
	 * will SLEEP until successful.
	 */
	if (info->swi_flags & HERMON_SWHDL_KMEMCACHE_INIT) {
		rsrc_pool->rsrc_private = kmem_cache_create(
		    info->swi_rsrcname, rsrc_pool->rsrc_quantum, 0,
		    info->swi_constructor, info->swi_destructor, NULL,
		    rsrc_pool->rsrc_state, NULL, 0);
	}


	/* Allocate the central list of SW handle pointers */
	if (info->swi_flags & HERMON_SWHDL_TABLE_INIT) {
		info->swi_table_ptr = kmem_zalloc(num_swhdl * prealloc_sz,
		    KM_SLEEP);
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_sw_handles_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
/* ARGSUSED */
static void
hermon_rsrc_sw_handles_fini(hermon_state_t *state,
    hermon_rsrc_sw_hdl_info_t *info)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;
	uint64_t		num_swhdl, prealloc_sz;

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
}


/*
 * hermon_rsrc_pd_handles_init()
 *    Context: Only called from attach() path context
 */
static int
hermon_rsrc_pd_handles_init(hermon_state_t *state,
    hermon_rsrc_sw_hdl_info_t *info)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;
	vmem_t			*vmp;
	char			vmem_name[HERMON_RSRC_NAME_MAXLEN];
	int			status;

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->swi_rsrcpool;
	ASSERT(rsrc_pool != NULL);

	/* Initialize the resource pool for software handle table */
	status = hermon_rsrc_sw_handles_init(state, info);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Build vmem arena name from Hermon instance */
	HERMON_RSRC_NAME(vmem_name, HERMON_PDHDL_VMEM);

	/* Create new vmem arena for PD numbers */
	vmp = vmem_create(vmem_name, (caddr_t)1, info->swi_num, 1, NULL,
	    NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);
	if (vmp == NULL) {
		/* Unable to create vmem arena */
		info->swi_table_ptr = NULL;
		hermon_rsrc_sw_handles_fini(state, info);
		return (DDI_FAILURE);
	}
	rsrc_pool->rsrc_vmp = vmp;

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_pd_handles_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
hermon_rsrc_pd_handles_fini(hermon_state_t *state,
    hermon_rsrc_sw_hdl_info_t *info)
{
	hermon_rsrc_pool_info_t	*rsrc_pool;

	ASSERT(state != NULL);
	ASSERT(info != NULL);

	rsrc_pool = info->swi_rsrcpool;

	/* Destroy the specially created UAR scratch table vmem arena */
	vmem_destroy(rsrc_pool->rsrc_vmp);

	/* Destroy the "hermon_sw_pd_t" kmem_cache */
	hermon_rsrc_sw_handles_fini(state, info);
}


/*
 * hermon_rsrc_mbox_alloc()
 *    Context: Only called from attach() path context
 */
static int
hermon_rsrc_mbox_alloc(hermon_rsrc_pool_info_t *pool_info, uint_t num,
    hermon_rsrc_t *hdl)
{
	hermon_rsrc_priv_mbox_t	*priv;
	caddr_t			kaddr;
	size_t			real_len, temp_len;
	int			status;

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Get the private pointer for the mailboxes */
	priv = pool_info->rsrc_private;
	ASSERT(priv != NULL);

	/* Allocate a DMA handle for the mailbox */
	status = ddi_dma_alloc_handle(priv->pmb_dip, &priv->pmb_dmaattr,
	    DDI_DMA_SLEEP, NULL, &hdl->hr_dmahdl);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Allocate memory for the mailbox */
	temp_len = (num << pool_info->rsrc_shift);
	status = ddi_dma_mem_alloc(hdl->hr_dmahdl, temp_len,
	    &priv->pmb_devaccattr, priv->pmb_xfer_mode, DDI_DMA_SLEEP,
	    NULL, &kaddr, &real_len, &hdl->hr_acchdl);
	if (status != DDI_SUCCESS) {
		/* No more memory available for mailbox entries */
		ddi_dma_free_handle(&hdl->hr_dmahdl);
		return (DDI_FAILURE);
	}

	hdl->hr_addr = (void *)kaddr;
	hdl->hr_len  = (uint32_t)real_len;

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_mbox_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_rsrc_mbox_free(hermon_rsrc_t *hdl)
{
	ASSERT(hdl != NULL);

	/* Use ddi_dma_mem_free() to free up sys memory for mailbox */
	ddi_dma_mem_free(&hdl->hr_acchdl);

	/* Free the DMA handle for the mailbox */
	ddi_dma_free_handle(&hdl->hr_dmahdl);
}


/*
 * hermon_rsrc_hw_entry_alloc()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_rsrc_hw_entry_alloc(hermon_rsrc_pool_info_t *pool_info, uint_t num,
    uint_t num_align, uint_t sleepflag, hermon_rsrc_t *hdl)
{
	void			*addr;
	uint64_t		offset;
	uint32_t		align;
	int			status;
	int			flag;

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/*
	 * Use vmem_xalloc() to get a properly aligned pointer (based on
	 * the number requested) to the HW entry(ies).  This handles the
	 * cases (for special QPCs and for RDB entries) where we need more
	 * than one and need to ensure that they are properly aligned.
	 */
	flag = (sleepflag == HERMON_SLEEP) ? VM_SLEEP : VM_NOSLEEP;
	hdl->hr_len = (num << pool_info->rsrc_shift);
	align = (num_align << pool_info->rsrc_shift);

	addr = vmem_xalloc(pool_info->rsrc_vmp, hdl->hr_len,
	    align, 0, 0, NULL, NULL, flag | VM_FIRSTFIT);

	if (addr == NULL) {
		/* No more HW entries available */
		return (DDI_FAILURE);
	}

	hdl->hr_acchdl = NULL;	/* only used for mbox resources */

	/* Calculate vaddr and HW table index */
	offset = (uintptr_t)addr - (uintptr_t)pool_info->rsrc_start;
	hdl->hr_addr = addr;	/* only used for mbox and uarpg resources */
	hdl->hr_indx = offset >> pool_info->rsrc_shift;

	if (pool_info->rsrc_loc == HERMON_IN_ICM) {
		int num_to_hdl;
		hermon_rsrc_type_t rsrc_type = pool_info->rsrc_type;

		num_to_hdl = (rsrc_type == HERMON_QPC ||
		    rsrc_type == HERMON_CQC || rsrc_type == HERMON_SRQC);

		/* confirm ICM is mapped, and allocate if necessary */
		status = hermon_rsrc_hw_entry_icm_confirm(pool_info, num, hdl,
		    num_to_hdl);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		hdl->hr_addr = NULL;	/* not used for ICM resources */
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_hw_entry_reserve()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_rsrc_hw_entry_reserve(hermon_rsrc_pool_info_t *pool_info, uint_t num,
    uint_t num_align, uint_t sleepflag, hermon_rsrc_t *hdl)
{
	void			*addr;
	uint64_t		offset;
	uint32_t		align;
	int			flag;

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);
	ASSERT(pool_info->rsrc_loc == HERMON_IN_ICM);

	/*
	 * Use vmem_xalloc() to get a properly aligned pointer (based on
	 * the number requested) to the HW entry(ies).  This handles the
	 * cases (for special QPCs and for RDB entries) where we need more
	 * than one and need to ensure that they are properly aligned.
	 */
	flag = (sleepflag == HERMON_SLEEP) ? VM_SLEEP : VM_NOSLEEP;
	hdl->hr_len = (num << pool_info->rsrc_shift);
	align = (num_align << pool_info->rsrc_shift);

	addr = vmem_xalloc(pool_info->rsrc_vmp, hdl->hr_len,
	    align, 0, 0, NULL, NULL, flag | VM_FIRSTFIT);

	if (addr == NULL) {
		/* No more HW entries available */
		return (DDI_FAILURE);
	}

	hdl->hr_acchdl = NULL;	/* only used for mbox resources */

	/* Calculate vaddr and HW table index */
	offset = (uintptr_t)addr - (uintptr_t)pool_info->rsrc_start;
	hdl->hr_addr = NULL;
	hdl->hr_indx = offset >> pool_info->rsrc_shift;

	/* ICM will be allocated and mapped if and when it gets used */

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_hw_entry_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_rsrc_hw_entry_free(hermon_rsrc_pool_info_t *pool_info,
    hermon_rsrc_t *hdl)
{
	void			*addr;
	uint64_t		offset;
	int			status;

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Calculate the allocated address */
	offset = hdl->hr_indx << pool_info->rsrc_shift;
	addr = (void *)(uintptr_t)(offset + (uintptr_t)pool_info->rsrc_start);

	/* Use vmem_xfree() to free up the HW table entry */
	vmem_xfree(pool_info->rsrc_vmp, addr, hdl->hr_len);

	if (pool_info->rsrc_loc == HERMON_IN_ICM) {
		int num_to_hdl;
		hermon_rsrc_type_t rsrc_type = pool_info->rsrc_type;

		num_to_hdl = (rsrc_type == HERMON_QPC ||
		    rsrc_type == HERMON_CQC || rsrc_type == HERMON_SRQC);

		/* free ICM references, and free ICM if required */
		status = hermon_rsrc_hw_entry_icm_free(pool_info, hdl,
		    num_to_hdl);
		if (status != DDI_SUCCESS)
			HERMON_WARNING(pool_info->rsrc_state,
			    "failure in hw_entry_free");
	}
}

/*
 * hermon_rsrc_hw_entry_icm_confirm()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_rsrc_hw_entry_icm_confirm(hermon_rsrc_pool_info_t *pool_info, uint_t num,
    hermon_rsrc_t *hdl, int num_to_hdl)
{
	hermon_state_t		*state;
	hermon_icm_table_t	*icm_table;
	uint8_t			*bitmap;
	hermon_dma_info_t	*dma_info;
	hermon_rsrc_type_t	type;
	uint32_t		rindx, span_offset;
	uint32_t		span_avail;
	int			num_backed;
	int			status;
	uint32_t		index1, index2;

	/*
	 * Utility routine responsible for ensuring that there is memory
	 * backing the ICM resources allocated via hermon_rsrc_hw_entry_alloc().
	 * Confirm existing ICM mapping(s) or allocate ICM memory for the
	 * given hardware resources being allocated, and increment the
	 * ICM DMA structure(s) reference count.
	 *
	 * We may be allocating more objects than can fit in a single span,
	 * or more than will fit in the remaining contiguous memory (from
	 * the offset indicated by hdl->ar_indx) in the span in question.
	 * In either of these cases, we'll be breaking up our allocation
	 * into multiple spans.
	 */
	state = pool_info->rsrc_state;
	type  = pool_info->rsrc_type;
	icm_table = &state->hs_icm[type];

	rindx = hdl->hr_indx;
	hermon_index(index1, index2, rindx, icm_table, span_offset);

	if (hermon_rsrc_verbose) {
		IBTF_DPRINTF_L2("hermon", "hermon_rsrc_hw_entry_icm_confirm: "
		    "type (0x%x) num (0x%x) length (0x%x) index (0x%x, 0x%x): ",
		    type, num, hdl->hr_len, index1, index2);
	}

	mutex_enter(&icm_table->icm_table_lock);
	hermon_bitmap(bitmap, dma_info, icm_table, index1, num_to_hdl);
	while (num) {
#ifndef __lock_lint
		while (icm_table->icm_busy) {
			cv_wait(&icm_table->icm_table_cv,
			    &icm_table->icm_table_lock);
		}
#endif
		if (!HERMON_BMAP_BIT_ISSET(bitmap, index2)) {
			/* Allocate ICM for this span */
			icm_table->icm_busy = 1;
			mutex_exit(&icm_table->icm_table_lock);
			status = hermon_icm_alloc(state, type, index1, index2);
			mutex_enter(&icm_table->icm_table_lock);
			icm_table->icm_busy = 0;
			cv_broadcast(&icm_table->icm_table_cv);
			if (status != DDI_SUCCESS) {
				goto fail_alloc;
			}
			if (hermon_rsrc_verbose) {
				IBTF_DPRINTF_L2("hermon", "hermon_rsrc_"
				    "hw_entry_icm_confirm: ALLOCATED ICM: "
				    "type (0x%x) index (0x%x, 0x%x)",
				    type, index1, index2);
			}
		}

		/*
		 * We need to increment the refcnt of this span by the
		 * number of objects in this resource allocation that are
		 * backed by this span. Given that the rsrc allocation is
		 * contiguous, this value will be the number of objects in
		 * the span from 'span_offset' onward, either up to a max
		 * of the total number of objects, or the end of the span.
		 * So, determine the number of objects that can be backed
		 * by this span ('span_avail'), then determine the number
		 * of backed resources.
		 */
		span_avail = icm_table->span - span_offset;
		if (num > span_avail) {
			num_backed = span_avail;
		} else {
			num_backed = num;
		}

		/*
		 * Now that we know 'num_backed', increment the refcnt,
		 * decrement the total number, and set 'span_offset' to
		 * 0 in case we roll over into the next span.
		 */
		dma_info[index2].icm_refcnt += num_backed;
		rindx += num_backed;
		num -= num_backed;

		if (hermon_rsrc_verbose) {
			IBTF_DPRINTF_L2("ALLOC", "ICM type (0x%x) index "
			    "(0x%x, 0x%x) num_backed (0x%x)",
			    type, index1, index2, num_backed);
			IBTF_DPRINTF_L2("ALLOC", "ICM type (0x%x) refcnt now "
			    "(0x%x) num_remaining (0x%x)", type,
			    dma_info[index2].icm_refcnt, num);
		}
		if (num == 0)
			break;

		hermon_index(index1, index2, rindx, icm_table, span_offset);
		hermon_bitmap(bitmap, dma_info, icm_table, index1, num_to_hdl);
	}
	mutex_exit(&icm_table->icm_table_lock);

	return (DDI_SUCCESS);

fail_alloc:
	/* JBDB */
	if (hermon_rsrc_verbose) {
		IBTF_DPRINTF_L2("hermon", "hermon_rsrc_"
		    "hw_entry_icm_confirm: FAILED ICM ALLOC: "
		    "type (0x%x) num remaind (0x%x) index (0x%x, 0x%x)"
		    "refcnt (0x%x)", type, num, index1, index2,
		    icm_table->icm_dma[index1][index2].icm_refcnt);
	}
	IBTF_DPRINTF_L2("hermon", "WARNING: "
	    "unimplemented fail code in hermon_rsrc_hw_entry_icm_alloc\n");

#if needs_work
	/* free refcnt's and any spans we've allocated */
	while (index-- != start) {
		/*
		 * JBDB - This is a bit tricky.  We need to
		 * free refcnt's on any spans that we've
		 * incremented them on, and completely free
		 * spans that we've allocated. How do we do
		 * this here? Does it need to be as involved
		 * as the core of icm_free() below, or can
		 * we leverage breadcrumbs somehow?
		 */
		HERMON_WARNING(state, "unable to allocate ICM memory: "
		    "UNIMPLEMENTED HANDLING!!");
	}
#else
	cmn_err(CE_WARN,
	    "unimplemented fail code in hermon_rsrc_hw_entry_icm_alloc\n");
#endif
	mutex_exit(&icm_table->icm_table_lock);

	HERMON_WARNING(state, "unable to allocate ICM memory");
	return (DDI_FAILURE);
}

/*
 * hermon_rsrc_hw_entry_icm_free()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_rsrc_hw_entry_icm_free(hermon_rsrc_pool_info_t *pool_info,
    hermon_rsrc_t *hdl, int num_to_hdl)
{
	hermon_state_t		*state;
	hermon_icm_table_t	*icm_table;
	uint8_t			*bitmap;
	hermon_dma_info_t	*dma_info;
	hermon_rsrc_type_t	type;
	uint32_t		span_offset;
	uint32_t		span_remain;
	int			num_freed;
	int			num;
	uint32_t		index1, index2, rindx;

	/*
	 * Utility routine responsible for freeing references to ICM
	 * DMA spans, and freeing the ICM memory if necessary.
	 *
	 * We may have allocated objects in a single contiguous resource
	 * allocation that reside in a number of spans, at any given
	 * starting offset within a span. We therefore must determine
	 * where this allocation starts, and then determine if we need
	 * to free objects in more than one span.
	 */
	state = pool_info->rsrc_state;
	type  = pool_info->rsrc_type;
	icm_table = &state->hs_icm[type];

	rindx = hdl->hr_indx;
	hermon_index(index1, index2, rindx, icm_table, span_offset);
	hermon_bitmap(bitmap, dma_info, icm_table, index1, num_to_hdl);

	/* determine the number of ICM objects in this allocation */
	num = hdl->hr_len >> pool_info->rsrc_shift;

	if (hermon_rsrc_verbose) {
		IBTF_DPRINTF_L2("hermon", "hermon_rsrc_hw_entry_icm_free: "
		    "type (0x%x) num (0x%x) length (0x%x) index (0x%x, 0x%x)",
		    type, num, hdl->hr_len, index1, index2);
	}
	mutex_enter(&icm_table->icm_table_lock);
	while (num) {
		/*
		 * As with the ICM confirm code above, we need to
		 * decrement the ICM span(s) by the number of
		 * resources being freed. So, determine the number
		 * of objects that are backed in this span from
		 * 'span_offset' onward, and set 'num_freed' to
		 * the smaller of either that number ('span_remain'),
		 * or the total number of objects being freed.
		 */
		span_remain = icm_table->span - span_offset;
		if (num > span_remain) {
			num_freed = span_remain;
		} else {
			num_freed = num;
		}

		/*
		 * Now that we know 'num_freed', decrement the refcnt,
		 * decrement the total number, and set 'span_offset' to
		 * 0 in case we roll over into the next span.
		 */
		dma_info[index2].icm_refcnt -= num_freed;
		num -= num_freed;
		rindx += num_freed;

		if (hermon_rsrc_verbose) {
			IBTF_DPRINTF_L2("FREE", "ICM type (0x%x) index "
			    "(0x%x, 0x%x) num_freed (0x%x)", type,
			    index1, index2, num_freed);
			IBTF_DPRINTF_L2("FREE", "ICM type (0x%x) refcnt now "
			    "(0x%x) num remaining (0x%x)", type,
			    icm_table->icm_dma[index1][index2].icm_refcnt, num);
		}

#if HERMON_ICM_FREE_ENABLED
		/* If we've freed the last object in this span, free it */
		if ((index1 != 0 || index2 != 0) &&
		    (dma_info[index2].icm_refcnt == 0)) {
			if (hermon_rsrc_verbose) {
				IBTF_DPRINTF_L2("hermon", "hermon_rsrc_hw_entry"
				    "_icm_free: freeing ICM type (0x%x) index"
				    " (0x%x, 0x%x)", type, index1, index2);
			}
			hermon_icm_free(state, type, index1, index2);
		}
#endif
		if (num == 0)
			break;

		hermon_index(index1, index2, rindx, icm_table, span_offset);
		hermon_bitmap(bitmap, dma_info, icm_table, index1, num_to_hdl);
	}
	mutex_exit(&icm_table->icm_table_lock);

	return (DDI_SUCCESS);
}



/*
 * hermon_rsrc_swhdl_alloc()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_rsrc_swhdl_alloc(hermon_rsrc_pool_info_t *pool_info, uint_t sleepflag,
    hermon_rsrc_t *hdl)
{
	void	*addr;
	int	flag;

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Allocate the software handle structure */
	flag = (sleepflag == HERMON_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	addr = kmem_cache_alloc(pool_info->rsrc_private, flag);
	if (addr == NULL) {
		return (DDI_FAILURE);
	}
	hdl->hr_len  = pool_info->rsrc_quantum;
	hdl->hr_addr = addr;

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_swhdl_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_rsrc_swhdl_free(hermon_rsrc_pool_info_t *pool_info, hermon_rsrc_t *hdl)
{
	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Free the software handle structure */
	kmem_cache_free(pool_info->rsrc_private, hdl->hr_addr);
}


/*
 * hermon_rsrc_pdhdl_alloc()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_rsrc_pdhdl_alloc(hermon_rsrc_pool_info_t *pool_info, uint_t sleepflag,
    hermon_rsrc_t *hdl)
{
	hermon_pdhdl_t	addr;
	void		*tmpaddr;
	int		flag, status;

	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Allocate the software handle */
	status = hermon_rsrc_swhdl_alloc(pool_info, sleepflag, hdl);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	addr = (hermon_pdhdl_t)hdl->hr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*addr))

	/* Allocate a PD number for the handle */
	flag = (sleepflag == HERMON_SLEEP) ? VM_SLEEP : VM_NOSLEEP;
	tmpaddr = vmem_alloc(pool_info->rsrc_vmp, 1, flag);
	if (tmpaddr == NULL) {
		/* No more PD number entries available */
		hermon_rsrc_swhdl_free(pool_info, hdl);
		return (DDI_FAILURE);
	}
	addr->pd_pdnum = (uint32_t)(uintptr_t)tmpaddr;
	addr->pd_rsrcp = hdl;
	hdl->hr_indx   = addr->pd_pdnum;

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_pdhdl_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_rsrc_pdhdl_free(hermon_rsrc_pool_info_t *pool_info, hermon_rsrc_t *hdl)
{
	ASSERT(pool_info != NULL);
	ASSERT(hdl != NULL);

	/* Use vmem_free() to free up the PD number */
	vmem_free(pool_info->rsrc_vmp, (void *)(uintptr_t)hdl->hr_indx, 1);

	/* Free the software handle structure */
	hermon_rsrc_swhdl_free(pool_info, hdl);
}


/*
 * hermon_rsrc_pdhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_rsrc_pdhdl_constructor(void *pd, void *priv, int flags)
{
	hermon_pdhdl_t	pdhdl;
	hermon_state_t	*state;

	pdhdl = (hermon_pdhdl_t)pd;
	state = (hermon_state_t *)priv;

	mutex_init(&pdhdl->pd_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_pdhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
hermon_rsrc_pdhdl_destructor(void *pd, void *priv)
{
	hermon_pdhdl_t	pdhdl;

	pdhdl = (hermon_pdhdl_t)pd;

	mutex_destroy(&pdhdl->pd_lock);
}


/*
 * hermon_rsrc_cqhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_rsrc_cqhdl_constructor(void *cq, void *priv, int flags)
{
	hermon_cqhdl_t	cqhdl;
	hermon_state_t	*state;

	cqhdl = (hermon_cqhdl_t)cq;
	state = (hermon_state_t *)priv;

	mutex_init(&cqhdl->cq_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_cqhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
hermon_rsrc_cqhdl_destructor(void *cq, void *priv)
{
	hermon_cqhdl_t	cqhdl;

	cqhdl = (hermon_cqhdl_t)cq;

	mutex_destroy(&cqhdl->cq_lock);
}


/*
 * hermon_rsrc_qphdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_rsrc_qphdl_constructor(void *qp, void *priv, int flags)
{
	hermon_qphdl_t	qphdl;
	hermon_state_t	*state;

	qphdl = (hermon_qphdl_t)qp;
	state = (hermon_state_t *)priv;

	mutex_init(&qphdl->qp_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_qphdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
hermon_rsrc_qphdl_destructor(void *qp, void *priv)
{
	hermon_qphdl_t	qphdl;

	qphdl = (hermon_qphdl_t)qp;

	mutex_destroy(&qphdl->qp_lock);
}


/*
 * hermon_rsrc_srqhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_rsrc_srqhdl_constructor(void *srq, void *priv, int flags)
{
	hermon_srqhdl_t	srqhdl;
	hermon_state_t	*state;

	srqhdl = (hermon_srqhdl_t)srq;
	state = (hermon_state_t *)priv;

	mutex_init(&srqhdl->srq_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_srqhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
hermon_rsrc_srqhdl_destructor(void *srq, void *priv)
{
	hermon_srqhdl_t	srqhdl;

	srqhdl = (hermon_srqhdl_t)srq;

	mutex_destroy(&srqhdl->srq_lock);
}


/*
 * hermon_rsrc_refcnt_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_rsrc_refcnt_constructor(void *rc, void *priv, int flags)
{
	hermon_sw_refcnt_t	*refcnt;
	hermon_state_t		*state;

	refcnt = (hermon_sw_refcnt_t *)rc;
	state  = (hermon_state_t *)priv;

	mutex_init(&refcnt->swrc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_refcnt_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
hermon_rsrc_refcnt_destructor(void *rc, void *priv)
{
	hermon_sw_refcnt_t	*refcnt;

	refcnt = (hermon_sw_refcnt_t *)rc;

	mutex_destroy(&refcnt->swrc_lock);
}


/*
 * hermon_rsrc_ahhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_rsrc_ahhdl_constructor(void *ah, void *priv, int flags)
{
	hermon_ahhdl_t	ahhdl;
	hermon_state_t	*state;

	ahhdl = (hermon_ahhdl_t)ah;
	state = (hermon_state_t *)priv;

	mutex_init(&ahhdl->ah_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));
	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_ahhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
hermon_rsrc_ahhdl_destructor(void *ah, void *priv)
{
	hermon_ahhdl_t	ahhdl;

	ahhdl = (hermon_ahhdl_t)ah;

	mutex_destroy(&ahhdl->ah_lock);
}


/*
 * hermon_rsrc_mrhdl_constructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_rsrc_mrhdl_constructor(void *mr, void *priv, int flags)
{
	hermon_mrhdl_t	mrhdl;
	hermon_state_t	*state;

	mrhdl = (hermon_mrhdl_t)mr;
	state = (hermon_state_t *)priv;

	mutex_init(&mrhdl->mr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	return (DDI_SUCCESS);
}


/*
 * hermon_rsrc_mrhdl_destructor()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
hermon_rsrc_mrhdl_destructor(void *mr, void *priv)
{
	hermon_mrhdl_t	mrhdl;

	mrhdl = (hermon_mrhdl_t)mr;

	mutex_destroy(&mrhdl->mr_lock);
}


/*
 * hermon_rsrc_mcg_entry_get_size()
 */
static int
hermon_rsrc_mcg_entry_get_size(hermon_state_t *state, uint_t *mcg_size_shift)
{
	uint_t	num_qp_per_mcg, max_qp_per_mcg, log2;

	/*
	 * Round the configured number of QP per MCG to next larger
	 * power-of-2 size and update.
	 */
	num_qp_per_mcg = state->hs_cfg_profile->cp_num_qp_per_mcg + 8;
	log2 = highbit(num_qp_per_mcg);
	if (ISP2(num_qp_per_mcg)) {
		log2 = log2 - 1;
	}
	state->hs_cfg_profile->cp_num_qp_per_mcg = (1 << log2) - 8;

	/* Now make sure number of QP per MCG makes sense */
	num_qp_per_mcg = state->hs_cfg_profile->cp_num_qp_per_mcg;
	max_qp_per_mcg = (1 << state->hs_devlim.log_max_qp_mcg);
	if (num_qp_per_mcg > max_qp_per_mcg) {
		return (DDI_FAILURE);
	}

	/* Return the (shift) size of an individual MCG HW entry */
	*mcg_size_shift = log2 + 2;

	return (DDI_SUCCESS);
}
