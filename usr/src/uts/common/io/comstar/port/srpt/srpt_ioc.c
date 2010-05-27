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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * I/O Controller functions for the Solaris COMSTAR SCSI RDMA Protocol
 * Target (SRPT) port provider.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/sdt.h>

#include "srp.h"
#include "srpt_impl.h"
#include "srpt_ioc.h"
#include "srpt_stp.h"
#include "srpt_ch.h"
#include "srpt_common.h"

/*
 * srpt_ioc_srq_size - Tunable parameter that specifies the number
 * of receive WQ entries that can be posted to the IOC shared
 * receive queue.
 */
uint32_t		srpt_ioc_srq_size = SRPT_DEFAULT_IOC_SRQ_SIZE;
extern uint16_t		srpt_send_msg_depth;
extern uint32_t		srpt_iu_size;
extern boolean_t	srpt_enable_by_default;

/* IOC profile capabilities mask must be big-endian */
typedef struct srpt_ioc_opcap_bits_s {
#if	defined(_BIT_FIELDS_LTOH)
	uint8_t		af:1,
			at:1,
			wf:1,
			wt:1,
			rf:1,
			rt:1,
			sf:1,
			st:1;
#elif	defined(_BIT_FIELDS_HTOL)
	uint8_t		st:1,
			sf:1,
			rt:1,
			rf:1,
			wt:1,
			wf:1,
			at:1,
			af:1;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
} srpt_ioc_opcap_bits_t;

typedef union {
	srpt_ioc_opcap_bits_t	bits;
	uint8_t			mask;
} srpt_ioc_opcap_mask_t;

/*
 * vmem arena variables - values derived from iSER
 */
#define	SRPT_MR_QUANTSIZE	0x400			/* 1K */
#define	SRPT_MIN_CHUNKSIZE	0x100000		/* 1MB */

/* use less memory on 32-bit kernels as it's much more constrained */
#ifdef _LP64
#define	SRPT_BUF_MR_CHUNKSIZE	0x1000000		/* 16MB */
#define	SRPT_BUF_POOL_MAX	0x40000000		/* 1GB */
#else
#define	SRPT_BUF_MR_CHUNKSIZE	0x400000		/* 4MB */
#define	SRPT_BUF_POOL_MAX	0x4000000		/* 64MB */
#endif

static ibt_mr_flags_t	srpt_dbuf_mr_flags =
    IBT_MR_ENABLE_LOCAL_WRITE | IBT_MR_ENABLE_REMOTE_WRITE |
    IBT_MR_ENABLE_REMOTE_READ;

void srpt_ioc_ib_async_hdlr(void *clnt, ibt_hca_hdl_t hdl,
	ibt_async_code_t code, ibt_async_event_t *event);

static struct ibt_clnt_modinfo_s srpt_ibt_modinfo = {
	IBTI_V_CURR,
	IBT_STORAGE_DEV,
	srpt_ioc_ib_async_hdlr,
	NULL,
	"srpt"
};

static srpt_ioc_t *srpt_ioc_init(ib_guid_t guid);
static void srpt_ioc_fini(srpt_ioc_t *ioc);
static boolean_t srpt_check_hca_cfg_enabled(ib_guid_t hca_guid);

static srpt_vmem_pool_t *srpt_vmem_create(const char *name, srpt_ioc_t *ioc,
    ib_memlen_t chunksize, uint64_t maxsize, ibt_mr_flags_t flags);
static void *srpt_vmem_alloc(srpt_vmem_pool_t *vm_pool, size_t size);
static int srpt_vmem_mr_compare(const void *a, const void *b);
static srpt_mr_t *srpt_vmem_chunk_alloc(srpt_vmem_pool_t *ioc,
    ib_memlen_t chunksize);
static void srpt_vmem_destroy(srpt_vmem_pool_t *vm_pool);
static void srpt_vmem_free(srpt_vmem_pool_t *vm_pool, void *vaddr, size_t size);
static srpt_mr_t *srpt_reg_mem(srpt_vmem_pool_t *vm_pool, ib_vaddr_t vaddr,
    ib_memlen_t len);
static void srpt_vmem_chunk_free(srpt_vmem_pool_t *vm_pool, srpt_mr_t *mr);
static void srpt_dereg_mem(srpt_ioc_t *ioc, srpt_mr_t *mr);
static int srpt_vmem_mr(srpt_vmem_pool_t *vm_pool, void *vaddr, size_t size,
    srpt_mr_t *mr);

/*
 * srpt_ioc_attach() - I/O Controller attach
 *
 * Attach to IBTF and initialize I/O controllers. The srpt_ctxt->sc_rwlock
 * should be held outside of this call.
 */
int
srpt_ioc_attach()
{
	int		status;
	int		hca_cnt;
	int		hca_ndx;
	ib_guid_t	*guid;

	ASSERT(srpt_ctxt != NULL);

	/*
	 * Attach to IBTF and initialize a list of IB devices.  Each
	 * HCA will be represented by an I/O Controller.
	 */
	status = ibt_attach(&srpt_ibt_modinfo, srpt_ctxt->sc_dip,
	    srpt_ctxt,  &srpt_ctxt->sc_ibt_hdl);
	if (status != DDI_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_attach, ibt_attach failed (0x%x)",
		    status);
		return (DDI_FAILURE);
	}

	hca_cnt = ibt_get_hca_list(&guid);
	if (hca_cnt < 1) {
		/*
		 * not a fatal error.  Service will be up and
		 * waiting for ATTACH events.
		 */
		SRPT_DPRINTF_L2("ioc_attach, no HCA found");
		return (DDI_SUCCESS);
	}

	for (hca_ndx = 0; hca_ndx < hca_cnt; hca_ndx++) {
		SRPT_DPRINTF_L2("ioc_attach, attaching HCA %016llx",
		    (u_longlong_t)guid[hca_ndx]);
		srpt_ioc_attach_hca(guid[hca_ndx], B_FALSE);
	}

	ibt_free_hca_list(guid, hca_cnt);
	SRPT_DPRINTF_L3("ioc_attach, added %d I/O Controller(s)",
	    srpt_ctxt->sc_num_iocs);
	return (DDI_SUCCESS);
}

/*
 * Initialize I/O Controllers.  sprt_ctxt->sc_rwlock must be locked by the
 * caller.
 *
 * 'checked' indicates no need to lookup the hca in the HCA configuration
 * list.
 */
void
srpt_ioc_attach_hca(ib_guid_t hca_guid, boolean_t checked)
{
	boolean_t	enable_hca = B_TRUE;
	srpt_ioc_t	*ioc;

	if (!checked) {
		enable_hca = srpt_check_hca_cfg_enabled(hca_guid);

		if (!enable_hca) {
			/* nothing to do */
			SRPT_DPRINTF_L2(
			    "ioc_attach_hca, HCA %016llx disabled "
			    "by srpt config",
			    (u_longlong_t)hca_guid);
			return;
		}
	}

	SRPT_DPRINTF_L2("ioc_attach_hca, adding I/O"
	    " Controller (%016llx)", (u_longlong_t)hca_guid);

	ioc = srpt_ioc_init(hca_guid);
	if (ioc == NULL) {
		/*
		 * IOC already exists or an error occurred.  Already
		 * logged by srpt_ioc_init()
		 */
		return;
	}

	/*
	 * Create the COMSTAR SRP Target for this IOC.  If this fails,
	 * remove the IOC.
	 */
	rw_enter(&ioc->ioc_rwlock, RW_WRITER);
	ioc->ioc_tgt_port = srpt_stp_alloc_port(ioc, ioc->ioc_guid);
	if (ioc->ioc_tgt_port == NULL) {
		SRPT_DPRINTF_L1("ioc_attach_hca: alloc SCSI"
		    " Target Port error on GUID(%016llx)",
		    (u_longlong_t)ioc->ioc_guid);
		rw_exit(&ioc->ioc_rwlock);
		srpt_ioc_fini(ioc);
		return;
	}
	rw_exit(&ioc->ioc_rwlock);

	/*
	 * New HCA added with default SCSI Target Port, SRP service
	 * will be started when SCSI Target Port is brought
	 * on-line by STMF.
	 */
	list_insert_tail(&srpt_ctxt->sc_ioc_list, ioc);
	SRPT_DPRINTF_L2("ioc_attach_hca, I/O Controller ibt HCA hdl (%p)",
	    (void *)ioc->ioc_ibt_hdl);

	srpt_ctxt->sc_num_iocs++;
}

/*
 * srpt_check_hca_cfg_enabled()
 *
 * Function to check the configuration for the enabled status of a given
 * HCA.  Returns B_TRUE if SRPT services should be activated for this HCA,
 * B_FALSE if it should be disabled.
 */
static boolean_t
srpt_check_hca_cfg_enabled(ib_guid_t hca_guid)
{
	int		status;
	char		buf[32];
	nvlist_t	*hcanv;
	boolean_t	enable_hca;

	enable_hca = srpt_enable_by_default;

	SRPT_FORMAT_HCAKEY(buf, sizeof (buf), (u_longlong_t)hca_guid);

	if (srpt_ctxt->sc_cfg_hca_nv != NULL) {
		status = nvlist_lookup_nvlist(srpt_ctxt->sc_cfg_hca_nv,
		    buf, &hcanv);
		if (status == 0) {
			SRPT_DPRINTF_L3("check_hca_cfg, found guid %s",  buf);
			(void) nvlist_lookup_boolean_value(hcanv,
			    SRPT_PROP_ENABLED, &enable_hca);
		} else {
			SRPT_DPRINTF_L3("check_hca_cfg, did not find guid %s",
			    buf);
		}
	}

	return (enable_hca);
}

/*
 * srpt_ioc_update()
 *
 * Using the configuration nvlist, enables or disables SRP services
 * the provided HCAs.  srpt_ctxt->sc_rwlock should be held outside of this call.
 */
void
srpt_ioc_update(void)
{
	boolean_t	enabled;
	nvpair_t	*nvp = NULL;
	uint64_t	hca_guid;
	nvlist_t	*nvl;
	nvlist_t	*cfg = srpt_ctxt->sc_cfg_hca_nv;

	if (cfg == NULL) {
		SRPT_DPRINTF_L2("ioc_update, no configuration data");
		return;
	}

	while ((nvp = nvlist_next_nvpair(cfg, nvp)) != NULL) {
		enabled = srpt_enable_by_default;

		if ((nvpair_value_nvlist(nvp, &nvl)) != 0) {
			SRPT_DPRINTF_L2("ioc_update, did not find an nvlist");
			continue;
		}

		if ((nvlist_lookup_uint64(nvl, SRPT_PROP_GUID, &hca_guid))
		    != 0) {
			SRPT_DPRINTF_L2("ioc_update, did not find a guid");
			continue;
		}

		(void) nvlist_lookup_boolean_value(nvl, SRPT_PROP_ENABLED,
		    &enabled);

		if (enabled) {
			SRPT_DPRINTF_L2("ioc_update, enabling guid %016llx",
			    (u_longlong_t)hca_guid);
			srpt_ioc_attach_hca(hca_guid, B_TRUE);
		} else {
			SRPT_DPRINTF_L2("ioc_update, disabling guid %016llx",
			    (u_longlong_t)hca_guid);
			srpt_ioc_detach_hca(hca_guid);
		}
	}
}

/*
 * srpt_ioc_detach() - I/O Controller detach
 *
 * srpt_ctxt->sc_rwlock should be held outside of this call.
 */
void
srpt_ioc_detach()
{
	srpt_ioc_t	*ioc;

	/*
	 * All SRP targets must be destroyed before calling this
	 * function.
	 */
	while ((ioc = list_head(&srpt_ctxt->sc_ioc_list)) != NULL) {
		SRPT_DPRINTF_L2("ioc_detach, removing I/O Controller(%p)"
		    " (%016llx), ibt_hdl(%p)",
		    (void *)ioc,
		    ioc ? (u_longlong_t)ioc->ioc_guid : 0x0ll,
		    (void *)ioc->ioc_ibt_hdl);

		list_remove(&srpt_ctxt->sc_ioc_list, ioc);
		srpt_ioc_fini(ioc);
		srpt_ctxt->sc_num_iocs--;
	}

	srpt_ctxt->sc_ibt_hdl = NULL;
}

/*
 * srpt_ioc_detach_hca()
 *
 * Stop SRP Target services on this HCA
 *
 * Note that this is not entirely synchronous with srpt_ioc_attach_hca()
 * in that we don't need to check the configuration to know whether to
 * disable an HCA.  We get here either because the IB framework has told
 * us the HCA has been detached, or because the administrator has explicitly
 * disabled this HCA.
 *
 * Must be called with srpt_ctxt->sc_rwlock locked as RW_WRITER.
 */
void
srpt_ioc_detach_hca(ib_guid_t hca_guid)
{
	srpt_ioc_t		*ioc;
	srpt_target_port_t	*tgt;
	stmf_status_t		stmf_status = STMF_SUCCESS;

	ioc = srpt_ioc_get_locked(hca_guid);
	if (ioc == NULL) {
		/* doesn't exist, nothing to do */
		return;
	}

	rw_enter(&ioc->ioc_rwlock, RW_WRITER);
	tgt = ioc->ioc_tgt_port;

	if (tgt != NULL) {
		stmf_status = srpt_stp_destroy_port(tgt);
		if (stmf_status == STMF_SUCCESS) {
			ioc->ioc_tgt_port = NULL;
			(void) srpt_stp_free_port(tgt);
		}
	}

	rw_exit(&ioc->ioc_rwlock);

	if (stmf_status != STMF_SUCCESS) {
		/* should never happen */
		return;
	}

	list_remove(&srpt_ctxt->sc_ioc_list, ioc);
	srpt_ctxt->sc_num_iocs--;

	srpt_ioc_fini(ioc);
	SRPT_DPRINTF_L2("ioc_detach_hca, HCA %016llx detached",
	    (u_longlong_t)hca_guid);
}

/*
 * srpt_ioc_init() - I/O Controller initialization
 *
 * Requires srpt_ctxt->rw_lock be held outside of call.
 */
static srpt_ioc_t *
srpt_ioc_init(ib_guid_t guid)
{
	ibt_status_t		status;
	srpt_ioc_t		*ioc;
	ibt_hca_attr_t		hca_attr;
	uint_t			iu_ndx;
	uint_t			err_ndx;
	ibt_mr_attr_t		mr_attr;
	ibt_mr_desc_t		mr_desc;
	srpt_iu_t		*iu;
	ibt_srq_sizes_t		srq_attr;
	char			namebuf[32];
	size_t			iu_offset;
	uint_t			srq_sz;

	status = ibt_query_hca_byguid(guid, &hca_attr);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_init, HCA query error (%d)",
		    status);
		return (NULL);
	}

	ioc = srpt_ioc_get_locked(guid);
	if (ioc != NULL) {
		SRPT_DPRINTF_L2("ioc_init, HCA already exists");
		return (NULL);
	}

	ioc = kmem_zalloc(sizeof (srpt_ioc_t), KM_SLEEP);

	rw_init(&ioc->ioc_rwlock, NULL, RW_DRIVER, NULL);
	rw_enter(&ioc->ioc_rwlock, RW_WRITER);

	bcopy(&hca_attr, &ioc->ioc_attr, sizeof (ibt_hca_attr_t));

	SRPT_DPRINTF_L2("ioc_init, HCA max mr=%d, mrlen=%lld",
	    hca_attr.hca_max_memr, (u_longlong_t)hca_attr.hca_max_memr_len);
	ioc->ioc_guid   = guid;

	status = ibt_open_hca(srpt_ctxt->sc_ibt_hdl, guid, &ioc->ioc_ibt_hdl);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_init, IBT open failed (%d)", status);
		goto hca_open_err;
	}

	status = ibt_alloc_pd(ioc->ioc_ibt_hdl, IBT_PD_NO_FLAGS,
	    &ioc->ioc_pd_hdl);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_init, IBT create PD failed (%d)", status);
		goto pd_alloc_err;
	}

	/*
	 * We require hardware support for SRQs.  We use a common SRQ to
	 * reduce channel memory consumption.
	 */
	if ((ioc->ioc_attr.hca_flags & IBT_HCA_SRQ) == 0) {
		SRPT_DPRINTF_L0(
		    "ioc_init, no SRQ capability, HCA not supported");
		goto srq_alloc_err;
	}

	SRPT_DPRINTF_L3("ioc_init, Using shared receive queues, max srq work"
	    " queue size(%d), def size = %d", ioc->ioc_attr.hca_max_srqs_sz,
	    srpt_ioc_srq_size);
	srq_sz = srq_attr.srq_wr_sz = min(srpt_ioc_srq_size,
	    ioc->ioc_attr.hca_max_srqs_sz) - 1;
	srq_attr.srq_sgl_sz = 1;

	status = ibt_alloc_srq(ioc->ioc_ibt_hdl, IBT_SRQ_NO_FLAGS,
	    ioc->ioc_pd_hdl, &srq_attr, &ioc->ioc_srq_hdl,
	    &ioc->ioc_srq_attr);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_init, IBT create SRQ failed(%d)", status);
		goto srq_alloc_err;
	}

	SRPT_DPRINTF_L2("ioc_init, Using SRQ size(%d), MAX SG size(%d)",
	    srq_sz, 1);

	ibt_set_srq_private(ioc->ioc_srq_hdl, ioc);

	/*
	 * Allocate a pool of SRP IU message buffers and post them to
	 * the I/O Controller SRQ.  We let the SRQ manage the free IU
	 * messages.
	 */
	ioc->ioc_num_iu_entries = srq_sz;

	ioc->ioc_iu_pool = kmem_zalloc(sizeof (srpt_iu_t) *
	    ioc->ioc_num_iu_entries, KM_SLEEP);

	ioc->ioc_iu_bufs = kmem_alloc(srpt_iu_size *
	    ioc->ioc_num_iu_entries, KM_SLEEP);

	if ((ioc->ioc_iu_pool == NULL) || (ioc->ioc_iu_bufs == NULL)) {
		SRPT_DPRINTF_L1("ioc_init, failed to allocate SRQ IUs");
		goto srq_iu_alloc_err;
	}

	mr_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)ioc->ioc_iu_bufs;
	mr_attr.mr_len   = srpt_iu_size * ioc->ioc_num_iu_entries;
	mr_attr.mr_as    = NULL;
	mr_attr.mr_flags = IBT_MR_ENABLE_LOCAL_WRITE;

	status = ibt_register_mr(ioc->ioc_ibt_hdl, ioc->ioc_pd_hdl,
	    &mr_attr, &ioc->ioc_iu_mr_hdl, &mr_desc);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_init, IU buffer pool MR err(%d)",
		    status);
		goto srq_iu_alloc_err;
	}

	for (iu_ndx = 0, iu = ioc->ioc_iu_pool; iu_ndx <
	    ioc->ioc_num_iu_entries; iu_ndx++, iu++) {

		iu_offset = (iu_ndx * srpt_iu_size);
		iu->iu_buf = (void *)((uintptr_t)ioc->ioc_iu_bufs + iu_offset);

		mutex_init(&iu->iu_lock, NULL, MUTEX_DRIVER, NULL);

		iu->iu_sge.ds_va  = mr_desc.md_vaddr + iu_offset;
		iu->iu_sge.ds_key = mr_desc.md_lkey;
		iu->iu_sge.ds_len = srpt_iu_size;
		iu->iu_ioc	  = ioc;
		iu->iu_pool_ndx   = iu_ndx;

		status = srpt_ioc_post_recv_iu(ioc, &ioc->ioc_iu_pool[iu_ndx]);
		if (status != IBT_SUCCESS) {
			SRPT_DPRINTF_L1("ioc_init, SRQ IU post err(%d)",
			    status);
			goto srq_iu_post_err;
		}
	}

	/*
	 * Initialize the dbuf vmem arena
	 */
	(void) snprintf(namebuf, sizeof (namebuf),
	    "srpt_buf_pool_%16llX", (u_longlong_t)guid);
	ioc->ioc_dbuf_pool = srpt_vmem_create(namebuf, ioc,
	    SRPT_BUF_MR_CHUNKSIZE, SRPT_BUF_POOL_MAX, srpt_dbuf_mr_flags);

	if (ioc->ioc_dbuf_pool == NULL) {
		goto stmf_db_alloc_err;
	}

	/*
	 * Allocate the I/O Controller STMF data buffer allocator.  The
	 * data store will span all targets associated with this IOC.
	 */
	ioc->ioc_stmf_ds = stmf_alloc(STMF_STRUCT_DBUF_STORE, 0, 0);
	if (ioc->ioc_stmf_ds == NULL) {
		SRPT_DPRINTF_L1("ioc_attach, STMF DBUF alloc failure for IOC");
		goto stmf_db_alloc_err;
	}
	ioc->ioc_stmf_ds->ds_alloc_data_buf = &srpt_ioc_ds_alloc_dbuf;
	ioc->ioc_stmf_ds->ds_free_data_buf  = &srpt_ioc_ds_free_dbuf;
	ioc->ioc_stmf_ds->ds_port_private   = ioc;

	rw_exit(&ioc->ioc_rwlock);
	return (ioc);

stmf_db_alloc_err:
	if (ioc->ioc_dbuf_pool != NULL) {
		srpt_vmem_destroy(ioc->ioc_dbuf_pool);
	}

srq_iu_post_err:
	if (ioc->ioc_iu_mr_hdl != NULL) {
		status = ibt_deregister_mr(ioc->ioc_ibt_hdl,
		    ioc->ioc_iu_mr_hdl);
		if (status != IBT_SUCCESS) {
			SRPT_DPRINTF_L1("ioc_init, error deregistering"
			    " memory region (%d)", status);
		}
	}
	for (err_ndx = 0, iu = ioc->ioc_iu_pool; err_ndx < iu_ndx;
	    err_ndx++, iu++) {
		mutex_destroy(&iu->iu_lock);
	}

srq_iu_alloc_err:
	if (ioc->ioc_iu_bufs != NULL) {
		kmem_free(ioc->ioc_iu_bufs, srpt_iu_size *
		    ioc->ioc_num_iu_entries);
	}
	if (ioc->ioc_iu_pool != NULL) {
		kmem_free(ioc->ioc_iu_pool,
		    sizeof (srpt_iu_t) * ioc->ioc_num_iu_entries);
	}
	if (ioc->ioc_srq_hdl != NULL) {
		status = ibt_free_srq(ioc->ioc_srq_hdl);
		if (status != IBT_SUCCESS) {
			SRPT_DPRINTF_L1("ioc_init, error freeing SRQ (%d)",
			    status);
		}

	}

srq_alloc_err:
	status = ibt_free_pd(ioc->ioc_ibt_hdl, ioc->ioc_pd_hdl);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_init, free PD error (%d)", status);
	}

pd_alloc_err:
	status = ibt_close_hca(ioc->ioc_ibt_hdl);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_init, close ioc error (%d)", status);
	}

hca_open_err:
	rw_exit(&ioc->ioc_rwlock);
	rw_destroy(&ioc->ioc_rwlock);
	kmem_free(ioc, sizeof (*ioc));
	return (NULL);
}

/*
 * srpt_ioc_fini() - I/O Controller Cleanup
 *
 * Requires srpt_ctxt->sc_rwlock be held outside of call.
 */
static void
srpt_ioc_fini(srpt_ioc_t *ioc)
{
	int		status;
	int		ndx;

	/*
	 * Note driver flows will have already taken all SRP
	 * services running on the I/O Controller off-line.
	 */
	ASSERT(ioc->ioc_tgt_port == NULL);
	rw_enter(&ioc->ioc_rwlock, RW_WRITER);
	if (ioc->ioc_ibt_hdl != NULL) {
		if (ioc->ioc_stmf_ds != NULL) {
			stmf_free(ioc->ioc_stmf_ds);
		}

		if (ioc->ioc_srq_hdl != NULL) {
			SRPT_DPRINTF_L4("ioc_fini, freeing SRQ");
			status = ibt_free_srq(ioc->ioc_srq_hdl);
			if (status != IBT_SUCCESS) {
				SRPT_DPRINTF_L1("ioc_fini, free SRQ"
				    " error (%d)", status);
			}
		}

		if (ioc->ioc_iu_mr_hdl != NULL) {
			status = ibt_deregister_mr(
			    ioc->ioc_ibt_hdl, ioc->ioc_iu_mr_hdl);
			if (status != IBT_SUCCESS) {
				SRPT_DPRINTF_L1("ioc_fini, error deregistering"
				    " memory region (%d)", status);
			}
		}

		if (ioc->ioc_iu_bufs != NULL) {
			kmem_free(ioc->ioc_iu_bufs, srpt_iu_size *
			    ioc->ioc_num_iu_entries);
		}

		if (ioc->ioc_iu_pool != NULL) {
			SRPT_DPRINTF_L4("ioc_fini, freeing IU entries");
			for (ndx = 0; ndx < ioc->ioc_num_iu_entries; ndx++) {
				mutex_destroy(&ioc->ioc_iu_pool[ndx].iu_lock);
			}

			SRPT_DPRINTF_L4("ioc_fini, free IU pool struct");
			kmem_free(ioc->ioc_iu_pool,
			    sizeof (srpt_iu_t) * (ioc->ioc_num_iu_entries));
			ioc->ioc_iu_pool = NULL;
			ioc->ioc_num_iu_entries = 0;
		}

		if (ioc->ioc_dbuf_pool != NULL) {
			srpt_vmem_destroy(ioc->ioc_dbuf_pool);
		}

		if (ioc->ioc_pd_hdl != NULL) {
			status = ibt_free_pd(ioc->ioc_ibt_hdl,
			    ioc->ioc_pd_hdl);
			if (status != IBT_SUCCESS) {
				SRPT_DPRINTF_L1("ioc_fini, free PD"
				    " error (%d)", status);
			}
		}

		status = ibt_close_hca(ioc->ioc_ibt_hdl);
		if (status != IBT_SUCCESS) {
			SRPT_DPRINTF_L1(
			    "ioc_fini, close ioc error (%d)", status);
		}
	}
	rw_exit(&ioc->ioc_rwlock);
	rw_destroy(&ioc->ioc_rwlock);
	kmem_free(ioc, sizeof (srpt_ioc_t));
}

/*
 * srpt_ioc_port_active() - I/O Controller port active
 */
static void
srpt_ioc_port_active(ibt_async_event_t *event)
{
	ibt_status_t		status;
	srpt_ioc_t		*ioc;
	srpt_target_port_t	*tgt = NULL;
	boolean_t		online_target = B_FALSE;
	stmf_change_status_t	cstatus;

	ASSERT(event != NULL);

	SRPT_DPRINTF_L3("ioc_port_active event handler, invoked");

	/*
	 * Find the HCA in question and if the HCA has completed
	 * initialization, and the SRP Target service for the
	 * the I/O Controller exists, then bind this port.
	 */
	ioc = srpt_ioc_get(event->ev_hca_guid);

	if (ioc == NULL) {
		SRPT_DPRINTF_L2("ioc_port_active, I/O Controller not"
		    " active");
		return;
	}

	tgt = ioc->ioc_tgt_port;
	if (tgt == NULL) {
		SRPT_DPRINTF_L2("ioc_port_active, no I/O Controller target"
		    " undefined");
		return;
	}


	/*
	 * We take the target lock here to serialize this operation
	 * with any STMF initiated target state transitions.  If
	 * SRP is off-line then the service handle is NULL.
	 */
	mutex_enter(&tgt->tp_lock);

	if (tgt->tp_ibt_svc_hdl != NULL) {
		status = srpt_ioc_svc_bind(tgt, event->ev_port);
		if ((status != IBT_SUCCESS) &&
		    (status != IBT_HCA_PORT_NOT_ACTIVE)) {
			SRPT_DPRINTF_L1("ioc_port_active, bind failed (%d)",
			    status);
		}
	} else {
		/* if we were offline because of no ports, try onlining now */
		if ((tgt->tp_num_active_ports == 0) &&
		    (tgt->tp_requested_state != tgt->tp_state) &&
		    (tgt->tp_requested_state == SRPT_TGT_STATE_ONLINE)) {
			online_target = B_TRUE;
			cstatus.st_completion_status = STMF_SUCCESS;
			cstatus.st_additional_info = "port active";
		}
	}

	mutex_exit(&tgt->tp_lock);

	if (online_target) {
		stmf_status_t	ret;

		ret = stmf_ctl(STMF_CMD_LPORT_ONLINE, tgt->tp_lport, &cstatus);

		if (ret == STMF_SUCCESS) {
			SRPT_DPRINTF_L1("ioc_port_active, port %d active, "
			    "target %016llx online requested", event->ev_port,
			    (u_longlong_t)ioc->ioc_guid);
		} else if (ret != STMF_ALREADY) {
			SRPT_DPRINTF_L1("ioc_port_active, port %d active, "
			    "target %016llx failed online request: %d",
			    event->ev_port, (u_longlong_t)ioc->ioc_guid,
			    (int)ret);
		}
	}
}

/*
 * srpt_ioc_port_down()
 */
static void
srpt_ioc_port_down(ibt_async_event_t *event)
{
	srpt_ioc_t		*ioc;
	srpt_target_port_t	*tgt;
	srpt_channel_t		*ch;
	srpt_channel_t		*next_ch;
	boolean_t		offline_target = B_FALSE;
	stmf_change_status_t	cstatus;

	SRPT_DPRINTF_L3("ioc_port_down event handler, invoked");

	/*
	 * Find the HCA in question and if the HCA has completed
	 * initialization, and the SRP Target service for the
	 * the I/O Controller exists, then logout initiators
	 * through this port.
	 */
	ioc = srpt_ioc_get(event->ev_hca_guid);

	if (ioc == NULL) {
		SRPT_DPRINTF_L2("ioc_port_down, I/O Controller not"
		    " active");
		return;
	}

	/*
	 * We only have one target now, but we could go through all
	 * SCSI target ports if more are added.
	 */
	tgt = ioc->ioc_tgt_port;
	if (tgt == NULL) {
		SRPT_DPRINTF_L2("ioc_port_down, no I/O Controller target"
		    " undefined");
		return;
	}
	mutex_enter(&tgt->tp_lock);

	/*
	 * For all channel's logged in through this port, initiate a
	 * disconnect.
	 */
	mutex_enter(&tgt->tp_ch_list_lock);
	ch = list_head(&tgt->tp_ch_list);
	while (ch != NULL) {
		next_ch = list_next(&tgt->tp_ch_list, ch);
		if (ch->ch_session && (ch->ch_session->ss_hw_port ==
		    event->ev_port)) {
			srpt_ch_disconnect(ch);
		}
		ch = next_ch;
	}
	mutex_exit(&tgt->tp_ch_list_lock);

	tgt->tp_num_active_ports--;

	/* if we have no active ports, take the target offline */
	if ((tgt->tp_num_active_ports == 0) &&
	    (tgt->tp_state == SRPT_TGT_STATE_ONLINE)) {
		cstatus.st_completion_status = STMF_SUCCESS;
		cstatus.st_additional_info = "no ports active";
		offline_target = B_TRUE;
	}

	mutex_exit(&tgt->tp_lock);

	if (offline_target) {
		stmf_status_t	ret;

		ret = stmf_ctl(STMF_CMD_LPORT_OFFLINE, tgt->tp_lport, &cstatus);

		if (ret == STMF_SUCCESS) {
			SRPT_DPRINTF_L1("ioc_port_down, port %d down, target "
			    "%016llx offline requested", event->ev_port,
			    (u_longlong_t)ioc->ioc_guid);
		} else if (ret != STMF_ALREADY) {
			SRPT_DPRINTF_L1("ioc_port_down, port %d down, target "
			    "%016llx failed offline request: %d",
			    event->ev_port,
			    (u_longlong_t)ioc->ioc_guid, (int)ret);
		}
	}
}

/*
 * srpt_ioc_ib_async_hdlr - I/O Controller IB asynchronous events
 */
/* ARGSUSED */
void
srpt_ioc_ib_async_hdlr(void *clnt, ibt_hca_hdl_t hdl,
	ibt_async_code_t code, ibt_async_event_t *event)
{
	srpt_channel_t		*ch;

	switch (code) {
	case IBT_EVENT_PORT_UP:
		srpt_ioc_port_active(event);
		break;

	case IBT_ERROR_PORT_DOWN:
		srpt_ioc_port_down(event);
		break;

	case IBT_HCA_ATTACH_EVENT:
		SRPT_DPRINTF_L2(
		    "ib_async_hdlr, received attach event for HCA 0x%016llx",
		    (u_longlong_t)event->ev_hca_guid);

		rw_enter(&srpt_ctxt->sc_rwlock, RW_WRITER);
		srpt_ioc_attach_hca(event->ev_hca_guid, B_FALSE);
		rw_exit(&srpt_ctxt->sc_rwlock);

		break;

	case IBT_HCA_DETACH_EVENT:
		SRPT_DPRINTF_L1(
		    "ioc_iob_async_hdlr, received HCA_DETACH_EVENT for "
		    "HCA 0x%016llx",
		    (u_longlong_t)event->ev_hca_guid);

		rw_enter(&srpt_ctxt->sc_rwlock, RW_WRITER);
		srpt_ioc_detach_hca(event->ev_hca_guid);
		rw_exit(&srpt_ctxt->sc_rwlock);

		break;

	case IBT_EVENT_EMPTY_CHAN:
		/* Channel in ERROR state is now empty */
		ch = (srpt_channel_t *)ibt_get_chan_private(event->ev_chan_hdl);
		SRPT_DPRINTF_L3(
		    "ioc_iob_async_hdlr, received empty channel error on %p",
		    (void *)ch);
		break;

	default:
		SRPT_DPRINTF_L2("ioc_ib_async_hdlr, event not "
		    "handled (%d)", code);
		break;
	}
}

/*
 * srpt_ioc_svc_bind()
 */
ibt_status_t
srpt_ioc_svc_bind(srpt_target_port_t *tgt, uint_t portnum)
{
	ibt_status_t		status;
	srpt_hw_port_t		*port;
	ibt_hca_portinfo_t	*portinfo;
	uint_t			qportinfo_sz;
	uint_t			qportnum;
	ib_gid_t		new_gid;
	srpt_ioc_t		*ioc;
	srpt_session_t		sess;

	ASSERT(tgt != NULL);
	ASSERT(tgt->tp_ioc != NULL);
	ioc = tgt->tp_ioc;

	if (tgt->tp_ibt_svc_hdl == NULL) {
		SRPT_DPRINTF_L2("ioc_svc_bind, NULL SCSI target port"
		    " service");
		return (IBT_INVALID_PARAM);
	}

	if (portnum == 0 || portnum > tgt->tp_nports) {
		SRPT_DPRINTF_L2("ioc_svc_bind, bad port (%d)", portnum);
		return (IBT_INVALID_PARAM);
	}
	status = ibt_query_hca_ports(ioc->ioc_ibt_hdl, portnum,
	    &portinfo, &qportnum, &qportinfo_sz);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ioc_svc_bind, query port error (%d)",
		    portnum);
		return (IBT_INVALID_PARAM);
	}

	ASSERT(portinfo != NULL);

	/*
	 * If port is not active do nothing, caller should attempt to bind
	 * after the port goes active.
	 */
	if (portinfo->p_linkstate != IBT_PORT_ACTIVE) {
		SRPT_DPRINTF_L2("ioc_svc_bind, port %d not in active state",
		    portnum);
		ibt_free_portinfo(portinfo, qportinfo_sz);
		return (IBT_HCA_PORT_NOT_ACTIVE);
	}

	port    = &tgt->tp_hw_port[portnum-1];
	new_gid = portinfo->p_sgid_tbl[0];
	ibt_free_portinfo(portinfo, qportinfo_sz);

	/*
	 * If previously bound and the port GID has changed,
	 * unbind the old GID.
	 */
	if (port->hwp_bind_hdl != NULL) {
		if (new_gid.gid_guid != port->hwp_gid.gid_guid ||
		    new_gid.gid_prefix != port->hwp_gid.gid_prefix) {
			SRPT_DPRINTF_L2("ioc_svc_bind, unregister current"
			    " bind");
			(void) ibt_unbind_service(tgt->tp_ibt_svc_hdl,
			    port->hwp_bind_hdl);
			port->hwp_bind_hdl = NULL;
		} else {
			SRPT_DPRINTF_L2("ioc_svc_bind, port %d already bound",
			    portnum);
		}
	}

	/* bind the new port GID */
	if (port->hwp_bind_hdl == NULL) {
		SRPT_DPRINTF_L2("ioc_svc_bind, bind service, %016llx:%016llx",
		    (u_longlong_t)new_gid.gid_prefix,
		    (u_longlong_t)new_gid.gid_guid);

		/*
		 * Pass SCSI Target Port as CM private data, the target will
		 * always exist while this service is bound.
		 */
		status = ibt_bind_service(tgt->tp_ibt_svc_hdl, new_gid, NULL,
		    tgt, &port->hwp_bind_hdl);
		if (status != IBT_SUCCESS && status != IBT_CM_SERVICE_EXISTS) {
			SRPT_DPRINTF_L1("ioc_svc_bind, bind error (%d)",
			    status);
			return (status);
		}
		port->hwp_gid.gid_prefix = new_gid.gid_prefix;
		port->hwp_gid.gid_guid = new_gid.gid_guid;
	}

	/* port is now active */
	tgt->tp_num_active_ports++;

	/* setting up a transient structure for the dtrace probe. */
	bzero(&sess, sizeof (srpt_session_t));
	ALIAS_STR(sess.ss_t_gid, new_gid.gid_prefix, new_gid.gid_guid);
	EUI_STR(sess.ss_t_name, tgt->tp_ibt_svc_id);

	DTRACE_SRP_1(service__up, srpt_session_t, &sess);

	return (IBT_SUCCESS);
}

/*
 * srpt_ioc_svc_unbind()
 */
void
srpt_ioc_svc_unbind(srpt_target_port_t *tgt, uint_t portnum)
{
	srpt_hw_port_t		*port;
	srpt_session_t		sess;
	ibt_status_t		ret;

	if (tgt == NULL) {
		SRPT_DPRINTF_L2("ioc_svc_unbind, SCSI target does not exist");
		return;
	}

	if (portnum == 0 || portnum > tgt->tp_nports) {
		SRPT_DPRINTF_L2("ioc_svc_unbind, bad port (%d)", portnum);
		return;
	}
	port = &tgt->tp_hw_port[portnum-1];

	/* setting up a transient structure for the dtrace probe. */
	bzero(&sess, sizeof (srpt_session_t));
	ALIAS_STR(sess.ss_t_gid, port->hwp_gid.gid_prefix,
	    port->hwp_gid.gid_guid);
	EUI_STR(sess.ss_t_name, tgt->tp_ibt_svc_id);

	DTRACE_SRP_1(service__down, srpt_session_t, &sess);

	if (tgt->tp_ibt_svc_hdl != NULL && port->hwp_bind_hdl != NULL) {
		SRPT_DPRINTF_L2("ioc_svc_unbind, unregister current bind");
		ret = ibt_unbind_service(tgt->tp_ibt_svc_hdl,
		    port->hwp_bind_hdl);
		if (ret != IBT_SUCCESS) {
			SRPT_DPRINTF_L1(
			    "ioc_svc_unbind, unregister port %d failed: %d",
			    portnum, ret);
		} else {
			port->hwp_bind_hdl = NULL;
			port->hwp_gid.gid_prefix = 0;
			port->hwp_gid.gid_guid = 0;
		}
	}
}

/*
 * srpt_ioc_svc_unbind_all()
 */
void
srpt_ioc_svc_unbind_all(srpt_target_port_t *tgt)
{
	uint_t		portnum;

	if (tgt == NULL) {
		SRPT_DPRINTF_L2("ioc_svc_unbind_all, NULL SCSI target port"
		    " specified");
		return;
	}
	for (portnum = 1; portnum <= tgt->tp_nports; portnum++) {
		srpt_ioc_svc_unbind(tgt, portnum);
	}
}

/*
 * srpt_ioc_get_locked()
 *
 * Requires srpt_ctxt->rw_lock be held outside of call.
 */
srpt_ioc_t *
srpt_ioc_get_locked(ib_guid_t guid)
{
	srpt_ioc_t	*ioc;

	ioc = list_head(&srpt_ctxt->sc_ioc_list);
	while (ioc != NULL) {
		if (ioc->ioc_guid == guid) {
			break;
		}
		ioc = list_next(&srpt_ctxt->sc_ioc_list, ioc);
	}
	return (ioc);
}

/*
 * srpt_ioc_get()
 */
srpt_ioc_t *
srpt_ioc_get(ib_guid_t guid)
{
	srpt_ioc_t	*ioc;

	rw_enter(&srpt_ctxt->sc_rwlock, RW_READER);
	ioc = srpt_ioc_get_locked(guid);
	rw_exit(&srpt_ctxt->sc_rwlock);
	return (ioc);
}

/*
 * srpt_ioc_post_recv_iu()
 */
ibt_status_t
srpt_ioc_post_recv_iu(srpt_ioc_t *ioc, srpt_iu_t *iu)
{
	ibt_status_t		status;
	ibt_recv_wr_t		wr;
	uint_t			posted;

	ASSERT(ioc != NULL);
	ASSERT(iu != NULL);

	wr.wr_id  = (ibt_wrid_t)(uintptr_t)iu;
	wr.wr_nds = 1;
	wr.wr_sgl = &iu->iu_sge;
	posted    = 0;

	status = ibt_post_srq(ioc->ioc_srq_hdl, &wr, 1, &posted);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("ioc_post_recv_iu, post error (%d)",
		    status);
	}
	return (status);
}

/*
 * srpt_ioc_repost_recv_iu()
 */
void
srpt_ioc_repost_recv_iu(srpt_ioc_t *ioc, srpt_iu_t *iu)
{
	srpt_channel_t		*ch;
	ibt_status_t		status;

	ASSERT(iu != NULL);
	ASSERT(mutex_owned(&iu->iu_lock));

	/*
	 * Some additional sanity checks while in debug state, all STMF
	 * related task activities should be complete prior to returning
	 * this IU to the available pool.
	 */
	ASSERT(iu->iu_stmf_task == NULL);
	ASSERT(iu->iu_sq_posted_cnt == 0);

	ch = iu->iu_ch;
	iu->iu_ch = NULL;
	iu->iu_num_rdescs = 0;
	iu->iu_rdescs = NULL;
	iu->iu_tot_xfer_len = 0;
	iu->iu_tag = 0;
	iu->iu_flags = 0;
	iu->iu_sq_posted_cnt = 0;

	status = srpt_ioc_post_recv_iu(ioc, iu);

	if (status != IBT_SUCCESS) {
		/*
		 * Very bad, we should initiate a shutdown of the I/O
		 * Controller here, off-lining any targets associated
		 * with this I/O Controller (and therefore disconnecting
		 * any logins that remain).
		 *
		 * In practice this should never happen so we put
		 * the code near the bottom of the implementation list.
		 */
		SRPT_DPRINTF_L0("ioc_repost_recv_iu, error RX IU (%d)",
		    status);
		ASSERT(0);
	} else if (ch != NULL) {
		atomic_inc_32(&ch->ch_req_lim_delta);
	}
}

/*
 * srpt_ioc_init_profile()
 *
 * SRP I/O Controller serialization lock must be held when this
 * routine is invoked.
 */
void
srpt_ioc_init_profile(srpt_ioc_t *ioc)
{
	srpt_ioc_opcap_mask_t		capmask = {0};

	ASSERT(ioc != NULL);

	ioc->ioc_profile.ioc_guid = h2b64(ioc->ioc_guid);
	(void) memcpy(ioc->ioc_profile.ioc_id_string,
	    "Solaris SRP Target 0.9a", 23);

	/*
	 * Note vendor ID and subsystem ID are 24 bit values.  Low order
	 * 8 bits in vendor ID field is slot and is initialized to zero.
	 * Low order 8 bits of subsystem ID is a reserved field and
	 * initialized to zero.
	 */
	ioc->ioc_profile.ioc_vendorid =
	    h2b32((uint32_t)(ioc->ioc_attr.hca_vendor_id << 8));
	ioc->ioc_profile.ioc_deviceid =
	    h2b32((uint32_t)ioc->ioc_attr.hca_device_id);
	ioc->ioc_profile.ioc_device_ver =
	    h2b16((uint16_t)ioc->ioc_attr.hca_version_id);
	ioc->ioc_profile.ioc_subsys_vendorid =
	    h2b32((uint32_t)(ioc->ioc_attr.hca_vendor_id << 8));
	ioc->ioc_profile.ioc_subsys_id = h2b32(0);
	ioc->ioc_profile.ioc_io_class = h2b16(SRP_REV_16A_IO_CLASS);
	ioc->ioc_profile.ioc_io_subclass = h2b16(SRP_IO_SUBCLASS);
	ioc->ioc_profile.ioc_protocol = h2b16(SRP_PROTOCOL);
	ioc->ioc_profile.ioc_protocol_ver = h2b16(SRP_PROTOCOL_VERSION);
	ioc->ioc_profile.ioc_send_msg_qdepth = h2b16(srpt_send_msg_depth);
	ioc->ioc_profile.ioc_rdma_read_qdepth =
	    ioc->ioc_attr.hca_max_rdma_out_chan;
	ioc->ioc_profile.ioc_send_msg_sz = h2b32(srpt_iu_size);
	ioc->ioc_profile.ioc_rdma_xfer_sz = h2b32(SRPT_DEFAULT_MAX_RDMA_SIZE);

	capmask.bits.st = 1;	/* Messages can be sent to IOC */
	capmask.bits.sf = 1;	/* Messages can be sent from IOC */
	capmask.bits.rf = 1;	/* RDMA Reads can be sent from IOC */
	capmask.bits.wf = 1;	/* RDMA Writes can be sent from IOC */
	ioc->ioc_profile.ioc_ctrl_opcap_mask = capmask.mask;

	/*
	 * We currently only have one target, but if we had a list we would
	 * go through that list and only count those that are ONLINE when
	 * setting the services count and entries.
	 */
	if (ioc->ioc_tgt_port->tp_srp_enabled) {
		ioc->ioc_profile.ioc_service_entries = 1;
		ioc->ioc_svc.srv_id = h2b64(ioc->ioc_guid);
		(void) snprintf((char *)ioc->ioc_svc.srv_name,
		    IB_DM_MAX_SVC_NAME_LEN, "SRP.T10:%016llx",
		    (u_longlong_t)ioc->ioc_guid);
	} else {
		ioc->ioc_profile.ioc_service_entries = 0;
		ioc->ioc_svc.srv_id = 0;
	}
}

/*
 * srpt_ioc_ds_alloc_dbuf()
 */
/* ARGSUSED */
stmf_data_buf_t *
srpt_ioc_ds_alloc_dbuf(struct scsi_task *task, uint32_t size,
	uint32_t *pminsize, uint32_t flags)
{
	srpt_iu_t		*iu;
	srpt_ioc_t		*ioc;
	srpt_ds_dbuf_t		*dbuf;
	stmf_data_buf_t		*stmf_dbuf;
	void			*buf;
	srpt_mr_t		mr;

	ASSERT(task != NULL);
	iu  = task->task_port_private;
	ioc = iu->iu_ioc;

	SRPT_DPRINTF_L4("ioc_ds_alloc_dbuf, invoked ioc(%p)"
	    " size(%d), flags(%x)",
	    (void *)ioc, size, flags);

	buf = srpt_vmem_alloc(ioc->ioc_dbuf_pool, size);
	if (buf == NULL) {
		return (NULL);
	}

	if (srpt_vmem_mr(ioc->ioc_dbuf_pool, buf, size, &mr) != 0) {
		goto stmf_alloc_err;
	}

	stmf_dbuf = stmf_alloc(STMF_STRUCT_DATA_BUF, sizeof (srpt_ds_dbuf_t),
	    0);
	if (stmf_dbuf == NULL) {
		SRPT_DPRINTF_L2("ioc_ds_alloc_dbuf, stmf_alloc failed");
		goto stmf_alloc_err;
	}

	dbuf = stmf_dbuf->db_port_private;
	dbuf->db_stmf_buf = stmf_dbuf;
	dbuf->db_mr_hdl = mr.mr_hdl;
	dbuf->db_ioc = ioc;
	dbuf->db_sge.ds_va = mr.mr_va;
	dbuf->db_sge.ds_key = mr.mr_lkey;
	dbuf->db_sge.ds_len = size;

	stmf_dbuf->db_buf_size = size;
	stmf_dbuf->db_data_size = size;
	stmf_dbuf->db_relative_offset = 0;
	stmf_dbuf->db_flags = 0;
	stmf_dbuf->db_xfer_status = 0;
	stmf_dbuf->db_sglist_length = 1;
	stmf_dbuf->db_sglist[0].seg_addr = buf;
	stmf_dbuf->db_sglist[0].seg_length = size;

	return (stmf_dbuf);

buf_mr_err:
	stmf_free(stmf_dbuf);

stmf_alloc_err:
	srpt_vmem_free(ioc->ioc_dbuf_pool, buf, size);

	return (NULL);
}

void
srpt_ioc_ds_free_dbuf(struct stmf_dbuf_store *ds,
	stmf_data_buf_t *dbuf)
{
	srpt_ioc_t	*ioc;

	SRPT_DPRINTF_L4("ioc_ds_free_dbuf, invoked buf (%p)",
	    (void *)dbuf);
	ioc = ds->ds_port_private;

	srpt_vmem_free(ioc->ioc_dbuf_pool, dbuf->db_sglist[0].seg_addr,
	    dbuf->db_buf_size);
	stmf_free(dbuf);
}

/* Memory arena routines */

static srpt_vmem_pool_t *
srpt_vmem_create(const char *name, srpt_ioc_t *ioc, ib_memlen_t chunksize,
    uint64_t maxsize, ibt_mr_flags_t flags)
{
	srpt_mr_t		*chunk;
	srpt_vmem_pool_t	*result;

	ASSERT(chunksize <= maxsize);

	result = kmem_zalloc(sizeof (srpt_vmem_pool_t), KM_SLEEP);

	result->svp_ioc = ioc;
	result->svp_chunksize = chunksize;
	result->svp_max_size = maxsize;
	result->svp_flags = flags;

	rw_init(&result->svp_lock, NULL, RW_DRIVER, NULL);
	avl_create(&result->svp_mr_list, srpt_vmem_mr_compare,
	    sizeof (srpt_mr_t), offsetof(srpt_mr_t, mr_avl));

	chunk = srpt_vmem_chunk_alloc(result, chunksize);

	avl_add(&result->svp_mr_list, chunk);
	result->svp_total_size = chunksize;

	result->svp_vmem = vmem_create(name,
	    (void*)(uintptr_t)chunk->mr_va,
	    (size_t)chunk->mr_len, SRPT_MR_QUANTSIZE,
	    NULL, NULL, NULL, 0, VM_SLEEP);

	return (result);
}

static void
srpt_vmem_destroy(srpt_vmem_pool_t *vm_pool)
{
	srpt_mr_t		*chunk;
	srpt_mr_t		*next;

	rw_enter(&vm_pool->svp_lock, RW_WRITER);
	vmem_destroy(vm_pool->svp_vmem);

	chunk = avl_first(&vm_pool->svp_mr_list);

	while (chunk != NULL) {
		next = AVL_NEXT(&vm_pool->svp_mr_list, chunk);
		avl_remove(&vm_pool->svp_mr_list, chunk);
		srpt_vmem_chunk_free(vm_pool, chunk);
		chunk = next;
	}

	avl_destroy(&vm_pool->svp_mr_list);

	rw_exit(&vm_pool->svp_lock);
	rw_destroy(&vm_pool->svp_lock);

	kmem_free(vm_pool, sizeof (srpt_vmem_pool_t));
}

static void *
srpt_vmem_alloc(srpt_vmem_pool_t *vm_pool, size_t size)
{
	void		*result;
	srpt_mr_t	*next;
	ib_memlen_t	chunklen;

	ASSERT(vm_pool != NULL);

	result = vmem_alloc(vm_pool->svp_vmem, size,
	    VM_NOSLEEP | VM_FIRSTFIT);

	if (result != NULL) {
		/* memory successfully allocated */
		return (result);
	}

	/* need more vmem */
	rw_enter(&vm_pool->svp_lock, RW_WRITER);
	chunklen = vm_pool->svp_chunksize;

	if (vm_pool->svp_total_size >= vm_pool->svp_max_size) {
		/* no more room to alloc */
		rw_exit(&vm_pool->svp_lock);
		return (NULL);
	}

	if ((vm_pool->svp_total_size + chunklen) > vm_pool->svp_max_size) {
		chunklen = vm_pool->svp_max_size - vm_pool->svp_total_size;
	}

	next = srpt_vmem_chunk_alloc(vm_pool, chunklen);
	if (next != NULL) {
		/*
		 * Note that the size of the chunk we got
		 * may not be the size we requested.  Use the
		 * length returned in the chunk itself.
		 */
		if (vmem_add(vm_pool->svp_vmem, (void*)(uintptr_t)next->mr_va,
		    next->mr_len, VM_NOSLEEP) == NULL) {
			srpt_vmem_chunk_free(vm_pool, next);
			SRPT_DPRINTF_L2("vmem_add failed");
		} else {
			vm_pool->svp_total_size += next->mr_len;
			avl_add(&vm_pool->svp_mr_list, next);
		}
	}

	rw_exit(&vm_pool->svp_lock);

	result = vmem_alloc(vm_pool->svp_vmem, size, VM_NOSLEEP | VM_FIRSTFIT);

	return (result);
}

static void
srpt_vmem_free(srpt_vmem_pool_t *vm_pool, void *vaddr, size_t size)
{
	vmem_free(vm_pool->svp_vmem, vaddr, size);
}

static int
srpt_vmem_mr(srpt_vmem_pool_t *vm_pool, void *vaddr, size_t size,
    srpt_mr_t *mr)
{
	avl_index_t		where;
	ib_vaddr_t		mrva = (ib_vaddr_t)(uintptr_t)vaddr;
	srpt_mr_t		chunk;
	srpt_mr_t		*nearest;
	ib_vaddr_t		chunk_end;
	int			status = DDI_FAILURE;

	rw_enter(&vm_pool->svp_lock, RW_READER);

	chunk.mr_va = mrva;
	nearest = avl_find(&vm_pool->svp_mr_list, &chunk, &where);

	if (nearest == NULL) {
		nearest = avl_nearest(&vm_pool->svp_mr_list, where,
		    AVL_BEFORE);
	}

	if (nearest != NULL) {
		/* Verify this chunk contains the specified address range */
		ASSERT(nearest->mr_va <= mrva);

		chunk_end = nearest->mr_va + nearest->mr_len;
		if (chunk_end >= mrva + size) {
			mr->mr_hdl = nearest->mr_hdl;
			mr->mr_va = mrva;
			mr->mr_len = size;
			mr->mr_lkey = nearest->mr_lkey;
			mr->mr_rkey = nearest->mr_rkey;
			status = DDI_SUCCESS;
		}
	}

	rw_exit(&vm_pool->svp_lock);
	return (status);
}

static srpt_mr_t *
srpt_vmem_chunk_alloc(srpt_vmem_pool_t *vm_pool, ib_memlen_t chunksize)
{
	void			*chunk = NULL;
	srpt_mr_t		*result = NULL;

	while ((chunk == NULL) && (chunksize >= SRPT_MIN_CHUNKSIZE)) {
		chunk = kmem_alloc(chunksize, KM_NOSLEEP);
		if (chunk == NULL) {
			SRPT_DPRINTF_L2("srpt_vmem_chunk_alloc: "
			    "failed to alloc chunk of %d, trying %d",
			    (int)chunksize, (int)chunksize/2);
			chunksize /= 2;
		}
	}

	if (chunk != NULL) {
		result = srpt_reg_mem(vm_pool, (ib_vaddr_t)(uintptr_t)chunk,
		    chunksize);
		if (result == NULL) {
			SRPT_DPRINTF_L2("srpt_vmem_chunk_alloc: "
			    "chunk registration failed");
			kmem_free(chunk, chunksize);
		}
	}

	return (result);
}

static void
srpt_vmem_chunk_free(srpt_vmem_pool_t *vm_pool, srpt_mr_t *mr)
{
	void			*chunk = (void *)(uintptr_t)mr->mr_va;
	ib_memlen_t		chunksize = mr->mr_len;

	srpt_dereg_mem(vm_pool->svp_ioc, mr);
	kmem_free(chunk, chunksize);
}

static srpt_mr_t *
srpt_reg_mem(srpt_vmem_pool_t *vm_pool, ib_vaddr_t vaddr, ib_memlen_t len)
{
	srpt_mr_t		*result = NULL;
	ibt_mr_attr_t		mr_attr;
	ibt_mr_desc_t		mr_desc;
	ibt_status_t		status;
	srpt_ioc_t		*ioc = vm_pool->svp_ioc;

	result = kmem_zalloc(sizeof (srpt_mr_t), KM_NOSLEEP);
	if (result == NULL) {
		SRPT_DPRINTF_L2("srpt_reg_mem: failed to allocate");
		return (NULL);
	}

	bzero(&mr_attr, sizeof (ibt_mr_attr_t));
	bzero(&mr_desc, sizeof (ibt_mr_desc_t));

	mr_attr.mr_vaddr = vaddr;
	mr_attr.mr_len = len;
	mr_attr.mr_as = NULL;
	mr_attr.mr_flags = vm_pool->svp_flags;

	status = ibt_register_mr(ioc->ioc_ibt_hdl, ioc->ioc_pd_hdl,
	    &mr_attr, &result->mr_hdl, &mr_desc);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("srpt_reg_mem: ibt_register_mr "
		    "failed %d", status);
		kmem_free(result, sizeof (srpt_mr_t));
		return (NULL);
	}

	result->mr_va = mr_attr.mr_vaddr;
	result->mr_len = mr_attr.mr_len;
	result->mr_lkey = mr_desc.md_lkey;
	result->mr_rkey = mr_desc.md_rkey;

	return (result);
}

static void
srpt_dereg_mem(srpt_ioc_t *ioc, srpt_mr_t *mr)
{
	ibt_status_t		status;

	status = ibt_deregister_mr(ioc->ioc_ibt_hdl, mr->mr_hdl);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("srpt_dereg_mem, error deregistering MR (%d)",
		    status);
	}
	kmem_free(mr, sizeof (srpt_mr_t));
}

static int
srpt_vmem_mr_compare(const void *a, const void *b)
{
	srpt_mr_t		*mr1 = (srpt_mr_t *)a;
	srpt_mr_t		*mr2 = (srpt_mr_t *)b;

	/* sort and match by virtual address */
	if (mr1->mr_va < mr2->mr_va) {
		return (-1);
	} else if (mr1->mr_va > mr2->mr_va) {
		return (1);
	}

	return (0);
}
