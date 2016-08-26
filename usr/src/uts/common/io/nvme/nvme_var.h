/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef _NVME_VAR_H
#define	_NVME_VAR_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/blkdev.h>
#include <sys/taskq_impl.h>

/*
 * NVMe driver state
 */

#ifdef __cplusplus
/* extern "C" { */
#endif

#define	NVME_FMA_INIT			0x1
#define	NVME_REGS_MAPPED 		0x2
#define	NVME_ADMIN_QUEUE 		0x4
#define	NVME_CTRL_LIMITS 		0x8
#define	NVME_INTERRUPTS  		0x10

#define	NVME_MIN_ADMIN_QUEUE_LEN	16
#define	NVME_MIN_IO_QUEUE_LEN		16
#define	NVME_DEFAULT_ADMIN_QUEUE_LEN	256
#define	NVME_DEFAULT_IO_QUEUE_LEN	1024
#define	NVME_DEFAULT_ASYNC_EVENT_LIMIT	10
#define	NVME_MIN_ASYNC_EVENT_LIMIT	1


typedef struct nvme nvme_t;
typedef struct nvme_namespace nvme_namespace_t;
typedef struct nvme_dma nvme_dma_t;
typedef struct nvme_cmd nvme_cmd_t;
typedef struct nvme_qpair nvme_qpair_t;
typedef struct nvme_task_arg nvme_task_arg_t;

struct nvme_dma {
	ddi_dma_handle_t nd_dmah;
	ddi_acc_handle_t nd_acch;
	ddi_dma_cookie_t nd_cookie;
	uint_t nd_ncookie;
	caddr_t nd_memp;
	size_t nd_len;
};

struct nvme_cmd {
	nvme_sqe_t nc_sqe;
	nvme_cqe_t nc_cqe;

	void (*nc_callback)(void *);
	bd_xfer_t *nc_xfer;
	boolean_t nc_completed;
	uint16_t nc_sqid;

	nvme_dma_t *nc_dma;

	kmutex_t nc_mutex;
	kcondvar_t nc_cv;

	taskq_ent_t nc_tqent;
	nvme_t *nc_nvme;
};

struct nvme_qpair {
	size_t nq_nentry;

	nvme_dma_t *nq_sqdma;
	nvme_sqe_t *nq_sq;
	uint_t nq_sqhead;
	uint_t nq_sqtail;
	uintptr_t nq_sqtdbl;

	nvme_dma_t *nq_cqdma;
	nvme_cqe_t *nq_cq;
	uint_t nq_cqhead;
	uint_t nq_cqtail;
	uintptr_t nq_cqhdbl;

	nvme_cmd_t **nq_cmd;
	uint16_t nq_next_cmd;
	uint_t nq_active_cmds;
	int nq_phase;

	kmutex_t nq_mutex;
};

struct nvme {
	dev_info_t *n_dip;
	int n_progress;

	caddr_t n_regs;
	ddi_acc_handle_t n_regh;

	kmem_cache_t *n_cmd_cache;

	size_t n_inth_sz;
	ddi_intr_handle_t *n_inth;
	int n_intr_cnt;
	uint_t n_intr_pri;
	int n_intr_cap;
	int n_intr_type;
	int n_intr_types;

	char *n_product;
	char *n_vendor;

	boolean_t n_dead;
	boolean_t n_strict_version;
	boolean_t n_ignore_unknown_vendor_status;
	uint32_t n_admin_queue_len;
	uint32_t n_io_queue_len;
	uint16_t n_async_event_limit;
	uint16_t n_abort_command_limit;
	uint64_t n_max_data_transfer_size;
	boolean_t n_volatile_write_cache_enabled;
	int n_error_log_len;

	int n_nssr_supported;
	int n_doorbell_stride;
	int n_timeout;
	int n_arbitration_mechanisms;
	int n_cont_queues_reqd;
	int n_max_queue_entries;
	int n_pageshift;
	int n_pagesize;

	int n_namespace_count;
	int n_ioq_count;

	nvme_identify_ctrl_t *n_idctl;

	nvme_qpair_t *n_adminq;
	nvme_qpair_t **n_ioq;

	nvme_namespace_t *n_ns;

	ddi_dma_attr_t n_queue_dma_attr;
	ddi_dma_attr_t n_prp_dma_attr;
	ddi_dma_attr_t n_sgl_dma_attr;
	ddi_device_acc_attr_t n_reg_acc_attr;
	ddi_iblock_cookie_t n_fm_ibc;
	int n_fm_cap;

	ksema_t n_abort_sema;

	ddi_taskq_t *n_cmd_taskq;

	nvme_error_log_entry_t *n_error_log;
	nvme_health_log_t *n_health_log;
	nvme_fwslot_log_t *n_fwslot_log;

	/* errors detected by driver */
	uint32_t n_dma_bind_err;
	uint32_t n_abort_failed;
	uint32_t n_cmd_timeout;
	uint32_t n_cmd_aborted;
	uint32_t n_async_resubmit_failed;
	uint32_t n_wrong_logpage;
	uint32_t n_unknown_logpage;
	uint32_t n_too_many_cookies;
	uint32_t n_admin_queue_full;

	/* errors detected by hardware */
	uint32_t n_data_xfr_err;
	uint32_t n_internal_err;
	uint32_t n_abort_rq_err;
	uint32_t n_abort_sq_del;
	uint32_t n_nvm_cap_exc;
	uint32_t n_nvm_ns_notrdy;
	uint32_t n_inv_cq_err;
	uint32_t n_inv_qid_err;
	uint32_t n_max_qsz_exc;
	uint32_t n_inv_int_vect;
	uint32_t n_inv_log_page;
	uint32_t n_inv_format;
	uint32_t n_inv_q_del;
	uint32_t n_cnfl_attr;
	uint32_t n_inv_prot;
	uint32_t n_readonly;

	/* errors reported by asynchronous events */
	uint32_t n_diagfail_event;
	uint32_t n_persistent_event;
	uint32_t n_transient_event;
	uint32_t n_fw_load_event;
	uint32_t n_reliability_event;
	uint32_t n_temperature_event;
	uint32_t n_spare_event;
	uint32_t n_vendor_event;
	uint32_t n_unknown_event;

};

struct nvme_namespace {
	nvme_t *ns_nvme;
	bd_handle_t ns_bd_hdl;

	uint32_t ns_id;
	size_t ns_block_count;
	size_t ns_block_size;
	size_t ns_best_block_size;

	boolean_t ns_ignore;

	nvme_identify_nsid_t *ns_idns;

	/*
	 * Section 7.7 of the spec describes how to get a unique ID for
	 * the controller: the vendor ID, the model name and the serial
	 * number shall be unique when combined.
	 *
	 * We add the hex namespace ID to get a unique ID for the namespace.
	 */
	char ns_devid[4 + 1 + 20 + 1 + 40 + 1 + 8 + 1];
};

struct nvme_task_arg {
	nvme_t *nt_nvme;
	nvme_cmd_t *nt_cmd;
};

#ifdef __cplusplus
/* } */
#endif

#endif /* _NVME_VAR_H */
