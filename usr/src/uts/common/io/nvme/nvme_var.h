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
 * Copyright 2016 The MathWorks, Inc. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2019 Unix Software Ltd.
 * Copyright 2026 Oxide Computer Company.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

#ifndef _NVME_VAR_H
#define	_NVME_VAR_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/blkdev.h>
#include <sys/taskq_impl.h>
#include <sys/list.h>
#include <sys/ddi_ufm.h>
#include <nvme_common.h>

/*
 * NVMe driver state
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	NVME_MODULE_NAME		"nvme"

typedef enum {
	NVME_PCI_CONFIG			= 1 << 0,
	NVME_FMA_INIT			= 1 << 1,
	NVME_REGS_MAPPED		= 1 << 2,
	NVME_ADMIN_QUEUE		= 1 << 3,
	NVME_CTRL_LIMITS		= 1 << 4,
	NVME_INTERRUPTS			= 1 << 5,
	NVME_UFM_INIT			= 1 << 6,
	NVME_MUTEX_INIT			= 1 << 7,
	NVME_MGMT_INIT			= 1 << 8,
	NVME_STAT_INIT			= 1 << 9,
	NVME_NS_INIT			= 1 << 10
} nvme_progress_t;

typedef enum {
	NVME_NS_LOCK	= 1 << 0,
	/*
	 * This flag indicates whether or not we've created a minor node for
	 * this namespace. We limit the number of minor nodes that we actually
	 * create in the file system due to minor node constraints. The
	 * controller minors are preferred to the namespace minors, so the lack
	 * of such a minor is considered a non-fatal condition. Minor nodes are
	 * removed all in one go right now when we detach, so this currently
	 * serves as an internal signifier.
	 */
	NVME_NS_MINOR	= 1 << 1
} nvme_ns_progress_t;

typedef enum {
	/*
	 * The controller fails to properly process commands on the admin queue
	 * if the first one has CID 0. Subsequent use of CID 0 doesn't present
	 * a problem.
	 */
	NVME_QUIRK_START_CID		= 1 << 0,
} nvme_quirk_t;

#define	NVME_MIN_ADMIN_QUEUE_LEN	16
#define	NVME_MIN_IO_QUEUE_LEN		16
#define	NVME_DEFAULT_ADMIN_QUEUE_LEN	256
#define	NVME_DEFAULT_IO_QUEUE_LEN	1024
#define	NVME_DEFAULT_ASYNC_EVENT_LIMIT	10
#define	NVME_MIN_ASYNC_EVENT_LIMIT	1
#define	NVME_DEFAULT_MIN_BLOCK_SIZE	512

typedef struct nvme nvme_t;
typedef struct nvme_namespace nvme_namespace_t;
typedef struct nvme_minor nvme_minor_t;
typedef struct nvme_lock nvme_lock_t;
typedef struct nvme_minor_lock_info nvme_minor_lock_info_t;
typedef struct nvme_dma nvme_dma_t;
typedef struct nvme_cmd nvme_cmd_t;
typedef struct nvme_cq nvme_cq_t;
typedef struct nvme_qpair nvme_qpair_t;
typedef struct nvme_task_arg nvme_task_arg_t;
typedef struct nvme_device_stat nvme_device_stat_t;
typedef struct nvme_admin_stat nvme_admin_stat_t;

/*
 * These states represent the minor's perspective. That is, of a minor's
 * namespace and controller lock, where is it?
 */
typedef enum {
	NVME_LOCK_STATE_UNLOCKED	= 0,
	NVME_LOCK_STATE_BLOCKED,
	NVME_LOCK_STATE_ACQUIRED
} nvme_minor_lock_state_t;

struct nvme_minor_lock_info {
	list_node_t nli_node;
	nvme_lock_t *nli_lock;
	nvme_minor_lock_state_t nli_state;
	nvme_lock_level_t nli_curlevel;
	/*
	 * While the minor points back to itself and the nvme_t should always
	 * point to the current controller, the namespace should only point to
	 * one if this is a particular namespace lock. The former two are
	 * initialized at minor initialization time.
	 */
	nvme_minor_t *nli_minor;
	nvme_t *nli_nvme;
	nvme_namespace_t *nli_ns;
	/*
	 * This is the common ioctl information that should be filled in when
	 * we're being woken up for any reason other than an interrupted signal.
	 * This should only be set while blocking.
	 */
	nvme_ioctl_common_t *nli_ioc;
	/*
	 * The following are provided for debugging purposes. In particular,
	 * information like the kthread_t and related that performed this should
	 * be considered suspect as it represents who took the operation, not
	 * who performed the operation (unless we're actively blocking).
	 */
	hrtime_t nli_last_change;
	uintptr_t nli_acq_kthread;
	pid_t nli_acq_pid;
};

struct nvme_minor {
	/*
	 * The following three fields are set when this is created.
	 */
	id_t nm_minor;
	nvme_t *nm_ctrl;
	nvme_namespace_t *nm_ns;
	/*
	 * This link is used to index this minor on the global list of active
	 * open-related minors. This is only manipulated under the
	 * nvme_open_minors_mutex.
	 */
	avl_node_t nm_avl;
	/*
	 * Information related to locking. Note, there is no pointer to a locked
	 * controller as the only one can be the one specified here. This data
	 * is protected by the controller's n_minor_mutex.
	 */
	kcondvar_t nm_cv;
	nvme_minor_lock_info_t nm_ctrl_lock;
	nvme_minor_lock_info_t nm_ns_lock;
};

struct nvme_lock {
	nvme_minor_lock_info_t *nl_writer;
	list_t nl_readers;
	list_t nl_pend_readers;
	list_t nl_pend_writers;
	/*
	 * The following are stats to indicate how often certain locking
	 * activities have occurred for debugging purposes.
	 */
	uint32_t nl_nwrite_locks;
	uint32_t nl_nread_locks;
	uint32_t nl_npend_writes;
	uint32_t nl_npend_reads;
	uint32_t nl_nnonblock;
	uint32_t nl_nsignals;
	uint32_t nl_nsig_unlock;
	uint32_t nl_nsig_blocks;
	uint32_t nl_nsig_acq;
};

struct nvme_dma {
	ddi_dma_handle_t nd_dmah;
	ddi_acc_handle_t nd_acch;
	ddi_dma_cookie_t nd_cookie;
	uint_t nd_ncookie;
	caddr_t nd_memp;
	size_t nd_len;
	boolean_t nd_cached;
};

typedef enum {
	NVME_CMD_ALLOCATED = 0,
	NVME_CMD_SUBMITTED,
	NVME_CMD_QUEUED,
	NVME_CMD_COMPLETED,
	NVME_CMD_LOST
} nvme_cmd_state_t;

typedef enum {
	NVME_CMD_F_DONTPANIC	= 1 << 0,
	NVME_CMD_F_USELOCK	= 1 << 1,
} nvme_cmd_flag_t;

/*
 * This command structure is shared between admin and I/O commands. When used
 * for an admin command, nc_mutex and nc_cv are used to synchronise access to
 * various fields, and to signal command completion. NVME_CMD_F_USELOCK in
 * nc_flags indicates whether the lock and CV are in use. For I/O commands,
 * these are neither initialised nor used.
 */
struct nvme_cmd {
	struct list_node nc_list;

	nvme_sqe_t nc_sqe;
	nvme_cqe_t nc_cqe;

	void (*nc_callback)(void *);
	bd_xfer_t *nc_xfer;

	uint32_t nc_timeout;
	nvme_cmd_flag_t nc_flags;
	nvme_cmd_state_t nc_state; /* Protected by nc_mutex iff F_USELOCK */
	uint16_t nc_sqid;

	hrtime_t nc_submit_ts;
	hrtime_t nc_queue_ts;

	nvme_dma_t *nc_dma;
	nvme_dma_t *nc_prp; /* DMA for PRP lists */

	kmutex_t nc_mutex;
	kcondvar_t nc_cv;

	taskq_ent_t nc_tqent;
	nvme_t *nc_nvme;
};

struct nvme_cq {
	size_t ncq_nentry;
	uint16_t ncq_id;

	nvme_dma_t *ncq_dma;
	nvme_cqe_t *ncq_cq;
	uint_t ncq_head;
	uintptr_t ncq_hdbl;
	int ncq_phase;

	taskq_t *ncq_cmd_taskq;

	kmutex_t ncq_mutex;
};

struct nvme_qpair {
	size_t nq_nentry;

	/* submission fields */
	nvme_dma_t *nq_sqdma;
	nvme_sqe_t *nq_sq;
	uint_t nq_sqhead;
	uint_t nq_sqtail;
	uintptr_t nq_sqtdbl;

	/* completion */
	nvme_cq_t *nq_cq;

	/* shared structures for completion and submission */
	nvme_cmd_t **nq_cmd;	/* active command array */
	uint16_t nq_next_cmd;	/* next potential empty queue slot */
	uint_t nq_active_cmds;	/* number of active cmds */
	uint32_t nq_active_timeout; /* sum of the timeouts of active cmds */

	kmutex_t nq_mutex;	/* protects shared state */
	ksema_t nq_sema; /* semaphore to ensure q always has >= 1 empty slot */
};

typedef struct nvme_mgmt_lock {
	kmutex_t nml_lock;
	kcondvar_t nml_cv;
	uintptr_t nml_bd_own;
} nvme_mgmt_lock_t;

struct nvme_device_stat {
	/* Errors detected by driver */
	kstat_named_t nds_dma_bind_err;
	kstat_named_t nds_abort_timeout;
	kstat_named_t nds_abort_failed;
	kstat_named_t nds_abort_successful;
	kstat_named_t nds_abort_unsuccessful;
	kstat_named_t nds_cmd_timeout;
	kstat_named_t nds_wrong_logpage;
	kstat_named_t nds_unknown_logpage;
	kstat_named_t nds_too_many_cookies;
	kstat_named_t nds_unknown_cid;

	/* Errors detected by hardware */
	kstat_named_t nds_inv_cmd_err;
	kstat_named_t nds_inv_field_err;
	kstat_named_t nds_inv_nsfmt_err;
	kstat_named_t nds_data_xfr_err;
	kstat_named_t nds_internal_err;
	kstat_named_t nds_abort_rq_err;
	kstat_named_t nds_abort_pwrloss_err;
	kstat_named_t nds_abort_sq_del;
	kstat_named_t nds_nvm_cap_exc;
	kstat_named_t nds_nvm_ns_notrdy;
	kstat_named_t nds_nvm_ns_formatting;
	kstat_named_t nds_inv_cq_err;
	kstat_named_t nds_inv_qid_err;
	kstat_named_t nds_max_qsz_exc;
	kstat_named_t nds_inv_int_vect;
	kstat_named_t nds_inv_log_page;
	kstat_named_t nds_inv_format;
	kstat_named_t nds_inv_q_del;
	kstat_named_t nds_cnfl_attr;
	kstat_named_t nds_inv_prot;
	kstat_named_t nds_readonly;
	kstat_named_t nds_inv_fwslot;
	kstat_named_t nds_inv_fwimg;
	kstat_named_t nds_fwact_creset;
	kstat_named_t nds_fwact_nssr;
	kstat_named_t nds_fwact_reset;
	kstat_named_t nds_fwact_mtfa;
	kstat_named_t nds_fwact_prohibited;
	kstat_named_t nds_fw_overlap;
	kstat_named_t nds_inv_cmdseq_err;
	kstat_named_t nds_ns_attached;
	kstat_named_t nds_ns_priv;
	kstat_named_t nds_ns_not_attached;
	kstat_named_t nds_inc_ctrl_list;
	kstat_named_t nds_ana_attach;
	kstat_named_t nds_ns_attach_lim;

	/* Errors reported by asynchronous events */
	kstat_named_t nds_diagfail_event;
	kstat_named_t nds_persistent_event;
	kstat_named_t nds_transient_event;
	kstat_named_t nds_fw_load_event;
	kstat_named_t nds_reliability_event;
	kstat_named_t nds_temperature_event;
	kstat_named_t nds_spare_event;
	kstat_named_t nds_vendor_event;
	kstat_named_t nds_notice_event;
	kstat_named_t nds_unknown_event;
};

#define	NAS_CNT 0
#define	NAS_AVG 1
#define	NAS_MAX 2
struct nvme_admin_stat {
	kstat_named_t nas_getlogpage[3];
	kstat_named_t nas_identify[3];
	kstat_named_t nas_abort[3];
	kstat_named_t nas_fwactivate[3];
	kstat_named_t nas_fwimgload[3];
	kstat_named_t nas_nsformat[3];
	kstat_named_t nas_vendor[3];
	kstat_named_t nas_other[3];
};

struct nvme {
	dev_info_t *n_dip;
	nvme_progress_t n_progress;
	nvme_quirk_t n_quirks;

	caddr_t n_regs;
	ddi_acc_handle_t n_regh;

	kmem_cache_t *n_cmd_cache;
	kmem_cache_t *n_prp_cache;

	size_t n_inth_sz;
	ddi_intr_handle_t *n_inth;
	int n_intr_cnt;
	uint_t n_intr_pri;
	int n_intr_cap;
	int n_intr_type;
	int n_intr_types;

	ddi_acc_handle_t n_pcicfg_handle;
	uint16_t n_vendor_id;
	uint16_t n_device_id;
	uint16_t n_subsystem_vendor_id;
	uint16_t n_subsystem_device_id;
	uint8_t n_revision_id;

	char *n_product;
	char *n_vendor;

	nvme_version_t n_version;
	boolean_t n_dead;
	nvme_ioctl_errno_t n_dead_status;
	taskq_ent_t n_dead_tqent;
	boolean_t n_strict_version;
	boolean_t n_ignore_unknown_vendor_status;
	uint32_t n_admin_queue_len;
	uint32_t n_io_squeue_len;
	uint32_t n_io_cqueue_len;
	uint16_t n_async_event_limit;
	uint_t n_min_block_size;
	uint16_t n_abort_command_limit;
	uint64_t n_max_data_transfer_size;
	boolean_t n_write_cache_present;
	boolean_t n_write_cache_enabled;
	int n_error_log_len;
	boolean_t n_async_event_supported;
	int n_submission_queues_supported;
	int n_completion_queues_supported;
	int n_submission_queues;
	int n_completion_queues;

	int n_nssr_supported;
	int n_doorbell_stride;
	int n_timeout;
	int n_arbitration_mechanisms;
	int n_cont_queues_reqd;
	int n_max_queue_entries;
	int n_pageshift;
	int n_pagesize;

	uint32_t n_namespace_count;
	uint_t n_namespaces_attachable;
	uint_t n_ioq_count;
	uint_t n_cq_count;

	/*
	 * This is cached identify controller and common namespace data that
	 * exists in the system. This generally can be used in the kernel;
	 * however, we have to be careful about what we use here because these
	 * values are not refreshed after attach. Therefore these are good for
	 * answering the question what does the controller support or what is in
	 * the common namespace information, but not otherwise. That means you
	 * shouldn't use this to try to answer how much capacity is still in the
	 * controller because this information is just cached.
	 */
	nvme_identify_ctrl_t *n_idctl;
	nvme_identify_nsid_t *n_idcomns;

	/* Pointer to the admin queue, which is always queue 0 in n_ioq. */
	nvme_qpair_t *n_adminq;
	/*
	 * All command queues, including the admin queue.
	 * Its length is: n_ioq_count + 1.
	 */
	nvme_qpair_t **n_ioq;
	nvme_cq_t **n_cq;

	nvme_namespace_t *n_ns;

	ddi_dma_attr_t n_queue_dma_attr;
	ddi_dma_attr_t n_prp_dma_attr;
	ddi_dma_attr_t n_sgl_dma_attr;
	ddi_device_acc_attr_t n_reg_acc_attr;
	ddi_iblock_cookie_t n_fm_ibc;
	int n_fm_cap;

	ksema_t n_abort_sema;

	/* protects namespace management operations */
	nvme_mgmt_lock_t n_mgmt;

	/*
	 * This lock protects the minor node locking state across the controller
	 * and all related namespaces.
	 */
	kmutex_t n_minor_mutex;
	nvme_lock_t n_lock;

	kstat_t *n_device_kstat;
	nvme_device_stat_t n_device_stat;

	kstat_t *n_admin_kstat;
	kmutex_t n_admin_stat_mutex;
	nvme_admin_stat_t n_admin_stat;

	/* hot removal NDI event handling */
	ddi_eventcookie_t n_rm_cookie;
	ddi_callback_id_t n_ev_rm_cb_id;

	/* DDI UFM handle */
	ddi_ufm_handle_t *n_ufmh;
	/* Cached Firmware Slot Information log page */
	nvme_fwslot_log_t *n_fwslot;
	/* Lock protecting the cached firmware slot info */
	kmutex_t n_fwslot_mutex;
};

struct nvme_namespace {
	nvme_t *ns_nvme;
	nvme_ns_progress_t ns_progress;
	uint8_t ns_eui64[8];
	uint8_t	ns_nguid[16];
	char	ns_name[11];

	bd_handle_t ns_bd_hdl;

	uint32_t ns_id;
	size_t ns_block_count;
	size_t ns_block_size;
	size_t ns_best_block_size;
	nvme_ns_state_t ns_state;

	nvme_identify_nsid_t *ns_idns;

	/*
	 * Namespace lock, see the theory statement for more information.
	 */
	nvme_lock_t ns_lock;

	/*
	 * If a namespace has neither NGUID nor EUI64, we create a devid in
	 * nvme_prepare_devid().
	 */
	char *ns_devid;
};

struct nvme_task_arg {
	nvme_t *nt_nvme;
	nvme_cmd_t *nt_cmd;
};

typedef enum {
	/*
	 * This indicates that there is no exclusive access required for this
	 * operation. However, this operation will fail if someone attempts to
	 * perform this operation and someone else holds a write lock.
	 */
	NVME_IOCTL_EXCL_NONE	= 0,
	/*
	 * This indicates that a write lock is required to perform the
	 * operation.
	 */
	NVME_IOCTL_EXCL_WRITE,
	/*
	 * This indicates that a write lock over the controller is required to
	 * perform the operation. An example of this is creating a namespace
	 * because it operates on the controller as a whole.
	 */
	NVME_IOCTL_EXCL_CTRL,
	/*
	 * This indicates that the exclusive check should be skipped. The only
	 * case this should be used in is the lock and unlock ioctls as they
	 * should be able to proceed even when the controller is being used
	 * exclusively.
	 */
	NVME_IOCTL_EXCL_SKIP
} nvme_ioctl_excl_t;

/*
 * This structure represents the set of checks that we apply to ioctl's using
 * the nvme_ioctl_common_t structure as part of validation.
 */
typedef struct nvme_ioctl_check {
	/*
	 * This indicates whether or not the command in question allows a
	 * namespace to be specified at all. If this is false, a namespace minor
	 * cannot be used and a controller minor must leave the nsid set to
	 * zero.
	 */
	boolean_t nck_ns_ok;
	/*
	 * This indicates that a minor node corresponding to a namespace is
	 * allowed to issue this.
	 */
	boolean_t nck_ns_minor_ok;
	/*
	 * This indicates that the controller should be skipped from all of the
	 * following processing behavior. That is, it's allowed to specify
	 * whatever it wants in the nsid field, regardless if it is valid or
	 * not. This is required for some of the Identify Command options that
	 * list endpoints. This should generally not be used and the driver
	 * should still validate the nuance here.
	 */
	boolean_t nck_skip_ctrl;
	/*
	 * This indicates that if we're on the controller's minor and we don't
	 * have an explicit namespace ID (i.e. 0), should the namespace be
	 * rewritten to be the broadcast namespace.
	 */
	boolean_t nck_ctrl_rewrite;
	/*
	 * This indicates whether or not the broadcast NSID is acceptable for
	 * the controller node.
	 */
	boolean_t nck_bcast_ok;

	/*
	 * This indicates to the lock checking code what kind of exclusive
	 * access is required. This check occurs after any namespace rewriting
	 * has occurred. When looking at exclusivity, a broadcast namespace or
	 * namespace 0 indicate that the controller is the target, otherwise the
	 * target namespace will be checked for a write lock.
	 */
	nvme_ioctl_excl_t nck_excl;
} nvme_ioctl_check_t;

/*
 * Constants
 */
extern uint_t nvme_vendor_specific_admin_cmd_max_timeout;
extern uint32_t nvme_vendor_specific_admin_cmd_size;

/*
 * Common functions.
 */
extern nvme_namespace_t *nvme_nsid2ns(nvme_t *, uint32_t);
extern boolean_t nvme_ioctl_error(nvme_ioctl_common_t *, nvme_ioctl_errno_t,
    uint32_t, uint32_t);
extern boolean_t nvme_ctrl_atleast(nvme_t *, const nvme_version_t *);
extern void nvme_ioctl_success(nvme_ioctl_common_t *);

/*
 * Validation related functions and kernel tunable limits.
 */
extern boolean_t nvme_validate_logpage(nvme_t *, nvme_ioctl_get_logpage_t *);
extern boolean_t nvme_validate_identify(nvme_t *, nvme_ioctl_identify_t *,
    boolean_t);
extern boolean_t nvme_validate_get_feature(nvme_t *,
    nvme_ioctl_get_feature_t *);
extern boolean_t nvme_validate_vuc(nvme_t *, nvme_ioctl_passthru_t *);
extern boolean_t nvme_validate_format(nvme_t *, nvme_ioctl_format_t *);
extern boolean_t nvme_validate_fw_load(nvme_t *, nvme_ioctl_fw_load_t *);
extern boolean_t nvme_validate_fw_commit(nvme_t *, nvme_ioctl_fw_commit_t *);
extern boolean_t nvme_validate_ctrl_attach_detach_ns(nvme_t *,
    nvme_ioctl_common_t *);
extern boolean_t nvme_validate_ns_delete(nvme_t *, nvme_ioctl_common_t *);
extern boolean_t nvme_validate_ns_create(nvme_t *, nvme_ioctl_ns_create_t *);

/*
 * Locking functions
 */
extern void nvme_rwlock(nvme_minor_t *, nvme_ioctl_lock_t *);
extern void nvme_rwunlock(nvme_minor_lock_info_t *, nvme_lock_t *);
extern void nvme_rwlock_ctrl_dead(void *);
extern void nvme_lock_init(nvme_lock_t *);
extern void nvme_lock_fini(nvme_lock_t *);

/*
 * Statistics functions
 */
extern boolean_t nvme_stat_init(nvme_t *);
extern void nvme_stat_cleanup(nvme_t *);
extern void nvme_admin_stat_cmd(nvme_t *, nvme_cmd_t *);

#ifdef __cplusplus
}
#endif

#endif /* _NVME_VAR_H */
