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
 * Copyright 2023 Racktop Systems, Inc.
 */
#ifndef _LMRC_H
#define	_LMRC_H

#include <sys/list.h>
#include <sys/types.h>

#include <sys/scsi/scsi.h>
#include <sys/taskq_impl.h>

#if !defined(_LITTLE_ENDIAN) || !defined(_BIT_FIELDS_LTOH)
#error "lmrc only works on little endian systems"
#endif

typedef enum lmrc_adapter_class	lmrc_adapter_class_t;
typedef enum lmrc_init_level	lmrc_init_level_t;
typedef struct lmrc_dma		lmrc_dma_t;
typedef struct lmrc_mpt_cmd	lmrc_mpt_cmd_t;
typedef struct lmrc_mfi_cmd	lmrc_mfi_cmd_t;
typedef struct lmrc_scsa_cmd	lmrc_scsa_cmd_t;
typedef struct lmrc_pd		lmrc_pd_t;
typedef struct lmrc_tgt		lmrc_tgt_t;
typedef struct lmrc		lmrc_t;

#include "lmrc_reg.h"
#include "lmrc_phys.h"

extern void *lmrc_state;

enum lmrc_adapter_class {
	LMRC_ACLASS_OTHER,
	LMRC_ACLASS_GEN3,
	LMRC_ACLASS_VENTURA,
	LMRC_ACLASS_AERO,
};

/* iports for RAID and physical targets */
#define	LMRC_IPORT_RAID		"v0"
#define	LMRC_IPORT_PHYS		"p0"

/* in seconds */
#define	LMRC_IO_TIMEOUT				10
#define	LMRC_RESET_TIMEOUT			180
#define	LMRC_RESET_WAIT_TIME			3
#define	LMRC_INTERNAL_CMD_WAIT_TIME		180

#define	LMRC_MAX_RESET_TRIES			3

enum lmrc_init_level {
	LMRC_INITLEVEL_BASIC =		(1 << 0),
	LMRC_INITLEVEL_THREAD =		(1 << 1),
	LMRC_INITLEVEL_FM =		(1 << 2),
	LMRC_INITLEVEL_REGS =		(1 << 3),
	LMRC_INITLEVEL_INTR =		(1 << 4),
	LMRC_INITLEVEL_SYNC =		(1 << 5),
	LMRC_INITLEVEL_HBA =		(1 << 6),
	LMRC_INITLEVEL_NODE =		(1 << 7),
	LMRC_INITLEVEL_TASKQ =		(1 << 8),
	LMRC_INITLEVEL_AEN =		(1 << 9),
	LMRC_INITLEVEL_MFICMDS =	(1 << 10),
	LMRC_INITLEVEL_MPTCMDS =	(1 << 11),
	LMRC_INITLEVEL_FW =		(1 << 12),
};

#define	INITLEVEL_SET(_lmrc, name)				\
	do {							\
		VERIFY(!((_lmrc)->l_init_level & (name)));	\
		(_lmrc)->l_init_level |= (name);		\
	} while (0)

#define	INITLEVEL_CLEAR(_lmrc, name)				\
	do {							\
		VERIFY((_lmrc)->l_init_level & (name));	\
		(_lmrc)->l_init_level &= ~(name);		\
	} while (0)

#define	INITLEVEL_ACTIVE(_lmrc, name)				\
	(((_lmrc)->l_init_level & (name)) != 0)

struct lmrc_dma {
	ddi_dma_handle_t	ld_hdl;
	ddi_acc_handle_t	ld_acc;
	void			*ld_buf;
	size_t			ld_len;
};

typedef	void (lmrc_mpt_cmd_cb_t)(lmrc_t *, lmrc_mpt_cmd_t *);

struct lmrc_mpt_cmd {
	list_node_t		mpt_node;
	lmrc_dma_t		mpt_chain_dma;
	lmrc_dma_t		mpt_sense_dma;
	uint16_t		mpt_smid;
	uint16_t		mpt_queue;

	lmrc_mfi_cmd_t		*mpt_mfi;
	struct scsi_pkt		*mpt_pkt;

	void			*mpt_io_frame;
	Mpi25IeeeSgeChain64_t	*mpt_chain;
	uint8_t			*mpt_sense;

	kmutex_t		mpt_lock;
	kcondvar_t		mpt_cv;
	boolean_t		mpt_complete;
	hrtime_t		mpt_timeout;

	taskq_ent_t		mpt_tqent;

	lmrc_t			*mpt_lmrc;
};

typedef	void (lmrc_mfi_cmd_cb_t)(lmrc_t *, lmrc_mfi_cmd_t *);

struct lmrc_mfi_cmd {
	list_node_t		mfi_node;
	lmrc_dma_t		mfi_frame_dma;

	lmrc_mfi_frame_t	*mfi_frame;
	uint32_t		mfi_idx;
	uint16_t		mfi_smid;

	kmutex_t		mfi_lock;
	kcondvar_t		mfi_cv;
	lmrc_dma_t		mfi_data_dma;

	lmrc_mfi_cmd_cb_t	*mfi_callback;
	taskq_ent_t		mfi_tqent;
	lmrc_mpt_cmd_t		*mfi_mpt;

	lmrc_t			*mfi_lmrc;
};

struct lmrc_scsa_cmd {
	lmrc_mpt_cmd_t		*sc_mpt;
	lmrc_tgt_t		*sc_tgt;
};

struct lmrc_tgt {
	krwlock_t		tgt_lock;
	kmutex_t		tgt_mpt_active_lock;
	list_t			tgt_mpt_active;
	lmrc_t			*tgt_lmrc;
	uint16_t		tgt_dev_id;
	uint8_t			tgt_type;
	uint8_t			tgt_interconnect_type;
	uint64_t		tgt_wwn;
	lmrc_pd_info_t		*tgt_pd_info;
	char			tgt_wwnstr[SCSI_WWN_BUFLEN];
};

struct lmrc {
	dev_info_t		*l_dip;
	dev_info_t		*l_raid_dip;
	dev_info_t		*l_phys_dip;

	char			l_iocname[16];

	lmrc_init_level_t	l_init_level;
	lmrc_adapter_class_t	l_class;

	kmutex_t		l_mpt_cmd_lock;
	list_t			l_mpt_cmd_list;
	lmrc_mpt_cmd_t		**l_mpt_cmds;

	kmutex_t		l_mfi_cmd_lock;
	list_t			l_mfi_cmd_list;
	lmrc_mfi_cmd_t		**l_mfi_cmds;

	lmrc_dma_t		l_ioreq_dma;
	lmrc_dma_t		l_reply_dma;

	ksema_t			l_ioctl_sema;

	kthread_t		*l_thread;
	kmutex_t		l_thread_lock;
	kcondvar_t		l_thread_cv;
	boolean_t		l_thread_stop;

	lmrc_ctrl_info_t	*l_ctrl_info;

	ddi_intr_handle_t	*l_intr_htable;
	size_t			l_intr_htable_size;
	int			l_intr_types;
	int			l_intr_type;
	int			l_intr_count;
	uint_t			l_intr_pri;
	int			l_intr_cap;

	uint16_t		*l_last_reply_idx;
	uint32_t		l_rphi[LMRC_MAX_REPLY_POST_HOST_INDEX];

	int			l_fm_capabilities;

	/* Controller HW/FW properties */
	boolean_t		l_disable_online_ctrl_reset;
	boolean_t		l_fw_fault;
	boolean_t		l_fw_msix_enabled;
	boolean_t		l_fw_sync_cache_support;
	size_t			l_fw_supported_vd_count;
	size_t			l_fw_supported_pd_count;

	boolean_t		l_msix_combined;
	boolean_t		l_atomic_desc_support;
	boolean_t		l_64bit_dma_support;
	boolean_t		l_max_256_vd_support;
	boolean_t		l_use_seqnum_jbod_fp;
	boolean_t		l_pdmap_tgtid_support;

	size_t			l_max_reply_queues;
	size_t			l_max_num_sge;
	size_t			l_max_sge_in_main_msg;
	size_t			l_max_sge_in_chain;

	uint32_t		l_fw_outstanding_cmds;
	uint32_t		l_max_fw_cmds;
	uint32_t		l_max_scsi_cmds;
	size_t			l_reply_q_depth;

	size_t			l_reply_alloc_sz;
	size_t			l_io_frames_alloc_sz;
	size_t			l_max_chain_frame_sz;
	size_t			l_chain_offset_mfi_pthru;
	size_t			l_chain_offset_io_request;

	size_t			l_max_raid_map_sz;
	size_t			l_max_map_sz;
	size_t			l_current_map_sz;

	size_t			l_nvme_page_sz;

	scsi_hba_tran_t		*l_hba_tran;
	dev_info_t		*l_iport;
	taskq_t			*l_taskq;

	ddi_dma_attr_t		l_dma_attr;
	ddi_dma_attr_t		l_dma_attr_32;
	ddi_device_acc_attr_t	l_acc_attr;
	caddr_t			l_regmap;
	ddi_acc_handle_t	l_reghandle;
	kmutex_t		l_reg_lock;

	krwlock_t		l_raidmap_lock;
	lmrc_fw_raid_map_t	*l_raidmap;

	krwlock_t		l_pdmap_lock;
	lmrc_pd_map_t		*l_pdmap;

	lmrc_tgt_t		l_targets[LMRC_MAX_LD + LMRC_MAX_PD];

	scsi_hba_tgtmap_t	*l_raid_tgtmap;
	scsi_hba_tgtmap_t	*l_phys_tgtmap;

};

int lmrc_check_acc_handle(ddi_acc_handle_t);
int lmrc_check_dma_handle(ddi_dma_handle_t);

void lmrc_dma_build_sgl(lmrc_t *, lmrc_mpt_cmd_t *, const ddi_dma_cookie_t *,
    uint_t);
size_t lmrc_dma_get_size(lmrc_dma_t *);
void lmrc_dma_set_addr64(lmrc_dma_t *, uint64_t *);
void lmrc_dma_set_addr32(lmrc_dma_t *, uint32_t *);
int lmrc_dma_alloc(lmrc_t *, ddi_dma_attr_t, lmrc_dma_t *, size_t, uint64_t,
    uint_t);
void lmrc_dma_free(lmrc_dma_t *);

void lmrc_disable_intr(lmrc_t *);
void lmrc_enable_intr(lmrc_t *);
uint_t lmrc_intr_ack(lmrc_t *);

void lmrc_send_atomic_request(lmrc_t *, lmrc_atomic_req_desc_t);
void lmrc_send_request(lmrc_t *, lmrc_req_desc_t);
lmrc_atomic_req_desc_t lmrc_build_atomic_request(lmrc_t *, lmrc_mpt_cmd_t *,
    uint8_t);

void lmrc_fm_ereport(lmrc_t *, const char *);

int lmrc_hba_attach(lmrc_t *);
void lmrc_hba_detach(lmrc_t *);

void lmrc_thread(void *);
int lmrc_adapter_init(lmrc_t *);
int lmrc_ioc_init(lmrc_t *);
int lmrc_fw_init(lmrc_t *);

void lmrc_tgt_init(lmrc_tgt_t *, uint16_t, char *, lmrc_pd_info_t *);
void lmrc_tgt_clear(lmrc_tgt_t *);
lmrc_tgt_t *lmrc_tgt_find(lmrc_t *, struct scsi_device *);

void lmrc_wakeup_mfi(lmrc_t *, lmrc_mfi_cmd_t *);
void lmrc_issue_mfi(lmrc_t *, lmrc_mfi_cmd_t *, lmrc_mfi_cmd_cb_t *);
int lmrc_wait_mfi(lmrc_t *, lmrc_mfi_cmd_t *, uint8_t);
int lmrc_issue_blocked_mfi(lmrc_t *, lmrc_mfi_cmd_t *);

int lmrc_poll_for_reply(lmrc_t *, lmrc_mpt_cmd_t *);
int lmrc_process_replies(lmrc_t *, uint8_t);

int lmrc_abort_mpt(lmrc_t *, lmrc_tgt_t *, lmrc_mpt_cmd_t *);
lmrc_mpt_cmd_t *lmrc_get_mpt(lmrc_t *);
void lmrc_put_mpt(lmrc_mpt_cmd_t *);

lmrc_mfi_cmd_t *lmrc_get_dcmd(lmrc_t *, uint16_t, uint32_t, uint32_t, uint_t);
void lmrc_put_dcmd(lmrc_t *, lmrc_mfi_cmd_t *);

lmrc_mfi_cmd_t *lmrc_get_mfi(lmrc_t *);
void lmrc_put_mfi(lmrc_mfi_cmd_t *);
int lmrc_abort_outstanding_mfi(lmrc_t *, const size_t);
int lmrc_build_mptmfi_passthru(lmrc_t *, lmrc_mfi_cmd_t *);

int lmrc_start_aen(lmrc_t *);

int lmrc_ctrl_shutdown(lmrc_t *);

/*
 * per-target active MPT command list functions
 */

/*
 * lmrc_tgt_first_active_mpt
 *
 * Returns the first active MPT command of a target. The MPT command is returned
 * locked.
 */
static inline lmrc_mpt_cmd_t *
lmrc_tgt_first_active_mpt(lmrc_tgt_t *tgt)
{
	lmrc_mpt_cmd_t *mpt = list_head(&tgt->tgt_mpt_active);

	ASSERT(mutex_owned(&tgt->tgt_mpt_active_lock));

	if (mpt != NULL)
		mutex_enter(&mpt->mpt_lock);

	return (mpt);
}

/*
 * lmrc_tgt_next_active_mpt
 *
 * Given a MPT command on the active list of a target, returns the next active
 * MPT command on that target. The given MPT command is unlocked, and the next
 * command is returned locked.
 */
static inline lmrc_mpt_cmd_t *
lmrc_tgt_next_active_mpt(lmrc_tgt_t *tgt, lmrc_mpt_cmd_t *mpt)
{
	lmrc_mpt_cmd_t *nextmpt;

	ASSERT(mutex_owned(&tgt->tgt_mpt_active_lock));

	nextmpt = list_next(&tgt->tgt_mpt_active, mpt);
	mutex_exit(&mpt->mpt_lock);

	if (nextmpt != NULL)
		mutex_enter(&nextmpt->mpt_lock);

	return (nextmpt);
}

/*
 * lmrc_tgt_add_active_mpt
 *
 * Adds a MPT command to the active command list of a target. The command
 * mutex must be held. There's no risk for a deadlock against the iterator
 * functions.
 */
static inline void
lmrc_tgt_add_active_mpt(lmrc_tgt_t *tgt, lmrc_mpt_cmd_t *mpt)
{
	ASSERT(mutex_owned(&mpt->mpt_lock));

	mutex_enter(&tgt->tgt_mpt_active_lock);
	list_insert_head(&tgt->tgt_mpt_active, mpt);
	mutex_exit(&tgt->tgt_mpt_active_lock);
}

/*
 * lmrc_tgt_rem_active_mpt
 *
 * Removes a MPT command from the active command list of a target. The command
 * must not be locked to avoid a deadlock with against the iterator functions.
 */
static inline void
lmrc_tgt_rem_active_mpt(lmrc_tgt_t *tgt, lmrc_mpt_cmd_t *mpt)
{
	ASSERT(!mutex_owned(&mpt->mpt_lock));

	mutex_enter(&tgt->tgt_mpt_active_lock);
	list_remove(&tgt->tgt_mpt_active, mpt);
	mutex_exit(&tgt->tgt_mpt_active_lock);
}

/*
 * Number of replies to be processed before the Reply Post Host register
 * is updated.
 */
#define	LMRC_THRESHOLD_REPLY_COUNT		50

#endif /* _LMRC_H */
