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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_1394_TARGETS_SCSA1394_IMPL_H
#define	_SYS_1394_TARGETS_SCSA1394_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * scsa1394 definitions
 */

#include <sys/1394/t1394.h>
#include <sys/sbp2/driver.h>
#include <sys/scsi/scsi.h>
#include <sys/cdio.h>
#include <sys/1394/targets/scsa1394/cmd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * each lun uses a worker thread for various deferred processing
 */
typedef enum {
	SCSA1394_THR_INIT,			/* initial state */
	SCSA1394_THR_RUN,			/* thread is running */
	SCSA1394_THR_EXIT			/* thread exited */
} scsa1394_thr_state_t;

/* thread requests */
enum {
	SCSA1394_THREQ_EXIT		= 0x1,	/* thread has to exit */
	SCSA1394_THREQ_TASK_STATUS	= 0x2,	/* task status received */
	SCSA1394_THREQ_NUDGE		= 0x4,	/* nudge SBP-2 layer */
	SCSA1394_THREQ_BUS_RESET	= 0x8,
	SCSA1394_THREQ_DISCONNECT	= 0x10,
	SCSA1394_THREQ_RECONNECT	= 0x20
};

typedef struct scsa1394_thread {
	void			(*thr_func)(void *);	/* function to be run */
	void			*thr_arg;	/* function argument */
	struct scsa1394_lun	*thr_lun;	/* lun we belong to */
	scsa1394_thr_state_t	thr_state;	/* state */
	kcondvar_t		thr_cv;		/* cv for request wait */
	int			thr_req;	/* request mask */
} scsa1394_thread_t;


/* 1394 device state */
typedef enum {
	SCSA1394_DEV_INIT		= 0,
	SCSA1394_DEV_ONLINE,
	SCSA1394_DEV_BUS_RESET,
	SCSA1394_DEV_DISCONNECTED,
	SCSA1394_DEV_PWRED_DOWN,
	SCSA1394_DEV_SUSPENDED
} scsa1394_dev_state_t;

enum { SCSA1394_STAT_NCMD_LAST = 8 };

/* per-lun statistics */
typedef struct scsa1394_lun_stat {
	/*
	 * ring buffer of the last N failed commands. stat_cmd_fail_last_idx
	 * is an index into stat_cmd_fail_last the array and points to the
	 * entry to be written next. The first 16 bytes are CDB bytes,
	 * the last 8 bytes are a timestamp (lbolt).
	 */
	uint64_t		stat_cmd_last_fail[SCSA1394_STAT_NCMD_LAST][3];
	int			stat_cmd_last_fail_idx;

	uint_t			stat_cmd_cnt;	/* # of commands submitted */
	uint_t			stat_cmd_buf_max_nsegs;
	uint_t			stat_cmd_buf_dma_partial;

	/*
	 * errors
	 */
	uint_t			stat_err_pkt_kmem_alloc;
	uint_t			stat_err_cmd_cdb_dmem_alloc;
	uint_t			stat_err_cmd_cdb_dbind;
	uint_t			stat_err_cmd_cdb_addr_alloc;
	uint_t			stat_err_cmd_buf_dbind;
	uint_t			stat_err_cmd_buf_addr_alloc;
	uint_t			stat_err_cmd_pt_kmem_alloc;
	uint_t			stat_err_cmd_pt_dmem_alloc;
	uint_t			stat_err_cmd_pt_addr_alloc;
	uint_t			stat_err_status_tran_err;
	uint_t			stat_err_status_conv;
	uint_t			stat_err_status_resp;
} scsa1394_lun_stat_t;

/* logical unit */
typedef struct scsa1394_lun {
	kmutex_t		l_mutex;	/* structure lock */
	struct scsa1394_state	*l_sp;		/* soft state */
	sbp2_lun_t		*l_lun;		/* SBP2 lun */
	sbp2_ses_t		*l_ses;		/* login session */
	dev_info_t		*l_cdip;	/* child devinfo */
	scsa1394_thread_t	l_worker_thread; /* worker thread */
	ddi_softintr_t		l_softintr_id;	/* soft interrupt */
	boolean_t		l_softintr_triggered; /* trigger indicator */
	int			l_softintr_req;	/* soft intr request mask */

	/* workarounds */
	int			l_lba_size;	/* LBA size */
	int			l_dtype_orig;	/* original DTYPE value */
	int			l_rmb_orig;	/* original RMB value */
	int			l_start_stop_fail_cnt; /* start/stop failures */
	boolean_t		l_start_stop_fake; /* fake start/stop unit */
	int			l_mode_sense_fail_cnt; /* mode sense failures */
	boolean_t		l_mode_sense_fake; /* fake mode sense command */
	boolean_t		l_nosup_tur;
	boolean_t		l_nosup_start_stop;
	boolean_t		l_nosup_inquiry;

	struct scsi_inquiry	l_fake_inq;

	scsa1394_lun_stat_t	l_stat;		/* statistics */
} scsa1394_lun_t;

_NOTE(MUTEX_PROTECTS_DATA(scsa1394_lun::l_mutex, scsa1394_lun))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsa1394_lun::{
    l_sp l_lun l_ses l_cdip l_worker_thread l_softintr_id
    l_nosup_tur l_nosup_start_stop l_nosup_inquiry }))
_NOTE(SCHEME_PROTECTS_DATA("statistics", scsa1394_lun::l_stat))

/* l_softintr_req */
enum {
	SCSA1394_SOFTINTR_STATUS_RCVD	= 0x1,	/* task status received */
	SCSA1394_SOFTINTR_RECONNECT	= 0x2	/* perform reconnect */
};

/* per-instance statistics */
typedef struct scsa1394_inst_stat {
	uint_t			stat_bus_reset_cnt;
	uint_t			stat_disconnect_cnt;
	uint_t			stat_reconnect_cnt;
	/*
	 * errors
	 */
} scsa1394_inst_stat_t;

/* per-instance soft state structure */
typedef struct scsa1394_state {
	kmutex_t		s_mutex;	/* structure mutex */
	dev_info_t		*s_dip;		/* device information */
	int			s_instance;	/* instance number */
	scsa1394_dev_state_t	s_dev_state;	/* device state */
	t1394_handle_t		s_t1394_hdl;	/* 1394 handle */
	t1394_attachinfo_t	s_attachinfo;	/* 1394 attach info */
	t1394_targetinfo_t	s_targetinfo;	/* 1394 target info */
	ddi_callback_id_t	s_reset_cb_id;	/* reset event cb id */
	ddi_callback_id_t	s_remove_cb_id;	/* remove event cb id */
	ddi_callback_id_t	s_insert_cb_id;	/* insert event cb id */
	boolean_t		s_event_entered; /* event serialization */
	kcondvar_t		s_event_cv;	/* event serialization cv */
	ddi_dma_attr_t		s_buf_dma_attr;	/* data buffer DMA attrs */
	ddi_dma_attr_t		s_pt_dma_attr;	/* page table DMA attrs */
	scsi_hba_tran_t		*s_tran;	/* SCSA HBA tran structure */
	sbp2_tgt_t		*s_tgt;		/* SBP-2 target */
	sbp2_cfgrom_t		*s_cfgrom;	/* Config ROM */
	int			s_nluns;	/* # of logical units */
	scsa1394_lun_t		*s_lun;		/* logical units */
	kmem_cache_t		*s_cmd_cache;	/* command kmem cache */
	ddi_taskq_t		*s_taskq;	/* common taskq for all luns */
	boolean_t		s_symbios;	/* need Symbios workaround? */
	boolean_t		s_disconnect_warned; /* disconnect warning */
	size_t			s_totalsec;	/* total sectors */
	size_t			s_secsz;	/* sector size */
	scsa1394_inst_stat_t	s_stat;		/* statistics */
} scsa1394_state_t;

_NOTE(MUTEX_PROTECTS_DATA(scsa1394_state::s_mutex, scsa1394_state))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsa1394_state::{
    s_dip s_instance s_t1394_hdl s_attachinfo s_reset_cb_id s_remove_cb_id
    s_insert_cb_id s_buf_dma_attr s_pt_dma_attr s_tran s_tgt s_cfgrom
    s_nluns s_lun s_cmd_cache s_taskq s_symbios s_targetinfo
    s_totalsec s_secsz}))
_NOTE(SCHEME_PROTECTS_DATA("statistics", scsa1394_state::s_stat))

_NOTE(LOCK_ORDER(scsa1394_state::s_mutex scsa1394_lun::l_mutex))

/* for sbp2_bus_buf.bb_hdl */
typedef struct scsa1394_bus_buf {
	scsa1394_state_t	*sbb_state;	/* soft state */
	t1394_addr_handle_t	sbb_addr_hdl;	/* 1394 address handle */
	ddi_dma_handle_t	sbb_dma_hdl;	/* DMA handle */
	ddi_acc_handle_t	sbb_acc_hdl;	/* access handle */
} scsa1394_bus_buf_t;

_NOTE(SCHEME_PROTECTS_DATA("unique per task", scsa1394_bus_buf))
_NOTE(SCHEME_PROTECTS_DATA("dev_info::devi_lock", dev_info::devi_state))

/* various translation macros */
#define	ADDR2TRAN(ap)	((ap)->a_hba_tran)
#define	TRAN2STATE(hba)	((scsa1394_state_t *)(hba)->tran_hba_private)
#define	ADDR2STATE(ap)	(TRAN2STATE(ADDR2TRAN(ap)))

#define	SCSA1394_NODEID(sp)	((sp)->s_attachinfo.localinfo.local_nodeID)
#define	SCSA1394_BUSGEN(sp)	((sp)->s_attachinfo.localinfo.bus_generation)

#define	SCSA1394_ORB_SIZE_ROUNDUP(sp, sz) SBP2_ORB_SIZE_ROUNDUP(sp->s_tgt, sz)
#define	SCSA1394_ADDR_SET(sp, var, addr) \
    SBP2_ADDR_SET(var, addr, SCSA1394_NODEID(sp))

/* macros to calculate LBA for 6/10/12-byte commands */
#define	SCSA1394_LBA_6BYTE(pkt)						\
	(((pkt)->pkt_cdbp[1] & 0x1f) << 16) +				\
	((pkt)->pkt_cdbp[2] << 8) + (pkt)->pkt_cdbp[3]
#define	SCSA1394_LEN_6BYTE(pkt)						\
	(pkt)->pkt_cdbp[4]

#define	SCSA1394_LEN_10BYTE(pkt)					\
	((pkt)->pkt_cdbp[7] << 8) + (pkt)->pkt_cdbp[8]
#define	SCSA1394_LBA_10BYTE(pkt)					\
	((pkt)->pkt_cdbp[2] << 24) + ((pkt)->pkt_cdbp[3] << 16) + 	\
	((pkt)->pkt_cdbp[4] << 8) +  (pkt)->pkt_cdbp[5]

#define	SCSA1394_LEN_12BYTE(pkt)					\
	((pkt)->pkt_cdbp[6] << 24) + ((pkt)->pkt_cdbp[7] << 16) +	\
	((pkt)->pkt_cdbp[8] << 8) +  (pkt)->pkt_cdbp[9]
#define	SCSA1394_LBA_12BYTE(pkt)					\
	((pkt)->pkt_cdbp[2] << 24) + ((pkt)->pkt_cdbp[3] << 16) +	\
	((pkt)->pkt_cdbp[4] << 8) +  (pkt)->pkt_cdbp[5]

/* macro to calculate LEN for SCMD_READ_CD command */
#define	SCSA1394_LEN_READ_CD(pkt)					\
	(((pkt)->pkt_cdbp[6] << 16) + ((pkt)->pkt_cdbp[7] << 8) +	\
	(pkt)->pkt_cdbp[8])

/* calculate block size for CD-RW writes */
#define	SCSA1394_CDRW_BLKSZ(bcount, len)	((bcount) / (len))
#define	SCSA1394_VALID_CDRW_BLKSZ(blksz)				\
	(((blksz) == CDROM_BLK_2048) || ((blksz) == CDROM_BLK_2352) ||	\
	((blksz) == CDROM_BLK_2336) || ((blksz) == CDROM_BLK_2324))

/* black/white list */
typedef struct scsa1394_bw_list {
	int	vid_match;
	int	vid;
} scsa1394_bw_list_t;

/* match type */
enum {
	SCSA1394_BW_ONE,
	SCSA1394_BW_ALL
};

#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))

/* misc constants */
enum {
	SCSA1394_COMPAT_MAX		= 1,	/* max @ of compatible names */
	SCSA1394_CLEANUP_LEVEL_MAX	= 256,
	SCSA1394_START_STOP_FAIL_MAX	= 3,	/* max start/stop failures */
	SCSA1394_MODE_SENSE_FAIL_MAX	= 3,	/* max mode sense failures */
	SCSA1394_START_STOP_TIMEOUT_MAX	= 30,
	SCSA1394_MAPIN_SIZE_MAX		= 512,
	SCSA1394_PROBE_TIMEOUT		= 15,	/* in seconds */

	SCSA1394_DTYPE_RBC		= 0x0E
};


/* SBP-2 routines */
int	scsa1394_sbp2_attach(scsa1394_state_t *);
void	scsa1394_sbp2_detach(scsa1394_state_t *);
void	scsa1394_sbp2_fake_inquiry(scsa1394_state_t *, struct scsi_inquiry *);
int	scsa1394_sbp2_threads_init(scsa1394_state_t *);
void	scsa1394_sbp2_threads_fini(scsa1394_state_t *);
int	scsa1394_sbp2_get_lun_type(scsa1394_lun_t *);
int	scsa1394_sbp2_login(scsa1394_state_t *, int);
void	scsa1394_sbp2_logout(scsa1394_state_t *, int, boolean_t);
void	scsa1394_sbp2_req(scsa1394_state_t *, int, int);
void	scsa1394_sbp2_disconnect(scsa1394_state_t *);
void	scsa1394_sbp2_seg2pt(scsa1394_lun_t *, scsa1394_cmd_t *);
void	scsa1394_sbp2_cmd2orb(scsa1394_lun_t *, scsa1394_cmd_t *);
int	scsa1394_sbp2_start(scsa1394_lun_t *, scsa1394_cmd_t *);
void	scsa1394_sbp2_nudge(scsa1394_lun_t *);
int	scsa1394_sbp2_reset(scsa1394_lun_t *, int, scsa1394_cmd_t *);
void	scsa1394_sbp2_flush_cmds(scsa1394_lun_t *, int, int, int);


/* HBA public routines */
int	scsa1394_thr_dispatch(scsa1394_thread_t *);
void	scsa1394_thr_cancel(scsa1394_thread_t *);
void	scsa1394_thr_wake(scsa1394_thread_t *, int);
void	scsa1394_thr_clear_req(scsa1394_thread_t *, int);
void	scsa1394_cmd_status_proc(scsa1394_lun_t *, scsa1394_cmd_t *);
boolean_t scsa1394_dev_is_online(scsa1394_state_t *);
void	scsa1394_sbp2_req_bus_reset(scsa1394_lun_t *);
void	scsa1394_sbp2_req_reconnect(scsa1394_lun_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_SCSA1394_IMPL_H */
