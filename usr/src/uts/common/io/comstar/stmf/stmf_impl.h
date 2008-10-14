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
#ifndef _STMF_IMPL_H
#define	_STMF_IMPL_H

#include <sys/stmf_defines.h>
#include <sys/stmf_ioctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef	uint32_t stmf_event_handle_t;
#define	STMF_MAX_NUM_EVENTS		(sizeof (stmf_event_handle_t) * 8)
#define	STMF_EVENT_ADD(h, e)		(atomic_or_32(&(h), \
						((uint32_t)1) << (e)))
#define	STMF_EVENT_REMOVE(h, e)		(atomic_and_32(&(h), \
						~(((uint32_t)1) << (e))))
#define	STMF_EVENT_ENABLED(h, e)	(((h) & ((uint32_t)1) << (e)) != 0)
#define	STMF_EVENT_CLEAR_ALL(h)		((h) = 0)
#define	STMF_EVENT_ALLOC_HANDLE(h)	((h) = 0)
#define	STMF_EVENT_FREE_HANDLE(h)	((h) = 0)

struct stmf_i_scsi_task;
struct stmf_itl_data;

typedef struct stmf_i_lu_provider {
	stmf_lu_provider_t	*ilp_lp;
	uint32_t		ilp_alloc_size;
	uint32_t		ilp_nlus;	/* # LUNs being exported */
	uint32_t		ilp_cb_in_progress:1,
				ilp_rsvd:31;
	struct stmf_i_lu_provider *ilp_next;
	struct stmf_pp_data	*ilp_ppd;
} stmf_i_lu_provider_t;

typedef struct stmf_i_lu {
	stmf_lu_t	*ilu_lu;
	uint32_t	ilu_alloc_size;
	uint32_t	ilu_flags;
	uint32_t	ilu_ref_cnt;
	uint8_t		ilu_state;
	uint8_t		ilu_prev_state;
	stmf_event_handle_t ilu_event_hdl;
	struct stmf_i_lu *ilu_next;
	struct stmf_i_lu *ilu_prev;
	char		*ilu_alias;
	kmutex_t	ilu_task_lock;
	uint32_t	ilu_task_cntr1;
	uint32_t	ilu_task_cntr2;
	uint32_t	*ilu_cur_task_cntr;
	uint32_t	ilu_ntasks;	 /* # of tasks in the ilu_task list */
	uint32_t	ilu_ntasks_free;	/* # of tasks that are free */
	uint32_t	ilu_ntasks_min_free; /* # minimal free tasks */
	struct stmf_i_scsi_task	*ilu_tasks;
	struct stmf_i_scsi_task *ilu_free_tasks;
	struct stmf_itl_data	*ilu_itl_list;

	/* point to the luid entry in stmf_state.stmf_luid_list */
	void		*ilu_luid;
} stmf_i_lu_t;

/*
 * ilu_flags
 */
#define	ILU_STALL_DEREGISTER		0x0001
#define	ILU_RESET_ACTIVE		0x0002

typedef struct stmf_i_port_provider {
	stmf_port_provider_t	*ipp_pp;
	uint32_t		ipp_alloc_size;
	uint32_t		ipp_npps;
	uint32_t		ipp_cb_in_progress:1,
				ipp_rsvd:31;
	struct stmf_i_port_provider *ipp_next;
	struct stmf_pp_data	*ipp_ppd;
} stmf_i_port_provider_t;

typedef struct stmf_i_local_port {
	stmf_local_port_t	*ilport_lport;
	uint32_t		ilport_alloc_size;
	uint32_t		ilport_nsessions;
	struct stmf_i_scsi_session *ilport_ss_list;
	krwlock_t		ilport_lock;
	struct stmf_i_local_port *ilport_next;
	struct stmf_i_local_port *ilport_prev;
	uint8_t			ilport_state;
	uint8_t			ilport_prev_state;
	uint16_t		ilport_rtpid; /* relative tpid */
	stmf_event_handle_t	ilport_event_hdl;
	clock_t			ilport_last_online_clock;
	clock_t			ilport_avg_interval;
	uint32_t		ilport_online_times;
	uint32_t		ilport_flags;
	/* which target group this port belongs to in stmf_state.stmf_tg_list */
	void			*ilport_tg;
	/* XXX Need something to track all the remote ports also */
} stmf_i_local_port_t;

#define	STMF_AVG_ONLINE_INTERVAL	(30 * drv_usectohz(1000000))

/*
 * ilport flags
 */
#define	ILPORT_FORCED_OFFLINE		0x01
#define	ILPORT_SS_GOT_INITIAL_LUNS	0x02

typedef struct stmf_i_scsi_session {
	stmf_scsi_session_t	*iss_ss;
	uint32_t		iss_alloc_size;
	uint32_t		iss_flags;
	struct stmf_i_scsi_session *iss_next;
	/*
	 * Ideally we should maintain 2 maps. One would indicate a new map
	 * which will become available only upon receipt of a REPORT LUN
	 * cmd.
	 */
	struct stmf_lun_map	*iss_sm;
	/*
	 * which host group the host of this session belongs to in
	 * stmf_state.stmf_hg_list
	 */
	void			*iss_hg;
	krwlock_t		*iss_lockp;
	time_t			iss_creation_time;
} stmf_i_scsi_session_t;

/*
 * iss flags
 */
#define	ISS_LUN_INVENTORY_CHANGED		0x0001
#define	ISS_RESET_ACTIVE			0x0002
#define	ISS_BEING_CREATED			0x0004
#define	ISS_GOT_INITIAL_LUNS			0x0008
#define	ISS_EVENT_ACTIVE			0x0010

#define	ITASK_MAX_NCMDS			14
#define	ITASK_DEFAULT_POLL_TIMEOUT	0
struct stmf_worker;
typedef struct stmf_i_scsi_task {
	scsi_task_t		*itask_task;
	uint32_t		itask_alloc_size;
	uint32_t		itask_flags;
	struct stmf_worker	*itask_worker;
	uint32_t		*itask_ilu_task_cntr;
	struct stmf_i_scsi_task	*itask_worker_next;
	struct stmf_i_scsi_task	*itask_lu_next;
	struct stmf_i_scsi_task	*itask_lu_prev;
	struct stmf_i_scsi_task	*itask_lu_free_next;
	struct stmf_i_scsi_task	*itask_abort_next;
	struct stmf_itl_data	*itask_itl_datap;
	clock_t			itask_start_time;	/* abort and normal */
	/* For now we only support 4 parallel buffers. Should be enough. */
	stmf_data_buf_t		*itask_dbufs[4];
	clock_t			itask_poll_timeout;
	uint8_t			itask_cmd_stack[ITASK_MAX_NCMDS];
	uint8_t			itask_ncmds;
	uint8_t			itask_allocated_buf_map;
	uint16_t		itask_cdb_buf_size;
} stmf_i_scsi_task_t;

#define	ITASK_DEFAULT_ABORT_TIMEOUT	5

/*
 * itask_flags
 */
#define	ITASK_IN_FREE_LIST		0x0001
#define	ITASK_IN_TRANSITION		0x0002
#define	ITASK_IN_WORKER_QUEUE		0x0004
#define	ITASK_BEING_ABORTED		0x0008
#define	ITASK_BEING_COMPLETED		0x0010
#define	ITASK_KNOWN_TO_TGT_PORT		0x0020
#define	ITASK_KNOWN_TO_LU		0x0040
#define	ITASK_LU_ABORT_CALLED		0x0080
#define	ITASK_TGT_PORT_ABORT_CALLED	0x0100
#define	ITASK_DEFAULT_HANDLING		0x0200
#define	ITASK_CAUSING_LU_RESET		0x0400
#define	ITASK_CAUSING_TARGET_RESET	0x0800

/*
 * itask cmds.
 */
#define	ITASK_CMD_MASK			0x1F
#define	ITASK_CMD_BUF_NDX(cmd)		(((uint8_t)(cmd)) >> 5)
#define	ITASK_CMD_NEW_TASK		0x1
#define	ITASK_CMD_DATA_XFER_DONE	0x2
#define	ITASK_CMD_STATUS_DONE		0x3
#define	ITASK_CMD_ABORT			0x4
#define	ITASK_CMD_SEND_STATUS		0x5
#define	ITASK_CMD_POLL			0x10
#define	ITASK_CMD_POLL_LU		(ITASK_CMD_POLL | 1)
#define	ITASK_CMD_POLL_LPORT		(ITASK_CMD_POLL | 2)

/*
 * struct maintained on a per itl basis when the lu registers ITL handle.
 */
typedef struct stmf_itl_data {
	uint32_t			itl_counter;
	uint8_t				itl_flags;
	uint8_t				itl_hdlrm_reason;
	uint16_t			itl_lun;
	void				*itl_handle;
	struct stmf_i_scsi_session	*itl_session;
	struct stmf_itl_data		*itl_next;
} stmf_itl_data_t;

/*
 * itl flags
 */
#define	STMF_ITL_BEING_TERMINATED	0x01

/*
 * data structures to maintain provider private data.
 */
typedef struct stmf_pp_data {
	struct stmf_pp_data	*ppd_next;
	void			*ppd_provider;
	nvlist_t		*ppd_nv;
	uint32_t		ppd_lu_provider:1,
				ppd_port_provider:1,
				ppd_rsvd:30;
	uint32_t		ppd_alloc_size;
	char			ppd_name[8];
} stmf_pp_data_t;

typedef struct stmf_worker {
	kthread_t		*worker_tid;
	stmf_i_scsi_task_t	*worker_task_head;
	stmf_i_scsi_task_t	*worker_task_tail;
	stmf_i_scsi_task_t	*worker_wait_head;
	stmf_i_scsi_task_t	*worker_wait_tail;
	kmutex_t		worker_lock;
	kcondvar_t		worker_cv;
	uint32_t		worker_flags;
	uint32_t		worker_queue_depth;	/* ntasks cur queued */
	uint32_t		worker_max_qdepth_pu;	/* maxqd / unit time */
	uint32_t		worker_max_sys_qdepth_pu; /* for all workers */
	uint32_t		worker_ref_count;	/* # IOs referencing */
} stmf_worker_t;

/*
 * worker flags
 */
#define	STMF_WORKER_STARTED		1
#define	STMF_WORKER_ACTIVE		2
#define	STMF_WORKER_TERMINATE		4

/*
 * data struct for managing transfers.
 */
typedef struct stmf_xfer_data {
	uint32_t	alloc_size;	/* Including this struct */
	uint32_t	size_done;
	uint32_t	size_left;
	uint8_t		buf[4];
} stmf_xfer_data_t;

/*
 * Define frequently used macros
 */
#define	TASK_TO_ITASK(x_task)	\
	((stmf_i_scsi_task_t *)(x_task)->task_stmf_private)

void stmf_dlun_init();
stmf_status_t stmf_dlun_fini();
void stmf_worker_init();
stmf_status_t stmf_worker_fini();
void stmf_task_free(scsi_task_t *task);
void stmf_task_lu_free(scsi_task_t *task);
void stmf_do_task_abort(scsi_task_t *task);
void stmf_do_itl_dereg(stmf_lu_t *lu, stmf_itl_data_t *itl,
		uint8_t hdlrm_reason);
void stmf_generate_lu_event(stmf_i_lu_t *ilu, int eventid,
				void *arg, uint32_t flags);
void stmf_generate_lport_event(stmf_i_local_port_t *ilport, int eventid,
						void *arg, uint32_t flags);

#ifdef	__cplusplus
}
#endif

#endif /* _STMF_IMPL_H */
