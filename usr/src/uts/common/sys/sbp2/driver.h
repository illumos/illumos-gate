/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ifndef	_SYS_SBP2_DRIVER_H
#define	_SYS_SBP2_DRIVER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Serial Bus Protocol 2 (SBP-2) driver interfaces
 */

#include <sys/sbp2/defs.h>
#include <sys/sbp2/bus.h>
#include <sys/sysmacros.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Config ROM definitions
 *
 * bus info block
 */
typedef struct sbp2_cfgrom_bib {
	int			cb_len;		/* info_length */
	uint32_t		*cb_buf;	/* data buffer */
} sbp2_cfgrom_bib_t;

/* directory */
typedef struct sbp2_cfgrom_dir {
	struct sbp2_cfgrom_ent	*cd_ent;	/* array of entries */
	int			cd_cnt;		/* # of entries with data */
	int			cd_size;	/* # of allocated entries */
} sbp2_cfgrom_dir_t;

/* directory entry */
typedef struct sbp2_cfgrom_ent {
	uint8_t			ce_kt;		/* key type */
	uint8_t			ce_kv;		/* key value */
	uint16_t		ce_len;		/* length in quadlets */
	uint64_t		ce_offset;	/* entry's CSR offset */
	struct sbp2_cfgrom_ent	*ce_ref;	/* referred entry (text leaf) */
	union {					/* data depends on key type: */
		uint32_t	imm;		/* immediate value */
		uint32_t	offset;		/* CSR offset */
		uint32_t	*leaf;		/* leaf */
		sbp2_cfgrom_dir_t dir;		/* directory */
	} ce_data;
} sbp2_cfgrom_ent_t;

/* entire Config ROM */
typedef struct sbp2_cfgrom {
	sbp2_cfgrom_bib_t	cr_bib;		/* bus info block */
	sbp2_cfgrom_ent_t	cr_root;	/* root directory */
} sbp2_cfgrom_t;

_NOTE(SCHEME_PROTECTS_DATA("stable data", {
    sbp2_cfgrom_bib sbp2_cfgrom_dir sbp2_cfgrom_ent sbp2_cfgrom }))

/*
 * SBP-2 definitions
 */

/* task states */
typedef enum {
	SBP2_TASK_INIT,		/* initial state */
	SBP2_TASK_PEND,		/* put on the list, pending completion */
	SBP2_TASK_COMP,		/* task completed */
	SBP2_TASK_PROC		/* status being processed */
} sbp2_task_state_t;

/* task errors */
typedef enum {
	SBP2_TASK_ERR_NONE,	/* no error */
	SBP2_TASK_ERR_DEAD,	/* agent dead */
	SBP2_TASK_ERR_BUS,	/* bus error */
	SBP2_TASK_ERR_TIMEOUT,	/* timed out */
	SBP2_TASK_ERR_ABORT,	/* task aborted */
	SBP2_TASK_ERR_LUN_RESET, /* lun reset */
	SBP2_TASK_ERR_TGT_RESET	/* target reset */
} sbp2_task_error;

/*
 * task
 */
typedef struct sbp2_task {
	struct sbp2_task	*ts_next;	/* next task */
	struct sbp2_task	*ts_prev;	/* previous task */
	struct sbp2_ses		*ts_ses;	/* session we belong to */
	void			*ts_drv_priv;	/* driver private data */
	sbp2_bus_buf_t		*ts_buf;	/* bus buffer */
	int			ts_timeout;	/* task timeout in seconds */
	timeout_id_t		ts_timeout_id;	/* timeout ID */
	sbp2_task_state_t	ts_state;	/* task state */
	sbp2_task_error		ts_error;	/* error */
	int			ts_bus_error;	/* bus error */
	sbp2_status_t		ts_status;	/* status block */
	hrtime_t		ts_time_start;
	hrtime_t		ts_time_comp;
} sbp2_task_t;

_NOTE(SCHEME_PROTECTS_DATA("unique per call", sbp2_task))

/* fetch agent */
typedef struct sbp2_agent {
	struct sbp2_tgt		*a_tgt;		/* target we belong to */
	kmutex_t		a_mutex;	/* structure mutex */
	uint16_t		a_state;	/* current agent state */
	kcondvar_t		a_cv;		/* agent state cv */
	boolean_t		a_acquired;	/* acquired flag */

	/* commands */
	void			*a_cmd;		/* fetch agent cmd */
	mblk_t			*a_cmd_data;	/* cmd data */

	sbp2_task_t		*a_active_task;	/* active task */

	/* register offsets */
	uint64_t		a_reg_agent_state; /* AGENT_STATE */
	uint64_t		a_reg_agent_reset; /* AGENT_RESET */
	uint64_t		a_reg_orbp;	/* ORB_POINTER */
	uint64_t		a_reg_doorbell;	/* DOORBELL */
	uint64_t		a_reg_unsol_status_enable;
						/* UNSOLICITED_STATUS_ENABLE */
} sbp2_agent_t;

_NOTE(MUTEX_PROTECTS_DATA(sbp2_agent::a_mutex, sbp2_agent))
_NOTE(SCHEME_PROTECTS_DATA("stable data", sbp2_agent::{
    a_tgt a_reg_agent_state a_reg_agent_reset a_reg_orbp a_reg_doorbell
    a_reg_unsol_status_enable }))
_NOTE(SCHEME_PROTECTS_DATA("a_acquired", sbp2_agent::{
    a_cmd a_cmd_data a_active_task }))

/* session is a period between login and logout */
typedef struct sbp2_ses {
	struct sbp2_tgt		*s_tgt;		/* target we belong to */
	struct sbp2_lun		*s_lun;		/* unit we belong to */
	kmutex_t		s_mutex;	/* structure mutex */
	struct sbp2_ses		*s_next;	/* next session */

	uint16_t		s_id;		/* login ID */
	uint64_t		s_agent_offset;	/* fetch agent offset */
	sbp2_agent_t		s_agent;	/* fetch agent */
	sbp2_bus_buf_t		s_status_fifo_buf; /* status FIFO */

	/* task list (command ORB's) */
	kmutex_t		s_task_mutex;		/* protects task list */
	sbp2_task_t		*s_task_head;		/* first on the list */
	sbp2_task_t		*s_task_tail;		/* last on the list */
	int			s_task_cnt;		/* # tasks */
	void			(*s_status_cb)(void *, sbp2_task_t *);
	void			*s_status_cb_arg;
} sbp2_ses_t;

_NOTE(MUTEX_PROTECTS_DATA(sbp2_ses::s_mutex, sbp2_ses))
_NOTE(SCHEME_PROTECTS_DATA("stable data", sbp2_ses::{
    s_tgt s_lun s_id s_agent_offset s_agent s_status_fifo_buf s_status_cb
    s_status_cb_arg }))
_NOTE(MUTEX_PROTECTS_DATA(sbp2_ses::s_task_mutex, sbp2_ses::{
    s_task_head s_task_tail s_task_cnt }))
_NOTE(MUTEX_PROTECTS_DATA(sbp2_ses::s_task_mutex, sbp2_task::{
    ts_next ts_prev }))

/* buffer list */
typedef struct sbp2_buf_list {
	kmutex_t		bl_mutex;
	int			bl_len;		/* number of elements */
	sbp2_bus_buf_t		*bl_head;	/* first element */
	sbp2_bus_buf_t		*bl_tail;	/* last element */
} sbp2_buf_list_t;

/* logical unit */
typedef struct sbp2_lun {
	struct sbp2_tgt		*l_tgt;		/* target we belong to */
	uint16_t		l_lun;		/* logical unit number */
	uint8_t			l_type;		/* device type */
	sbp2_ses_t		*l_ses;		/* login sessions */
	sbp2_buf_list_t		l_orb_freelist;	/* ORB freelist */


	sbp2_login_resp_t	l_login_resp;	/* login response */
	boolean_t		l_logged_in;	/* true if logged in */
	boolean_t		l_reconnecting;	/* true if being reconnected */
} sbp2_lun_t;

enum {
	SBP2_ORB_FREELIST_MAX	= 3	/* max # of elements on freelist */
};

/* per-target statistics */
typedef struct sbp2_tgt_stat {
	hrtime_t		stat_cfgrom_last_parse_time;
	uint_t			stat_submit_orbp;
	uint_t			stat_submit_doorbell;
	uint_t			stat_status_dead;
	uint_t			stat_status_short;
	uint_t			stat_status_unsolicited;
	uint_t			stat_status_notask;
	uint_t			stat_status_mgt_notask;
	uint_t			stat_agent_worbp;
	uint_t			stat_agent_worbp_fail;
	uint_t			stat_agent_wreset;
	uint_t			stat_agent_wreset_fail;
	uint_t			stat_task_max;
} sbp2_tgt_stat_t;

/* target */
typedef struct sbp2_tgt {
	struct sbp2_bus		*t_bus;			/* bus */
	void			*t_bus_hdl;		/* bus handle */
	kmutex_t		t_mutex;		/* structure mutex */
	sbp2_lun_t		*t_lun;			/* logical unit array */
	int			t_nluns;		/* # logical units */
	int			t_nluns_alloc;		/* # luns allocated */

	/* congif ROM */
	sbp2_cfgrom_t		t_cfgrom;		/* parsed cfgrom */
	hrtime_t		t_last_cfgrd;		/* cfgrom timestamp */
	int			t_orb_size;		/* ORB_size */

	/* management agent */
	uint64_t		t_mgt_agent;		/* mgt agent address */
	int			t_mot;			/* mgt timeout, ms */
	boolean_t		t_mgt_agent_acquired;	/* acquired flag */
	kcondvar_t		t_mgt_agent_cv;		/* cv for busy flag */
	sbp2_bus_buf_t		t_mgt_orb_buf;		/* mgt ORB */
	void			*t_mgt_cmd;		/* command */
	mblk_t			*t_mgt_cmd_data;	/* command data */
	sbp2_bus_buf_t		t_mgt_status_fifo_buf;	/* status FIFO buf */
	sbp2_status_t		t_mgt_status;		/* status block */
	boolean_t		t_mgt_status_rcvd;	/* status received? */
	kcondvar_t		t_mgt_status_cv;	/* status FIFO cv */
	sbp2_bus_buf_t		t_mgt_login_resp_buf;	/* login response */

	sbp2_tgt_stat_t		t_stat;			/* statistics */
} sbp2_tgt_t;

_NOTE(MUTEX_PROTECTS_DATA(sbp2_tgt::t_mutex, sbp2_tgt))
_NOTE(SCHEME_PROTECTS_DATA("stable data", sbp2_tgt::{
    t_bus t_bus_hdl t_lun t_nluns t_nluns_alloc t_cfgrom t_last_cfgrd
    t_orb_size t_mgt_agent t_mot }))
_NOTE(SCHEME_PROTECTS_DATA("t_mgt_agent_cv", sbp2_tgt::{
    t_mgt_orb_buf t_mgt_cmd t_mgt_cmd_data t_mgt_status_fifo_buf
    t_mgt_status_rcvd t_mgt_login_resp_buf }))
_NOTE(SCHEME_PROTECTS_DATA("statistics", sbp2_tgt::t_stat))

_NOTE(MUTEX_PROTECTS_DATA(sbp2_tgt::t_mutex, sbp2_lun))
_NOTE(SCHEME_PROTECTS_DATA("stable data", sbp2_lun::{
    l_tgt l_lun l_type l_ses }))
_NOTE(SCHEME_PROTECTS_DATA("t_mgt_agent_cv", sbp2_lun::l_login_resp))

_NOTE(LOCK_ORDER(sbp2_tgt::t_mutex sbp2_ses::s_mutex))
_NOTE(LOCK_ORDER(sbp2_tgt::t_mutex sbp2_ses::s_task_mutex))
_NOTE(LOCK_ORDER(sbp2_tgt::t_mutex sbp2_agent::a_mutex))

#define	SBP2_ORB_SIZE_ROUNDUP(tp, size) roundup(size, (tp)->t_orb_size)

/* walker flags */
enum {
	SBP2_WALK_DIRONLY	= 0x01	/* walk directories only */
};

/* walker return codes */
enum {
	SBP2_WALK_CONTINUE,
	SBP2_WALK_STOP
};

int sbp2_tgt_init(void *, struct sbp2_bus *, int, sbp2_tgt_t **);
void sbp2_tgt_fini(sbp2_tgt_t *);
void sbp2_tgt_disconnect(sbp2_tgt_t *);
int sbp2_tgt_reconnect(sbp2_tgt_t *);
int sbp2_tgt_reset(sbp2_tgt_t *, int *);
int sbp2_tgt_get_cfgrom(sbp2_tgt_t *, sbp2_cfgrom_t **);
int sbp2_tgt_get_lun_cnt(sbp2_tgt_t *);
sbp2_lun_t *sbp2_tgt_get_lun(sbp2_tgt_t *, int);

int sbp2_lun_reset(sbp2_lun_t *, int *);
int sbp2_lun_login(sbp2_lun_t *, sbp2_ses_t **, void (*)(void *, sbp2_task_t *),
    void *, int *);
int sbp2_lun_logout(sbp2_lun_t *, sbp2_ses_t **, int *, boolean_t);

int sbp2_ses_reconnect(sbp2_ses_t *, int *, uint16_t);
int sbp2_ses_submit_task(sbp2_ses_t *, sbp2_task_t *);
void sbp2_ses_nudge(sbp2_ses_t *);
int sbp2_ses_remove_task(sbp2_ses_t *, sbp2_task_t *);
sbp2_task_t *sbp2_ses_find_task_state(sbp2_ses_t *, sbp2_task_state_t);
sbp2_task_t *sbp2_ses_remove_first_task(sbp2_ses_t *);
sbp2_task_t *sbp2_ses_remove_first_task_state(sbp2_ses_t *, sbp2_task_state_t);
sbp2_task_t *sbp2_ses_cancel_first_task(sbp2_ses_t *);
int sbp2_ses_agent_reset(sbp2_ses_t *, int *);
int sbp2_ses_abort_task(sbp2_ses_t *, sbp2_task_t *, int *);
int sbp2_ses_abort_task_set(sbp2_ses_t *, int *);

int sbp2_task_orb_alloc(sbp2_lun_t *, sbp2_task_t *, int);
void sbp2_task_orb_free(sbp2_lun_t *, sbp2_task_t *);
void *sbp2_task_orb_kaddr(sbp2_task_t *);
void sbp2_task_orb_sync(sbp2_lun_t *, sbp2_task_t *, int);

void sbp2_swap32_buf(uint32_t *, int);

void sbp2_cfgrom_walk(sbp2_cfgrom_ent_t *,
    int (*)(void *, sbp2_cfgrom_ent_t *, int), void *);
sbp2_cfgrom_ent_t *sbp2_cfgrom_ent_by_key(sbp2_cfgrom_ent_t *, int8_t, int8_t,
    int);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBP2_DRIVER_H */
