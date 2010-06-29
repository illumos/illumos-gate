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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_RCTL_H
#define	_SYS_RCTL_H

#include <sys/kmem.h>
#include <sys/resource.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Available local actions and flags.
 */
#define	RCTL_LOCAL_NOACTION		0x00000000
#define	RCTL_LOCAL_SIGNAL		0x00000001
#define	RCTL_LOCAL_DENY			0x00000002

#define	RCTL_LOCAL_MAXIMAL		0x80000000
#define	RCTL_LOCAL_PROJDB		0x40000000

#define	RCTL_LOCAL_ACTION_MASK		0xffff0000
#define	RCTL_LOCAL_MASK			0xc0000003

/*
 * Available global actions and flags.
 */
#define	RCTL_GLOBAL_NOACTION		0x00000000
#define	RCTL_GLOBAL_SYSLOG		0x00000001

#define	RCTL_GLOBAL_NOBASIC		0x80000000
#define	RCTL_GLOBAL_LOWERABLE		0x40000000
#define	RCTL_GLOBAL_DENY_ALWAYS		0x20000000
#define	RCTL_GLOBAL_DENY_NEVER		0x10000000
#define	RCTL_GLOBAL_FILE_SIZE		0x08000000
#define	RCTL_GLOBAL_CPU_TIME		0x04000000
#define	RCTL_GLOBAL_SIGNAL_NEVER	0x02000000
#define	RCTL_GLOBAL_NOLOCALACTION	RCTL_GLOBAL_SIGNAL_NEVER
#define	RCTL_GLOBAL_INFINITE		0x01000000
#define	RCTL_GLOBAL_UNOBSERVABLE	0x00800000
#define	RCTL_GLOBAL_SYSLOG_NEVER	0x00080000

#define	RCTL_GLOBAL_BYTES		0x00400000
#define	RCTL_GLOBAL_SECONDS		0x00200000
#define	RCTL_GLOBAL_COUNT		0x00100000

#define	RCTL_GLOBAL_ACTION_MASK		0xffff0000
#define	RCTL_GLOBAL_MASK		0xfff80001

/*
 * getrctl(2) flag values
 */
#define	RCTL_FIRST		0x00000000
#define	RCTL_NEXT		0x00000001
#define	RCTL_USAGE		0x00000002

/*
 * setrctl(2) flag values
 */

#define	RCTL_INSERT		0x00000000
#define	RCTL_DELETE		0x00000001
#define	RCTL_REPLACE		0x00000002

#define	RCTL_USE_RECIPIENT_PID	0x10000000

#define	RCTLSYS_ACTION_MASK 	0xffff0000
#define	RCTLSYS_MASK		0x10000003

/*
 * rctl_priv_t: rctl privilege defined values
 *   A large amount of space has been deliberately left between these privileges
 *   to permit future enrichment of the control privilege value.
 */
#define	RCPRIV_BASIC		0x01000000
#define	RCPRIV_PRIVILEGED	0x04000000
#define	RCPRIV_SYSTEM		0x07000000

typedef u_longlong_t rctl_qty_t; /* resource control numerical values   */
typedef int rctl_priv_t;

typedef struct rctlblk rctlblk_t;

extern int setrctl(const char *, rctlblk_t *, rctlblk_t *, int);
extern int getrctl(const char *, rctlblk_t *, rctlblk_t *, int);

typedef enum {
	RCENTITY_PROCESS,
	RCENTITY_TASK,
	RCENTITY_PROJECT,
	RCENTITY_ZONE
} rctl_entity_t;
#define	RC_MAX_ENTITY RCENTITY_ZONE

#ifndef _KERNEL

typedef struct rctl_set rctl_set_t;

#else /* _KERNEL */

#include <sys/mutex.h>

/*
 * rctl_test return bitfield
 */
#define	RCT_NONE		0x00000000
#define	RCT_DENY		0x00000001
#define	RCT_SIGNAL		0x00000002
#define	RCT_STRLOG		0x00000004

#define	RCT_LK_ABANDONED	0x80000000

/*
 * rctl_set_dup flags
 */
#define	RCD_DUP			0x1
#define	RCD_CALLBACK		0x2

/*
 * rctl_action/rctl_test action safety states
 */
#define	RCA_SAFE		0x0 /* safe for signal and siginfo delivery */
#define	RCA_UNSAFE_SIGINFO	0x1 /* not safe to allocate for siginfo */
#define	RCA_UNSAFE_ALL		0x2 /* not safe to send signal */

typedef struct rctl_val {
	struct rctl_val *rcv_prev;		/* previous (lower) value */
	struct rctl_val *rcv_next;		/* next (higher) value */
	rctl_priv_t	rcv_privilege;		/* appropriate RCPRIV_* cst */
	rctl_qty_t	rcv_value;		/* enforced value of control */
	uint_t		rcv_flagaction;		/* properties and actions */
	int		rcv_action_signal;	/* signal to send as action */
	struct proc	*rcv_action_recipient;	/* process to receive signal */
	id_t		rcv_action_recip_pid;	/* pid of that process */
	hrtime_t	rcv_firing_time;	/* time rctl_val last fired */
} rctl_val_t;

typedef int rctl_hndl_t;

struct rctl;
struct proc;
struct task;
struct kproject;
struct zone;
struct kstat;

typedef struct rctl_entity_p_struct {
	rctl_entity_t rcep_t;
	union {
		struct proc *proc;
		struct task *task;
		struct kproject *proj;
		struct zone *zone;
	} rcep_p;
} rctl_entity_p_t;

typedef struct rctl_ops {
	void		(*rco_action)(struct rctl *, struct proc *,
	    rctl_entity_p_t *);
	rctl_qty_t	(*rco_get_usage)(struct rctl *, struct proc *);
	int		(*rco_set)(struct rctl *, struct proc *,
	    rctl_entity_p_t *, rctl_qty_t);
	int		(*rco_test)(struct rctl *, struct proc *,
	    rctl_entity_p_t *, rctl_val_t *, rctl_qty_t, uint_t);
} rctl_ops_t;

#define	RCTLOP_ACTION(r, p, e) (r->rc_dict_entry->rcd_ops->rco_action(r, p, e))
#define	RCTLOP_GET_USAGE(r, p) (r->rc_dict_entry->rcd_ops->rco_get_usage(r, p))
#define	RCTLOP_SET(r, p, e, v) (r->rc_dict_entry->rcd_ops->rco_set(r, p, e, v))
#define	RCTLOP_TEST(r, p, e, v, i, f) \
	(r->rc_dict_entry->rcd_ops->rco_test(r, p, e, v, i, f))

/*
 * Default resource control callback functions.
 */
void rcop_no_action(struct rctl *, struct proc *, rctl_entity_p_t *);
rctl_qty_t rcop_no_usage(struct rctl *, struct proc *);
int rcop_no_set(struct rctl *, struct proc *, rctl_entity_p_t *, rctl_qty_t);
int rcop_no_test(struct rctl *, struct proc *, rctl_entity_p_t *,
    struct rctl_val *, rctl_qty_t, uint_t);
int rcop_absolute_test(struct rctl *, struct proc *, rctl_entity_p_t *,
    struct rctl_val *, rctl_qty_t, uint_t);

#define	RCTLOP_NO_USAGE(r) \
	(r->rc_dict_entry->rcd_ops->rco_get_usage == rcop_no_usage)

extern rctl_ops_t rctl_default_ops;
extern rctl_ops_t rctl_absolute_ops;

typedef struct rctl {
	struct rctl	*rc_next;		/* next in set hash chain    */
	rctl_val_t	*rc_values;		/* list of enforced value    */
	rctl_val_t	*rc_cursor;		/* currently enforced value  */
	struct rctl_dict_entry *rc_dict_entry;	/* global control properties */
	rctl_hndl_t	rc_id;			/* control handle (hash key) */
	rctl_val_t	*rc_projdb;		/* project database rctls    */
} rctl_t;

/*
 * The rctl_set is the collection of resource controls associated with an
 * individual entity within the system.  All of the controls are applicable to
 * the same entity, which we call out explicitly in rcs_entity.
 */
typedef struct rctl_set {
	kmutex_t	rcs_lock;		/* global set lock	  */
	rctl_entity_t	rcs_entity;		/* entity type		  */
	rctl_t		**rcs_ctls;		/* hash table of controls */
} rctl_set_t;

typedef struct rctl_dict_entry {
	struct rctl_dict_entry *rcd_next;	/* next in dict hash chain */
	char		*rcd_name;		/* resource control name */
	rctl_val_t	*rcd_default_value;	/* system control value */
	rctl_ops_t	*rcd_ops;		/* callback operations */
	rctl_hndl_t	rcd_id;			/* control handle */
	rctl_entity_t	rcd_entity;		/* entity type */
	int		rcd_flagaction;		/* global properties/actions */
	int		rcd_syslog_level;	/* event syslog level */
	int		rcd_strlog_flags;	/* derived from syslog level */
	rctl_qty_t	rcd_max_native;		/* native model "infinity" */
	rctl_qty_t	rcd_max_ilp32;		/* ILP32 model "infinity" */
} rctl_dict_entry_t;

typedef struct rctl_alloc_gp {
	uint_t	rcag_nctls;	/* number of rctls needed/allocated */
	uint_t	rcag_nvals;	/* number of rctl values needed/allocated */
	rctl_t	*rcag_ctls;	/* list of allocated rctls */
	rctl_val_t *rcag_vals;	/* list of allocated rctl values */
} rctl_alloc_gp_t;

extern kmem_cache_t *rctl_cache;	/* kmem cache for rctl structures */
extern kmem_cache_t *rctl_val_cache;	/* kmem cache for rctl values */

extern rctl_hndl_t rctlproc_legacy[];
extern uint_t rctlproc_flags[];
extern int rctlproc_signals[];

void rctl_init(void);
void rctlproc_init(void);
void rctlproc_default_init(struct proc *, rctl_alloc_gp_t *);

rctl_hndl_t rctl_register(const char *, rctl_entity_t, int, rctl_qty_t,
    rctl_qty_t, rctl_ops_t *);

rctl_hndl_t rctl_hndl_lookup(const char *);
rctl_dict_entry_t *rctl_dict_lookup(const char *);
rctl_dict_entry_t *rctl_dict_lookup_hndl(rctl_hndl_t);
void rctl_add_default_limit(const char *, rctl_qty_t, rctl_priv_t, uint_t);
void rctl_add_legacy_limit(const char *, const char *, const char *,
    rctl_qty_t, rctl_qty_t);

rctl_qty_t rctl_model_maximum(rctl_dict_entry_t *, struct proc *);
rctl_qty_t rctl_model_value(rctl_dict_entry_t *, struct proc *, rctl_qty_t);

int rctl_invalid_value(rctl_dict_entry_t *, rctl_val_t *);
rctl_qty_t rctl_enforced_value(rctl_hndl_t, rctl_set_t *, struct proc *);

int rctl_test(rctl_hndl_t, rctl_set_t *, struct proc *, rctl_qty_t, uint_t);
int rctl_action(rctl_hndl_t, rctl_set_t *, struct proc *, uint_t);

int rctl_test_entity(rctl_hndl_t, rctl_set_t *, struct proc *,
    rctl_entity_p_t *, rctl_qty_t, uint_t);
int rctl_action_entity(rctl_hndl_t, rctl_set_t *, struct proc *,
    rctl_entity_p_t *, uint_t);

int rctl_val_cmp(rctl_val_t *, rctl_val_t *, int);
int rctl_val_list_insert(rctl_val_t **, rctl_val_t *);

rctl_set_t *rctl_set_create(void);
rctl_set_t *rctl_entity_obtain_rset(rctl_dict_entry_t *, struct proc *);
rctl_alloc_gp_t *rctl_set_init_prealloc(rctl_entity_t);
rctl_set_t *rctl_set_init(rctl_entity_t, struct proc *, rctl_entity_p_t *,
    rctl_set_t *, rctl_alloc_gp_t *);
rctl_alloc_gp_t *rctl_set_dup_prealloc(rctl_set_t *);
int rctl_set_dup_ready(rctl_set_t *, rctl_alloc_gp_t *);
rctl_set_t *rctl_set_dup(rctl_set_t *, struct proc *, struct proc *,
    rctl_entity_p_t *, rctl_set_t *, rctl_alloc_gp_t *, int);
void rctl_set_reset(rctl_set_t *, struct proc *, rctl_entity_p_t *);
void rctl_set_tearoff(rctl_set_t *, struct proc *);
int rctl_set_find(rctl_set_t *, rctl_hndl_t, rctl_t **);
void rctl_set_free(rctl_set_t *);

void rctl_prealloc_destroy(rctl_alloc_gp_t *);

size_t rctl_build_name_buf(char **);

int rctl_global_get(const char *name, rctl_dict_entry_t *);
int rctl_global_set(const char *name, rctl_dict_entry_t *);

int rctl_local_delete(rctl_hndl_t, rctl_val_t *, struct proc *p);
int rctl_local_insert(rctl_hndl_t, rctl_val_t *, struct proc *p);
int rctl_local_insert_all(rctl_hndl_t, rctl_val_t *, rctl_val_t *,
    struct proc *p);
int rctl_local_replace_all(rctl_hndl_t, rctl_val_t *, rctl_val_t *,
    struct proc *p);
int rctl_local_get(rctl_hndl_t, rctl_val_t *, rctl_val_t *, struct proc *p);
int rctl_local_replace(rctl_hndl_t, rctl_val_t *, rctl_val_t *,
    struct proc *p);

/* tag declaration to appease the compiler */
struct cred;
rctl_alloc_gp_t *rctl_rlimit_set_prealloc(uint_t);
int rctl_rlimit_set(rctl_hndl_t, struct proc *, struct rlimit64 *,
    rctl_alloc_gp_t *, int, int, const struct cred *);
int rctl_rlimit_get(rctl_hndl_t, struct proc *, struct rlimit64 *);

/* specific rctl utility functions */
int rctl_incr_locked_mem(struct proc *, struct kproject *, rctl_qty_t,
    int);
void rctl_decr_locked_mem(struct proc *, struct kproject *, rctl_qty_t,
    int);
int rctl_incr_swap(struct proc *, struct zone *, size_t);
void rctl_decr_swap(struct zone *, size_t);

int rctl_incr_lofi(struct proc *, struct zone *, size_t);
void rctl_decr_lofi(struct zone *, size_t);

struct kstat *rctl_kstat_create_zone(struct zone *, char *, uchar_t, uint_t,
    uchar_t);

struct kstat *rctl_kstat_create_project(struct kproject *, char *, uchar_t,
    uint_t, uchar_t);

struct kstat *rctl_kstat_create_task(struct task *, char *, uchar_t,
    uint_t, uchar_t);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RCTL_H */
