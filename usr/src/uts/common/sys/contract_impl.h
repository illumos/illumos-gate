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

#ifndef	_SYS_CONTRACT_IMPL_H
#define	_SYS_CONTRACT_IMPL_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/poll.h>
#include <sys/condvar.h>
#include <sys/contract.h>
#include <sys/model.h>
#include <sys/cred.h>
#include <sys/mutex.h>
#include <sys/list.h>
#include <sys/avl.h>
#include <sys/nvpair.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/zone.h>
#include <sys/project.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int ct_debug;

#define	CT_DEBUG(args)	if (ct_debug) cmn_err args

#ifdef _SYSCALL32

/*
 * 32-bit versions of the event, status and parameter structures, for use
 * (only) by the 64-bit kernel.  See sys/contract.h for the normal versions.
 * Use pack(4) to get offsets and structure size correct on amd64.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct ct_event32 {
	ctid_t	ctev_id;
	uint32_t ctev_pad1;
	ctevid_t ctev_evid;
	ct_typeid_t ctev_cttype;
	uint32_t ctev_flags;
	uint32_t ctev_type;
	uint32_t ctev_nbytes;
	uint32_t ctev_goffset;
	uint32_t ctev_pad2;
	caddr32_t ctev_buffer;
} ct_event32_t;

typedef struct ct_status32 {
	ctid_t	ctst_id;
	zoneid_t ctst_zoneid;
	ct_typeid_t ctst_type;
	pid_t	ctst_holder;
	ctstate_t ctst_state;
	int	ctst_nevents;
	int	ctst_ntime;
	int	ctst_qtime;
	uint64_t ctst_nevid;
	uint_t	ctst_detail;
	uint_t	ctst_nbytes;
	uint_t	ctst_critical;
	uint_t	ctst_informative;
	uint64_t ctst_cookie;
	caddr32_t ctst_buffer;
} ct_status32_t;

typedef struct ct_param32 {
	uint32_t  ctpm_id;
	uint32_t  ctpm_size;
	caddr32_t ctpm_value;
} ct_param32_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif /* _SYSCALL32 */

/*
 * in kernel version of parameter structure.
 */
typedef struct ct_kparam {
	ct_param_t	param;		/* copy of user ct_param_t */
	void		*ctpm_kbuf;	/* kernel buffer for parameter value */
	uint32_t	ret_size;	/* parameter value size for copyout */
} ct_kparam_t;

struct proc;

/*
 * Contract template ops vector
 */
typedef struct ctmplops {
	struct ct_template	*(*ctop_dup)(struct ct_template *);
	void		(*ctop_free)(struct ct_template *);
	int		(*ctop_set)(struct ct_template *, ct_kparam_t *,
			const cred_t *);
	int		(*ctop_get)(struct ct_template *, ct_kparam_t *);
	int		(*ctop_create)(struct ct_template *, ctid_t *);
	uint_t		allevents;
} ctmplops_t;

/*
 * Contract template
 */
typedef struct ct_template {
	kmutex_t	ctmpl_lock;
	ctmplops_t	*ctmpl_ops;
	struct ct_type	*ctmpl_type;
	void		*ctmpl_data;
	uint64_t	ctmpl_cookie;	/* term: contract cookie */
	uint_t		ctmpl_ev_crit;	/* term: critical events */
	uint_t		ctmpl_ev_info;	/* term: informative events */
} ct_template_t;


typedef enum ct_listnum {
	CTEL_CONTRACT,			/* ../contracts/type/<id>/events */
	CTEL_BUNDLE,			/* ../contracts/type/bundle */
	CTEL_PBUNDLE,			/* ../contracts/type/pbundle */
	CTEL_MAX
} ct_listnum_t;

typedef enum ctqflags {
	CTQ_DEAD = 1,	/* contract explicitly cancelled */
	CTQ_REFFED = 2	/* queue is reference counted */
} ctqflags_t;

typedef enum ct_ack {
	CT_ACK = 1,	/* accept break */
	CT_NACK,	/* disallow break */
	CT_NONE		/* no matching contracts */
} ct_ack_t;

/*
 * Contract event queue
 */
typedef struct ct_equeue {
	kmutex_t ctq_lock;
	timespec_t ctq_atime;		/* access time */
	ct_listnum_t ctq_listno;	/* which list node */
	list_t	ctq_events;		/* list of events */
	list_t	ctq_listeners;		/* list of all listeners */
	list_t	ctq_tail;		/* list of tail listeners */
	int	ctq_nlisteners;		/* number of listeners */
	int	ctq_nreliable;		/* number of reliable listeners */
	int	ctq_ninf;		/* number of informative events */
	int	ctq_max;		/* max informative events */
	ctqflags_t ctq_flags;		/* queue flags */
} ct_equeue_t;

typedef struct ct_member {
	list_node_t	ctm_node;	/* list membership */
	int		ctm_refs;	/* number of references per list */
	int		ctm_trimmed;	/* membership has been trimmed */
	int		ctm_nreliable;	/* reliable listeners */
} ct_member_t;

typedef struct ct_kevent {
	kmutex_t	cte_lock;
	uint64_t	cte_id;		/* event id */
	uint_t		cte_type;	/* event type */
	int		cte_refs;
	ct_member_t	cte_nodes[CTEL_MAX]; /* event queue membership */
	int		cte_flags;	/* see above */
	nvlist_t 	*cte_data;	/* event data */
	nvlist_t 	*cte_gdata;	/* global-zone only data */

	struct contract	*cte_contract;	/* contract */
} ct_kevent_t;

/*
 * Contract vnode linkage.
 * Avoid having too much knowledge about the FS.
 */
typedef struct contract_vnode {
	list_node_t	ctv_node;
	vnode_t		*ctv_vnode;
} contract_vnode_t;

/*
 * Contract ops vector
 *   free - when reference count drops to zero
 *   abandon - when holding process dies or relinquishes interest
 *   destroy - when contract is to be completely destroyed
 *   status - when contractfs needs to return detailed status information
 */
typedef struct contops {
	void	(*contop_free)(struct contract *);
	void	(*contop_abandon)(struct contract *);
	void	(*contop_destroy)(struct contract *);
	void	(*contop_status)(struct contract *, zone_t *, int, nvlist_t *,
	    void *, model_t);
	int	(*contop_ack)(struct contract *, uint_t evtype,
	    uint64_t evid);
	int	(*contop_nack)(struct contract *, uint_t evtype,
	    uint64_t evid);
	int	(*contop_qack)(struct contract *, uint_t, uint64_t);
	int	(*contop_newct)(struct contract *);
} contops_t;

typedef ct_template_t *(ct_f_default_t)(void);

/*
 * Contract type information.
 */
typedef struct ct_type {
	uint64_t	ct_type_evid;	/* last event id */
	ct_typeid_t	ct_type_index;	/* index in ct_types array */
	const char	*ct_type_name;	/* type as a string */
	kmutex_t	ct_type_lock;	/* protects ct_type_avl */
	avl_tree_t	ct_type_avl;	/* ordered list of type contracts */
	timestruc_t	ct_type_timestruc; /* time last contract was written */
	ct_equeue_t	ct_type_events;	/* bundle queue */
	contops_t	*ct_type_ops;
	ct_f_default_t	*ct_type_default; /* creates a fresh template */
} ct_type_t;

typedef enum ctflags {
	CTF_INHERIT = 0x1
} ctflags_t;

typedef struct ct_time {
	long	ctm_total;	/* Total time allowed for event */
	clock_t	ctm_start;	/* starting lbolt for event */
} ct_time_t;

/*
 * Contract
 */
typedef struct contract {
	uint64_t	ct_ref;		/* reference count */
	kmutex_t	ct_reflock;	/* reference count lock */
	kmutex_t	ct_evtlock;	/* event dispatch lock */

					/* Static data */
	kproject_t	*ct_proj;	/* project of creator */
	uid_t		ct_cuid;	/* uid of contract author */
	zoneid_t	ct_zoneid;	/* zoneid of creator */
	uint64_t	ct_czuniqid;	/* unique id of creator's zone */
	timespec_t	ct_ctime;	/* creation time */
	ct_type_t	*ct_type;	/* contract type information */
	void		*ct_data;	/* contract type data */
	ctid_t		ct_id;		/* contract ID */
	uint64_t	ct_cookie;	/* term: contract cookie */
	uint_t		ct_ev_crit;	/* term: critical events */
	uint_t		ct_ev_info;	/* term: informative events */

					/* Protected by other locks */
	uint64_t	ct_mzuniqid;	/* unique id of members' zone */
	avl_node_t	ct_ctavl;	/* avl membership */
	avl_node_t	ct_cttavl;	/* type avl membership */
	avl_node_t	ct_ctlist;	/* position in holder's list */

	kmutex_t	ct_lock;	/* lock for everything below */
	ctstate_t	ct_state;	/* contract's state */
	list_t		ct_vnodes;	/* vnodes list */
	ctflags_t	ct_flags;	/* contract flags */
	ct_equeue_t	ct_events;	/* contract event queue */
	struct proc	*ct_owner;	/* contract owner (if owned) */
	struct contract	*ct_regent;	/* [prospective] regent contract */
	int		ct_evcnt;	/* number of critical events */
	ct_kevent_t	*ct_nevent;	/* negotiation event */
	ct_time_t	ct_ntime;	/* negotiation time tracker */
	ct_time_t	ct_qtime;	/* quantum time tracker */
} contract_t;

#define	CTLF_COPYOUT	0x1		/* performing copyout */
#define	CTLF_RESET	0x2		/* event pointer reset or moved */
#define	CTLF_DEAD	0x4		/* dead listener */
#define	CTLF_RELIABLE	0x8		/* reliable listener */
#define	CTLF_CRITICAL	0x10		/* waiting for critical event */

typedef struct ct_listener {
	list_node_t	ctl_allnode;	/* entry in list of all listeners */
	list_node_t	ctl_tailnode;	/* entry in list of tail listeners */
	ct_equeue_t	*ctl_equeue;	/* queue */
	ct_kevent_t	*ctl_position;	/* position in queue */
	int		ctl_flags;	/* state flags */
	kcondvar_t	ctl_cv;		/* for waiting for an event */
	pollhead_t	ctl_pollhead;	/* so we can poll(2) */
} ct_listener_t;

/*
 * Contract template interfaces
 */
void ctmpl_free(ct_template_t *);
int ctmpl_set(ct_template_t *, ct_kparam_t *, const cred_t *);
int ctmpl_get(ct_template_t *, ct_kparam_t *);
ct_template_t *ctmpl_dup(ct_template_t *);
void ctmpl_activate(ct_template_t *);
void ctmpl_clear(ct_template_t *);
int ctmpl_create(ct_template_t *, ctid_t *);

/*
 * Contract parameter functions
 */
int ctparam_copyin(const void *, ct_kparam_t *, int, int);
int ctparam_copyout(ct_kparam_t *, void *, int);

/*
 * Contract functions
 */
void contract_init(void);
int contract_abandon(contract_t *, struct proc *, int);
int contract_adopt(contract_t *, struct proc *);
void contract_destroy(contract_t *);
void contract_exit(struct proc *);
int contract_ack(contract_t *ct, uint64_t evid, int cmd);
int contract_qack(contract_t *ct, uint64_t evid);
int contract_newct(contract_t *ct);

/*
 * Event interfaces
 */
uint64_t cte_publish_all(contract_t *, ct_kevent_t *, nvlist_t *, nvlist_t *);
void cte_add_listener(ct_equeue_t *, ct_listener_t *);
void cte_remove_listener(ct_listener_t *);
void cte_reset_listener(ct_listener_t *);
int cte_get_event(ct_listener_t *, int, void *, const cred_t *, uint64_t, int);
int cte_next_event(ct_listener_t *, uint64_t);
int cte_set_reliable(ct_listener_t *, const cred_t *);

/*
 * Contract implementation interfaces
 */
int contract_compar(const void *, const void *);
void ctmpl_init(ct_template_t *, ctmplops_t *, ct_type_t *, void *);
void ctmpl_copy(ct_template_t *, ct_template_t *);
int ctmpl_create_inval(ct_template_t *, ctid_t *);
int contract_ctor(contract_t *, ct_type_t *, ct_template_t *, void *, ctflags_t,
    struct proc *, int);
void contract_hold(contract_t *);
void contract_rele(contract_t *);
uint64_t contract_getzuniqid(contract_t *);
void contract_setzuniqid(contract_t *, uint64_t);
void contract_rele_unlocked(contract_t *);
void contract_status_common(contract_t *, zone_t *, void *, model_t);
void contract_orphan(contract_t *);
ctid_t contract_lookup(uint64_t, ctid_t);
ctid_t contract_plookup(struct proc *, ctid_t, uint64_t);
contract_t *contract_ptr(id_t, uint64_t);
ctid_t contract_max(void);
int contract_owned(contract_t *, const cred_t *, int);

/*
 * Type interfaces
 */
extern int ct_ntypes;
extern ct_type_t **ct_types;

ct_type_t *contract_type_init(ct_typeid_t, const char *, contops_t *,
    ct_f_default_t *);
int contract_type_count(ct_type_t *);
ctid_t contract_type_max(ct_type_t *);
ctid_t contract_type_lookup(ct_type_t *, uint64_t, ctid_t);
contract_t *contract_type_ptr(ct_type_t *, ctid_t, uint64_t);
void contract_type_time(ct_type_t *, timestruc_t *);
ct_equeue_t *contract_type_bundle(ct_type_t *);
ct_equeue_t *contract_type_pbundle(ct_type_t *, struct proc *);

/*
 * FS interfaces
 */
vnode_t *contract_vnode_get(contract_t *, vfs_t *);
void contract_vnode_set(contract_t *, contract_vnode_t *, vnode_t *);
int contract_vnode_clear(contract_t *, contract_vnode_t *);

/*
 * Negotiation stubs
 */
int contract_ack_inval(contract_t *, uint_t, uint64_t);
int contract_qack_inval(contract_t *, uint_t, uint64_t);
int contract_qack_notsup(contract_t *, uint_t, uint64_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONTRACT_IMPL_H */
