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

/*
 * This file include internal used definition and data structure of hooks
 */

#ifndef _SYS_HOOK_IMPL_H
#define	_SYS_HOOK_IMPL_H

#include <sys/hook.h>
#include <sys/condvar_impl.h>
#include <sys/netstack.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum fwflag_e {
	FWF_NONE		= 0x00,
	FWF_DESTROY_ACTIVE	= 0x01,
	FWF_ADD_ACTIVE		= 0x04,
	FWF_DEL_ACTIVE		= 0x08,
	FWF_DESTROY_WANTED	= 0x10,
	FWF_ADD_WANTED		= 0x40,
	FWF_DEL_WANTED		= 0x80,
	FWF_NOT_READY		= 0x100
} fwflag_t;

#define	FWF_ADD_WAIT_MASK	(FWF_ADD_ACTIVE|FWF_DEL_ACTIVE|FWF_ADD_WANTED)
#define	FWF_DEL_WAIT_MASK	(FWF_ADD_ACTIVE|FWF_DEL_ACTIVE|\
    FWF_ADD_WANTED|FWF_DEL_WANTED)
#define	FWF_UNSAFE		(FWF_DESTROY_ACTIVE|FWF_NOT_READY)
#define	FWF_DESTROY		(FWF_DESTROY_ACTIVE|FWF_DESTROY_WANTED)
#define	FWF_DESTROY_OK(x)	((x)->fw_flags == FWF_DESTROY_WANTED)

typedef struct flagwait_s {
	kcondvar_t	fw_cv;
	kmutex_t	fw_lock;
	uint32_t	fw_flags;
	cvwaitlock_t	*fw_owner;
} flagwait_t;


/*
 * The following diagram describes the linking together of data structures
 * used in this implementation of callback hooks.  The start of it all is
 * the "familylist" variable in hook.c.  The relationships between data
 * structures is:
 * - there is a list of hook families;
 * - each hook family can have a list of hook events;
 * - each hook_event_t must be uniquely associated with one family and event;
 * - each hook event can have a list of registered hooks to call.
 *
 *   familylist                    +--------------+
 *       |                         | hook_event_t |<--\
 *       |                         +--------------+   |
 *       V                                            |
 * +-------------------+       ->+------------------+ |     ->+--------------+
 * | hook_family_int_t |      /  | hook_event_int_t | |    /  | hook_int_t   |
 * | +---------------+ |     /   |                  | /   /   | +----------+ |
 * | | hook_family_t | |    /    | hei_event---------/   /    | | hook_t   | |
 * | +---------------+ |   /     | hei_nhead----------\ /     | +----------+ |
 * |                   |  /      |                  |  X      |              |
 * | hfi_head------------/       | hei_head-----------/ \     | hi_entry--\  |
 * | hfi_entry--\      |         | hei_entry--\     |   |     +-----------|--+
 * +------------|------+         +------------|-----+   |                 |
 *              |                             |         |                 |
 *              V                             V         |                 V
 * +-------------------+         +------------------+   |     +--------------+
 * | hook_family_int_t |         | hook_event_int_t |   |     | hook_int_t   |
 *                                                      V
 *                                             +--------------+
 *                                             |
 * ...
 */

typedef struct hook_hook_kstat {
	kstat_named_t			hook_version;
	kstat_named_t			hook_flags;
	kstat_named_t			hook_hint;
	kstat_named_t			hook_hintvalue;
	kstat_named_t			hook_position;
	kstat_named_t			hook_hits;
} hook_hook_kstat_t;

/*
 * hook_int: internal storage of hook
 */
typedef struct hook_int {
	TAILQ_ENTRY(hook_int)		hi_entry;
	hook_t				hi_hook;
	hook_hook_kstat_t		hi_kstats;
	kstat_t				*hi_kstatp;
	char				*hi_ksname;
	cvwaitlock_t			hi_notify_lock;
} hook_int_t;

/*
 * hook_int_head: tail queue of hook_int
 */
TAILQ_HEAD(hook_int_head, hook_int);
typedef struct hook_int_head hook_int_head_t;


typedef struct hook_notify {
	TAILQ_ENTRY(hook_notify)	hn_entry;
	hook_notify_fn_t		hn_func;
	void				*hn_arg;
	uint32_t			hn_flags;
} hook_notify_t;

TAILQ_HEAD(hook_notify_head, hook_notify);
typedef struct hook_notify_head hook_notify_head_t;


typedef struct hook_event_kstat {
	kstat_named_t			hooks_added;
	kstat_named_t			hooks_removed;
	kstat_named_t			events;
} hook_event_kstat_t;

/*
 * hook_event_int: internal storage of hook_event
 */
typedef struct hook_event_int {
	cvwaitlock_t			hei_lock;
	SLIST_ENTRY(hook_event_int)	hei_entry;
	hook_event_t			*hei_event;
	hook_int_head_t			hei_head;
	kstat_t				*hei_kstatp;
	hook_event_kstat_t		hei_kstats;
	hook_notify_head_t		hei_nhead;
	flagwait_t			hei_waiter;
	boolean_t			hei_condemned;
	boolean_t			hei_shutdown;
} hook_event_int_t;

/*
 * hook_event_int_head: singly-linked list of hook_event_int
 */
SLIST_HEAD(hook_event_int_head, hook_event_int);
typedef struct hook_event_int_head hook_event_int_head_t;

/*
 * hook_family_int: internal storage of hook_family
 */
typedef struct hook_family_int {
	cvwaitlock_t			hfi_lock;
	SLIST_ENTRY(hook_family_int)	hfi_entry;
	hook_event_int_head_t		hfi_head;
	hook_family_t 			hfi_family;
	kstat_t				*hfi_kstat;
	struct hook_stack		*hfi_stack;
	hook_notify_head_t		hfi_nhead;
	flagwait_t			hfi_waiter;
	boolean_t			hfi_condemned;
	boolean_t			hfi_shutdown;
} hook_family_int_t;

/*
 * hook_family_int_head: singly-linked list of hook_family
 */
SLIST_HEAD(hook_family_int_head, hook_family_int);
typedef struct hook_family_int_head hook_family_int_head_t;

/*
 * hook stack instances
 */
struct hook_stack {
	cvwaitlock_t			hks_lock;
	SLIST_ENTRY(hook_stack)		hks_entry;
	hook_family_int_head_t		hks_familylist;	/* family list head */
	netstack_t			*hks_netstack;
	netstackid_t			hks_netstackid;
	hook_notify_head_t		hks_nhead;
	int				hks_shutdown;
	flagwait_t			hks_waiter;
};
typedef struct hook_stack hook_stack_t;
SLIST_HEAD(hook_stack_head, hook_stack);
typedef struct hook_stack_head hook_stack_head_t;

/*
 * Names of hooks families currently defined by Solaris
 */
#define	Hn_ARP	"arp"
#define	Hn_IPV4	"inet"
#define	Hn_IPV6	"inet6"

extern int hook_run(hook_family_int_t *, hook_event_token_t, hook_data_t);
extern int hook_register(hook_family_int_t *, char *, hook_t *);

extern int hook_unregister(hook_family_int_t *, char *, hook_t *);
extern hook_event_int_t *hook_event_add(hook_family_int_t *, hook_event_t *);
extern int hook_event_notify_register(hook_family_int_t *, char *,
    hook_notify_fn_t, void *);
extern int hook_event_notify_unregister(hook_family_int_t *, char *,
    hook_notify_fn_t);
extern int hook_event_remove(hook_family_int_t *, hook_event_t *);
extern int hook_event_shutdown(hook_family_int_t *, hook_event_t *);

extern hook_family_int_t *hook_family_add(hook_family_t *, hook_stack_t *,
    void **);
extern int hook_family_notify_register(hook_family_int_t *, hook_notify_fn_t,
    void *);
extern int hook_family_notify_unregister(hook_family_int_t *, hook_notify_fn_t);
extern int hook_family_remove(hook_family_int_t *);
extern int hook_family_shutdown(hook_family_int_t *);

extern int hook_stack_notify_register(netstackid_t, hook_notify_fn_t, void *);
extern int hook_stack_notify_unregister(netstackid_t, hook_notify_fn_t);


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_HOOK_IMPL_H */
