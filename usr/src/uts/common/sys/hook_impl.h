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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file include internal used definition and data structure of hooks
 */

#ifndef _SYS_HOOK_IMPL_H
#define	_SYS_HOOK_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/hook.h>
#include <sys/condvar_impl.h>
#include <sys/netstack.h>

#ifdef	__cplusplus
extern "C" {
#endif

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
 * | +---------------+ |   /     |                  |   /     | +----------+ |
 * |                   |  /      |                  |  /      |              |
 * | hfi_head------------/       | hei_head-----------/       | hi_entry--\  |
 * | hfi_entry--\      |         | hei_entry--\     |         +-----------|--+
 * +------------|------+         +------------|-----+                     |
 *              |                             |                           |
 *              V                             V                           V
 * +-------------------+         +------------------+         +--------------+
 * | hook_family_int_t |         | hook_event_int_t |         | hook_int_t   |
 * ...
 */

/*
 * hook_int: internal storage of hook
 */
typedef struct hook_int {
	TAILQ_ENTRY(hook_int)	hi_entry;
	hook_t			hi_hook;
} hook_int_t;

/*
 * Hook_int_head: tail queue of hook_int
 */
TAILQ_HEAD(hook_int_head, hook_int);
typedef struct hook_int_head hook_int_head_t;

/*
 * hook_event_int: internal storage of hook_event
 */
typedef struct hook_event_int {
	cvwaitlock_t			hei_lock;
	SLIST_ENTRY(hook_event_int)	hei_entry;
	hook_event_t			*hei_event;
	hook_int_head_t			hei_head;
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
	SLIST_ENTRY(hook_family_int)	hfi_entry;
	hook_event_int_head_t		hfi_head;
	hook_family_t 			hfi_family;
	void				*hfi_ptr;
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
	cvwaitlock_t hks_familylock;		/* global lock */
	hook_family_int_head_t hks_familylist;	/* family list head */
	netstack_t *hk_netstack;
};
typedef struct hook_stack hook_stack_t;

/*
 * Names of hooks families currently defined by Solaris
 */
#define	Hn_ARP	"arp"
#define	Hn_IPV4	"inet"
#define	Hn_IPV6	"inet6"

extern hook_family_int_t *hook_family_add(hook_family_t *, hook_stack_t *);
extern int hook_family_remove(hook_family_int_t *);
extern hook_event_int_t *hook_event_add(hook_family_int_t *, hook_event_t *);
extern int hook_event_remove(hook_family_int_t *, hook_event_t *);
extern int hook_register(hook_family_int_t *, char *, hook_t *);
extern int hook_unregister(hook_family_int_t *, char *, hook_t *);
extern int hook_run(hook_event_token_t, hook_data_t, netstack_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_HOOK_IMPL_H */
