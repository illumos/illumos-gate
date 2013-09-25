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
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_SUNLDI_IMPL_H
#define	_SYS_SUNLDI_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/dditypes.h>
#include <sys/vnode.h>

/*
 * NOTE
 *
 * The contents of this file are private to this implementation
 * of Solaris and are subject to change at any time without notice.
 *
 * Applications and drivers using these interfaces will fail
 * to run on future releases.
 */

/*
 * LDI hash definitions
 */
#define	LH_HASH_SZ	32
#define	LI_HASH_SZ	32

/*
 * Obsolete LDI event interfaces are available for now but are deprecated and a
 * warning will be issued to consumers.
 */
#define	LDI_OBSOLETE_EVENT	1

/*
 * Flag for LDI handle's lh_flags field
 */
#define	LH_FLAGS_NOTIFY	0x0001		/* invoked in context of a notify */

/*
 * LDI initialization function
 */
void ldi_init(void);

/*
 * LDI streams linking interfaces
 */
extern int ldi_mlink_lh(vnode_t *, int, intptr_t, cred_t *, int *);
extern void ldi_mlink_fp(struct stdata *, struct file *, int, int);
extern void ldi_munlink_fp(struct stdata *, struct file *, int);

/*
 * LDI module identifier
 */
struct ldi_ident {
	/* protected by ldi_ident_hash_lock */
	struct ldi_ident		*li_next;
	uint_t				li_ref;

	/* unique/static fields in the ident */
	char				li_modname[MODMAXNAMELEN];
	modid_t				li_modid;
	major_t				li_major;
	dev_info_t			*li_dip;
	dev_t				li_dev;
};

/*
 * LDI handle
 */
struct ldi_handle {
	/* protected by ldi_handle_hash_lock */
	struct ldi_handle		*lh_next;
	uint_t				lh_ref;
	uint_t				lh_flags;

	/* unique/static fields in the handle */
	uint_t				lh_type;
	struct ldi_ident		*lh_ident;
	vnode_t				*lh_vp;

#ifdef	LDI_OBSOLETE_EVENT
	/* fields protected by lh_lock */
	kmutex_t			lh_lock[1];
	struct ldi_event		*lh_events;
#endif
};

/*
 * LDI event information
 */
#ifdef	LDI_OBSOLETE_EVENT
typedef struct ldi_event {
	/* fields protected by le_lhp->lh_lock */
	struct ldi_event	*le_next;
	struct ldi_event	*le_prev;

	/* unique/static fields in the handle */
	struct ldi_handle	*le_lhp;
	void			(*le_handler)();
	void			*le_arg;
	ddi_callback_id_t	le_id;
} ldi_event_t;
#endif

typedef struct ldi_ev_callback_impl {
	struct ldi_handle	*lec_lhp;
	dev_info_t		*lec_dip;
	dev_t			lec_dev;
	int			lec_spec;
	int			(*lec_notify)();
	void			(*lec_finalize)();
	void			*lec_arg;
	void			*lec_cookie;
	void			*lec_id;
	list_node_t		lec_list;
} ldi_ev_callback_impl_t;

/*
 * Members of "struct ldi_ev_callback_list" are protected by their le_lock
 * member.  The struct is currently only used once, as a file-level global,
 * and the locking protocol is currently implemented in ldi_ev_lock() and
 * ldi_ev_unlock().
 *
 * When delivering events to subscribers, ldi_invoke_notify() and
 * ldi_invoke_finalize() will walk the list of callbacks: le_head.  It is
 * possible that an invoked callback function will need to unregister an
 * arbitrary number of callbacks from this list.
 *
 * To enable ldi_ev_remove_callbacks() to remove elements from the list
 * without breaking the walk-in-progress, we store the next element in the
 * walk direction on the struct as le_walker_next and le_walker_prev.
 */
struct ldi_ev_callback_list {
	kmutex_t		le_lock;
	kcondvar_t		le_cv;
	int			le_busy;
	void			*le_thread;
	list_t			le_head;
	ldi_ev_callback_impl_t	*le_walker_next;
	ldi_ev_callback_impl_t	*le_walker_prev;
};

int ldi_invoke_notify(dev_info_t *dip, dev_t dev, int spec_type, char *event,
    void *ev_data);
void ldi_invoke_finalize(dev_info_t *dip, dev_t dev, int spec_type, char *event,
    int ldi_result, void *ev_data);
int e_ddi_offline_notify(dev_info_t *dip);
void e_ddi_offline_finalize(dev_info_t *dip, int result);


/*
 * LDI device usage interfaces
 *
 * ldi_usage_count(), ldi_usage_walker(), and ldi_usage_t
 *
 * These functions are used by the devinfo driver and fuser to get a
 * device usage information from the LDI. These functions along with
 * the ldi_usage_t data structure allow these other subsystems to have
 * no knowledge of how the LDI stores it's internal state.
 *
 * ldi_usage_count() provides an count of how many kernel
 *	device clients currently exist.
 *
 * ldi_usage_walker() reports all kernel device usage information.
 */
#define	LDI_USAGE_CONTINUE	0
#define	LDI_USAGE_TERMINATE	1

typedef struct ldi_usage {
	/*
	 * information about the kernel subsystem that is accessing
	 * the target device
	 */
	modid_t		src_modid;
	char		*src_name;
	dev_info_t	*src_dip;
	dev_t		src_devt;

	/*
	 * information about the target device that is open
	 */
	modid_t		tgt_modid;
	char		*tgt_name;
	dev_info_t	*tgt_dip;
	dev_t		tgt_devt;
	int		tgt_spec_type;
} ldi_usage_t;

int ldi_usage_count();
void ldi_usage_walker(void *arg,
    int (*callback)(const ldi_usage_t *ldi_usage, void *arg));

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_SUNLDI_IMPL_H */
