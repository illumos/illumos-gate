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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/disp.h>
#include <sys/list.h>
#include <sys/mutex.h>
#include <sys/note.h>
#include <sys/rwlock.h>
#include <sys/stropts.h>
#include <sys/taskq.h>
#include <sys/socketvar.h>
#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/sockfilter_impl.h>

/*
 * Socket Filter Framework
 *
 * Socket filter entry (sof_entry_t):
 *
 *   There exists one entry for each configured filter (done via soconfig(1M)),
 *   and they are all in sof_entry_list. In addition to the global list, each
 *   sockparams entry maintains a list of filters that is interested in that
 *   particular socket type. So the filter entry may be referenced by multiple
 *   sockparams. The set of sockparams referencing a filter may change as
 *   socket types are added and/or removed from the system. Both sof_entry_list
 *   and the sockparams list is protected by sockconf_lock.
 *
 *   Each filter entry has a ref count which is incremented whenever a filter
 *   is attached to a socket. An entry is marked SOFEF_CONDEMED when it is
 *   unconfigured, which will result in the entry being freed when its ref
 *   count reaches zero.
 *
 * Socket filter module (sof_module_t):
 *
 *   Modules are created by sof_register() and placed in sof_module_list,
 *   which is protected by sof_module_lock. Each module has a reference count
 *   that is incremented when a filter entry is using the module. A module
 *   can be destroyed by sof_unregister() only when its ref count is zero.
 *
 * Socket filter instance (sof_instance_t):
 *
 *   Whenever a filter is attached to a socket (sonode), a new instance is
 *   created. The socket is guaranteed to be single threaded when filters are
 *   being attached/detached. The instance uses the sonode's so_lock for
 *   protection.
 *
 *   The lifetime of an instance is the same as the socket it's attached to.
 *
 * How things link together:
 *
 *      sockparams.sp_{auto,prog}_filters -> sp_filter_t -> sp_filter_t
 *      ^                                    |              |
 *      |                                    |              |
 *   sonode.so_filter_top -> sof_instance_t  |              |
 *                                     |     |              |
 *                                     v     v              v
 *    sof_entry_list -> sof_entry_t -> sof_entry -> ... -> sof_entry_t
 *                                     |
 *                                     v
 *           sof_module_list -> sof_module_t -> ... -> sof_module_t
 */

static list_t	sof_entry_list;		/* list of configured filters */

static list_t	sof_module_list;	/* list of loaded filter modules */
static kmutex_t	sof_module_lock;	/* protect the module list */

static sof_kstat_t	sof_stat;
static kstat_t		*sof_stat_ksp;

#ifdef DEBUG
static int socket_filter_debug = 0;
#endif

/*
 * A connection that has been deferred for more than `sof_defer_drop_time'
 * ticks can be dropped to make room for new connections. A connection that
 * is to be dropped is moved over to `sof_close_deferred_list' where it will
 * be closed by sof_close_deferred() (which is running on a taskq). Connections
 * will not be moved over to the close list if it grows larger than
 * `sof_close_deferred_max_backlog'.
 */
clock_t		sof_defer_drop_time = 3000;
uint_t		sof_close_deferred_max_backlog = 1000;

taskq_t		*sof_close_deferred_taskq;
boolean_t	sof_close_deferred_running;
uint_t		sof_close_deferred_backlog;
list_t		sof_close_deferred_list;
kmutex_t	sof_close_deferred_lock;

static void	sof_close_deferred(void *);

static void		sof_module_rele(sof_module_t *);
static sof_module_t	*sof_module_hold_by_name(const char *, const char *);

static int		sof_entry_load_module(sof_entry_t *);
static void		sof_entry_hold(sof_entry_t *);
static void		sof_entry_rele(sof_entry_t *);
static int		sof_entry_kstat_create(sof_entry_t *);
static void		sof_entry_kstat_destroy(sof_entry_t *);

static sof_instance_t	*sof_instance_create(sof_entry_t *, struct sonode *);
static void		sof_instance_destroy(sof_instance_t *);

static int
sof_kstat_update(kstat_t *ksp, int rw)
{
	_NOTE(ARGUNUSED(ksp));

	if (rw == KSTAT_WRITE)
		return (EACCES);

	sof_stat.sofks_defer_close_backlog.value.ui64 =
	    sof_close_deferred_backlog;

	return (0);
}

void
sof_init(void)
{
	list_create(&sof_entry_list, sizeof (sof_entry_t),
	    offsetof(sof_entry_t, sofe_node));
	list_create(&sof_module_list, sizeof (sof_module_t),
	    offsetof(sof_module_t, sofm_node));
	list_create(&sof_close_deferred_list, sizeof (struct sonode),
	    offsetof(struct sonode, so_acceptq_node));

	sof_close_deferred_taskq = taskq_create("sof_close_deferred_taskq",
	    1, minclsyspri, 1, INT_MAX, TASKQ_PREPOPULATE);
	sof_close_deferred_running = B_FALSE;
	sof_close_deferred_backlog = 0;

	mutex_init(&sof_close_deferred_lock, NULL, MUTEX_DEFAULT, 0);
	mutex_init(&sof_module_lock, NULL, MUTEX_DEFAULT, 0);

	sof_stat_ksp = kstat_create("sockfs", 0, "sockfilter", "misc",
	    KSTAT_TYPE_NAMED, sizeof (sof_kstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (sof_stat_ksp == NULL)
		return;

	kstat_named_init(&sof_stat.sofks_defer_closed, "defer_closed",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&sof_stat.sofks_defer_close_backlog,
	    "defer_close_backlog", KSTAT_DATA_UINT64);
	kstat_named_init(&sof_stat.sofks_defer_close_failed_backlog_too_big,
	    "defer_close_failed_backlog_too_big", KSTAT_DATA_UINT64);

	sof_stat_ksp->ks_data = &sof_stat;
	sof_stat_ksp->ks_update = sof_kstat_update;
	kstat_install(sof_stat_ksp);
}

/*
 * Process filter options.
 */
static int
sof_setsockopt_impl(struct sonode *so, int option_name,
    const void *optval, socklen_t optlen, struct cred *cr)
{
	struct sockparams *sp = so->so_sockparams;
	sof_entry_t *ent = NULL;
	sp_filter_t *fil;
	sof_instance_t *inst;
	sof_rval_t rval;
	int error;

	_NOTE(ARGUNUSED(optlen));

	/*
	 * Is the filter in a state where filters can be attached?
	 */
	if (!(so->so_state & SS_FILOP_OK))
		return (EINVAL);

	if (option_name == FIL_ATTACH) {
		/*
		 * Make sure there isn't already another instance of the
		 * same filter attached to the socket.
		 */
		for (inst = so->so_filter_top; inst != NULL;
		    inst = inst->sofi_next) {
			if (strncmp(inst->sofi_filter->sofe_name,
			    (const char *)optval, SOF_MAXNAMELEN) == 0)
				return (EEXIST);
		}
		/* Look up the filter. */
		rw_enter(&sockconf_lock, RW_READER);
		for (fil = list_head(&sp->sp_prog_filters); fil != NULL;
		    fil = list_next(&sp->sp_prog_filters, fil)) {
			ent = fil->spf_filter;
			ASSERT(ent->sofe_flags & SOFEF_PROG);

			if (strncmp(ent->sofe_name, (const char *)optval,
			    SOF_MAXNAMELEN) == 0)
				break;
		}
		/* No such filter */
		if (fil == NULL) {
			rw_exit(&sockconf_lock);
			return (ENOENT);
		}
		inst = sof_instance_create(ent, so);
		rw_exit(&sockconf_lock);

		/* Failed to create an instance; must be out of memory */
		if (inst == NULL)
			return (ENOMEM);

		/*
		 * This might be the first time the filter is being used,
		 * so try to load the module if it's not already registered.
		 */
		if (ent->sofe_mod == NULL &&
		    (error = sof_entry_load_module(ent)) != 0) {
			sof_instance_destroy(inst);
			return (error);
		}

		/* Module loaded OK, so there must be an ops vector */
		ASSERT(ent->sofe_mod != NULL);

		/*
		 * Check again to confirm ATTACH is ok. See if the the module
		 * is not SOF_ATT_SAFE after an unsafe operation has taken
		 * place.
		 */
		if ((ent->sofe_mod->sofm_flags & SOF_ATT_SAFE) == 0 &&
		    so->so_state & SS_FILOP_UNSF) {
			sof_instance_destroy(inst);
			return (EINVAL);
		}

		inst->sofi_ops = &ent->sofe_mod->sofm_ops;

		SOF_STAT_ADD(inst, tot_active_attach, 1);
		if (inst->sofi_ops->sofop_attach_active != NULL) {
			rval = inst->sofi_ops->sofop_attach_active(
			    (sof_handle_t)inst, so->so_family, so->so_type,
			    so->so_protocol, cr, &inst->sofi_cookie);
			if (rval != SOF_RVAL_CONTINUE) {
				switch (rval) {
				case SOF_RVAL_DETACH:
					/*
					 * Filter does not want to to attach.
					 * An error is returned so the user
					 * knows the request did not go
					 * through.
					 */
					error = EINVAL;
					break;
				default:
					SOF_STAT_ADD(inst, attach_failures, 1);
					/* Not a valid rval for active attach */
					ASSERT(rval != SOF_RVAL_DEFER);
					error = sof_rval2errno(rval);
					break;
				}
				sof_instance_destroy(inst);
				return (error);
			}
		}
		return (0);
	} else if (option_name == FIL_DETACH) {
		for (inst = so->so_filter_top; inst != NULL;
		    inst = inst->sofi_next) {

			ent = inst->sofi_filter;
			if (strncmp(ent->sofe_name, (const char *)optval,
			    SOF_MAXNAMELEN) == 0)
				break;
		}
		if (inst == NULL)
			return (ENXIO);

		/* automatic filters cannot be detached */
		if (inst->sofi_filter->sofe_flags & SOFEF_AUTO)
			return (EINVAL);

		if (inst->sofi_ops->sofop_detach != NULL)
			inst->sofi_ops->sofop_detach((sof_handle_t)inst,
			    inst->sofi_cookie, cr);
		sof_instance_destroy(inst);

		return (0);
	} else {
		return (EINVAL);
	}
}

int
sof_setsockopt(struct sonode *so, int option_name,
    const void *optval, socklen_t optlen, struct cred *cr)
{
	int error;

	/*
	 * By grabbing the lock as a writer we ensure that no other socket
	 * operations can start while the filter stack is being manipulated.
	 *
	 * We do a tryenter so that in case there is an active thread we
	 * ask the caller to try again instead of blocking here until the
	 * other thread is done (which could be indefinitely in case of recv).
	 */
	if (!rw_tryenter(&so->so_fallback_rwlock, RW_WRITER)) {
		return (EAGAIN);
	}

	/* Bail out if a fallback has taken place */
	if (so->so_state & SS_FALLBACK_COMP)
		error = EINVAL;
	else
		error = sof_setsockopt_impl(so, option_name, optval,
		    optlen, cr);
	rw_exit(&so->so_fallback_rwlock);

	return (error);
}

/*
 * Get filter socket options.
 */
static int
sof_getsockopt_impl(struct sonode *so, int option_name,
    void *optval, socklen_t *optlenp, struct cred *cr)
{
	sof_instance_t *inst;
	struct fil_info *fi;
	socklen_t maxsz = *optlenp;
	int i;
	uint_t cnt;

	_NOTE(ARGUNUSED(cr));

	if (option_name == FIL_LIST) {
		fi = (struct fil_info *)optval;

		if (maxsz < sizeof (*fi))
			return (EINVAL);

		for (inst = so->so_filter_top, cnt = 0; inst != NULL;
		    inst = inst->sofi_next)
			cnt++;
		for (inst = so->so_filter_top, i = 0;
		    inst != NULL && (i+1) * sizeof (*fi) <= maxsz;
		    inst = inst->sofi_next, i++) {
			fi[i].fi_flags =
			    (inst->sofi_filter->sofe_flags & SOFEF_AUTO) ?
			    FILF_AUTO : FILF_PROG;
			if (inst->sofi_flags & SOFIF_BYPASS)
				fi[i].fi_flags |= FILF_BYPASS;
			(void) strncpy(fi[i].fi_name,
			    inst->sofi_filter->sofe_name, FILNAME_MAX);
			ASSERT(cnt > 0);
			fi[i].fi_pos = --cnt;
		}
		*optlenp = i * sizeof (*fi);
		return (0);
	} else {
		return (EINVAL);
	}
}

int
sof_getsockopt(struct sonode *so, int option_name,
    void *optval, socklen_t *optlenp, struct cred *cr)
{
	int error;

	/*
	 * The fallback lock is used here to serialize set and get
	 * filter operations.
	 */
	rw_enter(&so->so_fallback_rwlock, RW_READER);
	if (so->so_state & SS_FALLBACK_COMP)
		error = EINVAL;
	else
		error = sof_getsockopt_impl(so, option_name, optval, optlenp,
		    cr);
	rw_exit(&so->so_fallback_rwlock);

	return (error);
}

/*
 * The socket `so' wants to inherit the filter stack from `pso'.
 * Returns 0 if all went well or an errno otherwise.
 */
int
sof_sonode_inherit_filters(struct sonode *so, struct sonode *pso)
{
	sof_instance_t *inst, *pinst;
	sof_rval_t rval;
	int error;
	struct sockaddr_in6 laddrbuf, faddrbuf;
	struct sockaddr_in6 *laddr, *faddr;
	socklen_t laddrlen, faddrlen;

	/*
	 * Make sure there is enough room to retrieve the addresses
	 */
	if (so->so_proto_props.sopp_maxaddrlen > sizeof (laddrbuf)) {
		laddr = kmem_zalloc(so->so_proto_props.sopp_maxaddrlen,
		    KM_NOSLEEP);
		if (laddr == NULL)
			return (ENOMEM);
		faddr = kmem_zalloc(so->so_proto_props.sopp_maxaddrlen,
		    KM_NOSLEEP);
		if (faddr == NULL) {
			kmem_free(laddr, so->so_proto_props.sopp_maxaddrlen);
			return (ENOMEM);
		}
		laddrlen = faddrlen = so->so_proto_props.sopp_maxaddrlen;
	} else {
		laddrlen = faddrlen = sizeof (laddrbuf);
		laddr = &laddrbuf;
		faddr = &faddrbuf;
	}

	error = (*so->so_downcalls->sd_getpeername)
	    (so->so_proto_handle, (struct sockaddr *)faddr, &faddrlen, kcred);
	if (error != 0)
		goto out;
	error = (*so->so_downcalls->sd_getsockname)
	    (so->so_proto_handle, (struct sockaddr *)laddr, &laddrlen, kcred);
	if (error != 0)
		goto out;

	/*
	 * The stack is built bottom up. Filters are allowed to modify the
	 * the foreign and local addresses during attach.
	 */
	for (pinst = pso->so_filter_bottom;
	    pinst != NULL && !(pinst->sofi_flags & SOFIF_BYPASS);
	    pinst = pinst->sofi_prev) {
		inst = sof_instance_create(pinst->sofi_filter, so);
		if (inst == NULL) {
			error = ENOMEM;
			goto out;
		}
		/*
		 * The filter module must be loaded since it's already
		 * attached to the listener.
		 */
		ASSERT(pinst->sofi_ops != NULL);
		inst->sofi_ops = pinst->sofi_ops;

		SOF_STAT_ADD(inst, tot_passive_attach, 1);
		if (inst->sofi_ops->sofop_attach_passive != NULL) {
			rval = inst->sofi_ops->sofop_attach_passive(
			    (sof_handle_t)inst,
			    (sof_handle_t)pinst, pinst->sofi_cookie,
			    (struct sockaddr *)laddr, laddrlen,
			    (struct sockaddr *)faddr, faddrlen,
			    &inst->sofi_cookie);
			if (rval != SOF_RVAL_CONTINUE) {
				if (rval == SOF_RVAL_DEFER) {
					mutex_enter(&so->so_lock);
					inst->sofi_flags |= SOFIF_DEFER;
					so->so_state |= SS_FIL_DEFER;
					mutex_exit(&so->so_lock);
					so->so_filter_defertime =
					    ddi_get_lbolt();
					SOF_STAT_ADD(inst, ndeferred, 1);
				} else if (rval == SOF_RVAL_DETACH) {
					sof_instance_destroy(inst);
				} else {
					SOF_STAT_ADD(inst, attach_failures, 1);
					error = sof_rval2errno(rval);
					/*
					 * Filters that called attached will be
					 * destroyed when the socket goes away,
					 * after detach is called.
					 */
					goto out;
				}
			}
		}
	}

out:
	if (laddr != &laddrbuf) {
		kmem_free(laddr, so->so_proto_props.sopp_maxaddrlen);
		kmem_free(faddr, so->so_proto_props.sopp_maxaddrlen);
	}
	return (error);
}

/*
 * Attach any automatic filters to sonode `so'. Returns 0 if all went well
 * and an errno otherwise.
 */
int
sof_sonode_autoattach_filters(struct sonode *so, cred_t *cr)
{
	struct sockparams *sp = so->so_sockparams;
	sp_filter_t *fil;
	sof_instance_t *inst;
	sof_rval_t rval;
	int error;

	/*
	 * A created instance is added to the top of the sonode's filter
	 * stack, so traverse the config list in reverse order.
	 */
	rw_enter(&sockconf_lock, RW_READER);
	for (fil = list_tail(&sp->sp_auto_filters);
	    fil != NULL; fil = list_prev(&sp->sp_auto_filters, fil)) {
		ASSERT(fil->spf_filter->sofe_flags & SOFEF_AUTO);
		if (!sof_instance_create(fil->spf_filter, so)) {
			rw_exit(&sockconf_lock);
			error = ENOMEM; /* must have run out of memory */
			goto free_all;
		}
	}
	rw_exit(&sockconf_lock);

	/*
	 * Notify each filter that it's being attached.
	 */
	inst = so->so_filter_top;
	while (inst != NULL) {
		sof_entry_t *ent = inst->sofi_filter;
		sof_instance_t *ninst = inst->sofi_next;

		/*
		 * This might be the first time the filter is being used,
		 * so try to load the module if it's not already registered.
		 */
		if (ent->sofe_mod == NULL &&
		    (error = sof_entry_load_module(ent)) != 0)
			goto free_detached;

		/* Module loaded OK, so there must be an ops vector */
		ASSERT(ent->sofe_mod != NULL);
		inst->sofi_ops = &ent->sofe_mod->sofm_ops;

		SOF_STAT_ADD(inst, tot_active_attach, 1);
		if (inst->sofi_ops->sofop_attach_active != NULL) {
			rval = inst->sofi_ops->sofop_attach_active(
			    (sof_handle_t)inst, so->so_family, so->so_type,
			    so->so_protocol, cr, &inst->sofi_cookie);
			if (rval != SOF_RVAL_CONTINUE) {
				switch (rval) {
				case SOF_RVAL_DETACH:
					/* filter does not want to attach */
					sof_instance_destroy(inst);
					break;
				default:
					SOF_STAT_ADD(inst, attach_failures, 1);
					/* Not a valid rval for active attach */
					ASSERT(rval != SOF_RVAL_DEFER);
					error = sof_rval2errno(rval);
					goto free_detached;
				}
			}
		}
		inst = ninst;
	}
	return (0);

free_all:
	inst = so->so_filter_top;
free_detached:
	ASSERT(inst != NULL);
	/*
	 * Destroy all filters for which attach was not called. The other
	 * filters will be destroyed (and detach called) when the socket
	 * is freed.
	 */
	do {
		sof_instance_t *t = inst->sofi_next;
		sof_instance_destroy(inst);
		inst = t;
	} while (inst != NULL);

	return (error);
}

/*
 * Detaches and frees all filters attached to sonode `so'.
 */
void
sof_sonode_cleanup(struct sonode *so)
{
	sof_instance_t *inst;

	while ((inst = so->so_filter_top) != NULL) {
		(inst->sofi_ops->sofop_detach)((sof_handle_t)inst,
		    inst->sofi_cookie, kcred);
		sof_instance_destroy(inst);
	}
}

/*
 * Notifies all active filters attached to `so' about the `event' and
 * where `arg' is an event specific argument.
 */
void
sof_sonode_notify_filters(struct sonode *so, sof_event_t event, uintptr_t arg)
{
	sof_instance_t *inst;

	for (inst = so->so_filter_bottom; inst != NULL;
	    inst = inst->sofi_prev) {
		if (SOF_INTERESTED(inst, notify))
			(inst->sofi_ops->sofop_notify)((sof_handle_t)inst,
			    inst->sofi_cookie, event, arg);
	}
}

/*
 * The socket `so' is closing. Notify filters and make sure that there
 * are no pending tx operations.
 */
void
sof_sonode_closing(struct sonode *so)
{
	/*
	 * Notify filters that the socket is being closed. It's OK for
	 * filters to inject data.
	 */
	sof_sonode_notify_filters(so, SOF_EV_CLOSING, (uintptr_t)B_TRUE);

	/*
	 * Stop any future attempts to inject data, and wait for any
	 * pending operations to complete. This has to be done to ensure
	 * that no data is sent down to the protocol once a close
	 * downcall has been made.
	 */
	mutex_enter(&so->so_lock);
	so->so_state |= SS_FIL_STOP;
	while (so->so_filter_tx > 0)
		cv_wait(&so->so_closing_cv, &so->so_lock);
	mutex_exit(&so->so_lock);
}

/*
 * Called when socket `so' wants to get rid of a deferred connection.
 * Returns TRUE if a connection was dropped.
 */
boolean_t
sof_sonode_drop_deferred(struct sonode *so)
{
	struct sonode *def;
	clock_t now = ddi_get_lbolt();

	if (sof_close_deferred_backlog > sof_close_deferred_max_backlog) {
		SOF_GLOBAL_STAT_BUMP(defer_close_failed_backlog_too_big);
		return (B_FALSE);
	}
	mutex_enter(&so->so_acceptq_lock);
	if ((def = list_head(&so->so_acceptq_defer)) != NULL &&
	    (now - def->so_filter_defertime) > sof_defer_drop_time) {
		list_remove(&so->so_acceptq_defer, def);
		so->so_acceptq_len--;
		mutex_exit(&so->so_acceptq_lock);
		def->so_listener = NULL;
	} else {
		mutex_exit(&so->so_acceptq_lock);
		return (B_FALSE);
	}

	mutex_enter(&sof_close_deferred_lock);
	list_insert_tail(&sof_close_deferred_list, def);
	sof_close_deferred_backlog++;
	if (!sof_close_deferred_running) {
		mutex_exit(&sof_close_deferred_lock);
		(void) taskq_dispatch(sof_close_deferred_taskq,
		    sof_close_deferred, NULL, TQ_NOSLEEP);
	} else {
		mutex_exit(&sof_close_deferred_lock);
	}
	return (B_TRUE);
}

/*
 * Called from a taskq to close connections that have been deferred for
 * too long.
 */
void
sof_close_deferred(void *unused)
{
	struct sonode *drop;

	_NOTE(ARGUNUSED(unused));

	mutex_enter(&sof_close_deferred_lock);
	if (!sof_close_deferred_running) {
		sof_close_deferred_running = B_TRUE;
		while ((drop =
		    list_remove_head(&sof_close_deferred_list)) != NULL) {
			sof_close_deferred_backlog--;
			mutex_exit(&sof_close_deferred_lock);

			SOF_GLOBAL_STAT_BUMP(defer_closed);
			(void) socket_close(drop, 0, kcred);
			socket_destroy(drop);

			mutex_enter(&sof_close_deferred_lock);
		}
		sof_close_deferred_running = B_FALSE;
		ASSERT(sof_close_deferred_backlog == 0);
	}
	mutex_exit(&sof_close_deferred_lock);
}

/*
 * Creates a new filter instance from the entry `ent' and attaches
 * it to the sonode `so'. On success, return a pointer to the created
 * instance.
 *
 * The new instance will be placed on the top of the filter stack.
 *
 * The caller is responsible for assigning the instance's ops vector and
 * calling the filter's attach callback.
 *
 * No locks are held while manipulating the sonode fields because we are
 * guaranteed that this operation is serialized.
 *
 * We can be sure that the entry `ent' will not disappear, because the
 * caller is either holding sockconf_lock (in case of an active open), or is
 * already holding a reference (in case of a passive open, the listener has
 * one).
 */
static sof_instance_t *
sof_instance_create(sof_entry_t *ent, struct sonode *so)
{
	sof_instance_t *inst;

	inst = kmem_zalloc(sizeof (sof_instance_t), KM_NOSLEEP);
	if (inst == NULL)
		return (NULL);
	sof_entry_hold(ent);
	inst->sofi_filter = ent;
	inst->sofi_sonode = so;

	inst->sofi_next = so->so_filter_top;
	if (so->so_filter_top != NULL)
		so->so_filter_top->sofi_prev = inst;
	else
		so->so_filter_bottom = inst;
	so->so_filter_top = inst;
	so->so_filter_active++;

	return (inst);
}
/*
 * Destroys the filter instance `inst' and unlinks it from the sonode.
 *
 * Any filter private state must be destroyed (via the detach callback)
 * before the instance is destroyed.
 */
static void
sof_instance_destroy(sof_instance_t *inst)
{
	struct sonode *so = inst->sofi_sonode;

	ASSERT(inst->sofi_sonode != NULL);
	ASSERT(inst->sofi_filter != NULL);
	ASSERT(inst->sofi_prev != NULL || so->so_filter_top == inst);
	ASSERT(inst->sofi_next != NULL || so->so_filter_bottom == inst);

	if (inst->sofi_prev != NULL)
		inst->sofi_prev->sofi_next = inst->sofi_next;
	else
		so->so_filter_top = inst->sofi_next;

	if (inst->sofi_next != NULL)
		inst->sofi_next->sofi_prev = inst->sofi_prev;
	else
		so->so_filter_bottom = inst->sofi_prev;

	if (!(inst->sofi_flags & SOFIF_BYPASS)) {
		ASSERT(so->so_filter_active > 0);
		so->so_filter_active--;
	}
	if (inst->sofi_flags & SOFIF_DEFER)
		SOF_STAT_ADD(inst, ndeferred, -1);
	sof_entry_rele(inst->sofi_filter);
	kmem_free(inst, sizeof (sof_instance_t));
}

static sof_entry_t *
sof_entry_find(const char *name)
{
	sof_entry_t *ent;

	for (ent = list_head(&sof_entry_list); ent != NULL;
	    ent = list_next(&sof_entry_list, ent)) {
		if (strncmp(ent->sofe_name, name, SOF_MAXNAMELEN) == 0)
			return (ent);
	}
	return (NULL);
}

void
sof_entry_free(sof_entry_t *ent)
{
	ASSERT(ent->sofe_refcnt == 0);
	ASSERT(!list_link_active(&ent->sofe_node));

	if (ent->sofe_hintarg != NULL) {
		ASSERT(ent->sofe_hint == SOF_HINT_BEFORE ||
		    ent->sofe_hint == SOF_HINT_AFTER);
		kmem_free(ent->sofe_hintarg, strlen(ent->sofe_hintarg) + 1);
		ent->sofe_hintarg = NULL;
	}
	if (ent->sofe_socktuple_cnt > 0) {
		ASSERT(ent->sofe_socktuple != NULL);
		kmem_free(ent->sofe_socktuple,
		    sizeof (sof_socktuple_t) * ent->sofe_socktuple_cnt);
		ent->sofe_socktuple = NULL;
		ent->sofe_socktuple_cnt = 0;
	}
	sof_entry_kstat_destroy(ent);

	mutex_destroy(&ent->sofe_lock);
	kmem_free(ent, sizeof (sof_entry_t));
}

static int
sof_entry_kstat_update(kstat_t *ksp, int rw)
{
	sof_entry_t *ent = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ent->sofe_kstat.sofek_nactive.value.ui64 = ent->sofe_refcnt;

	return (0);
}

/*
 * Create the kstat for filter entry `ent'.
 */
static int
sof_entry_kstat_create(sof_entry_t *ent)
{
	char name[SOF_MAXNAMELEN + 7];

	(void) snprintf(name, sizeof (name), "filter_%s", ent->sofe_name);
	ent->sofe_ksp = kstat_create("sockfs", 0, name, "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (sof_entry_kstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (ent->sofe_ksp == NULL)
		return (ENOMEM);

	kstat_named_init(&ent->sofe_kstat.sofek_nactive, "nactive",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ent->sofe_kstat.sofek_tot_active_attach,
	    "tot_active_attach", KSTAT_DATA_UINT64);
	kstat_named_init(&ent->sofe_kstat.sofek_tot_passive_attach,
	    "tot_passive_attach", KSTAT_DATA_UINT64);
	kstat_named_init(&ent->sofe_kstat.sofek_ndeferred, "ndeferred",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ent->sofe_kstat.sofek_attach_failures,
	    "attach_failures", KSTAT_DATA_UINT64);

	ent->sofe_ksp->ks_data = &ent->sofe_kstat;
	ent->sofe_ksp->ks_update = sof_entry_kstat_update;
	ent->sofe_ksp->ks_private = ent;
	kstat_install(ent->sofe_ksp);

	return (0);
}

/*
 * Destroys the kstat for filter entry `ent'.
 */
static void
sof_entry_kstat_destroy(sof_entry_t *ent)
{
	if (ent->sofe_ksp != NULL) {
		kstat_delete(ent->sofe_ksp);
		ent->sofe_ksp = NULL;
	}
}

static void
sof_entry_hold(sof_entry_t *ent)
{
	mutex_enter(&ent->sofe_lock);
	ent->sofe_refcnt++;
	mutex_exit(&ent->sofe_lock);
}

/*
 * Decrement the reference count for `ent'. The entry will
 * drop its' reference on the filter module whenever its'
 * ref count reaches zero.
 */
static void
sof_entry_rele(sof_entry_t *ent)
{
	mutex_enter(&ent->sofe_lock);
	if (--ent->sofe_refcnt == 0) {
		sof_module_t *mod = ent->sofe_mod;
		ent->sofe_mod = NULL;
		if (ent->sofe_flags & SOFEF_CONDEMED) {
			mutex_exit(&ent->sofe_lock);
			sof_entry_free(ent);
		} else {
			mutex_exit(&ent->sofe_lock);
		}
		if (mod != NULL)
			sof_module_rele(mod);
	} else {
		mutex_exit(&ent->sofe_lock);
	}
}

/*
 * Loads the module used by `ent'
 */
static int
sof_entry_load_module(sof_entry_t *ent)
{
	sof_module_t *mod = sof_module_hold_by_name(ent->sofe_name,
	    ent->sofe_modname);

	if (mod == NULL)
		return (EINVAL);

	mutex_enter(&ent->sofe_lock);
	/* Another thread might have already loaded the module */
	ASSERT(ent->sofe_mod == mod || ent->sofe_mod == NULL);
	if (ent->sofe_mod != NULL) {
		mutex_exit(&ent->sofe_lock);
		sof_module_rele(mod);
	} else {
		ent->sofe_mod = mod;
		mutex_exit(&ent->sofe_lock);
	}

	return (0);
}

/*
 * Add filter entry `ent' to the global list and attach it to all sockparam
 * entries which the filter is interested in. Upon successful return the filter
 * will be available for applications to use.
 */
int
sof_entry_add(sof_entry_t *ent)
{
	int error;

	/*
	 * We hold sockconf_lock as a WRITER for the whole operation,
	 * so all operations must be non-blocking.
	 */
	rw_enter(&sockconf_lock, RW_WRITER);
	if (sof_entry_find(ent->sofe_name) != NULL) {
		rw_exit(&sockconf_lock);
		return (EEXIST);
	}

	/* The entry is unique; create the kstats */
	if (sof_entry_kstat_create(ent) != 0) {
		rw_exit(&sockconf_lock);
		return (ENOMEM);
	}

	/*
	 * Attach the filter to sockparams of interest.
	 */
	if ((error = sockparams_new_filter(ent)) != 0) {
		sof_entry_kstat_destroy(ent);
		rw_exit(&sockconf_lock);
		return (error);
	}
	/*
	 * Everything is OK; insert in global list.
	 */
	list_insert_tail(&sof_entry_list, ent);
	rw_exit(&sockconf_lock);

	return (0);
}

/*
 * Removes the filter entry `ent' from global list and all sockparams.
 */
sof_entry_t *
sof_entry_remove_by_name(const char *name)
{
	sof_entry_t *ent;

	rw_enter(&sockconf_lock, RW_WRITER);
	if ((ent = sof_entry_find(name)) == NULL) {
		rw_exit(&sockconf_lock);
		return (NULL);
	}
	list_remove(&sof_entry_list, ent);
	sockparams_filter_cleanup(ent);
	sof_entry_kstat_destroy(ent);
	rw_exit(&sockconf_lock);

	return (ent);
}

/*
 * Filter entry `ent' will process sockparams entry `sp' to determine whether
 * it should be attached to the sockparams. It should be called whenever a new
 * filter or sockparams is being added. Returns zero either if the filter is
 * not interested in the sockparams or if it successfully attached to the
 * sockparams. On failure an errno is returned.
 */
int
sof_entry_proc_sockparams(sof_entry_t *ent, struct sockparams *sp)
{
	uint_t i;
	sof_socktuple_t *t = ent->sofe_socktuple;
	sp_filter_t *new, *fil;

	/* Only interested in non-TPI sockets */
	if (strcmp(sp->sp_smod_name, SOTPI_SMOD_NAME) == 0)
		return (0);

	for (i = 0; i < ent->sofe_socktuple_cnt; i++) {
		if (t[i].sofst_family == sp->sp_family &&
		    t[i].sofst_type == sp->sp_type &&
		    t[i].sofst_protocol == sp->sp_protocol)
			break;
	}
	/* This filter is not interested in the sockparams entry */
	if (i == ent->sofe_socktuple_cnt)
		return (0);

	new = kmem_zalloc(sizeof (sp_filter_t), KM_NOSLEEP);
	if (new == NULL)
		return (ENOMEM);

	new->spf_filter = ent;
	if (ent->sofe_flags & SOFEF_PROG) {
		/* placement is irrelevant for programmatic filters */
		list_insert_head(&sp->sp_prog_filters, new);
		return (0);
	} else {
		ASSERT(ent->sofe_flags & SOFEF_AUTO);
		/*
		 * If the filter specifies a placement hint, then make sure
		 * it can be satisfied.
		 */
		switch (ent->sofe_hint) {
		case SOF_HINT_TOP:
			if ((fil = list_head(&sp->sp_auto_filters)) != NULL &&
			    fil->spf_filter->sofe_hint == SOF_HINT_TOP)
				break;
			list_insert_head(&sp->sp_auto_filters, new);
			return (0);
		case SOF_HINT_BOTTOM:
			if ((fil = list_tail(&sp->sp_auto_filters)) != NULL &&
			    fil->spf_filter->sofe_hint == SOF_HINT_BOTTOM)
				break;
			list_insert_tail(&sp->sp_auto_filters, new);
			return (0);
		case SOF_HINT_BEFORE:
		case SOF_HINT_AFTER:
			for (fil = list_head(&sp->sp_auto_filters);
			    fil != NULL;
			    fil = list_next(&sp->sp_auto_filters, fil)) {
				if (strncmp(ent->sofe_hintarg,
				    fil->spf_filter->sofe_name, SOF_MAXNAMELEN)
				    == 0) {
					break;
				}
			}

			if (fil != NULL) {
				if (ent->sofe_hint == SOF_HINT_BEFORE) {
					if (fil->spf_filter->sofe_hint ==
					    SOF_HINT_TOP)
						break;
					list_insert_before(&sp->sp_auto_filters,
					    fil, new);
				} else {
					if (fil->spf_filter->sofe_hint ==
					    SOF_HINT_BOTTOM)
						break;
					list_insert_after(&sp->sp_auto_filters,
					    fil, new);
				}
				return (0);
			}
			/*FALLTHRU*/
		case SOF_HINT_NONE:
			/*
			 * Insert the new filter at the beginning as long as it
			 * does not violate a TOP hint, otherwise insert in the
			 * next suitable location.
			 */
			if ((fil = list_head(&sp->sp_auto_filters)) != NULL &&
			    fil->spf_filter->sofe_hint == SOF_HINT_TOP) {
				list_insert_after(&sp->sp_auto_filters, fil,
				    new);
			} else {
				list_insert_head(&sp->sp_auto_filters, new);
			}
			return (0);
		}
		/* Failed to insert the filter */
		kmem_free(new, sizeof (sp_filter_t));
		return (ENOSPC);
	}
}

/*
 * Remove all filter entries attached to the sockparams entry `sp'.
 */
void
sof_sockparams_fini(struct sockparams *sp)
{
	sp_filter_t *fil;

	ASSERT(!list_link_active(&sp->sp_node));

	while ((fil = list_remove_head(&sp->sp_auto_filters)) != NULL)
		kmem_free(fil, sizeof (sp_filter_t));
	while ((fil = list_remove_head(&sp->sp_prog_filters)) != NULL)
		kmem_free(fil, sizeof (sp_filter_t));
}

/*
 * A new sockparams is being added. Walk all filters and attach those that
 * are interested in the entry.
 *
 * It should be called when the sockparams entry is about to be made available
 * for use and while holding the sockconf_lock.
 */
int
sof_sockparams_init(struct sockparams *sp)
{
	sof_entry_t *ent;

	ASSERT(RW_WRITE_HELD(&sockconf_lock));

	for (ent = list_head(&sof_entry_list); ent != NULL;
	    ent = list_next(&sof_entry_list, ent)) {
		if (sof_entry_proc_sockparams(ent, sp) != 0) {
			sof_sockparams_fini(sp);
			return (ENOMEM);
		}
	}
	return (0);
}

static sof_module_t *
sof_module_find(const char *name)
{
	sof_module_t *ent;

	ASSERT(MUTEX_HELD(&sof_module_lock));

	for (ent = list_head(&sof_module_list); ent != NULL;
	    ent = list_next(&sof_module_list, ent))
		if (strcmp(ent->sofm_name, name) == 0)
			return (ent);
	return (NULL);
}

/*
 * Returns a pointer to a module identified by `name' with its ref count
 * bumped. An attempt to load the module is done if it's not found in the
 * global list.
 */
sof_module_t *
sof_module_hold_by_name(const char *name, const char *modname)
{
	ddi_modhandle_t handle = NULL;
	sof_module_t *mod = NULL;
	char *modpath;
	int error;

	/*
	 * We'll go through the loop at most two times, which will only
	 * happen if the module needs to be loaded.
	 */
	for (;;) {
		mutex_enter(&sof_module_lock);
		mod = sof_module_find(name);
		if (mod != NULL || handle != NULL)
			break;
		mutex_exit(&sof_module_lock);

		modpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) snprintf(modpath, MAXPATHLEN, "%s/%s", SOF_MODPATH,
		    modname);
		handle = ddi_modopen(modpath, KRTLD_MODE_FIRST, &error);
		kmem_free(modpath, MAXPATHLEN);
		/* Failed to load, then bail */
		if (handle == NULL) {
			cmn_err(CE_WARN,
			    "Failed to load socket filter module: %s (err %d)",
			    modname, error);
			return (NULL);
		}
	}
	if (mod != NULL)
		mod->sofm_refcnt++;
	mutex_exit(&sof_module_lock);

	if (handle != NULL) {
		(void) ddi_modclose(handle);
		/*
		 * The module was loaded, but the filter module could not be
		 * found. It's likely a misconfigured filter.
		 */
		if (mod == NULL) {
			cmn_err(CE_WARN,
			    "Socket filter module %s was loaded, but did not" \
			    "register. Filter %s is likely misconfigured.",
			    modname, name);
		}
	}

	return (mod);
}

void
sof_module_rele(sof_module_t *mod)
{
	mutex_enter(&sof_module_lock);
	mod->sofm_refcnt--;
	mutex_exit(&sof_module_lock);
}

int
sof_rval2errno(sof_rval_t rval)
{
	if (rval > SOF_RVAL_CONTINUE) {
		return ((int)rval);
	} else {
#ifdef DEBUG
		if (socket_filter_debug)
			printf("sof_rval2errno: invalid rval '%d'\n", rval);
#endif
		return (EINVAL);
	}
}

/*
 * Walk through all the filters attached to `so' and allow each filter
 * to process the data using its data_out callback. `mp' is a b_cont chain.
 *
 * Returns the processed mblk, or NULL if mblk was consumed. The mblk might
 * have been consumed as a result of an error, in which case `errp' is set to
 * the appropriate errno.
 */
mblk_t *
sof_filter_data_out_from(struct sonode *so, sof_instance_t *start,
    mblk_t *mp, struct nmsghdr *msg, cred_t *cr, int *errp)
{
	sof_instance_t *inst;
	sof_rval_t rval;

	_NOTE(ARGUNUSED(so));

	for (inst = start; inst != NULL; inst = inst->sofi_next) {
		if (!SOF_INTERESTED(inst, data_out))
			continue;
		mp = (inst->sofi_ops->sofop_data_out)((sof_handle_t)inst,
		    inst->sofi_cookie, mp, msg, cr, &rval);
		DTRACE_PROBE2(filter__data, (sof_instance_t), inst,
		    (mblk_t *), mp);
		if (mp == NULL) {
			*errp = sof_rval2errno(rval);
			break;
		}
	}
	return (mp);
}

/*
 * Walk through all the filters attached to `so' and allow each filter
 * to process the data using its data_in_proc callback. `mp' is the start of
 * a possible b_next chain, and `lastmp' points to the last mblk in the chain.
 *
 * Returns the processed mblk, or NULL if all mblks in the chain were
 * consumed. `lastmp' is updated to point to the last mblk in the processed
 * chain.
 */
mblk_t *
sof_filter_data_in_proc(struct sonode *so, mblk_t *mp, mblk_t **lastmp)
{
	sof_instance_t *inst;
	size_t len = 0, orig = 0;
	ssize_t diff = 0;
	mblk_t *retmp = NULL, *tailmp, *nextmp;

	*lastmp = NULL;
	do {
		nextmp = mp->b_next;
		mp->b_next = mp->b_prev = NULL;
		len = orig = msgdsize(mp);
		for (inst = so->so_filter_bottom; inst != NULL;
		    inst = inst->sofi_prev) {
			if (!SOF_INTERESTED(inst, data_in_proc))
				continue;
			mp = (inst->sofi_ops->sofop_data_in_proc)(
			    (sof_handle_t)inst, inst->sofi_cookie, mp,
			    kcred, &len);
			if (mp == NULL)
				break;
		}
		DTRACE_PROBE2(filter__data, (sof_instance_t), inst,
		    (mblk_t *), mp);
		diff += len - orig;
		if (mp == NULL)
			continue;

		for (tailmp = mp; tailmp->b_cont != NULL;
		    tailmp = tailmp->b_cont)
			;
		mp->b_prev = tailmp;

		if (*lastmp == NULL)
			retmp = mp;
		else
			(*lastmp)->b_next = mp;
		*lastmp = mp;
	} while ((mp = nextmp) != NULL);

	/*
	 * The size of the chain has changed; make sure the rcv queue
	 * stays consistent and check if the flow control state should
	 * change.
	 */
	if (diff != 0) {
		DTRACE_PROBE2(filter__data__adjust__qlen,
		    (struct sonode *), so, (size_t), diff);
		mutex_enter(&so->so_lock);
		so->so_rcv_queued += diff;
		/* so_check_flow_control drops so_lock */
		(void) so_check_flow_control(so);
	}

	return (retmp);
}

int
sof_filter_bind(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlen, cred_t *cr)
{
	__SOF_FILTER_OP(so, bind, cr, addr, addrlen)
}

int
sof_filter_listen(struct sonode *so, int *backlogp, cred_t *cr)
{
	__SOF_FILTER_OP(so, listen, cr, backlogp)
}

int
sof_filter_connect(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlen, cred_t *cr)
{
	__SOF_FILTER_OP(so, connect, cr, addr, addrlen)
}

int
sof_filter_accept(struct sonode *so, cred_t *cr)
{
	sof_instance_t *inst;
	sof_rval_t rval;

	for (inst = so->so_filter_top; inst != NULL; inst = inst->sofi_next) {
		if (!SOF_INTERESTED(inst, accept))
			continue;
		rval = (inst->sofi_ops->sofop_accept)((sof_handle_t)inst,
		    inst->sofi_cookie, cr);
		DTRACE_PROBE2(filter__action, (sof_instance_t), inst,
		    (sof_rval_t), rval);
		if (rval != SOF_RVAL_CONTINUE) {
			ASSERT(rval != SOF_RVAL_RETURN);
			return (sof_rval2errno(rval));
		}
	}
	return (-1);
}

int
sof_filter_shutdown(struct sonode *so, int *howp, cred_t *cr)
{
	__SOF_FILTER_OP(so, shutdown, cr, howp)
}

int
sof_filter_getsockname(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	__SOF_FILTER_OP(so, getsockname, cr, addr, addrlenp)
}

int
sof_filter_getpeername(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	__SOF_FILTER_OP(so, getpeername, cr, addr, addrlenp)
}

int
sof_filter_setsockopt(struct sonode *so, int level, int option_name,
    void *optval, socklen_t *optlenp, cred_t *cr)
{
	__SOF_FILTER_OP(so, setsockopt, cr, level, option_name,
	    optval, optlenp)
}

int
sof_filter_getsockopt(struct sonode *so, int level, int option_name,
    void *optval, socklen_t *optlenp, cred_t *cr)
{
	__SOF_FILTER_OP(so, getsockopt, cr, level, option_name,
	    optval, optlenp)
}

int
sof_filter_ioctl(struct sonode *so, int cmd, intptr_t arg, int mode,
    int32_t *rvalp, cred_t *cr)
{
	__SOF_FILTER_OP(so, ioctl, cr, cmd, arg, mode, rvalp)
}

/*
 * sof_register(version, name, ops, flags)
 *
 * Register a socket filter identified by name `name' and which should use
 * the ops vector `ops' for event notification. `flags' should be set to 0
 * by default for "unsafe" modules or SOF_ATT_SAFE for "safe" modules. An
 * unsafe filter is one that cannot be attached after any socket operation has
 * occured. This is the legacy default. A "safe" filter can be attached even
 * after some basic initial socket operations have taken place. This set is
 * currently bind, getsockname, getsockopt and setsockopt. The order in which
 * a "safe" filter can be attached is more relaxed, and thus more flexible.
 * On success 0 is returned, otherwise an errno is returned.
 */
int
sof_register(int version, const char *name, const sof_ops_t *ops, int flags)
{
	sof_module_t *mod;

	if (version != SOF_VERSION)
		return (EINVAL);

	mod = kmem_zalloc(sizeof (sof_module_t), KM_SLEEP);
	mod->sofm_name = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(mod->sofm_name, name);
	mod->sofm_flags = flags;
	mod->sofm_ops = *ops;

	mutex_enter(&sof_module_lock);
	if (sof_module_find(name) != NULL) {
		mutex_exit(&sof_module_lock);
		kmem_free(mod->sofm_name, strlen(mod->sofm_name) + 1);
		kmem_free(mod, sizeof (sof_module_t));
		return (EEXIST);
	}
	list_insert_tail(&sof_module_list, mod);
	mutex_exit(&sof_module_lock);

	return (0);
}

/*
 * sof_unregister(name)
 *
 * Try to unregister the socket filter identified by `name'. If the filter
 * is successfully unregistered, then 0 is returned, otherwise an errno is
 * returned.
 */
int
sof_unregister(const char *name)
{
	sof_module_t *mod;

	mutex_enter(&sof_module_lock);
	mod = sof_module_find(name);
	if (mod != NULL) {
		if (mod->sofm_refcnt == 0) {
			list_remove(&sof_module_list, mod);
			mutex_exit(&sof_module_lock);

			kmem_free(mod->sofm_name, strlen(mod->sofm_name) + 1);
			kmem_free(mod, sizeof (sof_module_t));
			return (0);
		} else {
			mutex_exit(&sof_module_lock);
			return (EBUSY);
		}
	}
	mutex_exit(&sof_module_lock);

	return (ENXIO);
}

/*
 * sof_newconn_ready(handle)
 *
 * The filter `handle` no longer wants to defer the socket it is attached
 * to. A newconn notification will be generated if there is no other filter
 * that wants the socket deferred.
 */
void
sof_newconn_ready(sof_handle_t handle)
{
	sof_instance_t *inst = (sof_instance_t *)handle;
	struct sonode *so = inst->sofi_sonode;
	struct sonode *pso = so->so_listener;

	mutex_enter(&so->so_lock);
	if (!(inst->sofi_flags & SOFIF_DEFER)) {
		mutex_exit(&so->so_lock);
		return;
	}
	ASSERT(so->so_state & SS_FIL_DEFER);
	inst->sofi_flags &= ~SOFIF_DEFER;
	SOF_STAT_ADD(inst, ndeferred, -1);

	/*
	 * Check if any other filter has deferred the socket. The last
	 * filter to remove its DEFER flag will be the one generating the
	 * wakeup.
	 */
	for (inst = so->so_filter_top; inst != NULL; inst = inst->sofi_next) {
		/* Still deferred; nothing to do */
		if (inst->sofi_flags & SOFIF_DEFER) {
			mutex_exit(&so->so_lock);
			return;
		}
	}
	so->so_state &= ~SS_FIL_DEFER;
	mutex_exit(&so->so_lock);

	/*
	 * The socket is no longer deferred; move it over to the regular
	 * accept list and notify the user. However, it is possible that
	 * the socket is being dropped by sof_sonode_drop_deferred(), so
	 * first make sure the socket is on the deferred list.
	 */
	mutex_enter(&pso->so_acceptq_lock);
	if (!list_link_active(&so->so_acceptq_node)) {
		mutex_exit(&pso->so_acceptq_lock);
		return;
	}
	list_remove(&pso->so_acceptq_defer, so);
	list_insert_tail(&pso->so_acceptq_list, so);
	cv_signal(&pso->so_acceptq_cv);
	mutex_exit(&pso->so_acceptq_lock);

	mutex_enter(&pso->so_lock);
	so_notify_newconn(pso);		/* so_notify_newconn drops the lock */
}

/*
 * sof_bypass(handle)
 *
 * Stop generating callbacks for `handle'.
 */
void
sof_bypass(sof_handle_t handle)
{
	sof_instance_t *inst = (sof_instance_t *)handle;
	struct sonode *so = inst->sofi_sonode;

	mutex_enter(&so->so_lock);
	if (!(inst->sofi_flags & SOFIF_BYPASS)) {
		inst->sofi_flags |= SOFIF_BYPASS;
		ASSERT(so->so_filter_active > 0);
		so->so_filter_active--;
	}
	mutex_exit(&so->so_lock);
}

/*
 * sof_rcv_flowctrl(handle, enable)
 *
 * If `enable' is TRUE, then recv side flow control will be asserted for
 * the socket associated with `handle'. When `enable' is FALSE the filter
 * indicates that it no longer wants to assert flow control, however, the
 * condition will not be removed until there are no other filters asserting
 * flow control and there is space available in the receive buffer.
 */
void
sof_rcv_flowctrl(sof_handle_t handle, boolean_t enable)
{
	sof_instance_t *inst = (sof_instance_t *)handle;
	struct sonode *so = inst->sofi_sonode;

	mutex_enter(&so->so_lock);
	if (enable) {
		inst->sofi_flags |= SOFIF_RCV_FLOWCTRL;
		so->so_flowctrld = B_TRUE;
		so->so_state |= SS_FIL_RCV_FLOWCTRL;
		mutex_exit(&so->so_lock);
	} else {
		inst->sofi_flags &= ~SOFIF_RCV_FLOWCTRL;
		for (inst = so->so_filter_top; inst != NULL;
		    inst = inst->sofi_next) {
			/* another filter is asserting flow control */
			if (inst->sofi_flags & SOFIF_RCV_FLOWCTRL) {
				mutex_exit(&so->so_lock);
				return;
			}
		}
		so->so_state &= ~SS_FIL_RCV_FLOWCTRL;
		/* so_check_flow_control drops so_lock */
		(void) so_check_flow_control(so);
	}
	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * sof_snd_flowctrl(handle, enable)
 *
 * If `enable' is TRUE, then send side flow control will be asserted for
 * the socket associated with `handle'. When `enable' is FALSE the filter
 * indicates that is no longer wants to assert flow control, however, the
 * condition will not be removed until there are no other filters asserting
 * flow control and there are tx buffers available.
 */
void
sof_snd_flowctrl(sof_handle_t handle, boolean_t enable)
{
	sof_instance_t *inst = (sof_instance_t *)handle;
	struct sonode *so = inst->sofi_sonode;

	mutex_enter(&so->so_lock);
	if (enable) {
		inst->sofi_flags |= SOFIF_SND_FLOWCTRL;
		so->so_state |= SS_FIL_SND_FLOWCTRL;
	} else {
		inst->sofi_flags &= ~SOFIF_SND_FLOWCTRL;
		for (inst = so->so_filter_top; inst != NULL;
		    inst = inst->sofi_next) {
			if (inst->sofi_flags & SOFIF_SND_FLOWCTRL) {
				mutex_exit(&so->so_lock);
				return;
			}
		}
		so->so_state &= ~SS_FIL_SND_FLOWCTRL;
		/*
		 * Wake up writer if the socket is no longer flow controlled.
		 */
		if (!SO_SND_FLOWCTRLD(so)) {
			/* so_notify_writable drops so_lock */
			so_notify_writable(so);
			return;
		}
	}
	mutex_exit(&so->so_lock);
}

/*
 * sof_get_cookie(handle)
 *
 * Returns the cookie used by `handle'.
 */
void *
sof_get_cookie(sof_handle_t handle)
{
	return (((sof_instance_t *)handle)->sofi_cookie);
}

/*
 * sof_cas_cookie(handle, old, new)
 *
 * Compare-and-swap the cookie used by `handle'.
 */
void *
sof_cas_cookie(sof_handle_t handle, void *old, void *new)
{
	sof_instance_t *inst = (sof_instance_t *)handle;

	return (atomic_cas_ptr(&inst->sofi_cookie, old, new));
}

/*
 * sof_inject_data_out(handle, mp, msg, flowctrld)
 *
 * Submit `mp' for transmission. `msg' cannot by NULL, and may contain
 * ancillary data and destination address. Returns 0 when successful
 * in which case `flowctrld' is updated. If flow controlled, no new data
 * should be injected until a SOF_EV_INJECT_DATA_OUT_OK event is observed.
 * In case of failure, an errno is returned.
 *
 * Filters that are lower in the stack than `handle' will see the data
 * before it is transmitted and may end up modifying or freeing the data.
 */
int
sof_inject_data_out(sof_handle_t handle, mblk_t *mp, struct nmsghdr *msg,
    boolean_t *flowctrld)
{
	sof_instance_t *inst = (sof_instance_t *)handle;
	struct sonode *so = inst->sofi_sonode;
	int error;

	mutex_enter(&so->so_lock);
	if (so->so_state & SS_FIL_STOP) {
		mutex_exit(&so->so_lock);
		freemsg(mp);
		return (EPIPE);
	}
	so->so_filter_tx++;
	mutex_exit(&so->so_lock);

	error = so_sendmblk_impl(inst->sofi_sonode, msg, FNONBLOCK,
	    kcred, &mp, inst->sofi_next, B_TRUE);

	mutex_enter(&so->so_lock);
	ASSERT(so->so_filter_tx > 0);
	so->so_filter_tx--;
	if (so->so_state & SS_CLOSING)
		cv_signal(&so->so_closing_cv);
	mutex_exit(&so->so_lock);

	if (mp != NULL)
		freemsg(mp);

	if (error == ENOSPC) {
		*flowctrld = B_TRUE;
		error = 0;
	} else {
		*flowctrld = B_FALSE;
	}

	return (error);
}

/*
 * sof_inject_data_in(handle, mp, len, flag, flowctrld)
 *
 * Enqueue `mp' which contains `len' bytes of M_DATA onto the socket
 * associated with `handle'. `flags' should be set to 0. Returns 0 when
 * successful in which case `flowctrld' is updated. If flow controlled,
 * no new data should be injected until a SOF_EV_INJECT_DATA_IN_OK event
 * is observed.  In case of failure, an errno is returned.
 *
 * Filters that are higher in the stack than `handle' will see the data
 * before it is enqueued on the receive queue and may end up modifying or
 * freeing the data.
 */
int
sof_inject_data_in(sof_handle_t handle, mblk_t *mp, size_t len, int flags,
    boolean_t *flowctrld)
{
	sof_instance_t *inst = (sof_instance_t *)handle;
	ssize_t avail;
	int error = 0;

	ASSERT(flags == 0);
	avail = so_queue_msg_impl(inst->sofi_sonode, mp, len, flags, &error,
	    NULL, inst->sofi_prev);
	/* fallback should never happen when there is an active filter */
	ASSERT(error != EOPNOTSUPP);

	*flowctrld = (avail > 0) ? B_FALSE : B_TRUE;
	return (error);
}

/*
 * sof_newconn_move(handle, newparent)
 *
 * Private interface only to be used by KSSL.
 *
 * Moves the socket associated with `handle' from its current listening
 * socket to the listener associated with `newparent'. The socket being
 * moved must be in a deferred state and it is up to the consumer of the
 * interface to ensure that the `newparent' does not go away while this
 * operation is pending.
 */
boolean_t
sof_newconn_move(sof_handle_t handle, sof_handle_t newparent)
{
	sof_instance_t *inst = (sof_instance_t *)handle;
	sof_instance_t *newpinst = (sof_instance_t *)newparent;
	struct sonode *so, *old, *new;

	so = inst->sofi_sonode;
	ASSERT(so->so_state & SS_FIL_DEFER);

	if (inst->sofi_next != NULL || inst->sofi_prev != NULL ||
	    !(so->so_state & SS_FIL_DEFER))
		return (B_FALSE);

	old = so->so_listener;
	mutex_enter(&old->so_acceptq_lock);
	list_remove(&old->so_acceptq_defer, so);
	old->so_acceptq_len--;
	mutex_exit(&old->so_acceptq_lock);

	new = newpinst->sofi_sonode;
	mutex_enter(&new->so_acceptq_lock);
	list_insert_tail(&new->so_acceptq_defer, so);
	new->so_acceptq_len++;
	mutex_exit(&new->so_acceptq_lock);

	so->so_listener = new;

	return (B_TRUE);
}
