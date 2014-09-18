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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Support for the inotify facility, a Linux-borne facility for asynchronous
 * notification of certain events on specified files or directories.  Our
 * implementation broadly leverages the file event monitoring facility, and
 * would actually be quite straightforward were it not for a very serious
 * blunder in the inotify interface:  in addition to allowing for one to be
 * notified on events on a particular file or directory, inotify also allows
 * for one to be notified on certain events on files _within_ a watched
 * directory -- even though those events have absolutely nothing to do with
 * the directory itself.  This leads to all sorts of madness because file
 * operations are (of course) not undertaken on paths but rather on open
 * files -- and the relationships between open files and the paths that resolve
 * to those files are neither static nor isomorphic.  We implement this
 * concept by having _child watches_ when directories are watched with events
 * in IN_CHILD_EVENTS.  We add child watches when a watch on a directory is
 * first added, and we modify those child watches dynamically as files are
 * created, deleted, moved into or moved out of the specified directory.  This
 * mechanism works well, absent hard links.  Hard links, unfortunately, break
 * this rather badly, and the user is warned that watches on directories that
 * have multiple directory entries referring to the same file may behave
 * unexpectedly.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/inotify.h>
#include <sys/fem.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/vfs_opreg.h>
#include <sys/vmem.h>
#include <sys/avl.h>
#include <sys/sysmacros.h>
#include <sys/cyclic.h>
#include <sys/filio.h>

struct inotify_state;
struct inotify_kevent;

typedef struct inotify_watch inotify_watch_t;
typedef struct inotify_state inotify_state_t;
typedef struct inotify_kevent inotify_kevent_t;

struct inotify_watch {
	kmutex_t inw_lock;			/* lock protecting ref count */
	int inw_refcnt;				/* reference count */
	uint8_t inw_zombie:1;			/* boolean: is zombie */
	uint8_t inw_fired:1;			/* boolean: fired one-shot */
	uint8_t inw_active:1;			/* boolean: watch is active */
	uint8_t inw_orphaned:1;			/* boolean: orphaned */
	kcondvar_t inw_cv;			/* condvar for zombifier */
	uint32_t inw_mask;			/* mask of watch */
	int32_t inw_wd;				/* watch descriptor */
	vnode_t *inw_vp;			/* underlying vnode */
	inotify_watch_t *inw_parent;		/* parent, if a child */
	avl_node_t inw_byvp;			/* watches by vnode */
	avl_node_t inw_bywd;			/* watches by descriptor */
	avl_tree_t inw_children;		/* children, if a parent */
	char *inw_name;				/* name, if a child */
	list_node_t inw_orphan;			/* orphan list */
	inotify_state_t *inw_state;		/* corresponding state */
};

struct inotify_kevent {
	inotify_kevent_t *ine_next;		/* next event in queue */
	struct inotify_event ine_event;		/* event (variable size) */
};

#define	INOTIFY_EVENT_LENGTH(ev) \
	(sizeof (inotify_kevent_t) + (ev)->ine_event.len)

struct inotify_state {
	kmutex_t ins_lock;			/* lock protecting state */
	avl_tree_t ins_byvp;			/* watches by vnode */
	avl_tree_t ins_bywd;			/* watches by descriptor */
	vmem_t *ins_wds;			/* watch identifier arena */
	int ins_maxwatches;			/* maximum number of watches */
	int ins_maxevents;			/* maximum number of events */
	int ins_nevents;			/* current # of events */
	int32_t ins_size;			/* total size of events */
	inotify_kevent_t *ins_head;		/* head of event queue */
	inotify_kevent_t *ins_tail;		/* tail of event queue */
	pollhead_t ins_pollhd;			/* poll head */
	kcondvar_t ins_cv;			/* condvar for reading */
	list_t ins_orphans;			/* orphan list */
	cyclic_id_t ins_cleaner;		/* cyclic for cleaning */
	inotify_watch_t *ins_zombies;		/* zombie watch list */
	cred_t *ins_cred;			/* creator's credentials */
	inotify_state_t *ins_next;		/* next state on global list */
};

/*
 * Tunables (exported read-only in lx-branded zones via /proc).
 */
int	inotify_maxwatches = 8192;		/* max watches per instance */
int	inotify_maxevents = 16384;		/* max events */
int	inotify_maxinstances = 128;		/* max instances per user */

/*
 * Internal global variables.
 */
static kmutex_t		inotify_lock;		/* lock protecting state */
static dev_info_t	*inotify_devi;		/* device info */
static fem_t		*inotify_femp;		/* FEM pointer */
static vmem_t		*inotify_minor;		/* minor number arena */
static void		*inotify_softstate;	/* softstate pointer */
static inotify_state_t	*inotify_state;		/* global list if state */

static void inotify_watch_event(inotify_watch_t *, uint64_t, char *);
static void inotify_watch_insert(inotify_watch_t *, vnode_t *, char *);
static void inotify_watch_delete(inotify_watch_t *, uint32_t);
static void inotify_watch_remove(inotify_state_t *state,
	inotify_watch_t *watch);

static int
inotify_fop_close(femarg_t *vf, int flag, int count, offset_t offset,
    cred_t *cr, caller_context_t *ct)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval;

	if ((rval = vnext_close(vf, flag, count, offset, cr, ct)) == 0) {
		inotify_watch_event(watch, flag & FWRITE ?
		    IN_CLOSE_WRITE : IN_CLOSE_NOWRITE, NULL);
	}

	return (rval);
}

static int
inotify_fop_create(femarg_t *vf, char *name, vattr_t *vap, vcexcl_t excl,
    int mode, vnode_t **vpp, cred_t *cr, int flag, caller_context_t *ct,
    vsecattr_t *vsecp)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval;

	if ((rval = vnext_create(vf, name, vap, excl, mode,
	    vpp, cr, flag, ct, vsecp)) == 0) {
		inotify_watch_insert(watch, *vpp, name);
		inotify_watch_event(watch, IN_CREATE, name);
	}

	return (rval);
}

static int
inotify_fop_link(femarg_t *vf, vnode_t *svp, char *tnm, cred_t *cr,
    caller_context_t *ct, int flags)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval;

	if ((rval = vnext_link(vf, svp, tnm, cr, ct, flags)) == 0) {
		inotify_watch_insert(watch, svp, tnm);
		inotify_watch_event(watch, IN_CREATE, tnm);
	}

	return (rval);
}

static int
inotify_fop_mkdir(femarg_t *vf, char *name, vattr_t *vap, vnode_t **vpp,
    cred_t *cr, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval;

	if ((rval = vnext_mkdir(vf, name, vap, vpp, cr,
	    ct, flags, vsecp)) == 0) {
		inotify_watch_insert(watch, *vpp, name);
		inotify_watch_event(watch, IN_CREATE | IN_ISDIR, name);
	}

	return (rval);
}

static int
inotify_fop_open(femarg_t *vf, int mode, cred_t *cr, caller_context_t *ct)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval;

	if ((rval = vnext_open(vf, mode, cr, ct)) == 0)
		inotify_watch_event(watch, IN_OPEN, NULL);

	return (rval);
}

static int
inotify_fop_read(femarg_t *vf, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval = vnext_read(vf, uiop, ioflag, cr, ct);
	inotify_watch_event(watch, IN_ACCESS, NULL);

	return (rval);
}

static int
inotify_fop_readdir(femarg_t *vf, uio_t *uiop, cred_t *cr, int *eofp,
    caller_context_t *ct, int flags)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval = vnext_readdir(vf, uiop, cr, eofp, ct, flags);
	inotify_watch_event(watch, IN_ACCESS | IN_ISDIR, NULL);

	return (rval);
}

int
inotify_fop_remove(femarg_t *vf, char *nm, cred_t *cr, caller_context_t *ct,
    int flags)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval;

	if ((rval = vnext_remove(vf, nm, cr, ct, flags)) == 0)
		inotify_watch_event(watch, IN_DELETE, nm);

	return (rval);
}

int
inotify_fop_rmdir(femarg_t *vf, char *nm, vnode_t *cdir, cred_t *cr,
    caller_context_t *ct, int flags)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval;

	if ((rval = vnext_rmdir(vf, nm, cdir, cr, ct, flags)) == 0)
		inotify_watch_event(watch, IN_DELETE | IN_ISDIR, nm);

	return (rval);
}

static int
inotify_fop_setattr(femarg_t *vf, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval;

	if ((rval = vnext_setattr(vf, vap, flags, cr, ct)) == 0)
		inotify_watch_event(watch, IN_ATTRIB, NULL);

	return (rval);
}

static int
inotify_fop_write(femarg_t *vf, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;
	int rval = vnext_write(vf, uiop, ioflag, cr, ct);
	inotify_watch_event(watch, IN_MODIFY, NULL);

	return (rval);
}

static int
inotify_fop_vnevent(femarg_t *vf, vnevent_t vnevent, vnode_t *dvp, char *name,
    caller_context_t *ct)
{
	inotify_watch_t *watch = vf->fa_fnode->fn_available;

	switch (vnevent) {
	case VE_RENAME_SRC:
		inotify_watch_event(watch, IN_MOVE_SELF, NULL);
		inotify_watch_delete(watch, IN_MOVE_SELF);
		break;
	case VE_REMOVE:
		/*
		 * Linux will apparently fire an IN_ATTRIB event when the link
		 * count changes (including when it drops to 0 on a remove).
		 * This is merely somewhat odd; what is amazing is that this
		 * IN_ATTRIB event is not visible on an inotify watch on the
		 * parent directory.  (IN_ATTRIB events are normally sent to
		 * watches on the parent directory).  While it's hard to
		 * believe that this constitutes desired semantics, ltp
		 * unfortunately tests this case (if implicitly); in the name
		 * of bug-for-bug compatibility, we fire IN_ATTRIB iff we are
		 * explicitly watching the file that has been removed.
		 */
		if (watch->inw_parent == NULL)
			inotify_watch_event(watch, IN_ATTRIB, NULL);

		/*FALLTHROUGH*/
	case VE_RENAME_DEST:
		inotify_watch_event(watch, IN_DELETE_SELF, NULL);
		inotify_watch_delete(watch, IN_DELETE_SELF);
		break;
	case VE_RMDIR:
		/*
		 * It seems that IN_ISDIR should really be OR'd in here, but
		 * Linux doesn't seem to do that in this case; for the sake of
		 * bug-for-bug compatibility, we don't do it either.
		 */
		inotify_watch_event(watch, IN_DELETE_SELF, NULL);
		inotify_watch_delete(watch, IN_DELETE_SELF);
		break;
	case VE_CREATE:
		inotify_watch_event(watch, IN_MODIFY | IN_ATTRIB, NULL);
		break;
	case VE_LINK:
		inotify_watch_event(watch, IN_ATTRIB, NULL);
		break;
	case VE_RENAME_SRC_DIR:
		inotify_watch_event(watch, IN_MOVED_FROM, name);
		break;
	case VE_RENAME_DEST_DIR:
		if (name == NULL)
			name = dvp->v_path;

		inotify_watch_insert(watch, dvp, name);
		inotify_watch_event(watch, IN_MOVED_TO, name);
		break;
	case VE_SUPPORT:
	case VE_MOUNTEDOVER:
	case VE_TRUNCATE:
		break;
	}

	return (vnext_vnevent(vf, vnevent, dvp, name, ct));
}

const fs_operation_def_t inotify_vnodesrc_template[] = {
	VOPNAME_CLOSE,		{ .femop_close = inotify_fop_close },
	VOPNAME_CREATE,		{ .femop_create = inotify_fop_create },
	VOPNAME_LINK,		{ .femop_link = inotify_fop_link },
	VOPNAME_MKDIR,		{ .femop_mkdir = inotify_fop_mkdir },
	VOPNAME_OPEN,		{ .femop_open = inotify_fop_open },
	VOPNAME_READ,		{ .femop_read = inotify_fop_read },
	VOPNAME_READDIR,	{ .femop_readdir = inotify_fop_readdir },
	VOPNAME_REMOVE,		{ .femop_remove = inotify_fop_remove },
	VOPNAME_RMDIR,		{ .femop_rmdir = inotify_fop_rmdir },
	VOPNAME_SETATTR,	{ .femop_setattr = inotify_fop_setattr },
	VOPNAME_WRITE,		{ .femop_write = inotify_fop_write },
	VOPNAME_VNEVENT,	{ .femop_vnevent = inotify_fop_vnevent },
	NULL, NULL
};

static int
inotify_watch_cmpwd(inotify_watch_t *lhs, inotify_watch_t *rhs)
{
	if (lhs->inw_wd < rhs->inw_wd)
		return (-1);

	if (lhs->inw_wd > rhs->inw_wd)
		return (1);

	return (0);
}

static int
inotify_watch_cmpvp(inotify_watch_t *lhs, inotify_watch_t *rhs)
{
	uintptr_t lvp = (uintptr_t)lhs->inw_vp, rvp = (uintptr_t)rhs->inw_vp;

	if (lvp < rvp)
		return (-1);

	if (lvp > rvp)
		return (1);

	return (0);
}

static void
inotify_watch_hold(inotify_watch_t *watch)
{
	mutex_enter(&watch->inw_lock);
	VERIFY(watch->inw_refcnt > 0);
	watch->inw_refcnt++;
	mutex_exit(&watch->inw_lock);
}

static void
inotify_watch_release(inotify_watch_t *watch)
{
	mutex_enter(&watch->inw_lock);
	VERIFY(watch->inw_refcnt > 1);

	if (--watch->inw_refcnt == 1 && watch->inw_zombie) {
		/*
		 * We're down to our last reference; kick anyone that might be
		 * waiting.
		 */
		cv_signal(&watch->inw_cv);
	}

	mutex_exit(&watch->inw_lock);
}

static void
inotify_watch_event(inotify_watch_t *watch, uint64_t mask, char *name)
{
	inotify_kevent_t *event, *tail;
	inotify_state_t *state = watch->inw_state;
	uint32_t wd = watch->inw_wd, cookie = 0, len;
	int align = sizeof (uintptr_t) - 1;
	boolean_t removal = mask & IN_REMOVAL ? B_TRUE : B_FALSE;
	inotify_watch_t *source = watch;

	if (!(mask &= watch->inw_mask) || mask == IN_ISDIR)
		return;

	if (watch->inw_parent != NULL) {
		/*
		 * This is an event on the child; if this isn't a valid child
		 * event, return.  Otherwise, we move our watch to be our
		 * parent (which we know is around because we have a hold on
		 * it) and continue.
		 */
		if (!(mask & IN_CHILD_EVENTS))
			return;

		name = watch->inw_name;
		watch = watch->inw_parent;
	}

	if (!removal) {
		mutex_enter(&state->ins_lock);

		if (watch->inw_zombie ||
		    watch->inw_fired || !watch->inw_active) {
			mutex_exit(&state->ins_lock);
			return;
		}
	} else {
		if (!watch->inw_active)
			return;

		VERIFY(MUTEX_HELD(&state->ins_lock));
	}

	/*
	 * If this is an operation on a directory and it's a child event
	 * (event if it's not on a child), we specify IN_ISDIR.
	 */
	if (source->inw_vp->v_type == VDIR && (mask & IN_CHILD_EVENTS))
		mask |= IN_ISDIR;

	if (mask & (IN_MOVED_FROM | IN_MOVED_TO))
		cookie = (uint32_t)curthread->t_did;

	if (state->ins_nevents >= state->ins_maxevents) {
		/*
		 * We're at our maximum number of events -- turn our event
		 * into an IN_Q_OVERFLOW event, which will be coalesced if
		 * it's already the tail event.
		 */
		mask = IN_Q_OVERFLOW;
		wd = (uint32_t)-1;
		cookie = 0;
		len = 0;
	}

	if ((tail = state->ins_tail) != NULL && tail->ine_event.wd == wd &&
	    tail->ine_event.mask == mask && tail->ine_event.cookie == cookie &&
	    ((tail->ine_event.len == 0 && len == 0) ||
	    (name != NULL && tail->ine_event.len != 0 &&
	    strcmp(tail->ine_event.name, name) == 0))) {
		/*
		 * This is an implicitly coalesced event; we're done.
		 */
		if (!removal)
			mutex_exit(&state->ins_lock);
		return;
	}

	if (name != NULL) {
		if ((len = strlen(name) + 1) & align)
			len += (align + 1) - (len & align);
	} else {
		len = 0;
	}

	event = kmem_zalloc(sizeof (inotify_kevent_t) + len, KM_SLEEP);
	event->ine_event.wd = wd;
	event->ine_event.mask = (uint32_t)mask;
	event->ine_event.cookie = cookie;
	event->ine_event.len = len;

	if (name != NULL)
		strcpy(event->ine_event.name, name);

	if (tail != NULL) {
		tail->ine_next = event;
	} else {
		VERIFY(state->ins_head == NULL);
		state->ins_head = event;
		cv_broadcast(&state->ins_cv);
	}

	state->ins_tail = event;
	state->ins_nevents++;
	state->ins_size += sizeof (inotify_kevent_t) + len;

	if ((watch->inw_mask & IN_ONESHOT) && !watch->inw_fired) {
		/*
		 * If this is a one-shot, we need to remove the watch.  (Note
		 * that this will recurse back into inotify_watch_event() to
		 * fire the IN_IGNORED event -- but with "removal" set.)
		 */
		watch->inw_fired = 1;
		inotify_watch_remove(state, watch);
	}

	if (removal)
		return;

	mutex_exit(&state->ins_lock);
	pollwakeup(&state->ins_pollhd, POLLRDNORM | POLLIN);
}

/*
 * Destroy a watch.  By the time we're in here, the watch must have exactly
 * one reference.
 */
static void
inotify_watch_destroy(inotify_watch_t *watch)
{
	VERIFY(MUTEX_HELD(&watch->inw_lock));

	if (watch->inw_name != NULL)
		kmem_free(watch->inw_name, strlen(watch->inw_name) + 1);

	kmem_free(watch, sizeof (inotify_watch_t));
}

/*
 * Zombify a watch.  By the time we come in here, it must be true that the
 * watch has already been fem_uninstall()'d -- the only reference should be
 * in the state's data structure.  If we can get away with freeing it, we'll
 * do that -- but if the reference count is greater than one due to an active
 * vnode operation, we'll put this watch on the zombie list on the state
 * structure.
 */
static void
inotify_watch_zombify(inotify_watch_t *watch)
{
	inotify_state_t *state = watch->inw_state;

	VERIFY(MUTEX_HELD(&state->ins_lock));
	VERIFY(!watch->inw_zombie);

	watch->inw_zombie = 1;

	if (watch->inw_parent != NULL) {
		inotify_watch_release(watch->inw_parent);
	} else {
		avl_remove(&state->ins_byvp, watch);
		avl_remove(&state->ins_bywd, watch);
		vmem_free(state->ins_wds, (void *)(uintptr_t)watch->inw_wd, 1);
		watch->inw_wd = -1;
	}

	mutex_enter(&watch->inw_lock);

	if (watch->inw_refcnt == 1) {
		/*
		 * There are no operations in flight and there is no way
		 * for anyone to discover this watch -- we can destroy it.
		 */
		inotify_watch_destroy(watch);
	} else {
		/*
		 * There are operations in flight; we will need to enqueue
		 * this for later destruction.
		 */
		watch->inw_parent = state->ins_zombies;
		state->ins_zombies = watch;
		mutex_exit(&watch->inw_lock);
	}
}

static inotify_watch_t *
inotify_watch_add(inotify_state_t *state, inotify_watch_t *parent,
    const char *name, vnode_t *vp, uint32_t mask)
{
	inotify_watch_t *watch;
	int err;

	VERIFY(MUTEX_HELD(&state->ins_lock));

	watch = kmem_zalloc(sizeof (inotify_watch_t), KM_SLEEP);

	watch->inw_vp = vp;
	watch->inw_mask = mask;
	watch->inw_state = state;
	watch->inw_refcnt = 1;

	if (parent == NULL) {
		watch->inw_wd = (int)(uintptr_t)vmem_alloc(state->ins_wds,
		    1, VM_BESTFIT | VM_SLEEP);
		avl_add(&state->ins_byvp, watch);
		avl_add(&state->ins_bywd, watch);

		avl_create(&watch->inw_children,
		    (int(*)(const void *, const void *))inotify_watch_cmpvp,
		    sizeof (inotify_watch_t),
		    offsetof(inotify_watch_t, inw_byvp));
	} else {
		VERIFY(name != NULL);
		inotify_watch_hold(parent);
		watch->inw_mask &= IN_CHILD_EVENTS;
		watch->inw_parent = parent;
		watch->inw_name = kmem_alloc(strlen(name) + 1, KM_SLEEP);
		strcpy(watch->inw_name, name);

		avl_add(&parent->inw_children, watch);
	}

	/*
	 * Add our monitor to the vnode.  We must not have the watch lock held
	 * when we do this, as it will immediately hold our watch.
	 */
	err = fem_install(vp, inotify_femp, watch, OPARGUNIQ,
	    (void (*)(void *))inotify_watch_hold,
	    (void (*)(void *))inotify_watch_release);

	VERIFY(err == 0);

	return (watch);
}

/*
 * Remove a (non-child) watch.  This is called from either synchronous context
 * via inotify_rm_watch() or monitor context via either a vnevent or a
 * one-shot.
 */
static void
inotify_watch_remove(inotify_state_t *state, inotify_watch_t *watch)
{
	inotify_watch_t *child;
	int err;

	VERIFY(MUTEX_HELD(&state->ins_lock));
	VERIFY(watch->inw_parent == NULL);

	err = fem_uninstall(watch->inw_vp, inotify_femp, watch);
	VERIFY(err == 0);

	/*
	 * If we have children, we're going to remove them all and set them
	 * all to be zombies.
	 */
	while ((child = avl_first(&watch->inw_children)) != NULL) {
		VERIFY(child->inw_parent == watch);
		avl_remove(&watch->inw_children, child);

		err = fem_uninstall(child->inw_vp, inotify_femp, child);
		VERIFY(err == 0);

		/*
		 * If this child watch has been orphaned, remove it from the
		 * state's list of orphans.
		 */
		if (watch->inw_orphaned)
			list_remove(&state->ins_orphans, watch);

		VN_RELE(child->inw_vp);

		/*
		 * We're down (or should be down) to a single reference to
		 * this child watch; it's safe to zombify it.
		 */
		inotify_watch_zombify(child);
	}

	inotify_watch_event(watch, IN_IGNORED | IN_REMOVAL, NULL);
	VN_RELE(watch->inw_vp);

	/*
	 * It's now safe to zombify the watch -- we know that the only reference
	 * can come from operations in flight.
	 */
	inotify_watch_zombify(watch);
}

/*
 * Delete a watch.  Should only be called from VOP context.
 */
static void
inotify_watch_delete(inotify_watch_t *watch, uint32_t event)
{
	inotify_state_t *state = watch->inw_state;
	inotify_watch_t cmp = { .inw_vp = watch->inw_vp }, *parent;
	int err;

	if (event != IN_DELETE_SELF && !(watch->inw_mask & IN_CHILD_EVENTS))
		return;

	mutex_enter(&state->ins_lock);

	if (watch->inw_zombie) {
		mutex_exit(&state->ins_lock);
		return;
	}

	if ((parent = watch->inw_parent) == NULL) {
		if (event == IN_DELETE_SELF) {
			/*
			 * If we're here because we're being deleted and we
			 * are not a child watch, we need to delete the entire
			 * watch, children and all.
			 */
			inotify_watch_remove(state, watch);
		}

		mutex_exit(&state->ins_lock);
		return;
	} else {
		if (event == IN_DELETE_SELF &&
		    !(parent->inw_mask & IN_EXCL_UNLINK)) {
			/*
			 * This is a child watch for a file that is being
			 * removed and IN_EXCL_UNLINK has not been specified;
			 * indicate that it is orphaned and add it to the list
			 * of orphans.  (This list will be checked by the
			 * cleaning cyclic to determine when the watch has
			 * become the only hold on the vnode, at which point
			 * the watch can be zombified.)  Note that we check
			 * if the watch is orphaned before we orphan it:  hard
			 * links make it possible for VE_REMOVE to be called
			 * multiple times on the same vnode. (!)
			 */
			if (!watch->inw_orphaned) {
				watch->inw_orphaned = 1;
				list_insert_head(&state->ins_orphans, watch);
			}

			mutex_exit(&state->ins_lock);
			return;
		}

		if (watch->inw_orphaned) {
			/*
			 * If we're here, a file was orphaned and then later
			 * moved -- which almost certainly means that hard
			 * links are on the scene.  We choose the orphan over
			 * the move because we don't want to spuriously
			 * drop events if we can avoid it.
			 */
			list_remove(&state->ins_orphans, watch);
		}
	}

	if (avl_find(&parent->inw_children, &cmp, NULL) == NULL) {
		/*
		 * This watch has already been deleted from the parent.
		 */
		mutex_exit(&state->ins_lock);
		return;
	}

	avl_remove(&parent->inw_children, watch);
	err = fem_uninstall(watch->inw_vp, inotify_femp, watch);
	VERIFY(err == 0);

	VN_RELE(watch->inw_vp);

	/*
	 * It's now safe to zombify the watch -- which won't actually delete
	 * it as we know that the reference count is greater than 1.
	 */
	inotify_watch_zombify(watch);
	mutex_exit(&state->ins_lock);
}

/*
 * Insert a new child watch.  Should only be called from VOP context when
 * a child is created in a watched directory.
 */
static void
inotify_watch_insert(inotify_watch_t *watch, vnode_t *vp, char *name)
{
	inotify_state_t *state = watch->inw_state;
	inotify_watch_t cmp = { .inw_vp = vp };

	if (!(watch->inw_mask & IN_CHILD_EVENTS))
		return;

	mutex_enter(&state->ins_lock);

	if (watch->inw_zombie || watch->inw_parent != NULL || vp == NULL) {
		mutex_exit(&state->ins_lock);
		return;
	}

	if (avl_find(&watch->inw_children, &cmp, NULL) != NULL) {
		mutex_exit(&state->ins_lock);
		return;
	}

	VN_HOLD(vp);
	watch = inotify_watch_add(state, watch, name, vp, watch->inw_mask);
	VERIFY(watch != NULL);

	mutex_exit(&state->ins_lock);
}


static int
inotify_add_watch(inotify_state_t *state, vnode_t *vp, uint32_t mask,
    int32_t *wdp)
{
	inotify_watch_t *watch, cmp = { .inw_vp = vp };
	uint32_t set;

	set = (mask & (IN_ALL_EVENTS | IN_MODIFIERS)) | IN_UNMASKABLE;

	/*
	 * Lookup our vnode to determine if we already have a watch on it.
	 */
	mutex_enter(&state->ins_lock);

	if ((watch = avl_find(&state->ins_byvp, &cmp, NULL)) == NULL) {
		/*
		 * We don't have this watch; allocate a new one, provided that
		 * we have fewer than our limit.
		 */
		if (avl_numnodes(&state->ins_bywd) >= state->ins_maxwatches) {
			mutex_exit(&state->ins_lock);
			return (ENOSPC);
		}

		VN_HOLD(vp);
		watch = inotify_watch_add(state, NULL, NULL, vp, set);
		*wdp = watch->inw_wd;
		mutex_exit(&state->ins_lock);

		return (0);
	}

	VERIFY(!watch->inw_zombie);

	if (!(mask & IN_MASK_ADD)) {
		/*
		 * Note that if we're resetting our event mask and we're
		 * transitioning from an event mask that includes child events
		 * to one that doesn't, there will be potentially some stale
		 * child watches.  This is basically fine:  they won't fire,
		 * and they will correctly be removed when the watch is
		 * removed.
		 */
		watch->inw_mask = 0;
	}

	watch->inw_mask |= set;

	*wdp = watch->inw_wd;

	mutex_exit(&state->ins_lock);

	return (0);
}

static int
inotify_add_child(inotify_state_t *state, vnode_t *vp, char *name)
{
	inotify_watch_t *watch, cmp = { .inw_vp = vp };
	vnode_t *cvp;
	int err;

	/*
	 * Verify that the specified child doesn't have a directory component
	 * within it.
	 */
	if (strchr(name, '/') != NULL)
		return (EINVAL);

	/*
	 * Lookup the underlying file.  Note that this will succeed even if
	 * we don't have permissions to actually read the file.
	 */
	if ((err = lookupnameat(name,
	    UIO_SYSSPACE, NO_FOLLOW, NULL, &cvp, vp)) != 0) {
		return (err);
	}

	/*
	 * Use our vnode to find our watch, and then add our child watch to it.
	 */
	mutex_enter(&state->ins_lock);

	if ((watch = avl_find(&state->ins_byvp, &cmp, NULL)) == NULL) {
		/*
		 * This is unexpected -- it means that we don't have the
		 * watch that we thought we had.
		 */
		mutex_exit(&state->ins_lock);
		VN_RELE(cvp);
		return (ENXIO);
	}

	/*
	 * Now lookup the child vnode in the watch; we'll only add it if it
	 * isn't already there.
	 */
	cmp.inw_vp = cvp;

	if (avl_find(&watch->inw_children, &cmp, NULL) != NULL) {
		mutex_exit(&state->ins_lock);
		VN_RELE(cvp);
		return (0);
	}

	watch = inotify_watch_add(state, watch, name, cvp, watch->inw_mask);
	VERIFY(watch != NULL);
	mutex_exit(&state->ins_lock);

	return (0);
}

static int
inotify_rm_watch(inotify_state_t *state, int32_t wd)
{
	inotify_watch_t *watch, cmp = { .inw_wd = wd };

	mutex_enter(&state->ins_lock);

	if ((watch = avl_find(&state->ins_bywd, &cmp, NULL)) == NULL) {
		mutex_exit(&state->ins_lock);
		return (EINVAL);
	}

	inotify_watch_remove(state, watch);
	mutex_exit(&state->ins_lock);

	return (0);
}

static int
inotify_activate(inotify_state_t *state, int32_t wd)
{
	inotify_watch_t *watch, cmp = { .inw_wd = wd };

	mutex_enter(&state->ins_lock);

	if ((watch = avl_find(&state->ins_bywd, &cmp, NULL)) == NULL) {
		mutex_exit(&state->ins_lock);
		return (EINVAL);
	}

	watch->inw_active = 1;

	mutex_exit(&state->ins_lock);

	return (0);
}

/*
 * Called periodically as a cyclic to process the orphans and zombies.
 */
static void
inotify_clean(void *arg)
{
	inotify_state_t *state = arg;
	inotify_watch_t *watch, *parent, *next, **prev;
	int err;

	mutex_enter(&state->ins_lock);

	for (watch = list_head(&state->ins_orphans);
	    watch != NULL; watch = next) {
		next = list_next(&state->ins_orphans, watch);

		VERIFY(!watch->inw_zombie);
		VERIFY((parent = watch->inw_parent) != NULL);

		if (watch->inw_vp->v_count > 1)
			continue;

		avl_remove(&parent->inw_children, watch);
		err = fem_uninstall(watch->inw_vp, inotify_femp, watch);
		VERIFY(err == 0);

		list_remove(&state->ins_orphans, watch);

		VN_RELE(watch->inw_vp);
		inotify_watch_zombify(watch);
	}

	prev = &state->ins_zombies;

	while ((watch = *prev) != NULL) {
		mutex_enter(&watch->inw_lock);

		if (watch->inw_refcnt == 1) {
			*prev = watch->inw_parent;
			inotify_watch_destroy(watch);
			continue;
		}

		prev = &watch->inw_parent;
		mutex_exit(&watch->inw_lock);
	}

	mutex_exit(&state->ins_lock);
}

/*ARGSUSED*/
static int
inotify_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	inotify_state_t *state;
	major_t major = getemajor(*devp);
	minor_t minor = getminor(*devp);
	int instances = 0;
	cyc_handler_t hdlr;
	cyc_time_t when;
	char c[64];

	if (minor != INOTIFYMNRN_INOTIFY)
		return (ENXIO);

	mutex_enter(&inotify_lock);

	for (state = inotify_state; state != NULL; state = state->ins_next) {
		if (state->ins_cred == cred_p)
			instances++;
	}

	if (instances >= inotify_maxinstances) {
		mutex_exit(&inotify_lock);
		return (EMFILE);
	}

	minor = (minor_t)(uintptr_t)vmem_alloc(inotify_minor, 1,
	    VM_BESTFIT | VM_SLEEP);

	if (ddi_soft_state_zalloc(inotify_softstate, minor) != DDI_SUCCESS) {
		vmem_free(inotify_minor, (void *)(uintptr_t)minor, 1);
		mutex_exit(&inotify_lock);
		return (NULL);
	}

	state = ddi_get_soft_state(inotify_softstate, minor);
	*devp = makedevice(major, minor);

	crhold(cred_p);
	state->ins_cred = cred_p;
	state->ins_next = inotify_state;
	inotify_state = state;

	(void) snprintf(c, sizeof (c), "inotify_watchid_%d", minor);
	state->ins_wds = vmem_create(c, (void *)1, UINT32_MAX, 1,
	    NULL, NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);

	avl_create(&state->ins_bywd,
	    (int(*)(const void *, const void *))inotify_watch_cmpwd,
	    sizeof (inotify_watch_t),
	    offsetof(inotify_watch_t, inw_bywd));

	avl_create(&state->ins_byvp,
	    (int(*)(const void *, const void *))inotify_watch_cmpvp,
	    sizeof (inotify_watch_t),
	    offsetof(inotify_watch_t, inw_byvp));

	list_create(&state->ins_orphans, sizeof (inotify_watch_t),
	    offsetof(inotify_watch_t, inw_orphan));

	state->ins_maxwatches = inotify_maxwatches;
	state->ins_maxevents = inotify_maxevents;

	mutex_exit(&inotify_lock);

	mutex_enter(&cpu_lock);

	hdlr.cyh_func = inotify_clean;
	hdlr.cyh_level = CY_LOW_LEVEL;
	hdlr.cyh_arg = state;

	when.cyt_when = 0;
	when.cyt_interval = NANOSEC;

	state->ins_cleaner = cyclic_add(&hdlr, &when);
	mutex_exit(&cpu_lock);

	return (0);
}

/*ARGSUSED*/
static int
inotify_read(dev_t dev, uio_t *uio, cred_t *cr)
{
	inotify_state_t *state;
	inotify_kevent_t *event;
	minor_t minor = getminor(dev);
	int err = 0, nevents = 0;
	size_t len;

	state = ddi_get_soft_state(inotify_softstate, minor);

	mutex_enter(&state->ins_lock);

	while (state->ins_head == NULL) {
		if (uio->uio_fmode & (FNDELAY|FNONBLOCK)) {
			mutex_exit(&state->ins_lock);
			return (EAGAIN);
		}

		if (!cv_wait_sig_swap(&state->ins_cv, &state->ins_lock)) {
			mutex_exit(&state->ins_lock);
			return (EINTR);
		}
	}

	/*
	 * We have events and we have our lock; return as many as we can.
	 */
	while ((event = state->ins_head) != NULL) {
		len = sizeof (event->ine_event) + event->ine_event.len;

		if (uio->uio_resid < len) {
			if (nevents == 0)
				err = EINVAL;
			break;
		}

		nevents++;

		if ((err = uiomove(&event->ine_event, len, UIO_READ, uio)) != 0)
			break;

		VERIFY(state->ins_nevents > 0);
		state->ins_nevents--;

		VERIFY(state->ins_size > 0);
		state->ins_size -= INOTIFY_EVENT_LENGTH(event);

		if ((state->ins_head = event->ine_next) == NULL) {
			VERIFY(event == state->ins_tail);
			VERIFY(state->ins_nevents == 0);
			state->ins_tail = NULL;
		}

		kmem_free(event, INOTIFY_EVENT_LENGTH(event));
	}

	mutex_exit(&state->ins_lock);

	return (err);
}

/*ARGSUSED*/
static int
inotify_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	inotify_state_t *state;
	minor_t minor = getminor(dev);

	state = ddi_get_soft_state(inotify_softstate, minor);

	mutex_enter(&state->ins_lock);

	if (state->ins_head != NULL) {
		*reventsp = POLLRDNORM | POLLIN;
	} else {
		*reventsp = 0;

		if (!anyyet)
			*phpp = &state->ins_pollhd;
	}

	mutex_exit(&state->ins_lock);

	return (0);
}

/*ARGSUSED*/
static int
inotify_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	inotify_state_t *state;
	minor_t minor = getminor(dev);
	file_t *fp;
	int rval;

	state = ddi_get_soft_state(inotify_softstate, minor);

	switch (cmd) {
	case INOTIFYIOC_ADD_WATCH: {
		inotify_addwatch_t addwatch;
		file_t *fp;

		if (copyin((void *)arg, &addwatch, sizeof (addwatch)) != 0)
			return (EFAULT);

		if ((fp = getf(addwatch.inaw_fd)) == NULL)
			return (EBADF);

		rval = inotify_add_watch(state, fp->f_vnode,
		    addwatch.inaw_mask, rv);

		releasef(addwatch.inaw_fd);
		return (rval);
	}

	case INOTIFYIOC_ADD_CHILD: {
		inotify_addchild_t addchild;
		char name[MAXPATHLEN];

		if (copyin((void *)arg, &addchild, sizeof (addchild)) != 0)
			return (EFAULT);

		if (copyinstr(addchild.inac_name, name, MAXPATHLEN, NULL) != 0)
			return (EFAULT);

		if ((fp = getf(addchild.inac_fd)) == NULL)
			return (EBADF);

		rval = inotify_add_child(state, fp->f_vnode, name);

		releasef(addchild.inac_fd);
		return (rval);
	}

	case INOTIFYIOC_RM_WATCH:
		return (inotify_rm_watch(state, arg));

	case INOTIFYIOC_ACTIVATE:
		return (inotify_activate(state, arg));

	case FIONREAD:
		mutex_enter(&state->ins_lock);
		*rv = state->ins_size;
		mutex_exit(&state->ins_lock);

		return (0);

	default:
		break;
	}

	return (ENOTTY);
}

/*ARGSUSED*/
static int
inotify_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	inotify_state_t *state, **sp;
	inotify_watch_t *watch, *zombies;
	inotify_kevent_t *event;
	minor_t minor = getminor(dev);

	state = ddi_get_soft_state(inotify_softstate, minor);

	mutex_enter(&state->ins_lock);

	/*
	 * First, destroy all of our watches.
	 */
	while ((watch = avl_first(&state->ins_bywd)) != NULL)
		inotify_watch_remove(state, watch);

	/*
	 * And now destroy our event queue.
	 */
	while ((event = state->ins_head) != NULL) {
		state->ins_head = event->ine_next;
		kmem_free(event, INOTIFY_EVENT_LENGTH(event));
	}

	zombies = state->ins_zombies;
	state->ins_zombies = NULL;
	mutex_exit(&state->ins_lock);

	/*
	 * Now that our state lock is dropped, we can synchronously wait on
	 * any zombies.
	 */
	while ((watch = zombies) != NULL) {
		zombies = zombies->inw_parent;

		mutex_enter(&watch->inw_lock);

		while (watch->inw_refcnt > 1)
			cv_wait(&watch->inw_cv, &watch->inw_lock);

		inotify_watch_destroy(watch);
	}

	mutex_enter(&cpu_lock);
	cyclic_remove(state->ins_cleaner);
	mutex_exit(&cpu_lock);

	mutex_enter(&inotify_lock);

	/*
	 * Remove our state from our global list, and release our hold on
	 * the cred.
	 */
	for (sp = &inotify_state; *sp != state; sp = &((*sp)->ins_next))
		VERIFY(*sp != NULL);

	*sp = (*sp)->ins_next;
	crfree(state->ins_cred);

	ddi_soft_state_free(inotify_softstate, minor);
	vmem_free(inotify_minor, (void *)(uintptr_t)minor, 1);

	mutex_exit(&inotify_lock);

	return (0);
}

/*ARGSUSED*/
static int
inotify_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	mutex_enter(&inotify_lock);

	if (ddi_soft_state_init(&inotify_softstate,
	    sizeof (inotify_state_t), 0) != 0) {
		cmn_err(CE_NOTE, "/dev/inotify failed to create soft state");
		mutex_exit(&inotify_lock);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "inotify", S_IFCHR,
	    INOTIFYMNRN_INOTIFY, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		cmn_err(CE_NOTE, "/dev/inotify couldn't create minor node");
		ddi_soft_state_fini(&inotify_softstate);
		mutex_exit(&inotify_lock);
		return (DDI_FAILURE);
	}

	if (fem_create("inotify_fem",
	    inotify_vnodesrc_template, &inotify_femp) != 0) {
		cmn_err(CE_NOTE, "/dev/inotify couldn't create FEM state");
		ddi_remove_minor_node(devi, NULL);
		ddi_soft_state_fini(&inotify_softstate);
		mutex_exit(&inotify_lock);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	inotify_devi = devi;

	inotify_minor = vmem_create("inotify_minor", (void *)INOTIFYMNRN_CLONE,
	    UINT32_MAX - INOTIFYMNRN_CLONE, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);

	mutex_exit(&inotify_lock);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
inotify_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&inotify_lock);
	fem_free(inotify_femp);
	vmem_destroy(inotify_minor);

	ddi_remove_minor_node(inotify_devi, NULL);
	inotify_devi = NULL;

	ddi_soft_state_fini(&inotify_softstate);
	mutex_exit(&inotify_lock);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
inotify_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)inotify_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static struct cb_ops inotify_cb_ops = {
	inotify_open,		/* open */
	inotify_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	inotify_read,		/* read */
	nodev,			/* write */
	inotify_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	inotify_poll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops inotify_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	inotify_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	inotify_attach,		/* attach */
	inotify_detach,		/* detach */
	nodev,			/* reset */
	&inotify_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"inotify support",	/* name of module */
	&inotify_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
