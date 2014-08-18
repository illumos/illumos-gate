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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * File Events Notification
 * ------------------------
 *
 * The File Events Notification facility provides file and directory change
 * notification. It is implemented as an event source(PORT_SOURCE_FILE)
 * under the Event Ports framework. Therefore the API is an extension to
 * the Event Ports API.
 *
 * It uses the FEM (File Events Monitoring) framework to intercept
 * operations on the files & directories and generate appropriate events.
 *
 * It provides event notification in accordance with what an application
 * can find out by stat`ing the file and comparing time stamps. The various
 * system calls that update the file's access, modification, and change
 * time stamps are documented in the man page section 2.
 *
 * It is non intrusive. That is, having an active file event watch on a file
 * or directory will not prevent it from being removed or renamed or block an
 * unmount operation of the file system where the watched file or directory
 * resides.
 *
 *
 * Interface:
 * ----------
 *
 *   The object for this event source is of type 'struct file_obj *'
 *
 *   The file that needs to be monitored is specified in 'fo_name'.
 *   The time stamps collected by a stat(2) call are passed in fo_atime,
 *   fo_mtime, fo_ctime. At the time a file events watch is registered, the
 *   time stamps passed in are compared with the current time stamps of the
 *   file. If it has changed, relevant events are sent immediately. If the time
 *   stamps are all '0', they will not be compared.
 *
 *
 * The events are delivered to an event port. A port is created using
 * port_create().
 *
 * To register a file events watch on a file or directory.
 *
 *   port_associate(int port, PORT_SOURCE_FILE, (uintptr_t)&fobj, events, user)
 *
 *   'user' is the user pointer to be returned with the event.
 *
 * To de-register a file events watch,
 *
 *   port_dissociate(int port, PORT_SOURCE_FILE, (uintptr_t)&fobj)
 *
 * The events are collected using the port_get()/port_getn() interface. The
 * event source will be PORT_SOURCE_FILE.
 *
 * After an event is delivered, the file events watch gets de-activated. To
 * receive the next event, the process will have to re-register the watch and
 * activate it by calling port_associate() again. This behavior is intentional
 * and supports proper multi threaded programming when using file events
 * notification API.
 *
 *
 * Implementation overview:
 * ------------------------
 *
 * Each file events watch is represented by 'portfop_t' in the kernel. A
 * cache(in portfop_cache_t) of these portfop_t's are maintained per event
 * port by this source. The object here is the pointer to the file_obj
 * structure. The portfop_t's are hashed in using the object pointer. Therefore
 * it is possible to have multiple file events watches on a file by the same
 * process by using different object structure(file_obj_t) and hence can
 * receive multiple event notification for a file. These watches can be for
 * different event types.
 *
 * The cached entries of these file objects are retained, even after delivering
 * an event, marking them inactive for performance reasons. The assumption
 * is that the process would come back and re-register the file to receive
 * further events. When there are more then 'port_fop_maxpfps' watches per file
 * it will attempt to free the oldest inactive watches.
 *
 * In case the event that is being delivered is an exception event, the cached
 * entries get removed. An exception event on a file or directory means its
 * identity got changed(rename to/from, delete, mounted over, file system
 * unmount).
 *
 * If the event port gets closed, all the associated file event watches will be
 * removed and discarded.
 *
 *
 * Data structures:
 * ----------------
 *
 * The list of file event watches per file are managed by the data structure
 * portfop_vp_t. The first time a file events watch is registered for a file,
 * a portfop_vp_t is installed on the vnode_t's member v_fopdata. This gets
 * removed and freed only when the vnode becomes inactive. The FEM hooks are
 * also installed when the first watch is registered on a file. The FEM hooks
 * get un-installed when all the watches are removed.
 *
 * Each file events watch is represented by the structure portfop_t. They
 * get added to a list of portfop_t's on the vnode(portfop_vp_t). After
 * delivering an event, the portfop_t is marked inactive but retained. It is
 * moved to the end of the list. All the active portfop_t's are maintained at
 * the beginning. In case of exception events, the portfop_t will be removed
 * and discarded.
 *
 * To intercept unmount operations, FSEM hooks are added to the file system
 * under which files are being watched. A hash table('portfop_vfs_hash_t') of
 * active file systems is maintained. Each file system that has active watches
 * is represented by 'portfop_vfs_t' and is added to the hash table.
 * The vnode's 'portfop_vp_t' structure is added to the list of files(vnodes)
 * being watched on the portfop_vfs_t structure.
 *
 *
 * File system support:
 * -------------------
 *
 * The file system implementation has to provide vnode event notifications
 * (vnevents) in order to support watching any files on that file system.
 * The vnode events(vnevents) are notifications provided by the file system
 * for name based file operations like rename, remove etc, which do not go
 * thru the VOP_** interfaces. If the file system does not implement vnode
 * notifications, watching for file events on such file systems is not
 * supported. The vnode event notifications support is determined by the call
 * vnevent_support(vp) (VOP_VNEVENT(vp, VE_SUPPORT)), which the file system
 * has to implement.
 *
 *
 * Locking order:
 * --------------
 *
 * A file(vnode) can have file event watches registered by different processes.
 * There is one portfop_t per watch registered. These are on the vnode's list
 * protected by the mutex 'pvp_mutex' in 'portfop_vp_t'. The portfop_t's are
 * also on the per port cache. The cache is protected by the pfc_lock of
 * portfop_cache_t. The lock order here is 'pfc_lock' -> 'pvp_mutex'.
 *
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/poll_impl.h>
#include <sys/port_impl.h>
#include <sys/fem.h>
#include <sys/vfs_opreg.h>
#include <sys/atomic.h>
#include <sys/mount.h>
#include <sys/mntent.h>

/*
 * For special case support of mnttab (/etc/mnttab).
 */
extern struct vnode *vfs_mntdummyvp;
extern int mntfstype;

#define	PORTFOP_PVFSH(vfsp)	(&portvfs_hash[PORTFOP_PVFSHASH(vfsp)])
portfop_vfs_hash_t	 portvfs_hash[PORTFOP_PVFSHASH_SZ];

#define	PORTFOP_NVP	20
/*
 * Inactive file event watches(portfop_t) are retained on the vnode's list
 * for performance reason. If the applications re-registers the file, the
 * inactive entry is made active and moved up the list.
 *
 * If there are greater then the following number of watches on a vnode,
 * it will attempt to discard an oldest inactive watch(pfp) at the time
 * a new watch is being registered and when events get delivered. We
 * do this to avoid accumulating inactive watches on a file.
 */
int	port_fop_maxpfps = 20;

/* local functions */
static int	port_fop_callback(void *, int *, pid_t, int, void *);

static void	port_pcache_insert(portfop_cache_t *, portfop_t *);
static void	port_pcache_delete(portfop_cache_t *, portfop_t *);
static void	port_close_fop(void *arg, int port, pid_t pid, int lastclose);

/*
 * port fop functions that will be the fem hooks.
 */
static int port_fop_open(femarg_t *vf, int mode, cred_t *cr,
    caller_context_t *);
static int port_fop_read(femarg_t *vf, uio_t *uiop, int ioflag, cred_t *cr,
    struct caller_context *ct);
static int port_fop_write(femarg_t *vf, uio_t *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct);
static int port_fop_map(femarg_t *vf, offset_t off, struct as *as,
    caddr_t *addrp, size_t len, uchar_t prot, uchar_t maxport,
    uint_t flags, cred_t *cr, caller_context_t *ct);
static int port_fop_setattr(femarg_t *vf, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct);
static int port_fop_create(femarg_t *vf, char *name, vattr_t *vap,
    vcexcl_t excl, int mode, vnode_t **vpp, cred_t *cr, int flag,
    caller_context_t *ct, vsecattr_t *vsecp);
static int port_fop_remove(femarg_t *vf, char *nm, cred_t *cr,
    caller_context_t *ct, int flags);
static int port_fop_link(femarg_t *vf, vnode_t *svp, char *tnm, cred_t *cr,
    caller_context_t *ct, int flags);
static int port_fop_rename(femarg_t *vf, char *snm, vnode_t *tdvp, char *tnm,
    cred_t *cr, caller_context_t *ct, int flags);
static int port_fop_mkdir(femarg_t *vf, char *dirname, vattr_t *vap,
    vnode_t **vpp, cred_t *cr, caller_context_t *ct, int flags,
    vsecattr_t *vsecp);
static int port_fop_rmdir(femarg_t *vf, char *nm, vnode_t *cdir, cred_t *cr,
    caller_context_t *ct, int flags);
static int port_fop_readdir(femarg_t *vf, uio_t *uiop, cred_t *cr, int *eofp,
    caller_context_t *ct, int flags);
static int port_fop_symlink(femarg_t *vf, char *linkname, vattr_t *vap,
    char *target, cred_t *cr, caller_context_t *ct, int flags);
static int port_fop_setsecattr(femarg_t *vf, vsecattr_t *vsap, int flag,
    cred_t *cr, caller_context_t *ct);

static int port_fop_vnevent(femarg_t *vf, vnevent_t vnevent, vnode_t *dvp,
    char *cname, caller_context_t *ct);

static int port_fop_unmount(fsemarg_t *vf, int flag, cred_t *cr);


/*
 * Fem hooks.
 */
const fs_operation_def_t	port_vnodesrc_template[] = {
	VOPNAME_OPEN,		{ .femop_open = port_fop_open },
	VOPNAME_READ,		{ .femop_read = port_fop_read },
	VOPNAME_WRITE,		{ .femop_write = port_fop_write },
	VOPNAME_MAP,		{ .femop_map = port_fop_map },
	VOPNAME_SETATTR, 	{ .femop_setattr = port_fop_setattr },
	VOPNAME_CREATE,		{ .femop_create = port_fop_create },
	VOPNAME_REMOVE,		{ .femop_remove = port_fop_remove },
	VOPNAME_LINK,		{ .femop_link = port_fop_link },
	VOPNAME_RENAME,		{ .femop_rename = port_fop_rename },
	VOPNAME_MKDIR,		{ .femop_mkdir = port_fop_mkdir },
	VOPNAME_RMDIR,		{ .femop_rmdir = port_fop_rmdir },
	VOPNAME_READDIR,	{ .femop_readdir = port_fop_readdir },
	VOPNAME_SYMLINK,	{ .femop_symlink = port_fop_symlink },
	VOPNAME_SETSECATTR, 	{ .femop_setsecattr = port_fop_setsecattr },
	VOPNAME_VNEVENT,	{ .femop_vnevent = port_fop_vnevent },
	NULL,	NULL
};

/*
 * Fsem - vfs ops hooks
 */
const fs_operation_def_t	port_vfssrc_template[] = {
	VFSNAME_UNMOUNT, 	{ .fsemop_unmount = port_fop_unmount },
	NULL,	NULL
};

fem_t *fop_femop;
fsem_t *fop_fsemop;

static fem_t *
port_fop_femop()
{
	fem_t *femp;
	if (fop_femop != NULL)
		return (fop_femop);
	if (fem_create("portfop_fem",
	    (const struct fs_operation_def *)port_vnodesrc_template,
	    (fem_t **)&femp)) {
		return (NULL);
	}
	if (atomic_cas_ptr(&fop_femop, NULL, femp) != NULL) {
		/*
		 * some other thread beat us to it.
		 */
		fem_free(femp);
	}
	return (fop_femop);
}

static fsem_t *
port_fop_fsemop()
{
	fsem_t *fsemp;
	if (fop_fsemop != NULL)
		return (fop_fsemop);
	if (fsem_create("portfop_fsem", port_vfssrc_template, &fsemp)) {
		return (NULL);
	}
	if (atomic_cas_ptr(&fop_fsemop, NULL, fsemp) != NULL) {
		/*
		 * some other thread beat us to it.
		 */
		fsem_free(fsemp);
	}
	return (fop_fsemop);
}

/*
 * port_fop_callback()
 * - PORT_CALLBACK_DEFAULT
 *	The file event will be delivered to the application.
 * - PORT_CALLBACK_DISSOCIATE
 *	The object will be dissociated from  the port.
 * - PORT_CALLBACK_CLOSE
 *	The object will be dissociated from the port because the port
 *	is being closed.
 */
/* ARGSUSED */
static int
port_fop_callback(void *arg, int *events, pid_t pid, int flag, void *evp)
{
	portfop_t	*pfp = (portfop_t *)arg;
	port_kevent_t	*pkevp = (port_kevent_t *)evp;
	int		error = 0;

	ASSERT((events != NULL));
	if (flag == PORT_CALLBACK_DEFAULT) {
		if (curproc->p_pid != pid) {
				return (EACCES); /* deny delivery of events */
		}

		*events = pkevp->portkev_events;
		pkevp->portkev_events = 0;
		if (pfp != NULL) {
			pfp->pfop_flags &= ~PORT_FOP_KEV_ONQ;
		}
	}
	return (error);
}

/*
 * Inserts a portfop_t into the port sources cache's.
 */
static void
port_pcache_insert(portfop_cache_t *pfcp, portfop_t *pfp)
{
	portfop_t	**bucket;

	ASSERT(MUTEX_HELD(&pfcp->pfc_lock));
	bucket = PORT_FOP_BUCKET(pfcp, pfp->pfop_object);
	pfp->pfop_hashnext = *bucket;
	*bucket = pfp;
	pfcp->pfc_objcount++;
}

/*
 * Remove the pfp from the port source cache.
 */
static void
port_pcache_delete(portfop_cache_t *pfcp, portfop_t *pfp)
{
	portfop_t	*lpdp;
	portfop_t	*cpdp;
	portfop_t	**bucket;

	bucket = PORT_FOP_BUCKET(pfcp, pfp->pfop_object);
	cpdp = *bucket;
	if (pfp == cpdp) {
		*bucket = pfp->pfop_hashnext;
	} else {
		while (cpdp != NULL) {
			lpdp = cpdp;
			cpdp = cpdp->pfop_hashnext;
			if (cpdp == pfp) {
				/* portfop struct found */
				lpdp->pfop_hashnext = pfp->pfop_hashnext;
				break;
			}
		}
	}
	pfcp->pfc_objcount--;
}

/*
 * The vnode's(portfop_vp_t) pfp list management. The 'pvp_mutex' is held
 * when these routines are called.
 *
 * The 'pvp_lpfop' member points to the oldest inactive entry on the list.
 * It is used to discard the oldtest inactive pfp if the number of entries
 * exceed the limit.
 */
static void
port_fop_listinsert(portfop_vp_t *pvp, portfop_t *pfp, int where)
{
	if (where == 1) {
		list_insert_head(&pvp->pvp_pfoplist, (void *)pfp);
	} else {
		list_insert_tail(&pvp->pvp_pfoplist, (void *)pfp);
	}
	if (pvp->pvp_lpfop == NULL) {
		pvp->pvp_lpfop = pfp;
	}
	pvp->pvp_cnt++;
}

static void
port_fop_listinsert_head(portfop_vp_t *pvp, portfop_t *pfp)
{
	port_fop_listinsert(pvp, pfp, 1);
}

static void
port_fop_listinsert_tail(portfop_vp_t *pvp, portfop_t *pfp)
{
	/*
	 * We point lpfop to an inactive one, if it was initially pointing
	 * to an active one. Insert to the tail is done only when a pfp goes
	 * inactive.
	 */
	if (pvp->pvp_lpfop && pvp->pvp_lpfop->pfop_flags & PORT_FOP_ACTIVE) {
		pvp->pvp_lpfop = pfp;
	}
	port_fop_listinsert(pvp, pfp, 0);
}

static void
port_fop_listremove(portfop_vp_t *pvp, portfop_t *pfp)
{
	if (pvp->pvp_lpfop == pfp) {
		pvp->pvp_lpfop = list_next(&pvp->pvp_pfoplist, (void *)pfp);
	}

	list_remove(&pvp->pvp_pfoplist, (void *)pfp);

	pvp->pvp_cnt--;
	if (pvp->pvp_cnt && pvp->pvp_lpfop == NULL) {
		pvp->pvp_lpfop = list_head(&pvp->pvp_pfoplist);
	}
}

static void
port_fop_listmove(portfop_vp_t *pvp, list_t *tlist)
{
	list_move_tail(tlist, &pvp->pvp_pfoplist);
	pvp->pvp_lpfop = NULL;
	pvp->pvp_cnt = 0;
}

/*
 * Remove a portfop_t from the port cache hash table and discard it.
 * It is called only when pfp is not on the vnode's list. Otherwise,
 * port_remove_fop() is called.
 */
void
port_pcache_remove_fop(portfop_cache_t *pfcp, portfop_t *pfp)
{
	port_kevent_t	*pkevp;


	ASSERT(MUTEX_HELD(&pfcp->pfc_lock));

	pkevp = pfp->pfop_pev;
	pfp->pfop_pev = NULL;

	if (pkevp != NULL) {
		(void) port_remove_done_event(pkevp);
		port_free_event_local(pkevp, 0);
	}

	port_pcache_delete(pfcp, pfp);

	if (pfp->pfop_cname != NULL)
		kmem_free(pfp->pfop_cname, pfp->pfop_clen + 1);
	kmem_free(pfp, sizeof (portfop_t));
	if (pfcp->pfc_objcount == 0)
		cv_signal(&pfcp->pfc_lclosecv);
}

/*
 * if we have too many watches on the vnode, attempt to discard an
 * inactive one.
 */
static void
port_fop_trimpfplist(vnode_t *vp)
{
	portfop_vp_t *pvp;
	portfop_t *pfp = NULL;
	portfop_cache_t *pfcp;
	vnode_t	*tdvp;

	/*
	 * Due to a reference the vnode cannot disappear, v_fopdata should
	 * not change.
	 */
	if ((pvp = vp->v_fopdata) != NULL &&
	    pvp->pvp_cnt > port_fop_maxpfps) {
		mutex_enter(&pvp->pvp_mutex);
		pfp = pvp->pvp_lpfop;
		pfcp = pfp->pfop_pcache;
		/*
		 * only if we can get the cache lock, we need to
		 * do this due to reverse lock order and some thread
		 * that may be trying to reactivate this entry.
		 */
		if (mutex_tryenter(&pfcp->pfc_lock)) {
			if (pfp && !(pfp->pfop_flags & PORT_FOP_ACTIVE) &&
			    !(pfp->pfop_flags & PORT_FOP_KEV_ONQ)) {
				port_fop_listremove(pvp, pfp);
				pfp->pfop_flags |= PORT_FOP_REMOVING;
			} else {
				mutex_exit(&pfcp->pfc_lock);
				pfp = NULL;
			}
		} else {
			pfp = NULL;
		}
		mutex_exit(&pvp->pvp_mutex);

		/*
		 * discard pfp if any.
		 */
		if (pfp != NULL) {
			tdvp = pfp->pfop_dvp;
			port_pcache_remove_fop(pfcp, pfp);
			mutex_exit(&pfcp->pfc_lock);
			if (tdvp != NULL)
				VN_RELE(tdvp);
		}
	}
}

/*
 * This routine returns 1, if the vnode can be rele'ed by the caller.
 * The caller has to VN_RELE the vnode with out holding any
 * locks.
 */
int
port_fop_femuninstall(vnode_t *vp)
{
	portfop_vp_t	*pvp;
	vfs_t		*vfsp;
	portfop_vfs_t *pvfsp;
	portfop_vfs_hash_t	*pvfsh;
	kmutex_t	*mtx;
	int	ret = 0;

	/*
	 * if list is empty, uninstall fem.
	 */
	pvp = vp->v_fopdata;
	ASSERT(MUTEX_HELD(&pvp->pvp_mutex));

	/*
	 * make sure the list is empty.
	 */
	if (!list_head(&pvp->pvp_pfoplist)) {

		/*
		 * we could possibly uninstall the fem hooks when
		 * the vnode becomes inactive and the v_fopdata is
		 * free. But the hooks get triggered unnecessarily
		 * even though there are no active watches. So, we
		 * uninstall it here.
		 */
		(void) fem_uninstall(vp, (fem_t *)pvp->pvp_femp, vp);
		pvp->pvp_femp = NULL;


		/*
		 * If we successfully uninstalled fem, no process is watching
		 * this vnode, Remove it from the vfs's list of watched vnodes.
		 */
		pvfsp = pvp->pvp_pvfsp;
		vfsp = vp->v_vfsp;
		pvfsh = PORTFOP_PVFSH(vfsp);
		mtx = &pvfsh->pvfshash_mutex;
		mutex_enter(mtx);
		/*
		 * If unmount is in progress, that thread will remove and
		 * release the vnode from the vfs's list, just leave.
		 */
		if (!pvfsp->pvfs_unmount) {
			list_remove(&pvfsp->pvfs_pvplist, pvp);
			mutex_exit(mtx);
			ret = 1;
		} else {
			mutex_exit(mtx);
		}
	}
	mutex_exit(&pvp->pvp_mutex);
	return (ret);
}

/*
 * Remove pfp from the vnode's watch list and the cache and discard it.
 * If it is the last pfp on the vnode's list, the fem hooks get uninstalled.
 * Returns 1 if pfp removed successfully.
 *
 * The *active is set to indicate if the pfp was still active(no events had
 * been posted, or the posted event had not been collected yet and it was
 * able to remove it from the port's queue).
 *
 * vpp and dvpp will point to the vnode and directory vnode which the caller
 * is required to VN_RELE without holding any locks.
 */
int
port_remove_fop(portfop_t *pfp, portfop_cache_t *pfcp, int cleanup,
    int *active, vnode_t **vpp, vnode_t **dvpp)
{
	vnode_t		*vp;
	portfop_vp_t	*pvp;
	int	tactive = 0;

	ASSERT(MUTEX_HELD(&pfcp->pfc_lock));
	vp = pfp->pfop_vp;
	pvp = vp->v_fopdata;
	mutex_enter(&pvp->pvp_mutex);

	/*
	 * if not cleanup, remove it only if the pfp is still active and
	 * is not being removed by some other thread.
	 */
	if (!cleanup && (!(pfp->pfop_flags & PORT_FOP_ACTIVE) ||
	    pfp->pfop_flags & PORT_FOP_REMOVING)) {
		mutex_exit(&pvp->pvp_mutex);
		return (0);
	}

	/*
	 * mark it inactive.
	 */
	if (pfp->pfop_flags & PORT_FOP_ACTIVE) {
		pfp->pfop_flags &= ~PORT_FOP_ACTIVE;
		tactive = 1;
	}

	/*
	 * Check if the pfp is still on the vnode's list. This can
	 * happen if port_fop_excep() is in the process of removing it.
	 * In case of cleanup, just mark this pfp as inactive so that no
	 * new events (VNEVENT) will be delivered, and remove it from the
	 * event queue if it was already queued. Since the cache lock is
	 * held, the pfp will not disappear, even though it is being
	 * removed.
	 */
	if (pfp->pfop_flags & PORT_FOP_REMOVING) {
		mutex_exit(&pvp->pvp_mutex);
		if (!tactive && port_remove_done_event(pfp->pfop_pev)) {
			pfp->pfop_flags &= ~PORT_FOP_KEV_ONQ;
			tactive = 1;
		}
		if (active) {
			*active = tactive;
		}
		return (1);
	}

	/*
	 * if we find an event on the queue and removed it, then this
	 * association is considered active.
	 */
	if (!tactive && port_remove_done_event(pfp->pfop_pev)) {
		pfp->pfop_flags &= ~PORT_FOP_KEV_ONQ;
		tactive = 1;
	}

	if (active) {
		*active = tactive;
	}
	pvp = (portfop_vp_t *)vp->v_fopdata;

	/*
	 * remove pfp from the vnode's list
	 */
	port_fop_listremove(pvp, pfp);

	/*
	 * If no more associations on the vnode, uninstall fem hooks.
	 * The pvp mutex will be released in this routine.
	 */
	if (port_fop_femuninstall(vp))
		*vpp = vp;
	*dvpp = pfp->pfop_dvp;
	port_pcache_remove_fop(pfcp, pfp);
	return (1);
}

/*
 * This routine returns a pointer to a cached portfop entry, or NULL if it
 * does not find it in the hash table. The object pointer is used as index.
 * The entries are hashed by the object's address. We need to match the pid
 * as the evet port can be shared between processes. The file events
 * watches are per process only.
 */
portfop_t *
port_cache_lookup_fop(portfop_cache_t *pfcp, pid_t pid, uintptr_t obj)
{
	portfop_t	*pfp = NULL;
	portfop_t	**bucket;

	ASSERT(MUTEX_HELD(&pfcp->pfc_lock));
	bucket = PORT_FOP_BUCKET(pfcp, obj);
	pfp = *bucket;
	while (pfp != NULL) {
		if (pfp->pfop_object == obj && pfp->pfop_pid == pid)
			break;
		pfp = pfp->pfop_hashnext;
	}
	return (pfp);
}

/*
 * Given the file name, get the vnode and also the directory vnode
 * On return, the vnodes are held (VN_HOLD). The caller has to VN_RELE
 * the vnode(s).
 */
int
port_fop_getdvp(void *objptr, vnode_t **vp, vnode_t **dvp,
	char **cname, int *len, int follow)
{
	int error = 0;
	struct pathname pn;
	char *fname;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		fname = ((file_obj_t *)objptr)->fo_name;
#ifdef  _SYSCALL32_IMPL
	} else {
		fname = (caddr_t)(uintptr_t)((file_obj32_t *)objptr)->fo_name;
#endif	/* _SYSCALL32_IMPL */
	}

	/*
	 * lookuppn may fail with EINVAL, if dvp is  non-null(like when
	 * looking for "."). So call again with dvp = NULL.
	 */
	if ((error = pn_get(fname, UIO_USERSPACE, &pn)) != 0) {
		return (error);
	}

	error = lookuppn(&pn, NULL, follow, dvp, vp);
	if (error == EINVAL) {
		pn_free(&pn);
		if ((error = pn_get(fname, UIO_USERSPACE, &pn)) != 0) {
			return (error);
		}
		error = lookuppn(&pn, NULL, follow, NULL, vp);
		if (dvp != NULL) {
			*dvp = NULL;
		}
	}

	if (error == 0 && cname != NULL && len != NULL) {
		pn_setlast(&pn);
		*len = pn.pn_pathlen;
		*cname = kmem_alloc(*len + 1, KM_SLEEP);
		(void) strcpy(*cname, pn.pn_path);
	} else {
		if (cname != NULL && len != NULL) {
			*cname = NULL;
			*len = 0;
		}
	}

	pn_free(&pn);
	return (error);
}

port_source_t *
port_getsrc(port_t *pp, int source)
{
	port_source_t *pse;
	int	lock = 0;
	/*
	 * get the port source structure.
	 */
	if (!MUTEX_HELD(&pp->port_queue.portq_source_mutex)) {
		mutex_enter(&pp->port_queue.portq_source_mutex);
		lock = 1;
	}

	pse = pp->port_queue.portq_scache[PORT_SHASH(source)];
	for (; pse != NULL; pse = pse->portsrc_next) {
		if (pse->portsrc_source == source)
			break;
	}

	if (lock) {
		mutex_exit(&pp->port_queue.portq_source_mutex);
	}
	return (pse);
}


/*
 * Compare time stamps and generate an event if it has changed.
 * Note that the port cache pointer will be valid due to a reference
 * to the port. We need to grab the port cache lock and verify that
 * the pfp is still the same before proceeding to deliver an event.
 */
static void
port_check_timestamp(portfop_cache_t *pfcp, vnode_t *vp, vnode_t *dvp,
	portfop_t *pfp, void *objptr, uintptr_t object)
{
	vattr_t		vatt;
	portfop_vp_t	*pvp = vp->v_fopdata;
	int		events = 0;
	port_kevent_t	*pkevp;
	file_obj_t	*fobj;
	portfop_t	*tpfp;

	/*
	 * If time stamps are specified, get attributes and compare.
	 */
	vatt.va_mask = AT_ATIME|AT_MTIME|AT_CTIME;
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		fobj = (file_obj_t *)objptr;
		if (fobj->fo_atime.tv_sec || fobj->fo_atime.tv_nsec ||
		    fobj->fo_mtime.tv_sec || fobj->fo_mtime.tv_nsec ||
		    fobj->fo_ctime.tv_sec || fobj->fo_ctime.tv_nsec) {
			if (VOP_GETATTR(vp, &vatt, 0, CRED(), NULL)) {
				return;
			}
		} else {
			/*
			 * timestamp not specified, all 0's,
			 */
			return;
		}
#ifdef  _SYSCALL32_IMPL
	} else {
		file_obj32_t	*fobj32;
		fobj32 = (file_obj32_t *)objptr;
		if (fobj32->fo_atime.tv_sec || fobj32->fo_atime.tv_nsec ||
		    fobj32->fo_mtime.tv_sec || fobj32->fo_mtime.tv_nsec ||
		    fobj32->fo_ctime.tv_sec || fobj32->fo_ctime.tv_nsec) {
			if (VOP_GETATTR(vp, &vatt, 0, CRED(), NULL)) {
				return;
			}
		} else {
			/*
			 * timestamp not specified, all 0.
			 */
			return;
		}
#endif /* _SYSCALL32_IMPL */
	}

	/*
	 * Now grab the cache lock and verify that we are still
	 * dealing with the same pfp and curthread is the one
	 * which registered it. We need to do this to avoid
	 * delivering redundant events.
	 */
	mutex_enter(&pfcp->pfc_lock);
	tpfp = port_cache_lookup_fop(pfcp, curproc->p_pid, object);

	if (tpfp == NULL || tpfp != pfp ||
	    pfp->pfop_vp != vp || pfp->pfop_dvp != dvp ||
	    pfp->pfop_callrid != curthread ||
	    !(pfp->pfop_flags & PORT_FOP_ACTIVE)) {
		/*
		 * Some other event was delivered, the file
		 * watch was removed or reassociated. Just
		 * ignore it and leave
		 */
		mutex_exit(&pfcp->pfc_lock);
		return;
	}

	mutex_enter(&pvp->pvp_mutex);
	/*
	 * The pfp cannot disappear as the port cache lock is held.
	 * While the pvp_mutex is held, no events will get delivered.
	 */
	if (pfp->pfop_flags & PORT_FOP_ACTIVE &&
	    !(pfp->pfop_flags & PORT_FOP_REMOVING)) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			fobj = (file_obj_t *)objptr;
			if (pfp->pfop_events & FILE_ACCESS &&
			    (fobj->fo_atime.tv_sec || fobj->fo_atime.tv_nsec) &&
			    (vatt.va_atime.tv_sec != fobj->fo_atime.tv_sec ||
			    vatt.va_atime.tv_nsec != fobj->fo_atime.tv_nsec))
				events |= FILE_ACCESS;

			if (pfp->pfop_events & FILE_MODIFIED &&
			    (fobj->fo_mtime.tv_sec || fobj->fo_mtime.tv_nsec) &&
			    (vatt.va_mtime.tv_sec != fobj->fo_mtime.tv_sec ||
			    vatt.va_mtime.tv_nsec != fobj->fo_mtime.tv_nsec))
				events |= FILE_MODIFIED;

			if (pfp->pfop_events & FILE_ATTRIB &&
			    (fobj->fo_ctime.tv_sec || fobj->fo_ctime.tv_nsec) &&
			    (vatt.va_ctime.tv_sec != fobj->fo_ctime.tv_sec ||
			    vatt.va_ctime.tv_nsec != fobj->fo_ctime.tv_nsec))
				events |= FILE_ATTRIB;
#ifdef  _SYSCALL32_IMPL
		} else {
			file_obj32_t	*fobj32;
			fobj32 = (file_obj32_t *)objptr;
			if (pfp->pfop_events & FILE_ACCESS &&
			    (fobj32->fo_atime.tv_sec ||
			    fobj32->fo_atime.tv_nsec) &&
			    (vatt.va_atime.tv_sec != fobj32->fo_atime.tv_sec ||
			    vatt.va_atime.tv_nsec != fobj32->fo_atime.tv_nsec))
				events |= FILE_ACCESS;

			if (pfp->pfop_events & FILE_MODIFIED &&
			    (fobj32->fo_mtime.tv_sec ||
			    fobj32->fo_mtime.tv_nsec) &&
			    (vatt.va_mtime.tv_sec != fobj32->fo_mtime.tv_sec ||
			    vatt.va_mtime.tv_nsec != fobj32->fo_mtime.tv_nsec))
				events |= FILE_MODIFIED;

			if (pfp->pfop_events & FILE_ATTRIB &&
			    (fobj32->fo_ctime.tv_sec ||
			    fobj32->fo_ctime.tv_nsec) &&
			    (vatt.va_ctime.tv_sec != fobj32->fo_ctime.tv_sec ||
			    vatt.va_ctime.tv_nsec != fobj32->fo_ctime.tv_nsec))
				events |= FILE_ATTRIB;
#endif /* _SYSCALL32_IMPL */
		}

		/*
		 * No events to deliver
		 */
		if (events == 0) {
			mutex_exit(&pvp->pvp_mutex);
			mutex_exit(&pfcp->pfc_lock);
			return;
		}

		/*
		 * Deliver the event now.
		 */
		pkevp = pfp->pfop_pev;
		pfp->pfop_flags &= ~PORT_FOP_ACTIVE;
		pkevp->portkev_events |= events;
		/*
		 * Move it to the tail as active once are in the
		 * beginning of the list.
		 */
		port_fop_listremove(pvp, pfp);
		port_fop_listinsert_tail(pvp, pfp);
		port_send_event(pkevp);
		pfp->pfop_flags |= PORT_FOP_KEV_ONQ;
	}
	mutex_exit(&pvp->pvp_mutex);
	mutex_exit(&pfcp->pfc_lock);
}

/*
 * Add the event source to the port and return the port source cache pointer.
 */
int
port_fop_associate_source(portfop_cache_t **pfcpp, port_t *pp, int source)
{
	portfop_cache_t *pfcp;
	port_source_t	*pse;
	int		error;

	/*
	 * associate PORT_SOURCE_FILE source with the port, if it is
	 * not associated yet. Note the PORT_SOURCE_FILE source is
	 * associated once and will not be dissociated.
	 */
	if ((pse = port_getsrc(pp, PORT_SOURCE_FILE)) == NULL) {
		if (error = port_associate_ksource(pp->port_fd, source,
		    &pse, port_close_fop, pp, NULL)) {
			*pfcpp = NULL;
			return (error);
		}
	}

	/*
	 * Get the portfop cache pointer.
	 */
	if ((pfcp = pse->portsrc_data) == NULL) {
		/*
		 * This is the first time that a file is being associated,
		 * create the portfop cache.
		 */
		pfcp = kmem_zalloc(sizeof (portfop_cache_t), KM_SLEEP);
		mutex_enter(&pp->port_queue.portq_source_mutex);
		if (pse->portsrc_data == NULL) {
			pse->portsrc_data = pfcp;
			mutex_exit(&pp->port_queue.portq_source_mutex);
		} else {
			/*
			 * someone else created the port cache, free
			 * what we just now allocated.
			 */
			mutex_exit(&pp->port_queue.portq_source_mutex);
			kmem_free(pfcp, sizeof (portfop_cache_t));
			pfcp = pse->portsrc_data;
		}
	}
	*pfcpp = pfcp;
	return (0);
}

/*
 * Add the given pvp on the file system's list of vnodes watched.
 */
int
port_fop_pvfsadd(portfop_vp_t *pvp)
{
	int error = 0;
	vnode_t	*vp = pvp->pvp_vp;
	portfop_vfs_hash_t *pvfsh;
	portfop_vfs_t	 *pvfsp;
	fsem_t		*fsemp;

	pvfsh = PORTFOP_PVFSH(vp->v_vfsp);
	mutex_enter(&pvfsh->pvfshash_mutex);
	for (pvfsp = pvfsh->pvfshash_pvfsp; pvfsp &&
	    pvfsp->pvfs != vp->v_vfsp; pvfsp = pvfsp->pvfs_next)
		;

	if (!pvfsp) {
		if ((fsemp = port_fop_fsemop()) != NULL) {
			if ((error = fsem_install(vp->v_vfsp, fsemp,
			    vp->v_vfsp, OPUNIQ, NULL, NULL))) {
				mutex_exit(&pvfsh->pvfshash_mutex);
				return (error);
			}
		} else {
			mutex_exit(&pvfsh->pvfshash_mutex);
			return (EINVAL);
		}
		pvfsp = kmem_zalloc(sizeof (portfop_vfs_t), KM_SLEEP);
		pvfsp->pvfs = vp->v_vfsp;
		list_create(&(pvfsp->pvfs_pvplist), sizeof (portfop_vp_t),
		    offsetof(portfop_vp_t, pvp_pvfsnode));
		pvfsp->pvfs_fsemp = fsemp;
		pvfsp->pvfs_next = pvfsh->pvfshash_pvfsp;
		pvfsh->pvfshash_pvfsp = pvfsp;
	}

	/*
	 * check if an unmount is in progress.
	 */
	if (!pvfsp->pvfs_unmount) {
		/*
		 * insert the pvp on list.
		 */
		pvp->pvp_pvfsp = pvfsp;
		list_insert_head(&pvfsp->pvfs_pvplist, (void *)pvp);
	} else {
		error = EINVAL;
	}
	mutex_exit(&pvfsh->pvfshash_mutex);
	return (error);
}

/*
 * Installs the portfop_vp_t data structure on the
 * vnode. The 'pvp_femp == NULL' indicates it is not
 * active. The fem hooks have to be installed.
 * The portfop_vp_t is only freed when the vnode gets freed.
 */
void
port_install_fopdata(vnode_t *vp)
{
	portfop_vp_t *npvp;

	npvp = kmem_zalloc(sizeof (*npvp), KM_SLEEP);
	mutex_init(&npvp->pvp_mutex, NULL, MUTEX_DEFAULT, NULL);
	list_create(&npvp->pvp_pfoplist, sizeof (portfop_t),
	    offsetof(portfop_t, pfop_node));
	npvp->pvp_vp = vp;
	/*
	 * If v_fopdata is not null, some other thread beat us to it.
	 */
	if (atomic_cas_ptr(&vp->v_fopdata, NULL, npvp) != NULL) {
		mutex_destroy(&npvp->pvp_mutex);
		list_destroy(&npvp->pvp_pfoplist);
		kmem_free(npvp, sizeof (*npvp));
	}
}


/*
 * Allocate and add a portfop_t to the per port cache. Also add the portfop_t
 * to the vnode's list. The association is identified by the object pointer
 * address and pid.
 */
int
port_pfp_setup(portfop_t **pfpp, port_t *pp, vnode_t *vp, portfop_cache_t *pfcp,
	uintptr_t object, int events, void *user, char *cname, int clen,
	vnode_t *dvp)
{
	portfop_t	*pfp = NULL;
	port_kevent_t	*pkevp;
	fem_t		*femp;
	int		error = 0;
	portfop_vp_t	*pvp;


	/*
	 * The port cache mutex is held.
	 */
	*pfpp  = NULL;


	/*
	 * At this point the fem monitor is installed.
	 * Allocate a port event structure per vnode association.
	 */
	if (pfp == NULL) {
		if (error = port_alloc_event_local(pp, PORT_SOURCE_FILE,
		    PORT_ALLOC_CACHED, &pkevp)) {
			return (error);
		}
		pfp = kmem_zalloc(sizeof (portfop_t), KM_SLEEP);
		pfp->pfop_pev = pkevp;
	}

	pfp->pfop_vp = vp;
	pfp->pfop_pid = curproc->p_pid;
	pfp->pfop_pcache = pfcp;
	pfp->pfop_pp = pp;
	pfp->pfop_flags |= PORT_FOP_ACTIVE;
	pfp->pfop_cname = cname;
	pfp->pfop_clen = clen;
	pfp->pfop_dvp = dvp;
	pfp->pfop_object = object;

	pkevp->portkev_callback = port_fop_callback;
	pkevp->portkev_arg = pfp;
	pkevp->portkev_object = object;
	pkevp->portkev_user = user;
	pkevp->portkev_events = 0;

	port_pcache_insert(pfcp, pfp);

	/*
	 * Register a new file events monitor for this file(vnode), if not
	 * done already.
	 */
	if ((pvp = vp->v_fopdata) == NULL) {
		port_install_fopdata(vp);
		pvp = vp->v_fopdata;
	}

	mutex_enter(&pvp->pvp_mutex);
	/*
	 * if the vnode does not have the file events hooks, install it.
	 */
	if (pvp->pvp_femp == NULL) {
		if ((femp = port_fop_femop()) != NULL) {
			if (!(error = fem_install(pfp->pfop_vp, femp,
			    (void *)vp, OPUNIQ, NULL, NULL))) {
				pvp->pvp_femp = femp;
				/*
				 * add fsem_t hooks to the vfsp and add pvp to
				 * the list of vnodes for this vfs.
				 */
				if (!(error = port_fop_pvfsadd(pvp))) {
					/*
					 * Hold a reference to the vnode since
					 * we successfully installed the hooks.
					 */
					VN_HOLD(vp);
				} else {
					(void) fem_uninstall(vp, femp, vp);
					pvp->pvp_femp = NULL;
				}
			}
		} else {
			error = EINVAL;
		}
	}

	if (error) {
		/*
		 * pkevp will get freed here.
		 */
		pfp->pfop_cname = NULL;
		port_pcache_remove_fop(pfcp, pfp);
		mutex_exit(&pvp->pvp_mutex);
		return (error);
	}

	/*
	 * insert the pfp on the vnode's list. After this
	 * events can get delivered.
	 */
	pfp->pfop_events = events;
	port_fop_listinsert_head(pvp, pfp);

	mutex_exit(&pvp->pvp_mutex);
	/*
	 * Hold the directory vnode since we have a reference now.
	 */
	if (dvp != NULL)
		VN_HOLD(dvp);
	*pfpp = pfp;
	return (0);
}

vnode_t *
port_resolve_vp(vnode_t *vp)
{
	vnode_t *rvp;
	/*
	 * special case /etc/mnttab(mntfs type). The mntfstype != 0
	 * if mntfs got mounted.
	 */
	if (vfs_mntdummyvp && mntfstype != 0 &&
	    vp->v_vfsp->vfs_fstype == mntfstype) {
		VN_RELE(vp);
		vp = vfs_mntdummyvp;
		VN_HOLD(vfs_mntdummyvp);
	}

	/*
	 * This should take care of lofs mounted fs systems and nfs4
	 * hardlinks.
	 */
	if ((VOP_REALVP(vp, &rvp, NULL) == 0) && vp != rvp) {
		VN_HOLD(rvp);
		VN_RELE(vp);
		vp = rvp;
	}
	return (vp);
}

/*
 * Register a file events watch on the given file associated to the port *pp.
 *
 * The association is identified by the object pointer and the pid.
 * The events argument contains the events to be monitored for.
 *
 * The vnode will have a VN_HOLD once the fem hooks are installed.
 *
 * Every reference(pfp) to the directory vnode will have a VN_HOLD to ensure
 * that the directory vnode pointer does not change.
 */
int
port_associate_fop(port_t *pp, int source, uintptr_t object, int events,
    void *user)
{
	portfop_cache_t	*pfcp;
	vnode_t		*vp, *dvp, *oldvp = NULL, *olddvp = NULL, *orig;
	portfop_t	*pfp;
	int		error = 0;
	file_obj_t	fobj;
	void		*objptr;
	char		*cname;
	int		clen;
	int		follow;

	/*
	 * check that events specified are valid.
	 */
	if ((events & ~FILE_EVENTS_MASK) != 0)
		return (EINVAL);

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin((void *)object, &fobj, sizeof (file_obj_t)))
			return (EFAULT);
		objptr = (void *)&fobj;
#ifdef  _SYSCALL32_IMPL
	} else {
		file_obj32_t	fobj32;
		if (copyin((void *)object, &fobj32, sizeof (file_obj32_t)))
			return (EFAULT);
		objptr = (void *)&fobj32;
#endif  /* _SYSCALL32_IMPL */
	}

	vp = dvp = NULL;

	/*
	 * find out if we need to follow symbolic links.
	 */
	follow = !(events & FILE_NOFOLLOW);
	events = events & ~FILE_NOFOLLOW;

	/*
	 * lookup and find the vnode and its directory vnode of the given
	 * file.
	 */
	if ((error = port_fop_getdvp(objptr, &vp, &dvp, &cname, &clen,
	    follow)) != 0) {
		return (error);
	}

	if (dvp != NULL) {
		dvp = port_resolve_vp(dvp);
	}

	/*
	 * Not found
	 */
	if (vp == NULL) {
		error = ENOENT;
		goto errout;
	}

	vp = port_resolve_vp(orig = vp);

	if (vp != NULL && vnevent_support(vp, NULL)) {
		error = ENOTSUP;
		goto errout;
	}

	/*
	 * If dvp belongs to a different filesystem just ignore it, as hard
	 * links cannot exist across filesystems.  We make an exception for
	 * procfs, however, the magic of which we treat semantically as a hard
	 * link, allowing one to use /proc/[pid]/fd/[fd] for PORT_SOURCE_FILE
	 * and avoid spurious FILE_RENAME_FROM/FILE_RENAME_TO events.
	 */
	if (dvp != NULL && dvp->v_vfsp != vp->v_vfsp &&
	    !(orig->v_type == VPROC && vp != NULL && vp->v_type != VPROC)) {
		VN_RELE(dvp);
		dvp = NULL;
	}

	/*
	 * Associate this source to the port and get the per port
	 * fop cache pointer. If the source is already associated, it
	 * will just return the cache pointer.
	 */
	if (error = port_fop_associate_source(&pfcp, pp, source)) {
		goto errout;
	}

	/*
	 * Check if there is an existing association of this file.
	 */
	mutex_enter(&pfcp->pfc_lock);
	pfp = port_cache_lookup_fop(pfcp, curproc->p_pid, object);

	/*
	 * If it is not the same vnode, just discard it. VN_RELE needs to be
	 * called with no locks held, therefore save vnode pointers and
	 * vn_rele them later.
	 */
	if (pfp != NULL && (pfp->pfop_vp != vp || pfp->pfop_dvp != dvp)) {
		(void) port_remove_fop(pfp, pfcp, 1, NULL, &oldvp, &olddvp);
		pfp = NULL;
	}

	if (pfp == NULL) {
		vnode_t *tvp, *tdvp;
		portfop_t	*tpfp;
		int error;

		/*
		 * Add a new association, save the file name and the
		 * directory vnode pointer.
		 */
		if (error = port_pfp_setup(&pfp, pp, vp, pfcp, object,
		    events, user, cname, clen, dvp)) {
			mutex_exit(&pfcp->pfc_lock);
			goto errout;
		}

		pfp->pfop_callrid = curthread;
		/*
		 * File name used, so make sure we don't free it.
		 */
		cname = NULL;

		/*
		 * We need to check if the file was removed after the
		 * the lookup and before the fem hooks where added. If
		 * so, return error. The vnode will still exist as we have
		 * a hold on it.
		 *
		 * Drop the cache lock before calling port_fop_getdvp().
		 * port_fop_getdvp() may block either in the vfs layer
		 * or some filesystem.  Therefore there is potential
		 * for deadlock if cache lock is held and if some other
		 * thread is attempting to deliver file events which would
		 * require getting the cache lock, while it may be holding
		 * the filesystem or vfs layer locks.
		 */
		mutex_exit(&pfcp->pfc_lock);
		tvp = NULL;
		if ((error = port_fop_getdvp(objptr, &tvp, NULL,
		    NULL, NULL, follow)) == 0) {
			if (tvp != NULL) {
				tvp = port_resolve_vp(tvp);
				/*
				 * This vnode pointer is just used
				 * for comparison, so rele it
				 */
				VN_RELE(tvp);
			}
		}

		if (error || tvp == NULL || tvp != vp) {
			/*
			 * Since we dropped the cache lock, make sure
			 * we are still dealing with the same pfp and this
			 * is the thread which registered it.
			 */
			mutex_enter(&pfcp->pfc_lock);
			tpfp = port_cache_lookup_fop(pfcp,
			    curproc->p_pid, object);

			error = 0;
			if (tpfp == NULL || tpfp != pfp ||
			    pfp->pfop_vp != vp ||
			    pfp->pfop_dvp != dvp ||
			    pfp->pfop_callrid != curthread) {
				/*
				 * Some other event was delivered, the file
				 * watch was removed or reassociated, just
				 * ignore it and leave
				 */
				mutex_exit(&pfcp->pfc_lock);
				goto errout;
			}

			/*
			 * remove the pfp and fem hooks, if pfp still
			 * active and it is not being removed from
			 * the vnode list. This is checked in
			 * port_remove_fop with the vnode lock held.
			 * The vnode returned is VN_RELE'ed after dropping
			 * the locks.
			 */
			tdvp = tvp = NULL;
			if (port_remove_fop(pfp, pfcp, 0, NULL, &tvp, &tdvp)) {
				/*
				 * The pfp was removed, means no
				 * events where queued. Report the
				 * error now.
				 */
				error = EINVAL;
			}
			mutex_exit(&pfcp->pfc_lock);
			if (tvp != NULL)
				VN_RELE(tvp);
			if (tdvp != NULL)
				VN_RELE(tdvp);
			goto errout;
		}
	} else {
		portfop_vp_t	*pvp = vp->v_fopdata;

		/*
		 * Re-association of the object.
		 */
		mutex_enter(&pvp->pvp_mutex);

		/*
		 * remove any queued up event.
		 */
		if (port_remove_done_event(pfp->pfop_pev)) {
			pfp->pfop_flags &= ~PORT_FOP_KEV_ONQ;
		}

		/*
		 * set new events to watch.
		 */
		pfp->pfop_events = events;

		/*
		 * If not active, mark it active even if it is being
		 * removed. Then it can send an exception event.
		 *
		 * Move it to the head, as the active ones are only
		 * in the beginning. If removing, the pfp will be on
		 * a temporary list, no need to move it to the front
		 * all the entries will be processed. Some exception
		 * events will be delivered in port_fop_excep();
		 */
		if (!(pfp->pfop_flags & PORT_FOP_ACTIVE)) {
			pfp->pfop_flags |= PORT_FOP_ACTIVE;
			if (!(pfp->pfop_flags & PORT_FOP_REMOVING)) {
				pvp = (portfop_vp_t *)vp->v_fopdata;
				port_fop_listremove(pvp, pfp);
				port_fop_listinsert_head(pvp, pfp);
			}
		}
		pfp->pfop_callrid = curthread;
		mutex_exit(&pvp->pvp_mutex);
		mutex_exit(&pfcp->pfc_lock);
	}

	/*
	 * Compare time stamps and deliver events.
	 */
	if (vp->v_type != VFIFO) {
		port_check_timestamp(pfcp, vp, dvp, pfp, objptr, object);
	}

	error = 0;

	/*
	 *  If we have too many watches on the vnode, discard an
	 *  inactive watch.
	 */
	port_fop_trimpfplist(vp);

errout:
	/*
	 * Release the hold acquired due to the lookup operation.
	 */
	if (vp != NULL)
		VN_RELE(vp);
	if (dvp != NULL)
		VN_RELE(dvp);

	if (oldvp != NULL)
		VN_RELE(oldvp);
	if (olddvp != NULL)
		VN_RELE(olddvp);

	/*
	 * copied file name not used, free it.
	 */
	if (cname != NULL) {
		kmem_free(cname, clen + 1);
	}
	return (error);
}


/*
 * The port_dissociate_fop() function dissociates the file object
 * from the event port and removes any events that are already on the queue.
 * Only the owner of the association is allowed to dissociate the file from
 * the port. Returns  success (0) if it was found and removed. Otherwise
 * ENOENT.
 */
int
port_dissociate_fop(port_t *pp, uintptr_t object)
{
	portfop_cache_t	*pfcp;
	portfop_t	*pfp;
	port_source_t	*pse;
	int		active = 0;
	vnode_t		*tvp = NULL, *tdvp = NULL;

	pse = port_getsrc(pp, PORT_SOURCE_FILE);

	/*
	 * if this source is not associated or if there is no
	 * cache, nothing to do just return.
	 */
	if (pse == NULL ||
	    (pfcp = (portfop_cache_t *)pse->portsrc_data) == NULL)
		return (EINVAL);

	/*
	 * Check if this object is on the cache. Only the owner pid
	 * is allowed to dissociate.
	 */
	mutex_enter(&pfcp->pfc_lock);
	pfp = port_cache_lookup_fop(pfcp, curproc->p_pid, object);
	if (pfp == NULL) {
		mutex_exit(&pfcp->pfc_lock);
		return (ENOENT);
	}

	/*
	 * If this was the last association, it will release
	 * the hold on the vnode. There is a race condition where
	 * the the pfp is being removed due to an exception event
	 * in port_fop_sendevent()->port_fop_excep() and port_remove_fop().
	 * Since port source cache lock is held, port_fop_excep() cannot
	 * complete. The vnode itself will not disappear as long its pfps
	 * have a reference.
	 */
	(void) port_remove_fop(pfp, pfcp, 1, &active, &tvp, &tdvp);
	mutex_exit(&pfcp->pfc_lock);
	if (tvp != NULL)
		VN_RELE(tvp);
	if (tdvp != NULL)
		VN_RELE(tdvp);
	return (active ? 0 : ENOENT);
}


/*
 * port_close() calls this function to request the PORT_SOURCE_FILE source
 * to remove/free all resources allocated and associated with the port.
 */

/* ARGSUSED */
static void
port_close_fop(void *arg, int port, pid_t pid, int lastclose)
{
	port_t		*pp = arg;
	portfop_cache_t	*pfcp;
	portfop_t	**hashtbl;
	portfop_t	*pfp;
	portfop_t	*pfpnext;
	int		index, i;
	port_source_t	*pse;
	vnode_t 	*tdvp = NULL;
	vnode_t		*vpl[PORTFOP_NVP];

	pse = port_getsrc(pp, PORT_SOURCE_FILE);

	/*
	 * No source or no cache, nothing to do.
	 */
	if (pse == NULL ||
	    (pfcp = (portfop_cache_t *)pse->portsrc_data) == NULL)
		return;
	/*
	 * Scan the cache and free all allocated portfop_t and port_kevent_t
	 * structures of this pid. Note, no new association for this pid will
	 * be possible as the port is being closed.
	 *
	 * The common case is that the port is not shared and all the entries
	 * are of this pid and have to be freed. Since VN_RELE has to be
	 * called outside the lock, we do it in batches.
	 */
	hashtbl = (portfop_t **)pfcp->pfc_hash;
	index = i = 0;
	bzero(vpl, sizeof (vpl));
	mutex_enter(&pfcp->pfc_lock);
	while (index < PORTFOP_HASHSIZE) {
		pfp = hashtbl[index];
		while (pfp != NULL && i < (PORTFOP_NVP - 1)) {
			pfpnext = pfp->pfop_hashnext;
			if (pid == pfp->pfop_pid) {
				(void) port_remove_fop(pfp, pfcp, 1, NULL,
				    &vpl[i], &tdvp);
				if (vpl[i] != NULL) {
					i++;
				}
				if (tdvp != NULL) {
					vpl[i++] = tdvp;
					tdvp = NULL;
				}
			}
			pfp = pfpnext;
		}
		if (pfp == NULL)
			index++;
		/*
		 * Now call VN_RELE if we have collected enough vnodes or
		 * we have reached the end of the hash table.
		 */
		if (i >= (PORTFOP_NVP - 1) ||
		    (i > 0 && index == PORTFOP_HASHSIZE)) {
			mutex_exit(&pfcp->pfc_lock);
			while (i > 0) {
				VN_RELE(vpl[--i]);
				vpl[i] = NULL;
			}
			mutex_enter(&pfcp->pfc_lock);
		}
	}

	/*
	 * Due to a race between port_close_fop() and port_fop()
	 * trying to remove the pfp's from the port's cache, it is
	 * possible that some pfp's are still in the process of being
	 * freed so we wait.
	 */
	while (lastclose && pfcp->pfc_objcount) {
		(void) cv_wait_sig(&pfcp->pfc_lclosecv, &pfcp->pfc_lock);
	}
	mutex_exit(&pfcp->pfc_lock);
	/*
	 * last close, free the cache.
	 */
	if (lastclose) {
		ASSERT(pfcp->pfc_objcount == 0);
		pse->portsrc_data = NULL;
		kmem_free(pfcp, sizeof (portfop_cache_t));
	}
}

/*
 * Given the list of associations(watches), it will send exception events,
 * if still active, and discard them. The exception events are handled
 * separately because, the pfp needs to be removed from the port cache and
 * freed as the vnode's identity is changing or being removed. To remove
 * the pfp from the port's cache, we need to hold the cache lock (pfc_lock).
 * The lock order is pfc_lock -> pvp_mutex(vnode's) mutex and that is why
 * the cache's lock cannot be acquired in port_fop_sendevent().
 */
static void
port_fop_excep(list_t *tlist, int op)
{
	portfop_t	*pfp;
	portfop_cache_t *pfcp;
	port_t	*pp;
	port_kevent_t	*pkevp;
	vnode_t		*tdvp;
	int		error = 0;

	while (pfp = (portfop_t *)list_head(tlist)) {
		int removed = 0;
		/*
		 * remove from the temp list. Since PORT_FOP_REMOVING is
		 * set, no other thread should attempt to perform a
		 * list_remove on this pfp.
		 */
		list_remove(tlist, pfp);

		pfcp = pfp->pfop_pcache;
		mutex_enter(&pfcp->pfc_lock);

		/*
		 * Remove the event from the port queue if it was queued up.
		 * No need to clear the PORT_FOP_KEV_ONQ flag as this pfp is
		 * no longer on the vnode's list.
		 */
		if ((pfp->pfop_flags & PORT_FOP_KEV_ONQ)) {
			removed = port_remove_done_event(pfp->pfop_pev);
		}

		/*
		 * If still active or the event was queued up and
		 * had not been collected yet, send an EXCEPTION event.
		 */
		if (pfp->pfop_flags & (PORT_FOP_ACTIVE) || removed) {
			pp = pfp->pfop_pp;
			/*
			 * Allocate a port_kevent_t non cached to send this
			 * event since we will be de-registering.
			 * The port_kevent_t cannot be pointing back to the
			 * pfp anymore.
			 */
			pfp->pfop_flags &= ~PORT_FOP_ACTIVE;
			error = port_alloc_event_local(pp, PORT_SOURCE_FILE,
			    PORT_ALLOC_DEFAULT, &pkevp);
			if (!error) {

				pkevp->portkev_callback = port_fop_callback;
				pkevp->portkev_arg = NULL;
				pkevp->portkev_object =
				    pfp->pfop_pev->portkev_object;
				pkevp->portkev_user =
				    pfp->pfop_pev->portkev_user;
				/*
				 * Copy the pid of the watching process.
				 */
				pkevp->portkev_pid =
				    pfp->pfop_pev->portkev_pid;
				pkevp->portkev_events = op;
				port_send_event(pkevp);
			}
		}
		/*
		 * At this point the pfp has been removed from the vnode's
		 * list its cached port_kevent_t is not on the done queue.
		 * Remove the pfp and free it from the cache.
		 */
		tdvp = pfp->pfop_dvp;
		port_pcache_remove_fop(pfcp, pfp);
		mutex_exit(&pfcp->pfc_lock);
		if (tdvp != NULL)
			VN_RELE(tdvp);
	}
}

/*
 * Send the file events to all of the processes watching this
 * vnode. In case of hard links, the directory vnode pointer and
 * the file name are compared. If the names match, then the specified
 * event is sent or else, the FILE_ATTRIB event is sent, This is the
 * documented behavior.
 */
void
port_fop_sendevent(vnode_t *vp, int events, vnode_t *dvp, char *cname)
{
	port_kevent_t	*pkevp;
	portfop_t	*pfp, *npfp;
	portfop_vp_t	*pvp;
	list_t		tmplist;
	int		removeall = 0;

	pvp = (portfop_vp_t *)vp->v_fopdata;
	mutex_enter(&pvp->pvp_mutex);

	/*
	 * Check if the list is empty.
	 *
	 * All entries have been removed by some other thread.
	 * The vnode may be still active and we got called,
	 * but some other thread is in the process of removing the hooks.
	 */
	if (!list_head(&pvp->pvp_pfoplist)) {
		mutex_exit(&pvp->pvp_mutex);
		return;
	}

	if ((events & (FILE_EXCEPTION))) {
		/*
		 * If it is an event for which we are going to remove
		 * the watches so just move it a temporary list and
		 * release this vnode.
		 */
		list_create(&tmplist, sizeof (portfop_t),
		    offsetof(portfop_t, pfop_node));

		/*
		 * If it is an UNMOUNT, MOUNTEDOVER or no file name has been
		 * passed for an exception event, all associations need to be
		 * removed.
		 */
		if (dvp == NULL || cname == NULL) {
			removeall = 1;
		}
	}

	if (!removeall) {
		/*
		 * All the active ones are in the beginning of the list.
		 * Note that we process this list in reverse order to assure
		 * that events are delivered in the order that they were
		 * associated.
		 */
		for (pfp = (portfop_t *)list_tail(&pvp->pvp_pfoplist);
		    pfp && !(pfp->pfop_flags & PORT_FOP_ACTIVE); pfp = npfp) {
			npfp = list_prev(&pvp->pvp_pfoplist, pfp);
		}

		for (; pfp != NULL; pfp = npfp) {
			int levents = events;

			npfp = list_prev(&pvp->pvp_pfoplist, pfp);
			/*
			 * Hard links case - If the file is being
			 * removed/renamed, and the name matches
			 * the watched file, then it is an EXCEPTION
			 * event or else it will be just a FILE_ATTRIB.
			 */
			if ((events & (FILE_EXCEPTION))) {
				ASSERT(dvp != NULL && cname != NULL);
				if (pfp->pfop_dvp == NULL ||
				    (pfp->pfop_dvp == dvp &&
				    (strcmp(cname, pfp->pfop_cname) == 0))) {
					/*
					 * It is an exception event, move it
					 * to temp list and process it later.
					 * Note we don't set the pfp->pfop_vp
					 * to NULL even thought it has been
					 * removed from the vnode's list. This
					 * pointer is referenced in
					 * port_remove_fop(). The vnode it
					 * self cannot disappear until this
					 * pfp gets removed and freed.
					 */
					port_fop_listremove(pvp, pfp);
					list_insert_tail(&tmplist, (void *)pfp);
					pfp->pfop_flags  |= PORT_FOP_REMOVING;
					continue;
				} else {
					levents = FILE_ATTRIB;
				}

			}

			if (pfp->pfop_events & levents) {
				/*
				 * deactivate and move it to the tail.
				 * If the pfp was active, it cannot be
				 * on the port's done queue.
				 */
				pfp->pfop_flags &= ~PORT_FOP_ACTIVE;
				port_fop_listremove(pvp, pfp);
				port_fop_listinsert_tail(pvp, pfp);

				pkevp = pfp->pfop_pev;
				pkevp->portkev_events |=
				    (levents & pfp->pfop_events);
				port_send_event(pkevp);
				pfp->pfop_flags |= PORT_FOP_KEV_ONQ;
			}
		}
	}


	if ((events & (FILE_EXCEPTION))) {
		if (!removeall) {
			/*
			 * Check the inactive associations and remove them if
			 * the file name matches.
			 */
			for (; pfp; pfp = npfp) {
				npfp = list_next(&pvp->pvp_pfoplist, pfp);
				if (dvp == NULL || cname == NULL ||
				    pfp->pfop_dvp == NULL ||
				    (pfp->pfop_dvp == dvp &&
				    (strcmp(cname, pfp->pfop_cname) == 0))) {
					port_fop_listremove(pvp, pfp);
					list_insert_tail(&tmplist, (void *)pfp);
					pfp->pfop_flags  |= PORT_FOP_REMOVING;
				}
			}
		} else {
			/*
			 * Can be optimized to avoid two pass over this list
			 * by having a flag in the vnode's portfop_vp_t
			 * structure to indicate that it is going away,
			 * Or keep the list short by reusing inactive watches.
			 */
			port_fop_listmove(pvp, &tmplist);
			for (pfp = (portfop_t *)list_head(&tmplist);
			    pfp; pfp = list_next(&tmplist, pfp)) {
				pfp->pfop_flags |= PORT_FOP_REMOVING;
			}
		}

		/*
		 * Uninstall the fem hooks if there are no more associations.
		 * This will release the pvp mutex.
		 *
		 * Even thought all entries may have been removed,
		 * the vnode itself cannot disappear as there will be a
		 * hold on it due to this call to port_fop_sendevent. This is
		 * important to syncronize with a port_dissociate_fop() call
		 * that may be attempting to remove an object from the vnode's.
		 */
		if (port_fop_femuninstall(vp))
			VN_RELE(vp);

		/*
		 * Send exception events and discard the watch entries.
		 */
		port_fop_excep(&tmplist, events);
		list_destroy(&tmplist);

	} else {
		mutex_exit(&pvp->pvp_mutex);

		/*
		 * trim the list.
		 */
		port_fop_trimpfplist(vp);
	}
}

/*
 * Given the file operation, map it to the event types and send.
 */
void
port_fop(vnode_t *vp, int op, int retval)
{
	int event = 0;
	/*
	 * deliver events only if the operation was successful.
	 */
	if (retval)
		return;

	/*
	 * These events occurring on the watched file.
	 */
	if (op & FOP_MODIFIED_MASK) {
		event  = FILE_MODIFIED;
	}
	if (op & FOP_ACCESS_MASK) {
		event  |= FILE_ACCESS;
	}
	if (op & FOP_ATTRIB_MASK) {
		event  |= FILE_ATTRIB;
	}
	if (op & FOP_TRUNC_MASK) {
		event  |= FILE_TRUNC;
	}
	if (event) {
		port_fop_sendevent(vp, 	event, NULL, NULL);
	}
}

static int port_forceunmount(vfs_t *vfsp)
{
	char *fsname = vfssw[vfsp->vfs_fstype].vsw_name;

	if (fsname == NULL) {
		return (0);
	}

	if (strcmp(fsname, MNTTYPE_NFS) == 0) {
		return (1);
	}

	if (strcmp(fsname, MNTTYPE_NFS3) == 0) {
		return (1);
	}

	if (strcmp(fsname, MNTTYPE_NFS4) == 0) {
		return (1);
	}
	return (0);
}
/*
 * ----- the unmount filesystem op(fsem) hook.
 */
int
port_fop_unmount(fsemarg_t *vf, int flag, cred_t *cr)
{
	vfs_t	*vfsp = (vfs_t *)vf->fa_fnode->fn_available;
	kmutex_t	*mtx;
	portfop_vfs_t	*pvfsp, **ppvfsp;
	portfop_vp_t	*pvp;
	int error;
	int fmfs;

	fmfs = port_forceunmount(vfsp);

	mtx = &(portvfs_hash[PORTFOP_PVFSHASH(vfsp)].pvfshash_mutex);
	ppvfsp = &(portvfs_hash[PORTFOP_PVFSHASH(vfsp)].pvfshash_pvfsp);
	pvfsp = NULL;
	mutex_enter(mtx);
	/*
	 * since this fsem hook is triggered, the vfsp has to be on
	 * the hash list.
	 */
	for (pvfsp = *ppvfsp; pvfsp->pvfs != vfsp; pvfsp = pvfsp->pvfs_next)
	;

	/*
	 * For some of the filesystems, allow unmounts to proceed only if
	 * there are no files being watched or it is a forced unmount.
	 */
	if (fmfs && !(flag & MS_FORCE) &&
	    !list_is_empty(&pvfsp->pvfs_pvplist)) {
		mutex_exit(mtx);
		return (EBUSY);
	}

	/*
	 * Indicate that the unmount is in process. Don't remove it yet.
	 * The underlying filesystem unmount routine sets the VFS_UNMOUNTED
	 * flag on the vfs_t structure. But we call the filesystem unmount
	 * routine after removing all the file watches for this filesystem,
	 * otherwise the unmount will fail due to active vnodes.
	 * Meanwhile setting pvfsp->unmount = 1 will prevent any thread
	 * attempting to add a file watch.
	 */
	pvfsp->pvfs_unmount = 1;
	mutex_exit(mtx);

	/*
	 * uninstall the fsem hooks.
	 */
	(void) fsem_uninstall(vfsp, (fsem_t *)pvfsp->pvfs_fsemp, vfsp);

	while (pvp = list_head(&pvfsp->pvfs_pvplist)) {
		list_remove(&pvfsp->pvfs_pvplist, pvp);
		/*
		 * This should send an UNMOUNTED event to all the
		 * watched vnode of this filesystem and uninstall
		 * the fem hooks. We release the hold on the vnode here
		 * because port_fop_femuninstall() will not do it if
		 * unmount is in process.
		 */
		port_fop_sendevent(pvp->pvp_vp, UNMOUNTED, NULL, NULL);
		VN_RELE(pvp->pvp_vp);
	}

	error = vfsnext_unmount(vf, flag, cr);

	/*
	 * we free the pvfsp after the unmount has been completed.
	 */
	mutex_enter(mtx);
	for (; *ppvfsp && (*ppvfsp)->pvfs != vfsp;
	    ppvfsp = &(*ppvfsp)->pvfs_next)
	;

	/*
	 * remove and free it.
	 */
	ASSERT(list_head(&pvfsp->pvfs_pvplist) == NULL);
	if (*ppvfsp) {
		pvfsp = *ppvfsp;
		*ppvfsp = pvfsp->pvfs_next;
	}
	mutex_exit(mtx);
	kmem_free(pvfsp, sizeof (portfop_vfs_t));
	return (error);
}

/*
 * ------------------------------file op hooks--------------------------
 * The O_TRUNC operation is caught with the VOP_SETATTR(AT_SIZE) call.
 */
static int
port_fop_open(femarg_t *vf, int mode, cred_t *cr, caller_context_t *ct)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval = vnext_open(vf, mode, cr, ct);
	port_fop(vp, FOP_FILE_OPEN, retval);
	return (retval);
}

static int
port_fop_write(femarg_t *vf, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval =  vnext_write(vf, uiop, ioflag, cr, ct);
	port_fop(vp, FOP_FILE_WRITE, retval);
	return (retval);
}

static int
port_fop_map(femarg_t *vf, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxport, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval =  vnext_map(vf, off, as, addrp, len, prot, maxport,
	    flags, cr, ct);
	port_fop(vp, FOP_FILE_MAP, retval);
	return (retval);
}

static int
port_fop_read(femarg_t *vf, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval =  vnext_read(vf, uiop, ioflag, cr, ct);
	port_fop(vp, FOP_FILE_READ, retval);
	return (retval);
}


/*
 * AT_SIZE - is for the open(O_TRUNC) case.
 */
int
port_fop_setattr(femarg_t *vf, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;
	int		events = 0;

	retval = vnext_setattr(vf, vap, flags, cr, ct);
	if (vap->va_mask & AT_SIZE) {
		events |= FOP_FILE_TRUNC;
	}
	if (vap->va_mask & (AT_SIZE|AT_MTIME)) {
		events |= FOP_FILE_SETATTR_MTIME;
	}
	if (vap->va_mask & AT_ATIME) {
		events |= FOP_FILE_SETATTR_ATIME;
	}
	events |= FOP_FILE_SETATTR_CTIME;

	port_fop(vp, events, retval);
	return (retval);
}

int
port_fop_create(femarg_t *vf, char *name, vattr_t *vap, vcexcl_t excl,
    int mode, vnode_t **vpp, cred_t *cr, int flag,
    caller_context_t *ct, vsecattr_t *vsecp)
{
	int		retval, got = 1;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;
	vattr_t		vatt, vatt1;

	/*
	 * If the file already exists, then there will be no change
	 * to the directory. Therefore, we need to compare the
	 * modification time of the directory to determine if the
	 * file was actually created.
	 */
	vatt.va_mask = AT_ATIME|AT_MTIME|AT_CTIME;
	if (VOP_GETATTR(vp, &vatt, 0, CRED(), ct)) {
		got = 0;
	}
	retval = vnext_create(vf, name, vap, excl, mode, vpp, cr,
	    flag, ct, vsecp);

	vatt1.va_mask = AT_ATIME|AT_MTIME|AT_CTIME;
	if (got && !VOP_GETATTR(vp, &vatt1, 0, CRED(), ct)) {
		if ((vatt1.va_mtime.tv_sec > vatt.va_mtime.tv_sec ||
		    (vatt1.va_mtime.tv_sec = vatt.va_mtime.tv_sec &&
		    vatt1.va_mtime.tv_nsec > vatt.va_mtime.tv_nsec))) {
			/*
			 * File was created.
			 */
			port_fop(vp, FOP_FILE_CREATE, retval);
		}
	}
	return (retval);
}

int
port_fop_remove(femarg_t *vf, char *nm, cred_t *cr, caller_context_t *ct,
    int flags)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval = vnext_remove(vf, nm, cr, ct, flags);
	port_fop(vp, FOP_FILE_REMOVE, retval);
	return (retval);
}

int
port_fop_link(femarg_t *vf, vnode_t *svp, char *tnm, cred_t *cr,
    caller_context_t *ct, int flags)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval = vnext_link(vf, svp, tnm, cr, ct, flags);
	port_fop(vp, FOP_FILE_LINK, retval);
	return (retval);
}

/*
 * Rename operation is allowed only when from and to directories are
 * on the same filesystem. This is checked in vn_rename().
 * The target directory is notified thru a VNEVENT by the filesystem
 * if the source dir != target dir.
 */
int
port_fop_rename(femarg_t *vf, char *snm, vnode_t *tdvp, char *tnm, cred_t *cr,
    caller_context_t *ct, int flags)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval = vnext_rename(vf, snm, tdvp, tnm, cr, ct, flags);
	port_fop(vp, FOP_FILE_RENAMESRC, retval);
	return (retval);
}

int
port_fop_mkdir(femarg_t *vf, char *dirname, vattr_t *vap, vnode_t **vpp,
    cred_t *cr, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval = vnext_mkdir(vf, dirname, vap, vpp, cr, ct, flags, vsecp);
	port_fop(vp, FOP_FILE_MKDIR, retval);
	return (retval);
}

int
port_fop_rmdir(femarg_t *vf, char *nm, vnode_t *cdir, cred_t *cr,
    caller_context_t *ct, int flags)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval = vnext_rmdir(vf, nm, cdir, cr, ct, flags);
	port_fop(vp, FOP_FILE_RMDIR, retval);
	return (retval);
}

int
port_fop_readdir(femarg_t *vf, uio_t *uiop, cred_t *cr, int *eofp,
    caller_context_t *ct, int flags)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval = vnext_readdir(vf, uiop, cr, eofp, ct, flags);
	port_fop(vp, FOP_FILE_READDIR, retval);
	return (retval);
}

int
port_fop_symlink(femarg_t *vf, char *linkname, vattr_t *vap, char *target,
    cred_t *cr, caller_context_t *ct, int flags)
{
	int		retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	retval = vnext_symlink(vf, linkname, vap, target, cr, ct, flags);
	port_fop(vp, FOP_FILE_SYMLINK, retval);
	return (retval);
}

/*
 * acl, facl call this.
 */
int
port_fop_setsecattr(femarg_t *vf, vsecattr_t *vsap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int	retval;
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;
	retval = vnext_setsecattr(vf, vsap, flags, cr, ct);
	port_fop(vp, FOP_FILE_SETSECATTR, retval);
	return (retval);
}

/*
 * these are events on the watched file/directory
 */
int
port_fop_vnevent(femarg_t *vf, vnevent_t vnevent, vnode_t *dvp, char *name,
    caller_context_t *ct)
{
	vnode_t		*vp = (vnode_t *)vf->fa_fnode->fn_available;

	switch (vnevent) {
	case	VE_RENAME_SRC:
			port_fop_sendevent(vp, FILE_RENAME_FROM, dvp, name);
		break;
	case	VE_RENAME_DEST:
			port_fop_sendevent(vp, FILE_RENAME_TO, dvp, name);
		break;
	case	VE_REMOVE:
			port_fop_sendevent(vp, FILE_DELETE, dvp, name);
		break;
	case	VE_RMDIR:
			port_fop_sendevent(vp, FILE_DELETE, dvp, name);
		break;
	case	VE_CREATE:
			port_fop_sendevent(vp,
			    FILE_MODIFIED|FILE_ATTRIB|FILE_TRUNC, NULL, NULL);
		break;
	case	VE_LINK:
			port_fop_sendevent(vp, FILE_ATTRIB, NULL, NULL);
		break;

	case	VE_RENAME_DEST_DIR:
			port_fop_sendevent(vp, FILE_MODIFIED|FILE_ATTRIB,
			    NULL, NULL);
		break;

	case	VE_MOUNTEDOVER:
			port_fop_sendevent(vp, MOUNTEDOVER, NULL, NULL);
		break;
	case	VE_TRUNCATE:
			port_fop_sendevent(vp, FILE_TRUNC, NULL, NULL);
		break;
	default:
		break;
	}
	return (vnext_vnevent(vf, vnevent, dvp, name, ct));
}
