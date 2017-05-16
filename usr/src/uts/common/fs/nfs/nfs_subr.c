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
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2016, 2017 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/tiuser.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/session.h>
#include <sys/dnlc.h>
#include <sys/bitmap.h>
#include <sys/acl.h>
#include <sys/ddi.h>
#include <sys/pathname.h>
#include <sys/flock.h>
#include <sys/dirent.h>
#include <sys/flock.h>
#include <sys/callb.h>
#include <sys/atomic.h>
#include <sys/list.h>
#include <sys/tsol/tnet.h>
#include <sys/priv.h>
#include <sys/sdt.h>
#include <sys/attr.h>

#include <inet/ip6.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfs_clnt.h>
#include <nfs/rnode.h>
#include <nfs/nfs_acl.h>

#include <sys/tsol/label.h>

/*
 * The hash queues for the access to active and cached rnodes
 * are organized as doubly linked lists.  A reader/writer lock
 * for each hash bucket is used to control access and to synchronize
 * lookups, additions, and deletions from the hash queue.
 *
 * The rnode freelist is organized as a doubly linked list with
 * a head pointer.  Additions and deletions are synchronized via
 * a single mutex.
 *
 * In order to add an rnode to the free list, it must be hashed into
 * a hash queue and the exclusive lock to the hash queue be held.
 * If an rnode is not hashed into a hash queue, then it is destroyed
 * because it represents no valuable information that can be reused
 * about the file.  The exclusive lock to the hash queue must be
 * held in order to prevent a lookup in the hash queue from finding
 * the rnode and using it and assuming that the rnode is not on the
 * freelist.  The lookup in the hash queue will have the hash queue
 * locked, either exclusive or shared.
 *
 * The vnode reference count for each rnode is not allowed to drop
 * below 1.  This prevents external entities, such as the VM
 * subsystem, from acquiring references to vnodes already on the
 * freelist and then trying to place them back on the freelist
 * when their reference is released.  This means that the when an
 * rnode is looked up in the hash queues, then either the rnode
 * is removed from the freelist and that reference is transferred to
 * the new reference or the vnode reference count must be incremented
 * accordingly.  The mutex for the freelist must be held in order to
 * accurately test to see if the rnode is on the freelist or not.
 * The hash queue lock might be held shared and it is possible that
 * two different threads may race to remove the rnode from the
 * freelist.  This race can be resolved by holding the mutex for the
 * freelist.  Please note that the mutex for the freelist does not
 * need to held if the rnode is not on the freelist.  It can not be
 * placed on the freelist due to the requirement that the thread
 * putting the rnode on the freelist must hold the exclusive lock
 * to the hash queue and the thread doing the lookup in the hash
 * queue is holding either a shared or exclusive lock to the hash
 * queue.
 *
 * The lock ordering is:
 *
 *	hash bucket lock -> vnode lock
 *	hash bucket lock -> freelist lock
 */
static rhashq_t *rtable;

static kmutex_t rpfreelist_lock;
static rnode_t *rpfreelist = NULL;
static long rnew = 0;
long nrnode = 0;

static int rtablesize;
static int rtablemask;

static int hashlen = 4;

static struct kmem_cache *rnode_cache;

/*
 * Mutex to protect the following variables:
 *	nfs_major
 *	nfs_minor
 */
kmutex_t nfs_minor_lock;
int nfs_major;
int nfs_minor;

/* Do we allow preepoch (negative) time values otw? */
bool_t nfs_allow_preepoch_time = FALSE;	/* default: do not allow preepoch */

/*
 * Access cache
 */
static acache_hash_t *acache;
static long nacache;	/* used strictly to size the number of hash queues */

static int acachesize;
static int acachemask;
static struct kmem_cache *acache_cache;

/*
 * Client side utilities
 */

/*
 * client side statistics
 */
static const struct clstat clstat_tmpl = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "clgets",	KSTAT_DATA_UINT64 },
	{ "cltoomany",	KSTAT_DATA_UINT64 },
#ifdef DEBUG
	{ "clalloc",	KSTAT_DATA_UINT64 },
	{ "noresponse",	KSTAT_DATA_UINT64 },
	{ "failover",	KSTAT_DATA_UINT64 },
	{ "remap",	KSTAT_DATA_UINT64 },
#endif
};

/*
 * The following are statistics that describe behavior of the system as a whole
 * and doesn't correspond to any one particular zone.
 */
#ifdef DEBUG
static struct clstat_debug {
	kstat_named_t	nrnode;			/* number of allocated rnodes */
	kstat_named_t	access;			/* size of access cache */
	kstat_named_t	dirent;			/* size of readdir cache */
	kstat_named_t	dirents;		/* size of readdir buf cache */
	kstat_named_t	reclaim;		/* number of reclaims */
	kstat_named_t	clreclaim;		/* number of cl reclaims */
	kstat_named_t	f_reclaim;		/* number of free reclaims */
	kstat_named_t	a_reclaim;		/* number of active reclaims */
	kstat_named_t	r_reclaim;		/* number of rnode reclaims */
	kstat_named_t	rpath;			/* bytes used to store rpaths */
} clstat_debug = {
	{ "nrnode",	KSTAT_DATA_UINT64 },
	{ "access",	KSTAT_DATA_UINT64 },
	{ "dirent",	KSTAT_DATA_UINT64 },
	{ "dirents",	KSTAT_DATA_UINT64 },
	{ "reclaim",	KSTAT_DATA_UINT64 },
	{ "clreclaim",	KSTAT_DATA_UINT64 },
	{ "f_reclaim",	KSTAT_DATA_UINT64 },
	{ "a_reclaim",	KSTAT_DATA_UINT64 },
	{ "r_reclaim",	KSTAT_DATA_UINT64 },
	{ "r_path",	KSTAT_DATA_UINT64 },
};
#endif	/* DEBUG */

/*
 * We keep a global list of per-zone client data, so we can clean up all zones
 * if we get low on memory.
 */
static list_t nfs_clnt_list;
static kmutex_t nfs_clnt_list_lock;
static zone_key_t nfsclnt_zone_key;

static struct kmem_cache *chtab_cache;

/*
 * Some servers do not properly update the attributes of the
 * directory when changes are made.  To allow interoperability
 * with these broken servers, the nfs_disable_rddir_cache
 * parameter must be set in /etc/system
 */
int nfs_disable_rddir_cache = 0;

int		clget(clinfo_t *, servinfo_t *, cred_t *, CLIENT **,
		    struct chtab **);
void		clfree(CLIENT *, struct chtab *);
static int	acl_clget(mntinfo_t *, servinfo_t *, cred_t *, CLIENT **,
		    struct chtab **, struct nfs_clnt *);
static int	nfs_clget(mntinfo_t *, servinfo_t *, cred_t *, CLIENT **,
		    struct chtab **, struct nfs_clnt *);
static void	clreclaim(void *);
static int	nfs_feedback(int, int, mntinfo_t *);
static int	rfscall(mntinfo_t *, rpcproc_t, xdrproc_t, caddr_t, xdrproc_t,
		    caddr_t, cred_t *, int *, enum clnt_stat *, int,
		    failinfo_t *);
static int	aclcall(mntinfo_t *, rpcproc_t, xdrproc_t, caddr_t, xdrproc_t,
		    caddr_t, cred_t *, int *, int, failinfo_t *);
static void	rinactive(rnode_t *, cred_t *);
static int	rtablehash(nfs_fhandle *);
static vnode_t	*make_rnode(nfs_fhandle *, rhashq_t *, struct vfs *,
		    struct vnodeops *,
		    int (*)(vnode_t *, page_t *, u_offset_t *, size_t *, int,
			cred_t *),
		    int (*)(const void *, const void *), int *, cred_t *,
		    char *, char *);
static void	rp_rmfree(rnode_t *);
static void	rp_addhash(rnode_t *);
static void	rp_rmhash_locked(rnode_t *);
static rnode_t	*rfind(rhashq_t *, nfs_fhandle *, struct vfs *);
static void	destroy_rnode(rnode_t *);
static void	rddir_cache_free(rddir_cache *);
static int	nfs_free_data_reclaim(rnode_t *);
static int	nfs_active_data_reclaim(rnode_t *);
static int	nfs_free_reclaim(void);
static int	nfs_active_reclaim(void);
static int	nfs_rnode_reclaim(void);
static void	nfs_reclaim(void *);
static int	failover_safe(failinfo_t *);
static void	failover_newserver(mntinfo_t *mi);
static void	failover_thread(mntinfo_t *mi);
static int	failover_wait(mntinfo_t *);
static int	failover_remap(failinfo_t *);
static int	failover_lookup(char *, vnode_t *,
		    int (*)(vnode_t *, char *, vnode_t **,
			struct pathname *, int, vnode_t *, cred_t *, int),
		    int (*)(vnode_t *, vnode_t **, bool_t, cred_t *, int),
		    vnode_t **);
static void	nfs_free_r_path(rnode_t *);
static void	nfs_set_vroot(vnode_t *);
static char	*nfs_getsrvnames(mntinfo_t *, size_t *);

/*
 * from rpcsec module (common/rpcsec)
 */
extern int sec_clnt_geth(CLIENT *, struct sec_data *, cred_t *, AUTH **);
extern void sec_clnt_freeh(AUTH *);
extern void sec_clnt_freeinfo(struct sec_data *);

/*
 * used in mount policy
 */
extern ts_label_t *getflabel_cipso(vfs_t *);

/*
 * EIO or EINTR are not recoverable errors.
 */
#define	IS_RECOVERABLE_ERROR(error)	!((error == EINTR) || (error == EIO))

#ifdef DEBUG
#define	SRV_QFULL_MSG	"send queue to NFS%d server %s is full; still trying\n"
#define	SRV_NOTRESP_MSG	"NFS%d server %s not responding still trying\n"
#else
#define	SRV_QFULL_MSG	"send queue to NFS server %s is full still trying\n"
#define	SRV_NOTRESP_MSG	"NFS server %s not responding still trying\n"
#endif
/*
 * Common handle get program for NFS, NFS ACL, and NFS AUTH client.
 */
static int
clget_impl(clinfo_t *ci, servinfo_t *svp, cred_t *cr, CLIENT **newcl,
    struct chtab **chp, struct nfs_clnt *nfscl)
{
	struct chhead *ch, *newch;
	struct chhead **plistp;
	struct chtab *cp;
	int error;
	k_sigset_t smask;

	if (newcl == NULL || chp == NULL || ci == NULL)
		return (EINVAL);

	*newcl = NULL;
	*chp = NULL;

	/*
	 * Find an unused handle or create one
	 */
	newch = NULL;
	nfscl->nfscl_stat.clgets.value.ui64++;
top:
	/*
	 * Find the correct entry in the cache to check for free
	 * client handles.  The search is based on the RPC program
	 * number, program version number, dev_t for the transport
	 * device, and the protocol family.
	 */
	mutex_enter(&nfscl->nfscl_chtable_lock);
	plistp = &nfscl->nfscl_chtable;
	for (ch = nfscl->nfscl_chtable; ch != NULL; ch = ch->ch_next) {
		if (ch->ch_prog == ci->cl_prog &&
		    ch->ch_vers == ci->cl_vers &&
		    ch->ch_dev == svp->sv_knconf->knc_rdev &&
		    (strcmp(ch->ch_protofmly,
		    svp->sv_knconf->knc_protofmly) == 0))
			break;
		plistp = &ch->ch_next;
	}

	/*
	 * If we didn't find a cache entry for this quadruple, then
	 * create one.  If we don't have one already preallocated,
	 * then drop the cache lock, create one, and then start over.
	 * If we did have a preallocated entry, then just add it to
	 * the front of the list.
	 */
	if (ch == NULL) {
		if (newch == NULL) {
			mutex_exit(&nfscl->nfscl_chtable_lock);
			newch = kmem_alloc(sizeof (*newch), KM_SLEEP);
			newch->ch_timesused = 0;
			newch->ch_prog = ci->cl_prog;
			newch->ch_vers = ci->cl_vers;
			newch->ch_dev = svp->sv_knconf->knc_rdev;
			newch->ch_protofmly = kmem_alloc(
			    strlen(svp->sv_knconf->knc_protofmly) + 1,
			    KM_SLEEP);
			(void) strcpy(newch->ch_protofmly,
			    svp->sv_knconf->knc_protofmly);
			newch->ch_list = NULL;
			goto top;
		}
		ch = newch;
		newch = NULL;
		ch->ch_next = nfscl->nfscl_chtable;
		nfscl->nfscl_chtable = ch;
	/*
	 * We found a cache entry, but if it isn't on the front of the
	 * list, then move it to the front of the list to try to take
	 * advantage of locality of operations.
	 */
	} else if (ch != nfscl->nfscl_chtable) {
		*plistp = ch->ch_next;
		ch->ch_next = nfscl->nfscl_chtable;
		nfscl->nfscl_chtable = ch;
	}

	/*
	 * If there was a free client handle cached, then remove it
	 * from the list, init it, and use it.
	 */
	if (ch->ch_list != NULL) {
		cp = ch->ch_list;
		ch->ch_list = cp->ch_list;
		mutex_exit(&nfscl->nfscl_chtable_lock);
		if (newch != NULL) {
			kmem_free(newch->ch_protofmly,
			    strlen(newch->ch_protofmly) + 1);
			kmem_free(newch, sizeof (*newch));
		}
		(void) clnt_tli_kinit(cp->ch_client, svp->sv_knconf,
		    &svp->sv_addr, ci->cl_readsize, ci->cl_retrans, cr);
		error = sec_clnt_geth(cp->ch_client, svp->sv_secdata, cr,
		    &cp->ch_client->cl_auth);
		if (error || cp->ch_client->cl_auth == NULL) {
			CLNT_DESTROY(cp->ch_client);
			kmem_cache_free(chtab_cache, cp);
			return ((error != 0) ? error : EINTR);
		}
		ch->ch_timesused++;
		*newcl = cp->ch_client;
		*chp = cp;
		return (0);
	}

	/*
	 * There weren't any free client handles which fit, so allocate
	 * a new one and use that.
	 */
#ifdef DEBUG
	atomic_inc_64(&nfscl->nfscl_stat.clalloc.value.ui64);
#endif
	mutex_exit(&nfscl->nfscl_chtable_lock);

	nfscl->nfscl_stat.cltoomany.value.ui64++;
	if (newch != NULL) {
		kmem_free(newch->ch_protofmly, strlen(newch->ch_protofmly) + 1);
		kmem_free(newch, sizeof (*newch));
	}

	cp = kmem_cache_alloc(chtab_cache, KM_SLEEP);
	cp->ch_head = ch;

	sigintr(&smask, (int)ci->cl_flags & MI_INT);
	error = clnt_tli_kcreate(svp->sv_knconf, &svp->sv_addr, ci->cl_prog,
	    ci->cl_vers, ci->cl_readsize, ci->cl_retrans, cr, &cp->ch_client);
	sigunintr(&smask);

	if (error != 0) {
		kmem_cache_free(chtab_cache, cp);
#ifdef DEBUG
		atomic_dec_64(&nfscl->nfscl_stat.clalloc.value.ui64);
#endif
		/*
		 * Warning is unnecessary if error is EINTR.
		 */
		if (error != EINTR) {
			nfs_cmn_err(error, CE_WARN,
			    "clget: couldn't create handle: %m\n");
		}
		return (error);
	}
	(void) CLNT_CONTROL(cp->ch_client, CLSET_PROGRESS, NULL);
	auth_destroy(cp->ch_client->cl_auth);
	error = sec_clnt_geth(cp->ch_client, svp->sv_secdata, cr,
	    &cp->ch_client->cl_auth);
	if (error || cp->ch_client->cl_auth == NULL) {
		CLNT_DESTROY(cp->ch_client);
		kmem_cache_free(chtab_cache, cp);
#ifdef DEBUG
		atomic_dec_64(&nfscl->nfscl_stat.clalloc.value.ui64);
#endif
		return ((error != 0) ? error : EINTR);
	}
	ch->ch_timesused++;
	*newcl = cp->ch_client;
	ASSERT(cp->ch_client->cl_nosignal == FALSE);
	*chp = cp;
	return (0);
}

int
clget(clinfo_t *ci, servinfo_t *svp, cred_t *cr, CLIENT **newcl,
    struct chtab **chp)
{
	struct nfs_clnt *nfscl;

	nfscl = zone_getspecific(nfsclnt_zone_key, nfs_zone());
	ASSERT(nfscl != NULL);

	return (clget_impl(ci, svp, cr, newcl, chp, nfscl));
}

static int
acl_clget(mntinfo_t *mi, servinfo_t *svp, cred_t *cr, CLIENT **newcl,
    struct chtab **chp, struct nfs_clnt *nfscl)
{
	clinfo_t ci;
	int error;

	/*
	 * Set read buffer size to rsize
	 * and add room for RPC headers.
	 */
	ci.cl_readsize = mi->mi_tsize;
	if (ci.cl_readsize != 0)
		ci.cl_readsize += (RPC_MAXDATASIZE - NFS_MAXDATA);

	/*
	 * If soft mount and server is down just try once.
	 * meaning: do not retransmit.
	 */
	if (!(mi->mi_flags & MI_HARD) && (mi->mi_flags & MI_DOWN))
		ci.cl_retrans = 0;
	else
		ci.cl_retrans = mi->mi_retrans;

	ci.cl_prog = NFS_ACL_PROGRAM;
	ci.cl_vers = mi->mi_vers;
	ci.cl_flags = mi->mi_flags;

	/*
	 * clget calls sec_clnt_geth() to get an auth handle. For RPCSEC_GSS
	 * security flavor, the client tries to establish a security context
	 * by contacting the server. If the connection is timed out or reset,
	 * e.g. server reboot, we will try again.
	 */
	do {
		error = clget_impl(&ci, svp, cr, newcl, chp, nfscl);

		if (error == 0)
			break;

		/*
		 * For forced unmount or zone shutdown, bail out, no retry.
		 */
		if (FS_OR_ZONE_GONE(mi->mi_vfsp)) {
			error = EIO;
			break;
		}

		/* do not retry for softmount */
		if (!(mi->mi_flags & MI_HARD))
			break;

		/* let the caller deal with the failover case */
		if (FAILOVER_MOUNT(mi))
			break;

	} while (error == ETIMEDOUT || error == ECONNRESET);

	return (error);
}

static int
nfs_clget(mntinfo_t *mi, servinfo_t *svp, cred_t *cr, CLIENT **newcl,
    struct chtab **chp, struct nfs_clnt *nfscl)
{
	clinfo_t ci;
	int error;

	/*
	 * Set read buffer size to rsize
	 * and add room for RPC headers.
	 */
	ci.cl_readsize = mi->mi_tsize;
	if (ci.cl_readsize != 0)
		ci.cl_readsize += (RPC_MAXDATASIZE - NFS_MAXDATA);

	/*
	 * If soft mount and server is down just try once.
	 * meaning: do not retransmit.
	 */
	if (!(mi->mi_flags & MI_HARD) && (mi->mi_flags & MI_DOWN))
		ci.cl_retrans = 0;
	else
		ci.cl_retrans = mi->mi_retrans;

	ci.cl_prog = mi->mi_prog;
	ci.cl_vers = mi->mi_vers;
	ci.cl_flags = mi->mi_flags;

	/*
	 * clget calls sec_clnt_geth() to get an auth handle. For RPCSEC_GSS
	 * security flavor, the client tries to establish a security context
	 * by contacting the server. If the connection is timed out or reset,
	 * e.g. server reboot, we will try again.
	 */
	do {
		error = clget_impl(&ci, svp, cr, newcl, chp, nfscl);

		if (error == 0)
			break;

		/*
		 * For forced unmount or zone shutdown, bail out, no retry.
		 */
		if (FS_OR_ZONE_GONE(mi->mi_vfsp)) {
			error = EIO;
			break;
		}

		/* do not retry for softmount */
		if (!(mi->mi_flags & MI_HARD))
			break;

		/* let the caller deal with the failover case */
		if (FAILOVER_MOUNT(mi))
			break;

	} while (error == ETIMEDOUT || error == ECONNRESET);

	return (error);
}

static void
clfree_impl(CLIENT *cl, struct chtab *cp, struct nfs_clnt *nfscl)
{
	if (cl->cl_auth != NULL) {
		sec_clnt_freeh(cl->cl_auth);
		cl->cl_auth = NULL;
	}

	/*
	 * Timestamp this cache entry so that we know when it was last
	 * used.
	 */
	cp->ch_freed = gethrestime_sec();

	/*
	 * Add the free client handle to the front of the list.
	 * This way, the list will be sorted in youngest to oldest
	 * order.
	 */
	mutex_enter(&nfscl->nfscl_chtable_lock);
	cp->ch_list = cp->ch_head->ch_list;
	cp->ch_head->ch_list = cp;
	mutex_exit(&nfscl->nfscl_chtable_lock);
}

void
clfree(CLIENT *cl, struct chtab *cp)
{
	struct nfs_clnt *nfscl;

	nfscl = zone_getspecific(nfsclnt_zone_key, nfs_zone());
	ASSERT(nfscl != NULL);

	clfree_impl(cl, cp, nfscl);
}

#define	CL_HOLDTIME	60	/* time to hold client handles */

static void
clreclaim_zone(struct nfs_clnt *nfscl, uint_t cl_holdtime)
{
	struct chhead *ch;
	struct chtab *cp;	/* list of objects that can be reclaimed */
	struct chtab *cpe;
	struct chtab *cpl;
	struct chtab **cpp;
#ifdef DEBUG
	int n = 0;
#endif

	/*
	 * Need to reclaim some memory, so step through the cache
	 * looking through the lists for entries which can be freed.
	 */
	cp = NULL;

	mutex_enter(&nfscl->nfscl_chtable_lock);

	/*
	 * Here we step through each non-NULL quadruple and start to
	 * construct the reclaim list pointed to by cp.  Note that
	 * cp will contain all eligible chtab entries.  When this traversal
	 * completes, chtab entries from the last quadruple will be at the
	 * front of cp and entries from previously inspected quadruples have
	 * been appended to the rear of cp.
	 */
	for (ch = nfscl->nfscl_chtable; ch != NULL; ch = ch->ch_next) {
		if (ch->ch_list == NULL)
			continue;
		/*
		 * Search each list for entries older then
		 * cl_holdtime seconds.  The lists are maintained
		 * in youngest to oldest order so that when the
		 * first entry is found which is old enough, then
		 * all of the rest of the entries on the list will
		 * be old enough as well.
		 */
		cpl = ch->ch_list;
		cpp = &ch->ch_list;
		while (cpl != NULL &&
		    cpl->ch_freed + cl_holdtime > gethrestime_sec()) {
			cpp = &cpl->ch_list;
			cpl = cpl->ch_list;
		}
		if (cpl != NULL) {
			*cpp = NULL;
			if (cp != NULL) {
				cpe = cpl;
				while (cpe->ch_list != NULL)
					cpe = cpe->ch_list;
				cpe->ch_list = cp;
			}
			cp = cpl;
		}
	}

	mutex_exit(&nfscl->nfscl_chtable_lock);

	/*
	 * If cp is empty, then there is nothing to reclaim here.
	 */
	if (cp == NULL)
		return;

	/*
	 * Step through the list of entries to free, destroying each client
	 * handle and kmem_free'ing the memory for each entry.
	 */
	while (cp != NULL) {
#ifdef DEBUG
		n++;
#endif
		CLNT_DESTROY(cp->ch_client);
		cpl = cp->ch_list;
		kmem_cache_free(chtab_cache, cp);
		cp = cpl;
	}

#ifdef DEBUG
	/*
	 * Update clalloc so that nfsstat shows the current number
	 * of allocated client handles.
	 */
	atomic_add_64(&nfscl->nfscl_stat.clalloc.value.ui64, -n);
#endif
}

/* ARGSUSED */
static void
clreclaim(void *all)
{
	struct nfs_clnt *nfscl;

#ifdef DEBUG
	clstat_debug.clreclaim.value.ui64++;
#endif
	/*
	 * The system is low on memory; go through and try to reclaim some from
	 * every zone on the system.
	 */
	mutex_enter(&nfs_clnt_list_lock);
	nfscl = list_head(&nfs_clnt_list);
	for (; nfscl != NULL; nfscl = list_next(&nfs_clnt_list, nfscl))
		clreclaim_zone(nfscl, CL_HOLDTIME);
	mutex_exit(&nfs_clnt_list_lock);
}

/*
 * Minimum time-out values indexed by call type
 * These units are in "eights" of a second to avoid multiplies
 */
static unsigned int minimum_timeo[] = {
	6, 7, 10
};

/*
 * Back off for retransmission timeout, MAXTIMO is in hz of a sec
 */
#define	MAXTIMO	(20*hz)
#define	backoff(tim)	(((tim) < MAXTIMO) ? dobackoff(tim) : (tim))
#define	dobackoff(tim)	((((tim) << 1) > MAXTIMO) ? MAXTIMO : ((tim) << 1))

#define	MIN_NFS_TSIZE 512	/* minimum "chunk" of NFS IO */
#define	REDUCE_NFS_TIME (hz/2)	/* rtxcur we try to keep under */
#define	INCREASE_NFS_TIME (hz/3*8) /* srtt we try to keep under (scaled*8) */

/*
 * Function called when rfscall notices that we have been
 * re-transmitting, or when we get a response without retransmissions.
 * Return 1 if the transfer size was adjusted down - 0 if no change.
 */
static int
nfs_feedback(int flag, int which, mntinfo_t *mi)
{
	int kind;
	int r = 0;

	mutex_enter(&mi->mi_lock);
	if (flag == FEEDBACK_REXMIT1) {
		if (mi->mi_timers[NFS_CALLTYPES].rt_rtxcur != 0 &&
		    mi->mi_timers[NFS_CALLTYPES].rt_rtxcur < REDUCE_NFS_TIME)
			goto done;
		if (mi->mi_curread > MIN_NFS_TSIZE) {
			mi->mi_curread /= 2;
			if (mi->mi_curread < MIN_NFS_TSIZE)
				mi->mi_curread = MIN_NFS_TSIZE;
			r = 1;
		}

		if (mi->mi_curwrite > MIN_NFS_TSIZE) {
			mi->mi_curwrite /= 2;
			if (mi->mi_curwrite < MIN_NFS_TSIZE)
				mi->mi_curwrite = MIN_NFS_TSIZE;
			r = 1;
		}
	} else if (flag == FEEDBACK_OK) {
		kind = mi->mi_timer_type[which];
		if (kind == 0 ||
		    mi->mi_timers[kind].rt_srtt >= INCREASE_NFS_TIME)
			goto done;
		if (kind == 1) {
			if (mi->mi_curread >= mi->mi_tsize)
				goto done;
			mi->mi_curread +=  MIN_NFS_TSIZE;
			if (mi->mi_curread > mi->mi_tsize/2)
				mi->mi_curread = mi->mi_tsize;
		} else if (kind == 2) {
			if (mi->mi_curwrite >= mi->mi_stsize)
				goto done;
			mi->mi_curwrite += MIN_NFS_TSIZE;
			if (mi->mi_curwrite > mi->mi_stsize/2)
				mi->mi_curwrite = mi->mi_stsize;
		}
	}
done:
	mutex_exit(&mi->mi_lock);
	return (r);
}

#ifdef DEBUG
static int rfs2call_hits = 0;
static int rfs2call_misses = 0;
#endif

int
rfs2call(mntinfo_t *mi, rpcproc_t which, xdrproc_t xdrargs, caddr_t argsp,
    xdrproc_t xdrres, caddr_t resp, cred_t *cr, int *douprintf,
    enum nfsstat *statusp, int flags, failinfo_t *fi)
{
	int rpcerror;
	enum clnt_stat rpc_status;

	ASSERT(statusp != NULL);

	rpcerror = rfscall(mi, which, xdrargs, argsp, xdrres, resp,
	    cr, douprintf, &rpc_status, flags, fi);
	if (!rpcerror) {
		/*
		 * See crnetadjust() for comments.
		 */
		if (*statusp == NFSERR_ACCES &&
		    (cr = crnetadjust(cr)) != NULL) {
#ifdef DEBUG
			rfs2call_hits++;
#endif
			rpcerror = rfscall(mi, which, xdrargs, argsp, xdrres,
			    resp, cr, douprintf, NULL, flags, fi);
			crfree(cr);
#ifdef DEBUG
			if (*statusp == NFSERR_ACCES)
				rfs2call_misses++;
#endif
		}
	} else if (rpc_status == RPC_PROCUNAVAIL) {
		*statusp = NFSERR_OPNOTSUPP;
		rpcerror = 0;
	}

	return (rpcerror);
}

#define	NFS3_JUKEBOX_DELAY	10 * hz

static clock_t nfs3_jukebox_delay = 0;

#ifdef DEBUG
static int rfs3call_hits = 0;
static int rfs3call_misses = 0;
#endif

int
rfs3call(mntinfo_t *mi, rpcproc_t which, xdrproc_t xdrargs, caddr_t argsp,
    xdrproc_t xdrres, caddr_t resp, cred_t *cr, int *douprintf,
    nfsstat3 *statusp, int flags, failinfo_t *fi)
{
	int rpcerror;
	int user_informed;

	user_informed = 0;
	do {
		rpcerror = rfscall(mi, which, xdrargs, argsp, xdrres, resp,
		    cr, douprintf, NULL, flags, fi);
		if (!rpcerror) {
			cred_t *crr;
			if (*statusp == NFS3ERR_JUKEBOX) {
				if (ttoproc(curthread) == &p0) {
					rpcerror = EAGAIN;
					break;
				}
				if (!user_informed) {
					user_informed = 1;
					uprintf(
		"file temporarily unavailable on the server, retrying...\n");
				}
				delay(nfs3_jukebox_delay);
			}
			/*
			 * See crnetadjust() for comments.
			 */
			else if (*statusp == NFS3ERR_ACCES &&
			    (crr = crnetadjust(cr)) != NULL) {
#ifdef DEBUG
				rfs3call_hits++;
#endif
				rpcerror = rfscall(mi, which, xdrargs, argsp,
				    xdrres, resp, crr, douprintf,
				    NULL, flags, fi);

				crfree(crr);
#ifdef DEBUG
				if (*statusp == NFS3ERR_ACCES)
					rfs3call_misses++;
#endif
			}
		}
	} while (!rpcerror && *statusp == NFS3ERR_JUKEBOX);

	return (rpcerror);
}

#define	VALID_FH(fi)	(VTOR(fi->vp)->r_server == VTOMI(fi->vp)->mi_curr_serv)
#define	INC_READERS(mi)		{ \
	mi->mi_readers++; \
}
#define	DEC_READERS(mi)		{ \
	mi->mi_readers--; \
	if (mi->mi_readers == 0) \
		cv_broadcast(&mi->mi_failover_cv); \
}

static int
rfscall(mntinfo_t *mi, rpcproc_t which, xdrproc_t xdrargs, caddr_t argsp,
    xdrproc_t xdrres, caddr_t resp, cred_t *icr, int *douprintf,
    enum clnt_stat *rpc_status, int flags, failinfo_t *fi)
{
	CLIENT *client;
	struct chtab *ch;
	cred_t *cr = icr;
	enum clnt_stat status;
	struct rpc_err rpcerr, rpcerr_tmp;
	struct timeval wait;
	int timeo;		/* in units of hz */
	int my_rsize, my_wsize;
	bool_t tryagain;
	bool_t cred_cloned = FALSE;
	k_sigset_t smask;
	servinfo_t *svp;
	struct nfs_clnt *nfscl;
	zoneid_t zoneid = getzoneid();
	char *msg;
#ifdef DEBUG
	char *bufp;
#endif


	TRACE_2(TR_FAC_NFS, TR_RFSCALL_START,
	    "rfscall_start:which %d mi %p", which, mi);

	nfscl = zone_getspecific(nfsclnt_zone_key, nfs_zone());
	ASSERT(nfscl != NULL);

	nfscl->nfscl_stat.calls.value.ui64++;
	mi->mi_reqs[which].value.ui64++;

	rpcerr.re_status = RPC_SUCCESS;

	/*
	 * In case of forced unmount or zone shutdown, return EIO.
	 */

	if (FS_OR_ZONE_GONE(mi->mi_vfsp)) {
		rpcerr.re_status = RPC_FAILED;
		rpcerr.re_errno = EIO;
		return (rpcerr.re_errno);
	}

	/*
	 * Remember the transfer sizes in case
	 * nfs_feedback changes them underneath us.
	 */
	my_rsize = mi->mi_curread;
	my_wsize = mi->mi_curwrite;

	/*
	 * NFS client failover support
	 *
	 * If this rnode is not in sync with the current server (VALID_FH),
	 * we'd like to do a remap to get in sync.  We can be interrupted
	 * in failover_remap(), and if so we'll bail.  Otherwise, we'll
	 * use the best info we have to try the RPC.  Part of that is
	 * unconditionally updating the filehandle copy kept for V3.
	 *
	 * Locking: INC_READERS/DEC_READERS is a poor man's interrruptible
	 * rw_enter(); we're trying to keep the current server from being
	 * changed on us until we're done with the remapping and have a
	 * matching client handle.  We don't want to sending a filehandle
	 * to the wrong host.
	 */
failoverretry:
	if (FAILOVER_MOUNT(mi)) {
		mutex_enter(&mi->mi_lock);
		if (!(flags & RFSCALL_SOFT) && failover_safe(fi)) {
			if (failover_wait(mi)) {
				mutex_exit(&mi->mi_lock);
				return (EINTR);
			}
		}
		INC_READERS(mi);
		mutex_exit(&mi->mi_lock);
		if (fi) {
			if (!VALID_FH(fi) &&
			    !(flags & RFSCALL_SOFT) && failover_safe(fi)) {
				int remaperr;

				svp = mi->mi_curr_serv;
				remaperr = failover_remap(fi);
				if (remaperr != 0) {
#ifdef DEBUG
					if (remaperr != EINTR)
						nfs_cmn_err(remaperr, CE_WARN,
					    "rfscall couldn't failover: %m");
#endif
					mutex_enter(&mi->mi_lock);
					DEC_READERS(mi);
					mutex_exit(&mi->mi_lock);
					/*
					 * If failover_remap returns ETIMEDOUT
					 * and the filesystem is hard mounted
					 * we have to retry the call with a new
					 * server.
					 */
					if ((mi->mi_flags & MI_HARD) &&
					    IS_RECOVERABLE_ERROR(remaperr)) {
						if (svp == mi->mi_curr_serv)
							failover_newserver(mi);
						rpcerr.re_status = RPC_SUCCESS;
						goto failoverretry;
					}
					rpcerr.re_errno = remaperr;
					return (remaperr);
				}
			}
			if (fi->fhp && fi->copyproc)
				(*fi->copyproc)(fi->fhp, fi->vp);
		}
	}

	/* For TSOL, use a new cred which has net_mac_aware flag */
	if (!cred_cloned && is_system_labeled()) {
		cred_cloned = TRUE;
		cr = crdup(icr);
		(void) setpflags(NET_MAC_AWARE, 1, cr);
	}

	/*
	 * clget() calls clnt_tli_kinit() which clears the xid, so we
	 * are guaranteed to reprocess the retry as a new request.
	 */
	svp = mi->mi_curr_serv;
	rpcerr.re_errno = nfs_clget(mi, svp, cr, &client, &ch, nfscl);

	if (FAILOVER_MOUNT(mi)) {
		mutex_enter(&mi->mi_lock);
		DEC_READERS(mi);
		mutex_exit(&mi->mi_lock);

		if ((rpcerr.re_errno == ETIMEDOUT ||
		    rpcerr.re_errno == ECONNRESET) &&
		    failover_safe(fi)) {
			if (svp == mi->mi_curr_serv)
				failover_newserver(mi);
			goto failoverretry;
		}
	}
	if (rpcerr.re_errno != 0)
		return (rpcerr.re_errno);

	if (svp->sv_knconf->knc_semantics == NC_TPI_COTS_ORD ||
	    svp->sv_knconf->knc_semantics == NC_TPI_COTS) {
		timeo = (mi->mi_timeo * hz) / 10;
	} else {
		mutex_enter(&mi->mi_lock);
		timeo = CLNT_SETTIMERS(client,
		    &(mi->mi_timers[mi->mi_timer_type[which]]),
		    &(mi->mi_timers[NFS_CALLTYPES]),
		    (minimum_timeo[mi->mi_call_type[which]]*hz)>>3,
		    (void (*)())NULL, (caddr_t)mi, 0);
		mutex_exit(&mi->mi_lock);
	}

	/*
	 * If hard mounted fs, retry call forever unless hard error occurs.
	 */
	do {
		tryagain = FALSE;

		if (FS_OR_ZONE_GONE(mi->mi_vfsp)) {
			status = RPC_FAILED;
			rpcerr.re_status = RPC_FAILED;
			rpcerr.re_errno = EIO;
			break;
		}

		TICK_TO_TIMEVAL(timeo, &wait);

		/*
		 * Mask out all signals except SIGHUP, SIGINT, SIGQUIT
		 * and SIGTERM. (Preserving the existing masks).
		 * Mask out SIGINT if mount option nointr is specified.
		 */
		sigintr(&smask, (int)mi->mi_flags & MI_INT);
		if (!(mi->mi_flags & MI_INT))
			client->cl_nosignal = TRUE;

		/*
		 * If there is a current signal, then don't bother
		 * even trying to send out the request because we
		 * won't be able to block waiting for the response.
		 * Simply assume RPC_INTR and get on with it.
		 */
		if (ttolwp(curthread) != NULL && ISSIG(curthread, JUSTLOOKING))
			status = RPC_INTR;
		else {
			status = CLNT_CALL(client, which, xdrargs, argsp,
			    xdrres, resp, wait);
		}

		if (!(mi->mi_flags & MI_INT))
			client->cl_nosignal = FALSE;
		/*
		 * restore original signal mask
		 */
		sigunintr(&smask);

		switch (status) {
		case RPC_SUCCESS:
			if ((mi->mi_flags & MI_DYNAMIC) &&
			    mi->mi_timer_type[which] != 0 &&
			    (mi->mi_curread != my_rsize ||
			    mi->mi_curwrite != my_wsize))
				(void) nfs_feedback(FEEDBACK_OK, which, mi);
			break;

		case RPC_INTR:
			/*
			 * There is no way to recover from this error,
			 * even if mount option nointr is specified.
			 * SIGKILL, for example, cannot be blocked.
			 */
			rpcerr.re_status = RPC_INTR;
			rpcerr.re_errno = EINTR;
			break;

		case RPC_UDERROR:
			/*
			 * If the NFS server is local (vold) and
			 * it goes away then we get RPC_UDERROR.
			 * This is a retryable error, so we would
			 * loop, so check to see if the specific
			 * error was ECONNRESET, indicating that
			 * target did not exist at all.  If so,
			 * return with RPC_PROGUNAVAIL and
			 * ECONNRESET to indicate why.
			 */
			CLNT_GETERR(client, &rpcerr);
			if (rpcerr.re_errno == ECONNRESET) {
				rpcerr.re_status = RPC_PROGUNAVAIL;
				rpcerr.re_errno = ECONNRESET;
				break;
			}
			/*FALLTHROUGH*/

		default:		/* probably RPC_TIMEDOUT */
			if (IS_UNRECOVERABLE_RPC(status))
				break;

			/*
			 * increment server not responding count
			 */
			mutex_enter(&mi->mi_lock);
			mi->mi_noresponse++;
			mutex_exit(&mi->mi_lock);
#ifdef DEBUG
			nfscl->nfscl_stat.noresponse.value.ui64++;
#endif

			if (!(mi->mi_flags & MI_HARD)) {
				if (!(mi->mi_flags & MI_SEMISOFT) ||
				    (mi->mi_ss_call_type[which] == 0))
					break;
			}

			/*
			 * The call is in progress (over COTS).
			 * Try the CLNT_CALL again, but don't
			 * print a noisy error message.
			 */
			if (status == RPC_INPROGRESS) {
				tryagain = TRUE;
				break;
			}

			if (flags & RFSCALL_SOFT)
				break;

			/*
			 * On zone shutdown, just move on.
			 */
			if (zone_status_get(curproc->p_zone) >=
			    ZONE_IS_SHUTTING_DOWN) {
				rpcerr.re_status = RPC_FAILED;
				rpcerr.re_errno = EIO;
				break;
			}

			/*
			 * NFS client failover support
			 *
			 * If the current server just failed us, we'll
			 * start the process of finding a new server.
			 * After that, we can just retry.
			 */
			if (FAILOVER_MOUNT(mi) && failover_safe(fi)) {
				if (svp == mi->mi_curr_serv)
					failover_newserver(mi);
				clfree_impl(client, ch, nfscl);
				goto failoverretry;
			}

			tryagain = TRUE;
			timeo = backoff(timeo);

			CLNT_GETERR(client, &rpcerr_tmp);
			if ((status == RPC_CANTSEND) &&
			    (rpcerr_tmp.re_errno == ENOBUFS))
				msg = SRV_QFULL_MSG;
			else
				msg = SRV_NOTRESP_MSG;

			mutex_enter(&mi->mi_lock);
			if (!(mi->mi_flags & MI_PRINTED)) {
				mi->mi_flags |= MI_PRINTED;
				mutex_exit(&mi->mi_lock);
#ifdef DEBUG
				zprintf(zoneid, msg, mi->mi_vers,
				    svp->sv_hostname);
#else
				zprintf(zoneid, msg, svp->sv_hostname);
#endif
			} else
				mutex_exit(&mi->mi_lock);
			if (*douprintf && nfs_has_ctty()) {
				*douprintf = 0;
				if (!(mi->mi_flags & MI_NOPRINT))
#ifdef DEBUG
					uprintf(msg, mi->mi_vers,
					    svp->sv_hostname);
#else
					uprintf(msg, svp->sv_hostname);
#endif
			}

			/*
			 * If doing dynamic adjustment of transfer
			 * size and if it's a read or write call
			 * and if the transfer size changed while
			 * retransmitting or if the feedback routine
			 * changed the transfer size,
			 * then exit rfscall so that the transfer
			 * size can be adjusted at the vnops level.
			 */
			if ((mi->mi_flags & MI_DYNAMIC) &&
			    mi->mi_timer_type[which] != 0 &&
			    (mi->mi_curread != my_rsize ||
			    mi->mi_curwrite != my_wsize ||
			    nfs_feedback(FEEDBACK_REXMIT1, which, mi))) {
				/*
				 * On read or write calls, return
				 * back to the vnode ops level if
				 * the transfer size changed.
				 */
				clfree_impl(client, ch, nfscl);
				if (cred_cloned)
					crfree(cr);
				return (ENFS_TRYAGAIN);
			}
		}
	} while (tryagain);

	if (status != RPC_SUCCESS) {
		/*
		 * Let soft mounts use the timed out message.
		 */
		if (status == RPC_INPROGRESS)
			status = RPC_TIMEDOUT;
		nfscl->nfscl_stat.badcalls.value.ui64++;
		if (status != RPC_INTR) {
			mutex_enter(&mi->mi_lock);
			mi->mi_flags |= MI_DOWN;
			mutex_exit(&mi->mi_lock);
			CLNT_GETERR(client, &rpcerr);
#ifdef DEBUG
			bufp = clnt_sperror(client, svp->sv_hostname);
			zprintf(zoneid, "NFS%d %s failed for %s\n",
			    mi->mi_vers, mi->mi_rfsnames[which], bufp);
			if (nfs_has_ctty()) {
				if (!(mi->mi_flags & MI_NOPRINT)) {
					uprintf("NFS%d %s failed for %s\n",
					    mi->mi_vers, mi->mi_rfsnames[which],
					    bufp);
				}
			}
			kmem_free(bufp, MAXPATHLEN);
#else
			zprintf(zoneid,
			    "NFS %s failed for server %s: error %d (%s)\n",
			    mi->mi_rfsnames[which], svp->sv_hostname,
			    status, clnt_sperrno(status));
			if (nfs_has_ctty()) {
				if (!(mi->mi_flags & MI_NOPRINT)) {
					uprintf(
				"NFS %s failed for server %s: error %d (%s)\n",
					    mi->mi_rfsnames[which],
					    svp->sv_hostname, status,
					    clnt_sperrno(status));
				}
			}
#endif
			/*
			 * when CLNT_CALL() fails with RPC_AUTHERROR,
			 * re_errno is set appropriately depending on
			 * the authentication error
			 */
			if (status == RPC_VERSMISMATCH ||
			    status == RPC_PROGVERSMISMATCH)
				rpcerr.re_errno = EIO;
		}
	} else {
		/*
		 * Test the value of mi_down and mi_printed without
		 * holding the mi_lock mutex.  If they are both zero,
		 * then it is okay to skip the down and printed
		 * processing.  This saves on a mutex_enter and
		 * mutex_exit pair for a normal, successful RPC.
		 * This was just complete overhead.
		 */
		if (mi->mi_flags & (MI_DOWN | MI_PRINTED)) {
			mutex_enter(&mi->mi_lock);
			mi->mi_flags &= ~MI_DOWN;
			if (mi->mi_flags & MI_PRINTED) {
				mi->mi_flags &= ~MI_PRINTED;
				mutex_exit(&mi->mi_lock);
#ifdef DEBUG
			if (!(mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED))
				zprintf(zoneid, "NFS%d server %s ok\n",
				    mi->mi_vers, svp->sv_hostname);
#else
			if (!(mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED))
				zprintf(zoneid, "NFS server %s ok\n",
				    svp->sv_hostname);
#endif
			} else
				mutex_exit(&mi->mi_lock);
		}

		if (*douprintf == 0) {
			if (!(mi->mi_flags & MI_NOPRINT))
#ifdef DEBUG
				if (!(mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED))
					uprintf("NFS%d server %s ok\n",
					    mi->mi_vers, svp->sv_hostname);
#else
			if (!(mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED))
				uprintf("NFS server %s ok\n", svp->sv_hostname);
#endif
			*douprintf = 1;
		}
	}

	clfree_impl(client, ch, nfscl);
	if (cred_cloned)
		crfree(cr);

	ASSERT(rpcerr.re_status == RPC_SUCCESS || rpcerr.re_errno != 0);

	if (rpc_status != NULL)
		*rpc_status = rpcerr.re_status;

	TRACE_1(TR_FAC_NFS, TR_RFSCALL_END, "rfscall_end:errno %d",
	    rpcerr.re_errno);

	return (rpcerr.re_errno);
}

#ifdef DEBUG
static int acl2call_hits = 0;
static int acl2call_misses = 0;
#endif

int
acl2call(mntinfo_t *mi, rpcproc_t which, xdrproc_t xdrargs, caddr_t argsp,
    xdrproc_t xdrres, caddr_t resp, cred_t *cr, int *douprintf,
    enum nfsstat *statusp, int flags, failinfo_t *fi)
{
	int rpcerror;

	rpcerror = aclcall(mi, which, xdrargs, argsp, xdrres, resp,
	    cr, douprintf, flags, fi);
	if (!rpcerror) {
		/*
		 * See comments with crnetadjust().
		 */
		if (*statusp == NFSERR_ACCES &&
		    (cr = crnetadjust(cr)) != NULL) {
#ifdef DEBUG
			acl2call_hits++;
#endif
			rpcerror = aclcall(mi, which, xdrargs, argsp, xdrres,
			    resp, cr, douprintf, flags, fi);
			crfree(cr);
#ifdef DEBUG
			if (*statusp == NFSERR_ACCES)
				acl2call_misses++;
#endif
		}
	}

	return (rpcerror);
}

#ifdef DEBUG
static int acl3call_hits = 0;
static int acl3call_misses = 0;
#endif

int
acl3call(mntinfo_t *mi, rpcproc_t which, xdrproc_t xdrargs, caddr_t argsp,
    xdrproc_t xdrres, caddr_t resp, cred_t *cr, int *douprintf,
    nfsstat3 *statusp, int flags, failinfo_t *fi)
{
	int rpcerror;
	int user_informed;

	user_informed = 0;

	do {
		rpcerror = aclcall(mi, which, xdrargs, argsp, xdrres, resp,
		    cr, douprintf, flags, fi);
		if (!rpcerror) {
			cred_t *crr;
			if (*statusp == NFS3ERR_JUKEBOX) {
				if (!user_informed) {
					user_informed = 1;
					uprintf(
		"file temporarily unavailable on the server, retrying...\n");
				}
				delay(nfs3_jukebox_delay);
			}
			/*
			 * See crnetadjust() for comments.
			 */
			else if (*statusp == NFS3ERR_ACCES &&
			    (crr = crnetadjust(cr)) != NULL) {
#ifdef DEBUG
				acl3call_hits++;
#endif
				rpcerror = aclcall(mi, which, xdrargs, argsp,
				    xdrres, resp, crr, douprintf, flags, fi);

				crfree(crr);
#ifdef DEBUG
				if (*statusp == NFS3ERR_ACCES)
					acl3call_misses++;
#endif
			}
		}
	} while (!rpcerror && *statusp == NFS3ERR_JUKEBOX);

	return (rpcerror);
}

static int
aclcall(mntinfo_t *mi, rpcproc_t which, xdrproc_t xdrargs, caddr_t argsp,
    xdrproc_t xdrres, caddr_t resp, cred_t *icr, int *douprintf,
    int flags, failinfo_t *fi)
{
	CLIENT *client;
	struct chtab *ch;
	cred_t *cr = icr;
	bool_t cred_cloned = FALSE;
	enum clnt_stat status;
	struct rpc_err rpcerr;
	struct timeval wait;
	int timeo;		/* in units of hz */
#if 0 /* notyet */
	int my_rsize, my_wsize;
#endif
	bool_t tryagain;
	k_sigset_t smask;
	servinfo_t *svp;
	struct nfs_clnt *nfscl;
	zoneid_t zoneid = getzoneid();
#ifdef DEBUG
	char *bufp;
#endif

#if 0 /* notyet */
	TRACE_2(TR_FAC_NFS, TR_RFSCALL_START,
	    "rfscall_start:which %d mi %p", which, mi);
#endif

	nfscl = zone_getspecific(nfsclnt_zone_key, nfs_zone());
	ASSERT(nfscl != NULL);

	nfscl->nfscl_stat.calls.value.ui64++;
	mi->mi_aclreqs[which].value.ui64++;

	rpcerr.re_status = RPC_SUCCESS;

	if (FS_OR_ZONE_GONE(mi->mi_vfsp)) {
		rpcerr.re_status = RPC_FAILED;
		rpcerr.re_errno = EIO;
		return (rpcerr.re_errno);
	}

#if 0 /* notyet */
	/*
	 * Remember the transfer sizes in case
	 * nfs_feedback changes them underneath us.
	 */
	my_rsize = mi->mi_curread;
	my_wsize = mi->mi_curwrite;
#endif

	/*
	 * NFS client failover support
	 *
	 * If this rnode is not in sync with the current server (VALID_FH),
	 * we'd like to do a remap to get in sync.  We can be interrupted
	 * in failover_remap(), and if so we'll bail.  Otherwise, we'll
	 * use the best info we have to try the RPC.  Part of that is
	 * unconditionally updating the filehandle copy kept for V3.
	 *
	 * Locking: INC_READERS/DEC_READERS is a poor man's interrruptible
	 * rw_enter(); we're trying to keep the current server from being
	 * changed on us until we're done with the remapping and have a
	 * matching client handle.  We don't want to sending a filehandle
	 * to the wrong host.
	 */
failoverretry:
	if (FAILOVER_MOUNT(mi)) {
		mutex_enter(&mi->mi_lock);
		if (!(flags & RFSCALL_SOFT) && failover_safe(fi)) {
			if (failover_wait(mi)) {
				mutex_exit(&mi->mi_lock);
				return (EINTR);
			}
		}
		INC_READERS(mi);
		mutex_exit(&mi->mi_lock);
		if (fi) {
			if (!VALID_FH(fi) &&
			    !(flags & RFSCALL_SOFT) && failover_safe(fi)) {
				int remaperr;

				svp = mi->mi_curr_serv;
				remaperr = failover_remap(fi);
				if (remaperr != 0) {
#ifdef DEBUG
					if (remaperr != EINTR)
						nfs_cmn_err(remaperr, CE_WARN,
					    "aclcall couldn't failover: %m");
#endif
					mutex_enter(&mi->mi_lock);
					DEC_READERS(mi);
					mutex_exit(&mi->mi_lock);

					/*
					 * If failover_remap returns ETIMEDOUT
					 * and the filesystem is hard mounted
					 * we have to retry the call with a new
					 * server.
					 */
					if ((mi->mi_flags & MI_HARD) &&
					    IS_RECOVERABLE_ERROR(remaperr)) {
						if (svp == mi->mi_curr_serv)
							failover_newserver(mi);
						rpcerr.re_status = RPC_SUCCESS;
						goto failoverretry;
					}
					return (remaperr);
				}
			}
			if (fi->fhp && fi->copyproc)
				(*fi->copyproc)(fi->fhp, fi->vp);
		}
	}

	/* For TSOL, use a new cred which has net_mac_aware flag */
	if (!cred_cloned && is_system_labeled()) {
		cred_cloned = TRUE;
		cr = crdup(icr);
		(void) setpflags(NET_MAC_AWARE, 1, cr);
	}

	/*
	 * acl_clget() calls clnt_tli_kinit() which clears the xid, so we
	 * are guaranteed to reprocess the retry as a new request.
	 */
	svp = mi->mi_curr_serv;
	rpcerr.re_errno = acl_clget(mi, svp, cr, &client, &ch, nfscl);
	if (FAILOVER_MOUNT(mi)) {
		mutex_enter(&mi->mi_lock);
		DEC_READERS(mi);
		mutex_exit(&mi->mi_lock);

		if ((rpcerr.re_errno == ETIMEDOUT ||
		    rpcerr.re_errno == ECONNRESET) &&
		    failover_safe(fi)) {
			if (svp == mi->mi_curr_serv)
				failover_newserver(mi);
			goto failoverretry;
		}
	}
	if (rpcerr.re_errno != 0) {
		if (cred_cloned)
			crfree(cr);
		return (rpcerr.re_errno);
	}

	if (svp->sv_knconf->knc_semantics == NC_TPI_COTS_ORD ||
	    svp->sv_knconf->knc_semantics == NC_TPI_COTS) {
		timeo = (mi->mi_timeo * hz) / 10;
	} else {
		mutex_enter(&mi->mi_lock);
		timeo = CLNT_SETTIMERS(client,
		    &(mi->mi_timers[mi->mi_acl_timer_type[which]]),
		    &(mi->mi_timers[NFS_CALLTYPES]),
		    (minimum_timeo[mi->mi_acl_call_type[which]]*hz)>>3,
		    (void (*)()) 0, (caddr_t)mi, 0);
		mutex_exit(&mi->mi_lock);
	}

	/*
	 * If hard mounted fs, retry call forever unless hard error occurs.
	 */
	do {
		tryagain = FALSE;

		if (FS_OR_ZONE_GONE(mi->mi_vfsp)) {
			status = RPC_FAILED;
			rpcerr.re_status = RPC_FAILED;
			rpcerr.re_errno = EIO;
			break;
		}

		TICK_TO_TIMEVAL(timeo, &wait);

		/*
		 * Mask out all signals except SIGHUP, SIGINT, SIGQUIT
		 * and SIGTERM. (Preserving the existing masks).
		 * Mask out SIGINT if mount option nointr is specified.
		 */
		sigintr(&smask, (int)mi->mi_flags & MI_INT);
		if (!(mi->mi_flags & MI_INT))
			client->cl_nosignal = TRUE;

		/*
		 * If there is a current signal, then don't bother
		 * even trying to send out the request because we
		 * won't be able to block waiting for the response.
		 * Simply assume RPC_INTR and get on with it.
		 */
		if (ttolwp(curthread) != NULL && ISSIG(curthread, JUSTLOOKING))
			status = RPC_INTR;
		else {
			status = CLNT_CALL(client, which, xdrargs, argsp,
			    xdrres, resp, wait);
		}

		if (!(mi->mi_flags & MI_INT))
			client->cl_nosignal = FALSE;
		/*
		 * restore original signal mask
		 */
		sigunintr(&smask);

		switch (status) {
		case RPC_SUCCESS:
#if 0 /* notyet */
			if ((mi->mi_flags & MI_DYNAMIC) &&
			    mi->mi_timer_type[which] != 0 &&
			    (mi->mi_curread != my_rsize ||
			    mi->mi_curwrite != my_wsize))
				(void) nfs_feedback(FEEDBACK_OK, which, mi);
#endif
			break;

		/*
		 * Unfortunately, there are servers in the world which
		 * are not coded correctly.  They are not prepared to
		 * handle RPC requests to the NFS port which are not
		 * NFS requests.  Thus, they may try to process the
		 * NFS_ACL request as if it were an NFS request.  This
		 * does not work.  Generally, an error will be generated
		 * on the client because it will not be able to decode
		 * the response from the server.  However, it seems
		 * possible that the server may not be able to decode
		 * the arguments.  Thus, the criteria for deciding
		 * whether the server supports NFS_ACL or not is whether
		 * the following RPC errors are returned from CLNT_CALL.
		 */
		case RPC_CANTDECODERES:
		case RPC_PROGUNAVAIL:
		case RPC_CANTDECODEARGS:
		case RPC_PROGVERSMISMATCH:
			mutex_enter(&mi->mi_lock);
			mi->mi_flags &= ~(MI_ACL | MI_EXTATTR);
			mutex_exit(&mi->mi_lock);
			break;

		/*
		 * If the server supports NFS_ACL but not the new ops
		 * for extended attributes, make sure we don't retry.
		 */
		case RPC_PROCUNAVAIL:
			mutex_enter(&mi->mi_lock);
			mi->mi_flags &= ~MI_EXTATTR;
			mutex_exit(&mi->mi_lock);
			break;

		case RPC_INTR:
			/*
			 * There is no way to recover from this error,
			 * even if mount option nointr is specified.
			 * SIGKILL, for example, cannot be blocked.
			 */
			rpcerr.re_status = RPC_INTR;
			rpcerr.re_errno = EINTR;
			break;

		case RPC_UDERROR:
			/*
			 * If the NFS server is local (vold) and
			 * it goes away then we get RPC_UDERROR.
			 * This is a retryable error, so we would
			 * loop, so check to see if the specific
			 * error was ECONNRESET, indicating that
			 * target did not exist at all.  If so,
			 * return with RPC_PROGUNAVAIL and
			 * ECONNRESET to indicate why.
			 */
			CLNT_GETERR(client, &rpcerr);
			if (rpcerr.re_errno == ECONNRESET) {
				rpcerr.re_status = RPC_PROGUNAVAIL;
				rpcerr.re_errno = ECONNRESET;
				break;
			}
			/*FALLTHROUGH*/

		default:		/* probably RPC_TIMEDOUT */
			if (IS_UNRECOVERABLE_RPC(status))
				break;

			/*
			 * increment server not responding count
			 */
			mutex_enter(&mi->mi_lock);
			mi->mi_noresponse++;
			mutex_exit(&mi->mi_lock);
#ifdef DEBUG
			nfscl->nfscl_stat.noresponse.value.ui64++;
#endif

			if (!(mi->mi_flags & MI_HARD)) {
				if (!(mi->mi_flags & MI_SEMISOFT) ||
				    (mi->mi_acl_ss_call_type[which] == 0))
					break;
			}

			/*
			 * The call is in progress (over COTS).
			 * Try the CLNT_CALL again, but don't
			 * print a noisy error message.
			 */
			if (status == RPC_INPROGRESS) {
				tryagain = TRUE;
				break;
			}

			if (flags & RFSCALL_SOFT)
				break;

			/*
			 * On zone shutdown, just move on.
			 */
			if (zone_status_get(curproc->p_zone) >=
			    ZONE_IS_SHUTTING_DOWN) {
				rpcerr.re_status = RPC_FAILED;
				rpcerr.re_errno = EIO;
				break;
			}

			/*
			 * NFS client failover support
			 *
			 * If the current server just failed us, we'll
			 * start the process of finding a new server.
			 * After that, we can just retry.
			 */
			if (FAILOVER_MOUNT(mi) && failover_safe(fi)) {
				if (svp == mi->mi_curr_serv)
					failover_newserver(mi);
				clfree_impl(client, ch, nfscl);
				goto failoverretry;
			}

			tryagain = TRUE;
			timeo = backoff(timeo);
			mutex_enter(&mi->mi_lock);
			if (!(mi->mi_flags & MI_PRINTED)) {
				mi->mi_flags |= MI_PRINTED;
				mutex_exit(&mi->mi_lock);
#ifdef DEBUG
				zprintf(zoneid,
			"NFS_ACL%d server %s not responding still trying\n",
				    mi->mi_vers, svp->sv_hostname);
#else
				zprintf(zoneid,
			    "NFS server %s not responding still trying\n",
				    svp->sv_hostname);
#endif
			} else
				mutex_exit(&mi->mi_lock);
			if (*douprintf && nfs_has_ctty()) {
				*douprintf = 0;
				if (!(mi->mi_flags & MI_NOPRINT))
#ifdef DEBUG
					uprintf(
			"NFS_ACL%d server %s not responding still trying\n",
					    mi->mi_vers, svp->sv_hostname);
#else
					uprintf(
			    "NFS server %s not responding still trying\n",
					    svp->sv_hostname);
#endif
			}

#if 0 /* notyet */
			/*
			 * If doing dynamic adjustment of transfer
			 * size and if it's a read or write call
			 * and if the transfer size changed while
			 * retransmitting or if the feedback routine
			 * changed the transfer size,
			 * then exit rfscall so that the transfer
			 * size can be adjusted at the vnops level.
			 */
			if ((mi->mi_flags & MI_DYNAMIC) &&
			    mi->mi_acl_timer_type[which] != 0 &&
			    (mi->mi_curread != my_rsize ||
			    mi->mi_curwrite != my_wsize ||
			    nfs_feedback(FEEDBACK_REXMIT1, which, mi))) {
				/*
				 * On read or write calls, return
				 * back to the vnode ops level if
				 * the transfer size changed.
				 */
				clfree_impl(client, ch, nfscl);
				if (cred_cloned)
					crfree(cr);
				return (ENFS_TRYAGAIN);
			}
#endif
		}
	} while (tryagain);

	if (status != RPC_SUCCESS) {
		/*
		 * Let soft mounts use the timed out message.
		 */
		if (status == RPC_INPROGRESS)
			status = RPC_TIMEDOUT;
		nfscl->nfscl_stat.badcalls.value.ui64++;
		if (status == RPC_CANTDECODERES ||
		    status == RPC_PROGUNAVAIL ||
		    status == RPC_PROCUNAVAIL ||
		    status == RPC_CANTDECODEARGS ||
		    status == RPC_PROGVERSMISMATCH)
			CLNT_GETERR(client, &rpcerr);
		else if (status != RPC_INTR) {
			mutex_enter(&mi->mi_lock);
			mi->mi_flags |= MI_DOWN;
			mutex_exit(&mi->mi_lock);
			CLNT_GETERR(client, &rpcerr);
#ifdef DEBUG
			bufp = clnt_sperror(client, svp->sv_hostname);
			zprintf(zoneid, "NFS_ACL%d %s failed for %s\n",
			    mi->mi_vers, mi->mi_aclnames[which], bufp);
			if (nfs_has_ctty()) {
				if (!(mi->mi_flags & MI_NOPRINT)) {
					uprintf("NFS_ACL%d %s failed for %s\n",
					    mi->mi_vers, mi->mi_aclnames[which],
					    bufp);
				}
			}
			kmem_free(bufp, MAXPATHLEN);
#else
			zprintf(zoneid,
			    "NFS %s failed for server %s: error %d (%s)\n",
			    mi->mi_aclnames[which], svp->sv_hostname,
			    status, clnt_sperrno(status));
			if (nfs_has_ctty()) {
				if (!(mi->mi_flags & MI_NOPRINT))
					uprintf(
				"NFS %s failed for server %s: error %d (%s)\n",
					    mi->mi_aclnames[which],
					    svp->sv_hostname, status,
					    clnt_sperrno(status));
			}
#endif
			/*
			 * when CLNT_CALL() fails with RPC_AUTHERROR,
			 * re_errno is set appropriately depending on
			 * the authentication error
			 */
			if (status == RPC_VERSMISMATCH ||
			    status == RPC_PROGVERSMISMATCH)
				rpcerr.re_errno = EIO;
		}
	} else {
		/*
		 * Test the value of mi_down and mi_printed without
		 * holding the mi_lock mutex.  If they are both zero,
		 * then it is okay to skip the down and printed
		 * processing.  This saves on a mutex_enter and
		 * mutex_exit pair for a normal, successful RPC.
		 * This was just complete overhead.
		 */
		if (mi->mi_flags & (MI_DOWN | MI_PRINTED)) {
			mutex_enter(&mi->mi_lock);
			mi->mi_flags &= ~MI_DOWN;
			if (mi->mi_flags & MI_PRINTED) {
				mi->mi_flags &= ~MI_PRINTED;
				mutex_exit(&mi->mi_lock);
#ifdef DEBUG
				zprintf(zoneid, "NFS_ACL%d server %s ok\n",
				    mi->mi_vers, svp->sv_hostname);
#else
				zprintf(zoneid, "NFS server %s ok\n",
				    svp->sv_hostname);
#endif
			} else
				mutex_exit(&mi->mi_lock);
		}

		if (*douprintf == 0) {
			if (!(mi->mi_flags & MI_NOPRINT))
#ifdef DEBUG
				uprintf("NFS_ACL%d server %s ok\n",
				    mi->mi_vers, svp->sv_hostname);
#else
				uprintf("NFS server %s ok\n", svp->sv_hostname);
#endif
			*douprintf = 1;
		}
	}

	clfree_impl(client, ch, nfscl);
	if (cred_cloned)
		crfree(cr);

	ASSERT(rpcerr.re_status == RPC_SUCCESS || rpcerr.re_errno != 0);

#if 0 /* notyet */
	TRACE_1(TR_FAC_NFS, TR_RFSCALL_END, "rfscall_end:errno %d",
	    rpcerr.re_errno);
#endif

	return (rpcerr.re_errno);
}

int
vattr_to_sattr(struct vattr *vap, struct nfssattr *sa)
{
	uint_t mask = vap->va_mask;

	if (!(mask & AT_MODE))
		sa->sa_mode = (uint32_t)-1;
	else
		sa->sa_mode = vap->va_mode;
	if (!(mask & AT_UID))
		sa->sa_uid = (uint32_t)-1;
	else
		sa->sa_uid = (uint32_t)vap->va_uid;
	if (!(mask & AT_GID))
		sa->sa_gid = (uint32_t)-1;
	else
		sa->sa_gid = (uint32_t)vap->va_gid;
	if (!(mask & AT_SIZE))
		sa->sa_size = (uint32_t)-1;
	else
		sa->sa_size = (uint32_t)vap->va_size;
	if (!(mask & AT_ATIME))
		sa->sa_atime.tv_sec = sa->sa_atime.tv_usec = (int32_t)-1;
	else {
		/* check time validity */
		if (! NFS_TIME_T_OK(vap->va_atime.tv_sec)) {
			return (EOVERFLOW);
		}
		sa->sa_atime.tv_sec = vap->va_atime.tv_sec;
		sa->sa_atime.tv_usec = vap->va_atime.tv_nsec / 1000;
	}
	if (!(mask & AT_MTIME))
		sa->sa_mtime.tv_sec = sa->sa_mtime.tv_usec = (int32_t)-1;
	else {
		/* check time validity */
		if (! NFS_TIME_T_OK(vap->va_mtime.tv_sec)) {
			return (EOVERFLOW);
		}
		sa->sa_mtime.tv_sec = vap->va_mtime.tv_sec;
		sa->sa_mtime.tv_usec = vap->va_mtime.tv_nsec / 1000;
	}
	return (0);
}

int
vattr_to_sattr3(struct vattr *vap, sattr3 *sa)
{
	uint_t mask = vap->va_mask;

	if (!(mask & AT_MODE))
		sa->mode.set_it = FALSE;
	else {
		sa->mode.set_it = TRUE;
		sa->mode.mode = (mode3)vap->va_mode;
	}
	if (!(mask & AT_UID))
		sa->uid.set_it = FALSE;
	else {
		sa->uid.set_it = TRUE;
		sa->uid.uid = (uid3)vap->va_uid;
	}
	if (!(mask & AT_GID))
		sa->gid.set_it = FALSE;
	else {
		sa->gid.set_it = TRUE;
		sa->gid.gid = (gid3)vap->va_gid;
	}
	if (!(mask & AT_SIZE))
		sa->size.set_it = FALSE;
	else {
		sa->size.set_it = TRUE;
		sa->size.size = (size3)vap->va_size;
	}
	if (!(mask & AT_ATIME))
		sa->atime.set_it = DONT_CHANGE;
	else {
		/* check time validity */
		if (! NFS_TIME_T_OK(vap->va_atime.tv_sec)) {
			return (EOVERFLOW);
		}
		sa->atime.set_it = SET_TO_CLIENT_TIME;
		sa->atime.atime.seconds = (uint32)vap->va_atime.tv_sec;
		sa->atime.atime.nseconds = (uint32)vap->va_atime.tv_nsec;
	}
	if (!(mask & AT_MTIME))
		sa->mtime.set_it = DONT_CHANGE;
	else {
		/* check time validity */
		if (! NFS_TIME_T_OK(vap->va_mtime.tv_sec)) {
			return (EOVERFLOW);
		}
		sa->mtime.set_it = SET_TO_CLIENT_TIME;
		sa->mtime.mtime.seconds = (uint32)vap->va_mtime.tv_sec;
		sa->mtime.mtime.nseconds = (uint32)vap->va_mtime.tv_nsec;
	}
	return (0);
}

void
setdiropargs(struct nfsdiropargs *da, char *nm, vnode_t *dvp)
{

	da->da_fhandle = VTOFH(dvp);
	da->da_name = nm;
	da->da_flags = 0;
}

void
setdiropargs3(diropargs3 *da, char *nm, vnode_t *dvp)
{

	da->dirp = VTOFH3(dvp);
	da->name = nm;
}

int
setdirgid(vnode_t *dvp, gid_t *gidp, cred_t *cr)
{
	int error;
	rnode_t *rp;
	struct vattr va;

	va.va_mask = AT_MODE | AT_GID;
	error = VOP_GETATTR(dvp, &va, 0, cr, NULL);
	if (error)
		return (error);

	/*
	 * To determine the expected group-id of the created file:
	 *  1)	If the filesystem was not mounted with the Old-BSD-compatible
	 *	GRPID option, and the directory's set-gid bit is clear,
	 *	then use the process's gid.
	 *  2)	Otherwise, set the group-id to the gid of the parent directory.
	 */
	rp = VTOR(dvp);
	mutex_enter(&rp->r_statelock);
	if (!(VTOMI(dvp)->mi_flags & MI_GRPID) && !(va.va_mode & VSGID))
		*gidp = crgetgid(cr);
	else
		*gidp = va.va_gid;
	mutex_exit(&rp->r_statelock);
	return (0);
}

int
setdirmode(vnode_t *dvp, mode_t *omp, cred_t *cr)
{
	int error;
	struct vattr va;

	va.va_mask = AT_MODE;
	error = VOP_GETATTR(dvp, &va, 0, cr, NULL);
	if (error)
		return (error);

	/*
	 * Modify the expected mode (om) so that the set-gid bit matches
	 * that of the parent directory (dvp).
	 */
	if (va.va_mode & VSGID)
		*omp |= VSGID;
	else
		*omp &= ~VSGID;
	return (0);
}

void
nfs_setswaplike(vnode_t *vp, vattr_t *vap)
{

	if (vp->v_type == VREG && (vap->va_mode & (VEXEC | VSVTX)) == VSVTX) {
		if (!(vp->v_flag & VSWAPLIKE)) {
			mutex_enter(&vp->v_lock);
			vp->v_flag |= VSWAPLIKE;
			mutex_exit(&vp->v_lock);
		}
	} else {
		if (vp->v_flag & VSWAPLIKE) {
			mutex_enter(&vp->v_lock);
			vp->v_flag &= ~VSWAPLIKE;
			mutex_exit(&vp->v_lock);
		}
	}
}

/*
 * Free the resources associated with an rnode.
 */
static void
rinactive(rnode_t *rp, cred_t *cr)
{
	vnode_t *vp;
	cred_t *cred;
	char *contents;
	int size;
	vsecattr_t *vsp;
	int error;
	nfs3_pathconf_info *info;

	/*
	 * Before freeing anything, wait until all asynchronous
	 * activity is done on this rnode.  This will allow all
	 * asynchronous read ahead and write behind i/o's to
	 * finish.
	 */
	mutex_enter(&rp->r_statelock);
	while (rp->r_count > 0)
		cv_wait(&rp->r_cv, &rp->r_statelock);
	mutex_exit(&rp->r_statelock);

	/*
	 * Flush and invalidate all pages associated with the vnode.
	 */
	vp = RTOV(rp);
	if (vn_has_cached_data(vp)) {
		ASSERT(vp->v_type != VCHR);
		if ((rp->r_flags & RDIRTY) && !rp->r_error) {
			error = VOP_PUTPAGE(vp, (u_offset_t)0, 0, 0, cr, NULL);
			if (error && (error == ENOSPC || error == EDQUOT)) {
				mutex_enter(&rp->r_statelock);
				if (!rp->r_error)
					rp->r_error = error;
				mutex_exit(&rp->r_statelock);
			}
		}
		nfs_invalidate_pages(vp, (u_offset_t)0, cr);
	}

	/*
	 * Free any held credentials and caches which may be associated
	 * with this rnode.
	 */
	mutex_enter(&rp->r_statelock);
	cred = rp->r_cred;
	rp->r_cred = NULL;
	contents = rp->r_symlink.contents;
	size = rp->r_symlink.size;
	rp->r_symlink.contents = NULL;
	vsp = rp->r_secattr;
	rp->r_secattr = NULL;
	info = rp->r_pathconf;
	rp->r_pathconf = NULL;
	mutex_exit(&rp->r_statelock);

	/*
	 * Free the held credential.
	 */
	if (cred != NULL)
		crfree(cred);

	/*
	 * Free the access cache entries.
	 */
	(void) nfs_access_purge_rp(rp);

	/*
	 * Free the readdir cache entries.
	 */
	if (HAVE_RDDIR_CACHE(rp))
		nfs_purge_rddir_cache(vp);

	/*
	 * Free the symbolic link cache.
	 */
	if (contents != NULL) {

		kmem_free((void *)contents, size);
	}

	/*
	 * Free any cached ACL.
	 */
	if (vsp != NULL)
		nfs_acl_free(vsp);

	/*
	 * Free any cached pathconf information.
	 */
	if (info != NULL)
		kmem_free(info, sizeof (*info));
}

/*
 * Return a vnode for the given NFS Version 2 file handle.
 * If no rnode exists for this fhandle, create one and put it
 * into the hash queues.  If the rnode for this fhandle
 * already exists, return it.
 *
 * Note: make_rnode() may upgrade the hash bucket lock to exclusive.
 */
vnode_t *
makenfsnode(fhandle_t *fh, struct nfsfattr *attr, struct vfs *vfsp,
    hrtime_t t, cred_t *cr, char *dnm, char *nm)
{
	int newnode;
	int index;
	vnode_t *vp;
	nfs_fhandle nfh;
	vattr_t va;

	nfh.fh_len = NFS_FHSIZE;
	bcopy(fh, nfh.fh_buf, NFS_FHSIZE);

	index = rtablehash(&nfh);
	rw_enter(&rtable[index].r_lock, RW_READER);

	vp = make_rnode(&nfh, &rtable[index], vfsp, nfs_vnodeops,
	    nfs_putapage, nfs_rddir_compar, &newnode, cr, dnm, nm);

	if (attr != NULL) {
		if (!newnode) {
			rw_exit(&rtable[index].r_lock);
			(void) nfs_cache_fattr(vp, attr, &va, t, cr);
		} else {
			if (attr->na_type < NFNON || attr->na_type > NFSOC)
				vp->v_type = VBAD;
			else
				vp->v_type = n2v_type(attr);
			/*
			 * A translation here seems to be necessary
			 * because this function can be called
			 * with `attr' that has come from the wire,
			 * and been operated on by vattr_to_nattr().
			 * See nfsrootvp()->VOP_GETTATTR()->nfsgetattr()
			 * ->nfs_getattr_otw()->rfscall()->vattr_to_nattr()
			 * ->makenfsnode().
			 */
			if ((attr->na_rdev & 0xffff0000) == 0)
				vp->v_rdev = nfsv2_expdev(attr->na_rdev);
			else
				vp->v_rdev = expldev(n2v_rdev(attr));
			nfs_attrcache(vp, attr, t);
			rw_exit(&rtable[index].r_lock);
		}
	} else {
		if (newnode) {
			PURGE_ATTRCACHE(vp);
		}
		rw_exit(&rtable[index].r_lock);
	}

	return (vp);
}

/*
 * Return a vnode for the given NFS Version 3 file handle.
 * If no rnode exists for this fhandle, create one and put it
 * into the hash queues.  If the rnode for this fhandle
 * already exists, return it.
 *
 * Note: make_rnode() may upgrade the hash bucket lock to exclusive.
 */
vnode_t *
makenfs3node_va(nfs_fh3 *fh, vattr_t *vap, struct vfs *vfsp, hrtime_t t,
    cred_t *cr, char *dnm, char *nm)
{
	int newnode;
	int index;
	vnode_t *vp;

	index = rtablehash((nfs_fhandle *)fh);
	rw_enter(&rtable[index].r_lock, RW_READER);

	vp = make_rnode((nfs_fhandle *)fh, &rtable[index], vfsp,
	    nfs3_vnodeops, nfs3_putapage, nfs3_rddir_compar, &newnode, cr,
	    dnm, nm);

	if (vap == NULL) {
		if (newnode) {
			PURGE_ATTRCACHE(vp);
		}
		rw_exit(&rtable[index].r_lock);
		return (vp);
	}

	if (!newnode) {
		rw_exit(&rtable[index].r_lock);
		nfs_attr_cache(vp, vap, t, cr);
	} else {
		rnode_t *rp = VTOR(vp);

		vp->v_type = vap->va_type;
		vp->v_rdev = vap->va_rdev;

		mutex_enter(&rp->r_statelock);
		if (rp->r_mtime <= t)
			nfs_attrcache_va(vp, vap);
		mutex_exit(&rp->r_statelock);
		rw_exit(&rtable[index].r_lock);
	}

	return (vp);
}

vnode_t *
makenfs3node(nfs_fh3 *fh, fattr3 *attr, struct vfs *vfsp, hrtime_t t,
    cred_t *cr, char *dnm, char *nm)
{
	int newnode;
	int index;
	vnode_t *vp;
	vattr_t va;

	index = rtablehash((nfs_fhandle *)fh);
	rw_enter(&rtable[index].r_lock, RW_READER);

	vp = make_rnode((nfs_fhandle *)fh, &rtable[index], vfsp,
	    nfs3_vnodeops, nfs3_putapage, nfs3_rddir_compar, &newnode, cr,
	    dnm, nm);

	if (attr == NULL) {
		if (newnode) {
			PURGE_ATTRCACHE(vp);
		}
		rw_exit(&rtable[index].r_lock);
		return (vp);
	}

	if (!newnode) {
		rw_exit(&rtable[index].r_lock);
		(void) nfs3_cache_fattr3(vp, attr, &va, t, cr);
	} else {
		if (attr->type < NF3REG || attr->type > NF3FIFO)
			vp->v_type = VBAD;
		else
			vp->v_type = nf3_to_vt[attr->type];
		vp->v_rdev = makedevice(attr->rdev.specdata1,
		    attr->rdev.specdata2);
		nfs3_attrcache(vp, attr, t);
		rw_exit(&rtable[index].r_lock);
	}

	return (vp);
}

/*
 * Read this comment before making changes to rtablehash()!
 * This is a hash function in which seemingly obvious and harmless
 * changes can cause escalations costing million dollars!
 * Know what you are doing.
 *
 * rtablehash() implements Jenkins' one-at-a-time hash algorithm.  The
 * algorithm is currently detailed here:
 *
 *   http://burtleburtle.net/bob/hash/doobs.html
 *
 * Of course, the above link may not be valid by the time you are reading
 * this, but suffice it to say that the one-at-a-time algorithm works well in
 * almost all cases.  If you are changing the algorithm be sure to verify that
 * the hash algorithm still provides even distribution in all cases and with
 * any server returning filehandles in whatever order (sequential or random).
 */
static int
rtablehash(nfs_fhandle *fh)
{
	ulong_t hash, len, i;
	char *key;

	key = fh->fh_buf;
	len = (ulong_t)fh->fh_len;
	for (hash = 0, i = 0; i < len; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return (hash & rtablemask);
}

static vnode_t *
make_rnode(nfs_fhandle *fh, rhashq_t *rhtp, struct vfs *vfsp,
    struct vnodeops *vops,
    int (*putapage)(vnode_t *, page_t *, u_offset_t *, size_t *, int, cred_t *),
    int (*compar)(const void *, const void *),
    int *newnode, cred_t *cr, char *dnm, char *nm)
{
	rnode_t *rp;
	rnode_t *trp;
	vnode_t *vp;
	mntinfo_t *mi;

	ASSERT(RW_READ_HELD(&rhtp->r_lock));

	mi = VFTOMI(vfsp);
start:
	if ((rp = rfind(rhtp, fh, vfsp)) != NULL) {
		vp = RTOV(rp);
		nfs_set_vroot(vp);
		*newnode = 0;
		return (vp);
	}
	rw_exit(&rhtp->r_lock);

	mutex_enter(&rpfreelist_lock);
	if (rpfreelist != NULL && rnew >= nrnode) {
		rp = rpfreelist;
		rp_rmfree(rp);
		mutex_exit(&rpfreelist_lock);

		vp = RTOV(rp);

		if (rp->r_flags & RHASHED) {
			rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				VN_RELE_LOCKED(vp);
				mutex_exit(&vp->v_lock);
				rw_exit(&rp->r_hashq->r_lock);
				rw_enter(&rhtp->r_lock, RW_READER);
				goto start;
			}
			mutex_exit(&vp->v_lock);
			rp_rmhash_locked(rp);
			rw_exit(&rp->r_hashq->r_lock);
		}

		rinactive(rp, cr);

		mutex_enter(&vp->v_lock);
		if (vp->v_count > 1) {
			VN_RELE_LOCKED(vp);
			mutex_exit(&vp->v_lock);
			rw_enter(&rhtp->r_lock, RW_READER);
			goto start;
		}
		mutex_exit(&vp->v_lock);
		vn_invalid(vp);
		/*
		 * destroy old locks before bzero'ing and
		 * recreating the locks below.
		 */
		nfs_rw_destroy(&rp->r_rwlock);
		nfs_rw_destroy(&rp->r_lkserlock);
		mutex_destroy(&rp->r_statelock);
		cv_destroy(&rp->r_cv);
		cv_destroy(&rp->r_commit.c_cv);
		nfs_free_r_path(rp);
		avl_destroy(&rp->r_dir);
		/*
		 * Make sure that if rnode is recycled then
		 * VFS count is decremented properly before
		 * reuse.
		 */
		VFS_RELE(vp->v_vfsp);
		vn_reinit(vp);
	} else {
		vnode_t *new_vp;

		mutex_exit(&rpfreelist_lock);

		rp = kmem_cache_alloc(rnode_cache, KM_SLEEP);
		new_vp = vn_alloc(KM_SLEEP);

		atomic_inc_ulong((ulong_t *)&rnew);
#ifdef DEBUG
		clstat_debug.nrnode.value.ui64++;
#endif
		vp = new_vp;
	}

	bzero(rp, sizeof (*rp));
	rp->r_vnode = vp;
	nfs_rw_init(&rp->r_rwlock, NULL, RW_DEFAULT, NULL);
	nfs_rw_init(&rp->r_lkserlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&rp->r_statelock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rp->r_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&rp->r_commit.c_cv, NULL, CV_DEFAULT, NULL);
	rp->r_fh.fh_len = fh->fh_len;
	bcopy(fh->fh_buf, rp->r_fh.fh_buf, fh->fh_len);
	rp->r_server = mi->mi_curr_serv;
	if (FAILOVER_MOUNT(mi)) {
		/*
		 * If replicated servers, stash pathnames
		 */
		if (dnm != NULL && nm != NULL) {
			char *s, *p;
			uint_t len;

			len = (uint_t)(strlen(dnm) + strlen(nm) + 2);
			rp->r_path = kmem_alloc(len, KM_SLEEP);
#ifdef DEBUG
			clstat_debug.rpath.value.ui64 += len;
#endif
			s = rp->r_path;
			for (p = dnm; *p; p++)
				*s++ = *p;
			*s++ = '/';
			for (p = nm; *p; p++)
				*s++ = *p;
			*s = '\0';
		} else {
			/* special case for root */
			rp->r_path = kmem_alloc(2, KM_SLEEP);
#ifdef DEBUG
			clstat_debug.rpath.value.ui64 += 2;
#endif
			*rp->r_path = '.';
			*(rp->r_path + 1) = '\0';
		}
	}
	VFS_HOLD(vfsp);
	rp->r_putapage = putapage;
	rp->r_hashq = rhtp;
	rp->r_flags = RREADDIRPLUS;
	avl_create(&rp->r_dir, compar, sizeof (rddir_cache),
	    offsetof(rddir_cache, tree));
	vn_setops(vp, vops);
	vp->v_data = (caddr_t)rp;
	vp->v_vfsp = vfsp;
	vp->v_type = VNON;
	vp->v_flag |= VMODSORT;
	nfs_set_vroot(vp);

	/*
	 * There is a race condition if someone else
	 * alloc's the rnode while no locks are held, so we
	 * check again and recover if found.
	 */
	rw_enter(&rhtp->r_lock, RW_WRITER);
	if ((trp = rfind(rhtp, fh, vfsp)) != NULL) {
		vp = RTOV(trp);
		nfs_set_vroot(vp);
		*newnode = 0;
		rw_exit(&rhtp->r_lock);
		rp_addfree(rp, cr);
		rw_enter(&rhtp->r_lock, RW_READER);
		return (vp);
	}
	rp_addhash(rp);
	*newnode = 1;
	return (vp);
}

/*
 * Callback function to check if the page should be marked as
 * modified. In the positive case, p_fsdata is set to C_NOCOMMIT.
 */
int
nfs_setmod_check(page_t *pp)
{
	if (pp->p_fsdata != C_NOCOMMIT) {
		pp->p_fsdata = C_NOCOMMIT;
		return (1);
	}
	return (0);
}

static void
nfs_set_vroot(vnode_t *vp)
{
	rnode_t *rp;
	nfs_fhandle *rootfh;

	rp = VTOR(vp);
	rootfh = &rp->r_server->sv_fhandle;
	if (rootfh->fh_len == rp->r_fh.fh_len &&
	    bcmp(rootfh->fh_buf, rp->r_fh.fh_buf, rp->r_fh.fh_len) == 0) {
		if (!(vp->v_flag & VROOT)) {
			mutex_enter(&vp->v_lock);
			vp->v_flag |= VROOT;
			mutex_exit(&vp->v_lock);
		}
	}
}

static void
nfs_free_r_path(rnode_t *rp)
{
	char *path;
	size_t len;

	path = rp->r_path;
	if (path) {
		rp->r_path = NULL;
		len = strlen(path) + 1;
		kmem_free(path, len);
#ifdef DEBUG
		clstat_debug.rpath.value.ui64 -= len;
#endif
	}
}

/*
 * Put an rnode on the free list.
 *
 * Rnodes which were allocated above and beyond the normal limit
 * are immediately freed.
 */
void
rp_addfree(rnode_t *rp, cred_t *cr)
{
	vnode_t *vp;
	struct vfs *vfsp;

	vp = RTOV(rp);
	ASSERT(vp->v_count >= 1);
	ASSERT(rp->r_freef == NULL && rp->r_freeb == NULL);

	/*
	 * If we have too many rnodes allocated and there are no
	 * references to this rnode, or if the rnode is no longer
	 * accessible by it does not reside in the hash queues,
	 * or if an i/o error occurred while writing to the file,
	 * then just free it instead of putting it on the rnode
	 * freelist.
	 */
	vfsp = vp->v_vfsp;
	if (((rnew > nrnode || !(rp->r_flags & RHASHED) || rp->r_error ||
	    (vfsp->vfs_flag & VFS_UNMOUNTED)) && rp->r_count == 0)) {
		if (rp->r_flags & RHASHED) {
			rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				VN_RELE_LOCKED(vp);
				mutex_exit(&vp->v_lock);
				rw_exit(&rp->r_hashq->r_lock);
				return;
			}
			mutex_exit(&vp->v_lock);
			rp_rmhash_locked(rp);
			rw_exit(&rp->r_hashq->r_lock);
		}

		rinactive(rp, cr);

		/*
		 * Recheck the vnode reference count.  We need to
		 * make sure that another reference has not been
		 * acquired while we were not holding v_lock.  The
		 * rnode is not in the rnode hash queues, so the
		 * only way for a reference to have been acquired
		 * is for a VOP_PUTPAGE because the rnode was marked
		 * with RDIRTY or for a modified page.  This
		 * reference may have been acquired before our call
		 * to rinactive.  The i/o may have been completed,
		 * thus allowing rinactive to complete, but the
		 * reference to the vnode may not have been released
		 * yet.  In any case, the rnode can not be destroyed
		 * until the other references to this vnode have been
		 * released.  The other references will take care of
		 * either destroying the rnode or placing it on the
		 * rnode freelist.  If there are no other references,
		 * then the rnode may be safely destroyed.
		 */
		mutex_enter(&vp->v_lock);
		if (vp->v_count > 1) {
			VN_RELE_LOCKED(vp);
			mutex_exit(&vp->v_lock);
			return;
		}
		mutex_exit(&vp->v_lock);

		destroy_rnode(rp);
		return;
	}

	/*
	 * Lock the hash queue and then recheck the reference count
	 * to ensure that no other threads have acquired a reference
	 * to indicate that the rnode should not be placed on the
	 * freelist.  If another reference has been acquired, then
	 * just release this one and let the other thread complete
	 * the processing of adding this rnode to the freelist.
	 */
	rw_enter(&rp->r_hashq->r_lock, RW_WRITER);

	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		VN_RELE_LOCKED(vp);
		mutex_exit(&vp->v_lock);
		rw_exit(&rp->r_hashq->r_lock);
		return;
	}
	mutex_exit(&vp->v_lock);

	/*
	 * If there is no cached data or metadata for this file, then
	 * put the rnode on the front of the freelist so that it will
	 * be reused before other rnodes which may have cached data or
	 * metadata associated with them.
	 */
	mutex_enter(&rpfreelist_lock);
	if (rpfreelist == NULL) {
		rp->r_freef = rp;
		rp->r_freeb = rp;
		rpfreelist = rp;
	} else {
		rp->r_freef = rpfreelist;
		rp->r_freeb = rpfreelist->r_freeb;
		rpfreelist->r_freeb->r_freef = rp;
		rpfreelist->r_freeb = rp;
		if (!vn_has_cached_data(vp) &&
		    !HAVE_RDDIR_CACHE(rp) &&
		    rp->r_symlink.contents == NULL &&
		    rp->r_secattr == NULL &&
		    rp->r_pathconf == NULL)
			rpfreelist = rp;
	}
	mutex_exit(&rpfreelist_lock);

	rw_exit(&rp->r_hashq->r_lock);
}

/*
 * Remove an rnode from the free list.
 *
 * The caller must be holding rpfreelist_lock and the rnode
 * must be on the freelist.
 */
static void
rp_rmfree(rnode_t *rp)
{

	ASSERT(MUTEX_HELD(&rpfreelist_lock));
	ASSERT(rp->r_freef != NULL && rp->r_freeb != NULL);

	if (rp == rpfreelist) {
		rpfreelist = rp->r_freef;
		if (rp == rpfreelist)
			rpfreelist = NULL;
	}

	rp->r_freeb->r_freef = rp->r_freef;
	rp->r_freef->r_freeb = rp->r_freeb;

	rp->r_freef = rp->r_freeb = NULL;
}

/*
 * Put a rnode in the hash table.
 *
 * The caller must be holding the exclusive hash queue lock.
 */
static void
rp_addhash(rnode_t *rp)
{

	ASSERT(RW_WRITE_HELD(&rp->r_hashq->r_lock));
	ASSERT(!(rp->r_flags & RHASHED));

	rp->r_hashf = rp->r_hashq->r_hashf;
	rp->r_hashq->r_hashf = rp;
	rp->r_hashb = (rnode_t *)rp->r_hashq;
	rp->r_hashf->r_hashb = rp;

	mutex_enter(&rp->r_statelock);
	rp->r_flags |= RHASHED;
	mutex_exit(&rp->r_statelock);
}

/*
 * Remove a rnode from the hash table.
 *
 * The caller must be holding the hash queue lock.
 */
static void
rp_rmhash_locked(rnode_t *rp)
{

	ASSERT(RW_WRITE_HELD(&rp->r_hashq->r_lock));
	ASSERT(rp->r_flags & RHASHED);

	rp->r_hashb->r_hashf = rp->r_hashf;
	rp->r_hashf->r_hashb = rp->r_hashb;

	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~RHASHED;
	mutex_exit(&rp->r_statelock);
}

/*
 * Remove a rnode from the hash table.
 *
 * The caller must not be holding the hash queue lock.
 */
void
rp_rmhash(rnode_t *rp)
{

	rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
	rp_rmhash_locked(rp);
	rw_exit(&rp->r_hashq->r_lock);
}

/*
 * Lookup a rnode by fhandle.
 *
 * The caller must be holding the hash queue lock, either shared or exclusive.
 */
static rnode_t *
rfind(rhashq_t *rhtp, nfs_fhandle *fh, struct vfs *vfsp)
{
	rnode_t *rp;
	vnode_t *vp;

	ASSERT(RW_LOCK_HELD(&rhtp->r_lock));

	for (rp = rhtp->r_hashf; rp != (rnode_t *)rhtp; rp = rp->r_hashf) {
		vp = RTOV(rp);
		if (vp->v_vfsp == vfsp &&
		    rp->r_fh.fh_len == fh->fh_len &&
		    bcmp(rp->r_fh.fh_buf, fh->fh_buf, fh->fh_len) == 0) {
			/*
			 * remove rnode from free list, if necessary.
			 */
			if (rp->r_freef != NULL) {
				mutex_enter(&rpfreelist_lock);
				/*
				 * If the rnode is on the freelist,
				 * then remove it and use that reference
				 * as the new reference.  Otherwise,
				 * need to increment the reference count.
				 */
				if (rp->r_freef != NULL) {
					rp_rmfree(rp);
					mutex_exit(&rpfreelist_lock);
				} else {
					mutex_exit(&rpfreelist_lock);
					VN_HOLD(vp);
				}
			} else
				VN_HOLD(vp);
			return (rp);
		}
	}
	return (NULL);
}

/*
 * Return 1 if there is a active vnode belonging to this vfs in the
 * rtable cache.
 *
 * Several of these checks are done without holding the usual
 * locks.  This is safe because destroy_rtable(), rp_addfree(),
 * etc. will redo the necessary checks before actually destroying
 * any rnodes.
 */
int
check_rtable(struct vfs *vfsp)
{
	int index;
	rnode_t *rp;
	vnode_t *vp;

	for (index = 0; index < rtablesize; index++) {
		rw_enter(&rtable[index].r_lock, RW_READER);
		for (rp = rtable[index].r_hashf;
		    rp != (rnode_t *)(&rtable[index]);
		    rp = rp->r_hashf) {
			vp = RTOV(rp);
			if (vp->v_vfsp == vfsp) {
				if (rp->r_freef == NULL ||
				    (vn_has_cached_data(vp) &&
				    (rp->r_flags & RDIRTY)) ||
				    rp->r_count > 0) {
					rw_exit(&rtable[index].r_lock);
					return (1);
				}
			}
		}
		rw_exit(&rtable[index].r_lock);
	}
	return (0);
}

/*
 * Destroy inactive vnodes from the hash queues which belong to this
 * vfs.  It is essential that we destroy all inactive vnodes during a
 * forced unmount as well as during a normal unmount.
 */
void
destroy_rtable(struct vfs *vfsp, cred_t *cr)
{
	int index;
	rnode_t *rp;
	rnode_t *rlist;
	rnode_t *r_hashf;
	vnode_t *vp;

	rlist = NULL;

	for (index = 0; index < rtablesize; index++) {
		rw_enter(&rtable[index].r_lock, RW_WRITER);
		for (rp = rtable[index].r_hashf;
		    rp != (rnode_t *)(&rtable[index]);
		    rp = r_hashf) {
			/* save the hash pointer before destroying */
			r_hashf = rp->r_hashf;
			vp = RTOV(rp);
			if (vp->v_vfsp == vfsp) {
				mutex_enter(&rpfreelist_lock);
				if (rp->r_freef != NULL) {
					rp_rmfree(rp);
					mutex_exit(&rpfreelist_lock);
					rp_rmhash_locked(rp);
					rp->r_hashf = rlist;
					rlist = rp;
				} else
					mutex_exit(&rpfreelist_lock);
			}
		}
		rw_exit(&rtable[index].r_lock);
	}

	for (rp = rlist; rp != NULL; rp = rlist) {
		rlist = rp->r_hashf;
		/*
		 * This call to rp_addfree will end up destroying the
		 * rnode, but in a safe way with the appropriate set
		 * of checks done.
		 */
		rp_addfree(rp, cr);
	}

}

/*
 * This routine destroys all the resources associated with the rnode
 * and then the rnode itself.
 */
static void
destroy_rnode(rnode_t *rp)
{
	vnode_t *vp;
	vfs_t *vfsp;

	vp = RTOV(rp);
	vfsp = vp->v_vfsp;

	ASSERT(vp->v_count == 1);
	ASSERT(rp->r_count == 0);
	ASSERT(rp->r_lmpl == NULL);
	ASSERT(rp->r_mapcnt == 0);
	ASSERT(!(rp->r_flags & RHASHED));
	ASSERT(rp->r_freef == NULL && rp->r_freeb == NULL);
	atomic_dec_ulong((ulong_t *)&rnew);
#ifdef DEBUG
	clstat_debug.nrnode.value.ui64--;
#endif
	nfs_rw_destroy(&rp->r_rwlock);
	nfs_rw_destroy(&rp->r_lkserlock);
	mutex_destroy(&rp->r_statelock);
	cv_destroy(&rp->r_cv);
	cv_destroy(&rp->r_commit.c_cv);
	if (rp->r_flags & RDELMAPLIST)
		list_destroy(&rp->r_indelmap);
	nfs_free_r_path(rp);
	avl_destroy(&rp->r_dir);
	vn_invalid(vp);
	vn_free(vp);
	kmem_cache_free(rnode_cache, rp);
	VFS_RELE(vfsp);
}

/*
 * Flush all vnodes in this (or every) vfs.
 * Used by nfs_sync and by nfs_unmount.
 */
void
rflush(struct vfs *vfsp, cred_t *cr)
{
	int index;
	rnode_t *rp;
	vnode_t *vp, **vplist;
	long num, cnt;

	/*
	 * Check to see whether there is anything to do.
	 */
	num = rnew;
	if (num == 0)
		return;

	/*
	 * Allocate a slot for all currently active rnodes on the
	 * supposition that they all may need flushing.
	 */
	vplist = kmem_alloc(num * sizeof (*vplist), KM_SLEEP);
	cnt = 0;

	/*
	 * Walk the hash queues looking for rnodes with page
	 * lists associated with them.  Make a list of these
	 * files.
	 */
	for (index = 0; index < rtablesize; index++) {
		rw_enter(&rtable[index].r_lock, RW_READER);
		for (rp = rtable[index].r_hashf;
		    rp != (rnode_t *)(&rtable[index]);
		    rp = rp->r_hashf) {
			vp = RTOV(rp);
			/*
			 * Don't bother sync'ing a vp if it
			 * is part of virtual swap device or
			 * if VFS is read-only
			 */
			if (IS_SWAPVP(vp) || vn_is_readonly(vp))
				continue;
			/*
			 * If flushing all mounted file systems or
			 * the vnode belongs to this vfs, has pages
			 * and is marked as either dirty or mmap'd,
			 * hold and add this vnode to the list of
			 * vnodes to flush.
			 */
			if ((vfsp == NULL || vp->v_vfsp == vfsp) &&
			    vn_has_cached_data(vp) &&
			    ((rp->r_flags & RDIRTY) || rp->r_mapcnt > 0)) {
				VN_HOLD(vp);
				vplist[cnt++] = vp;
				if (cnt == num) {
					rw_exit(&rtable[index].r_lock);
					goto toomany;
				}
			}
		}
		rw_exit(&rtable[index].r_lock);
	}
toomany:

	/*
	 * Flush and release all of the files on the list.
	 */
	while (cnt-- > 0) {
		vp = vplist[cnt];
		(void) VOP_PUTPAGE(vp, (u_offset_t)0, 0, B_ASYNC, cr, NULL);
		VN_RELE(vp);
	}

	/*
	 * Free the space allocated to hold the list.
	 */
	kmem_free(vplist, num * sizeof (*vplist));
}

/*
 * This probably needs to be larger than or equal to
 * log2(sizeof (struct rnode)) due to the way that rnodes are
 * allocated.
 */
#define	ACACHE_SHIFT_BITS	9

static int
acachehash(rnode_t *rp, cred_t *cr)
{

	return ((((intptr_t)rp >> ACACHE_SHIFT_BITS) + crgetuid(cr)) &
	    acachemask);
}

#ifdef DEBUG
static long nfs_access_cache_hits = 0;
static long nfs_access_cache_misses = 0;
#endif

nfs_access_type_t
nfs_access_check(rnode_t *rp, uint32_t acc, cred_t *cr)
{
	vnode_t *vp;
	acache_t *ap;
	acache_hash_t *hp;
	nfs_access_type_t all;

	vp = RTOV(rp);
	if (!ATTRCACHE_VALID(vp) || nfs_waitfor_purge_complete(vp))
		return (NFS_ACCESS_UNKNOWN);

	if (rp->r_acache != NULL) {
		hp = &acache[acachehash(rp, cr)];
		rw_enter(&hp->lock, RW_READER);
		ap = hp->next;
		while (ap != (acache_t *)hp) {
			if (crcmp(ap->cred, cr) == 0 && ap->rnode == rp) {
				if ((ap->known & acc) == acc) {
#ifdef DEBUG
					nfs_access_cache_hits++;
#endif
					if ((ap->allowed & acc) == acc)
						all = NFS_ACCESS_ALLOWED;
					else
						all = NFS_ACCESS_DENIED;
				} else {
#ifdef DEBUG
					nfs_access_cache_misses++;
#endif
					all = NFS_ACCESS_UNKNOWN;
				}
				rw_exit(&hp->lock);
				return (all);
			}
			ap = ap->next;
		}
		rw_exit(&hp->lock);
	}

#ifdef DEBUG
	nfs_access_cache_misses++;
#endif
	return (NFS_ACCESS_UNKNOWN);
}

void
nfs_access_cache(rnode_t *rp, uint32_t acc, uint32_t resacc, cred_t *cr)
{
	acache_t *ap;
	acache_t *nap;
	acache_hash_t *hp;

	hp = &acache[acachehash(rp, cr)];

	/*
	 * Allocate now assuming that mostly an allocation will be
	 * required.  This allows the allocation to happen without
	 * holding the hash bucket locked.
	 */
	nap = kmem_cache_alloc(acache_cache, KM_NOSLEEP);
	if (nap != NULL) {
		nap->known = acc;
		nap->allowed = resacc;
		nap->rnode = rp;
		crhold(cr);
		nap->cred = cr;
		nap->hashq = hp;
	}

	rw_enter(&hp->lock, RW_WRITER);

	if (rp->r_acache != NULL) {
		ap = hp->next;
		while (ap != (acache_t *)hp) {
			if (crcmp(ap->cred, cr) == 0 && ap->rnode == rp) {
				ap->known |= acc;
				ap->allowed &= ~acc;
				ap->allowed |= resacc;
				rw_exit(&hp->lock);
				if (nap != NULL) {
					crfree(nap->cred);
					kmem_cache_free(acache_cache, nap);
				}
				return;
			}
			ap = ap->next;
		}
	}

	if (nap != NULL) {
#ifdef DEBUG
		clstat_debug.access.value.ui64++;
#endif
		nap->next = hp->next;
		hp->next = nap;
		nap->next->prev = nap;
		nap->prev = (acache_t *)hp;

		mutex_enter(&rp->r_statelock);
		nap->list = rp->r_acache;
		rp->r_acache = nap;
		mutex_exit(&rp->r_statelock);
	}

	rw_exit(&hp->lock);
}

int
nfs_access_purge_rp(rnode_t *rp)
{
	acache_t *ap;
	acache_t *tmpap;
	acache_t *rplist;

	/*
	 * If there aren't any cached entries, then there is nothing
	 * to free.
	 */
	if (rp->r_acache == NULL)
		return (0);

	mutex_enter(&rp->r_statelock);
	rplist = rp->r_acache;
	rp->r_acache = NULL;
	mutex_exit(&rp->r_statelock);

	/*
	 * Loop through each entry in the list pointed to in the
	 * rnode.  Remove each of these entries from the hash
	 * queue that it is on and remove it from the list in
	 * the rnode.
	 */
	for (ap = rplist; ap != NULL; ap = tmpap) {
		rw_enter(&ap->hashq->lock, RW_WRITER);
		ap->prev->next = ap->next;
		ap->next->prev = ap->prev;
		rw_exit(&ap->hashq->lock);

		tmpap = ap->list;
		crfree(ap->cred);
		kmem_cache_free(acache_cache, ap);
#ifdef DEBUG
		clstat_debug.access.value.ui64--;
#endif
	}

	return (1);
}

static const char prefix[] = ".nfs";

static kmutex_t newnum_lock;

int
newnum(void)
{
	static uint_t newnum = 0;
	uint_t id;

	mutex_enter(&newnum_lock);
	if (newnum == 0)
		newnum = gethrestime_sec() & 0xffff;
	id = newnum++;
	mutex_exit(&newnum_lock);
	return (id);
}

char *
newname(void)
{
	char *news;
	char *s;
	const char *p;
	uint_t id;

	id = newnum();
	news = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	s = news;
	p = prefix;
	while (*p != '\0')
		*s++ = *p++;
	while (id != 0) {
		*s++ = "0123456789ABCDEF"[id & 0x0f];
		id >>= 4;
	}
	*s = '\0';
	return (news);
}

/*
 * Snapshot callback for nfs:0:nfs_client as registered with the kstat
 * framework.
 */
static int
cl_snapshot(kstat_t *ksp, void *buf, int rw)
{
	ksp->ks_snaptime = gethrtime();
	if (rw == KSTAT_WRITE) {
		bcopy(buf, ksp->ks_private, sizeof (clstat_tmpl));
#ifdef DEBUG
		/*
		 * Currently only the global zone can write to kstats, but we
		 * add the check just for paranoia.
		 */
		if (INGLOBALZONE(curproc))
			bcopy((char *)buf + sizeof (clstat_tmpl), &clstat_debug,
			    sizeof (clstat_debug));
#endif
	} else {
		bcopy(ksp->ks_private, buf, sizeof (clstat_tmpl));
#ifdef DEBUG
		/*
		 * If we're displaying the "global" debug kstat values, we
		 * display them as-is to all zones since in fact they apply to
		 * the system as a whole.
		 */
		bcopy(&clstat_debug, (char *)buf + sizeof (clstat_tmpl),
		    sizeof (clstat_debug));
#endif
	}
	return (0);
}

static void *
clinit_zone(zoneid_t zoneid)
{
	kstat_t *nfs_client_kstat;
	struct nfs_clnt *nfscl;
	uint_t ndata;

	nfscl = kmem_alloc(sizeof (*nfscl), KM_SLEEP);
	mutex_init(&nfscl->nfscl_chtable_lock, NULL, MUTEX_DEFAULT, NULL);
	nfscl->nfscl_chtable = NULL;
	nfscl->nfscl_zoneid = zoneid;

	bcopy(&clstat_tmpl, &nfscl->nfscl_stat, sizeof (clstat_tmpl));
	ndata = sizeof (clstat_tmpl) / sizeof (kstat_named_t);
#ifdef DEBUG
	ndata += sizeof (clstat_debug) / sizeof (kstat_named_t);
#endif
	if ((nfs_client_kstat = kstat_create_zone("nfs", 0, "nfs_client",
	    "misc", KSTAT_TYPE_NAMED, ndata,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE, zoneid)) != NULL) {
		nfs_client_kstat->ks_private = &nfscl->nfscl_stat;
		nfs_client_kstat->ks_snapshot = cl_snapshot;
		kstat_install(nfs_client_kstat);
	}
	mutex_enter(&nfs_clnt_list_lock);
	list_insert_head(&nfs_clnt_list, nfscl);
	mutex_exit(&nfs_clnt_list_lock);
	return (nfscl);
}

/*ARGSUSED*/
static void
clfini_zone(zoneid_t zoneid, void *arg)
{
	struct nfs_clnt *nfscl = arg;
	chhead_t *chp, *next;

	if (nfscl == NULL)
		return;
	mutex_enter(&nfs_clnt_list_lock);
	list_remove(&nfs_clnt_list, nfscl);
	mutex_exit(&nfs_clnt_list_lock);
	clreclaim_zone(nfscl, 0);
	for (chp = nfscl->nfscl_chtable; chp != NULL; chp = next) {
		ASSERT(chp->ch_list == NULL);
		kmem_free(chp->ch_protofmly, strlen(chp->ch_protofmly) + 1);
		next = chp->ch_next;
		kmem_free(chp, sizeof (*chp));
	}
	kstat_delete_byname_zone("nfs", 0, "nfs_client", zoneid);
	mutex_destroy(&nfscl->nfscl_chtable_lock);
	kmem_free(nfscl, sizeof (*nfscl));
}

/*
 * Called by endpnt_destructor to make sure the client handles are
 * cleaned up before the RPC endpoints.  This becomes a no-op if
 * clfini_zone (above) is called first.  This function is needed
 * (rather than relying on clfini_zone to clean up) because the ZSD
 * callbacks have no ordering mechanism, so we have no way to ensure
 * that clfini_zone is called before endpnt_destructor.
 */
void
clcleanup_zone(zoneid_t zoneid)
{
	struct nfs_clnt *nfscl;

	mutex_enter(&nfs_clnt_list_lock);
	nfscl = list_head(&nfs_clnt_list);
	for (; nfscl != NULL; nfscl = list_next(&nfs_clnt_list, nfscl)) {
		if (nfscl->nfscl_zoneid == zoneid) {
			clreclaim_zone(nfscl, 0);
			break;
		}
	}
	mutex_exit(&nfs_clnt_list_lock);
}

int
nfs_subrinit(void)
{
	int i;
	ulong_t nrnode_max;

	/*
	 * Allocate and initialize the rnode hash queues
	 */
	if (nrnode <= 0)
		nrnode = ncsize;
	nrnode_max = (ulong_t)((kmem_maxavail() >> 2) / sizeof (struct rnode));
	if (nrnode > nrnode_max || (nrnode == 0 && ncsize == 0)) {
		zcmn_err(GLOBAL_ZONEID, CE_NOTE,
		    "!setting nrnode to max value of %ld", nrnode_max);
		nrnode = nrnode_max;
	}

	rtablesize = 1 << highbit(nrnode / hashlen);
	rtablemask = rtablesize - 1;
	rtable = kmem_alloc(rtablesize * sizeof (*rtable), KM_SLEEP);
	for (i = 0; i < rtablesize; i++) {
		rtable[i].r_hashf = (rnode_t *)(&rtable[i]);
		rtable[i].r_hashb = (rnode_t *)(&rtable[i]);
		rw_init(&rtable[i].r_lock, NULL, RW_DEFAULT, NULL);
	}
	rnode_cache = kmem_cache_create("rnode_cache", sizeof (rnode_t),
	    0, NULL, NULL, nfs_reclaim, NULL, NULL, 0);

	/*
	 * Allocate and initialize the access cache
	 */

	/*
	 * Initial guess is one access cache entry per rnode unless
	 * nacache is set to a non-zero value and then it is used to
	 * indicate a guess at the number of access cache entries.
	 */
	if (nacache > 0)
		acachesize = 1 << highbit(nacache / hashlen);
	else
		acachesize = rtablesize;
	acachemask = acachesize - 1;
	acache = kmem_alloc(acachesize * sizeof (*acache), KM_SLEEP);
	for (i = 0; i < acachesize; i++) {
		acache[i].next = (acache_t *)&acache[i];
		acache[i].prev = (acache_t *)&acache[i];
		rw_init(&acache[i].lock, NULL, RW_DEFAULT, NULL);
	}
	acache_cache = kmem_cache_create("nfs_access_cache",
	    sizeof (acache_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	/*
	 * Allocate and initialize the client handle cache
	 */
	chtab_cache = kmem_cache_create("client_handle_cache",
	    sizeof (struct chtab), 0, NULL, NULL, clreclaim, NULL, NULL, 0);
	/*
	 * Initialize the list of per-zone client handles (and associated data).
	 * This needs to be done before we call zone_key_create().
	 */
	list_create(&nfs_clnt_list, sizeof (struct nfs_clnt),
	    offsetof(struct nfs_clnt, nfscl_node));
	/*
	 * Initialize the zone_key for per-zone client handle lists.
	 */
	zone_key_create(&nfsclnt_zone_key, clinit_zone, NULL, clfini_zone);
	/*
	 * Initialize the various mutexes and reader/writer locks
	 */
	mutex_init(&rpfreelist_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&newnum_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&nfs_minor_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Assign unique major number for all nfs mounts
	 */
	if ((nfs_major = getudev()) == -1) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "nfs: init: can't get unique device number");
		nfs_major = 0;
	}
	nfs_minor = 0;

	if (nfs3_jukebox_delay == 0)
		nfs3_jukebox_delay = NFS3_JUKEBOX_DELAY;

	return (0);
}

void
nfs_subrfini(void)
{
	int i;

	/*
	 * Deallocate the rnode hash queues
	 */
	kmem_cache_destroy(rnode_cache);

	for (i = 0; i < rtablesize; i++)
		rw_destroy(&rtable[i].r_lock);
	kmem_free(rtable, rtablesize * sizeof (*rtable));

	/*
	 * Deallocated the access cache
	 */
	kmem_cache_destroy(acache_cache);

	for (i = 0; i < acachesize; i++)
		rw_destroy(&acache[i].lock);
	kmem_free(acache, acachesize * sizeof (*acache));

	/*
	 * Deallocate the client handle cache
	 */
	kmem_cache_destroy(chtab_cache);

	/*
	 * Destroy the various mutexes and reader/writer locks
	 */
	mutex_destroy(&rpfreelist_lock);
	mutex_destroy(&newnum_lock);
	mutex_destroy(&nfs_minor_lock);
	(void) zone_key_delete(nfsclnt_zone_key);
}

enum nfsstat
puterrno(int error)
{

	switch (error) {
	case EOPNOTSUPP:
		return (NFSERR_OPNOTSUPP);
	case ENAMETOOLONG:
		return (NFSERR_NAMETOOLONG);
	case ENOTEMPTY:
		return (NFSERR_NOTEMPTY);
	case EDQUOT:
		return (NFSERR_DQUOT);
	case ESTALE:
		return (NFSERR_STALE);
	case EREMOTE:
		return (NFSERR_REMOTE);
	case ENOSYS:
		return (NFSERR_OPNOTSUPP);
	case EOVERFLOW:
		return (NFSERR_INVAL);
	default:
		return ((enum nfsstat)error);
	}
	/* NOTREACHED */
}

int
geterrno(enum nfsstat status)
{

	switch (status) {
	case NFSERR_OPNOTSUPP:
		return (EOPNOTSUPP);
	case NFSERR_NAMETOOLONG:
		return (ENAMETOOLONG);
	case NFSERR_NOTEMPTY:
		return (ENOTEMPTY);
	case NFSERR_DQUOT:
		return (EDQUOT);
	case NFSERR_STALE:
		return (ESTALE);
	case NFSERR_REMOTE:
		return (EREMOTE);
	case NFSERR_WFLUSH:
		return (EIO);
	default:
		return ((int)status);
	}
	/* NOTREACHED */
}

enum nfsstat3
puterrno3(int error)
{

#ifdef DEBUG
	switch (error) {
	case 0:
		return (NFS3_OK);
	case EPERM:
		return (NFS3ERR_PERM);
	case ENOENT:
		return (NFS3ERR_NOENT);
	case EIO:
		return (NFS3ERR_IO);
	case ENXIO:
		return (NFS3ERR_NXIO);
	case EACCES:
		return (NFS3ERR_ACCES);
	case EEXIST:
		return (NFS3ERR_EXIST);
	case EXDEV:
		return (NFS3ERR_XDEV);
	case ENODEV:
		return (NFS3ERR_NODEV);
	case ENOTDIR:
		return (NFS3ERR_NOTDIR);
	case EISDIR:
		return (NFS3ERR_ISDIR);
	case EINVAL:
		return (NFS3ERR_INVAL);
	case EFBIG:
		return (NFS3ERR_FBIG);
	case ENOSPC:
		return (NFS3ERR_NOSPC);
	case EROFS:
		return (NFS3ERR_ROFS);
	case EMLINK:
		return (NFS3ERR_MLINK);
	case ENAMETOOLONG:
		return (NFS3ERR_NAMETOOLONG);
	case ENOTEMPTY:
		return (NFS3ERR_NOTEMPTY);
	case EDQUOT:
		return (NFS3ERR_DQUOT);
	case ESTALE:
		return (NFS3ERR_STALE);
	case EREMOTE:
		return (NFS3ERR_REMOTE);
	case ENOSYS:
	case EOPNOTSUPP:
		return (NFS3ERR_NOTSUPP);
	case EOVERFLOW:
		return (NFS3ERR_INVAL);
	default:
		zcmn_err(getzoneid(), CE_WARN,
		    "puterrno3: got error %d", error);
		return ((enum nfsstat3)error);
	}
#else
	switch (error) {
	case ENAMETOOLONG:
		return (NFS3ERR_NAMETOOLONG);
	case ENOTEMPTY:
		return (NFS3ERR_NOTEMPTY);
	case EDQUOT:
		return (NFS3ERR_DQUOT);
	case ESTALE:
		return (NFS3ERR_STALE);
	case ENOSYS:
	case EOPNOTSUPP:
		return (NFS3ERR_NOTSUPP);
	case EREMOTE:
		return (NFS3ERR_REMOTE);
	case EOVERFLOW:
		return (NFS3ERR_INVAL);
	default:
		return ((enum nfsstat3)error);
	}
#endif
}

int
geterrno3(enum nfsstat3 status)
{

#ifdef DEBUG
	switch (status) {
	case NFS3_OK:
		return (0);
	case NFS3ERR_PERM:
		return (EPERM);
	case NFS3ERR_NOENT:
		return (ENOENT);
	case NFS3ERR_IO:
		return (EIO);
	case NFS3ERR_NXIO:
		return (ENXIO);
	case NFS3ERR_ACCES:
		return (EACCES);
	case NFS3ERR_EXIST:
		return (EEXIST);
	case NFS3ERR_XDEV:
		return (EXDEV);
	case NFS3ERR_NODEV:
		return (ENODEV);
	case NFS3ERR_NOTDIR:
		return (ENOTDIR);
	case NFS3ERR_ISDIR:
		return (EISDIR);
	case NFS3ERR_INVAL:
		return (EINVAL);
	case NFS3ERR_FBIG:
		return (EFBIG);
	case NFS3ERR_NOSPC:
		return (ENOSPC);
	case NFS3ERR_ROFS:
		return (EROFS);
	case NFS3ERR_MLINK:
		return (EMLINK);
	case NFS3ERR_NAMETOOLONG:
		return (ENAMETOOLONG);
	case NFS3ERR_NOTEMPTY:
		return (ENOTEMPTY);
	case NFS3ERR_DQUOT:
		return (EDQUOT);
	case NFS3ERR_STALE:
		return (ESTALE);
	case NFS3ERR_REMOTE:
		return (EREMOTE);
	case NFS3ERR_BADHANDLE:
		return (ESTALE);
	case NFS3ERR_NOT_SYNC:
		return (EINVAL);
	case NFS3ERR_BAD_COOKIE:
		return (ENOENT);
	case NFS3ERR_NOTSUPP:
		return (EOPNOTSUPP);
	case NFS3ERR_TOOSMALL:
		return (EINVAL);
	case NFS3ERR_SERVERFAULT:
		return (EIO);
	case NFS3ERR_BADTYPE:
		return (EINVAL);
	case NFS3ERR_JUKEBOX:
		return (ENXIO);
	default:
		zcmn_err(getzoneid(), CE_WARN,
		    "geterrno3: got status %d", status);
		return ((int)status);
	}
#else
	switch (status) {
	case NFS3ERR_NAMETOOLONG:
		return (ENAMETOOLONG);
	case NFS3ERR_NOTEMPTY:
		return (ENOTEMPTY);
	case NFS3ERR_DQUOT:
		return (EDQUOT);
	case NFS3ERR_STALE:
	case NFS3ERR_BADHANDLE:
		return (ESTALE);
	case NFS3ERR_NOTSUPP:
		return (EOPNOTSUPP);
	case NFS3ERR_REMOTE:
		return (EREMOTE);
	case NFS3ERR_NOT_SYNC:
	case NFS3ERR_TOOSMALL:
	case NFS3ERR_BADTYPE:
		return (EINVAL);
	case NFS3ERR_BAD_COOKIE:
		return (ENOENT);
	case NFS3ERR_SERVERFAULT:
		return (EIO);
	case NFS3ERR_JUKEBOX:
		return (ENXIO);
	default:
		return ((int)status);
	}
#endif
}

rddir_cache *
rddir_cache_alloc(int flags)
{
	rddir_cache *rc;

	rc = kmem_alloc(sizeof (*rc), flags);
	if (rc != NULL) {
		rc->entries = NULL;
		rc->flags = RDDIR;
		cv_init(&rc->cv, NULL, CV_DEFAULT, NULL);
		mutex_init(&rc->lock, NULL, MUTEX_DEFAULT, NULL);
		rc->count = 1;
#ifdef DEBUG
		atomic_inc_64(&clstat_debug.dirent.value.ui64);
#endif
	}
	return (rc);
}

static void
rddir_cache_free(rddir_cache *rc)
{

#ifdef DEBUG
	atomic_dec_64(&clstat_debug.dirent.value.ui64);
#endif
	if (rc->entries != NULL) {
#ifdef DEBUG
		rddir_cache_buf_free(rc->entries, rc->buflen);
#else
		kmem_free(rc->entries, rc->buflen);
#endif
	}
	cv_destroy(&rc->cv);
	mutex_destroy(&rc->lock);
	kmem_free(rc, sizeof (*rc));
}

void
rddir_cache_hold(rddir_cache *rc)
{

	mutex_enter(&rc->lock);
	rc->count++;
	mutex_exit(&rc->lock);
}

void
rddir_cache_rele(rddir_cache *rc)
{

	mutex_enter(&rc->lock);
	ASSERT(rc->count > 0);
	if (--rc->count == 0) {
		mutex_exit(&rc->lock);
		rddir_cache_free(rc);
	} else
		mutex_exit(&rc->lock);
}

#ifdef DEBUG
char *
rddir_cache_buf_alloc(size_t size, int flags)
{
	char *rc;

	rc = kmem_alloc(size, flags);
	if (rc != NULL)
		atomic_add_64(&clstat_debug.dirents.value.ui64, size);
	return (rc);
}

void
rddir_cache_buf_free(void *addr, size_t size)
{

	atomic_add_64(&clstat_debug.dirents.value.ui64, -(int64_t)size);
	kmem_free(addr, size);
}
#endif

static int
nfs_free_data_reclaim(rnode_t *rp)
{
	char *contents;
	int size;
	vsecattr_t *vsp;
	nfs3_pathconf_info *info;
	int freed;
	cred_t *cred;

	/*
	 * Free any held credentials and caches which
	 * may be associated with this rnode.
	 */
	mutex_enter(&rp->r_statelock);
	cred = rp->r_cred;
	rp->r_cred = NULL;
	contents = rp->r_symlink.contents;
	size = rp->r_symlink.size;
	rp->r_symlink.contents = NULL;
	vsp = rp->r_secattr;
	rp->r_secattr = NULL;
	info = rp->r_pathconf;
	rp->r_pathconf = NULL;
	mutex_exit(&rp->r_statelock);

	if (cred != NULL)
		crfree(cred);

	/*
	 * Free the access cache entries.
	 */
	freed = nfs_access_purge_rp(rp);

	if (!HAVE_RDDIR_CACHE(rp) &&
	    contents == NULL &&
	    vsp == NULL &&
	    info == NULL)
		return (freed);

	/*
	 * Free the readdir cache entries
	 */
	if (HAVE_RDDIR_CACHE(rp))
		nfs_purge_rddir_cache(RTOV(rp));

	/*
	 * Free the symbolic link cache.
	 */
	if (contents != NULL) {

		kmem_free((void *)contents, size);
	}

	/*
	 * Free any cached ACL.
	 */
	if (vsp != NULL)
		nfs_acl_free(vsp);

	/*
	 * Free any cached pathconf information.
	 */
	if (info != NULL)
		kmem_free(info, sizeof (*info));

	return (1);
}

static int
nfs_active_data_reclaim(rnode_t *rp)
{
	char *contents;
	int size;
	vsecattr_t *vsp;
	nfs3_pathconf_info *info;
	int freed;

	/*
	 * Free any held credentials and caches which
	 * may be associated with this rnode.
	 */
	if (!mutex_tryenter(&rp->r_statelock))
		return (0);
	contents = rp->r_symlink.contents;
	size = rp->r_symlink.size;
	rp->r_symlink.contents = NULL;
	vsp = rp->r_secattr;
	rp->r_secattr = NULL;
	info = rp->r_pathconf;
	rp->r_pathconf = NULL;
	mutex_exit(&rp->r_statelock);

	/*
	 * Free the access cache entries.
	 */
	freed = nfs_access_purge_rp(rp);

	if (!HAVE_RDDIR_CACHE(rp) &&
	    contents == NULL &&
	    vsp == NULL &&
	    info == NULL)
		return (freed);

	/*
	 * Free the readdir cache entries
	 */
	if (HAVE_RDDIR_CACHE(rp))
		nfs_purge_rddir_cache(RTOV(rp));

	/*
	 * Free the symbolic link cache.
	 */
	if (contents != NULL) {

		kmem_free((void *)contents, size);
	}

	/*
	 * Free any cached ACL.
	 */
	if (vsp != NULL)
		nfs_acl_free(vsp);

	/*
	 * Free any cached pathconf information.
	 */
	if (info != NULL)
		kmem_free(info, sizeof (*info));

	return (1);
}

static int
nfs_free_reclaim(void)
{
	int freed;
	rnode_t *rp;

#ifdef DEBUG
	clstat_debug.f_reclaim.value.ui64++;
#endif
	freed = 0;
	mutex_enter(&rpfreelist_lock);
	rp = rpfreelist;
	if (rp != NULL) {
		do {
			if (nfs_free_data_reclaim(rp))
				freed = 1;
		} while ((rp = rp->r_freef) != rpfreelist);
	}
	mutex_exit(&rpfreelist_lock);
	return (freed);
}

static int
nfs_active_reclaim(void)
{
	int freed;
	int index;
	rnode_t *rp;

#ifdef DEBUG
	clstat_debug.a_reclaim.value.ui64++;
#endif
	freed = 0;
	for (index = 0; index < rtablesize; index++) {
		rw_enter(&rtable[index].r_lock, RW_READER);
		for (rp = rtable[index].r_hashf;
		    rp != (rnode_t *)(&rtable[index]);
		    rp = rp->r_hashf) {
			if (nfs_active_data_reclaim(rp))
				freed = 1;
		}
		rw_exit(&rtable[index].r_lock);
	}
	return (freed);
}

static int
nfs_rnode_reclaim(void)
{
	int freed;
	rnode_t *rp;
	vnode_t *vp;

#ifdef DEBUG
	clstat_debug.r_reclaim.value.ui64++;
#endif
	freed = 0;
	mutex_enter(&rpfreelist_lock);
	while ((rp = rpfreelist) != NULL) {
		rp_rmfree(rp);
		mutex_exit(&rpfreelist_lock);
		if (rp->r_flags & RHASHED) {
			vp = RTOV(rp);
			rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				VN_RELE_LOCKED(vp);
				mutex_exit(&vp->v_lock);
				rw_exit(&rp->r_hashq->r_lock);
				mutex_enter(&rpfreelist_lock);
				continue;
			}
			mutex_exit(&vp->v_lock);
			rp_rmhash_locked(rp);
			rw_exit(&rp->r_hashq->r_lock);
		}
		/*
		 * This call to rp_addfree will end up destroying the
		 * rnode, but in a safe way with the appropriate set
		 * of checks done.
		 */
		rp_addfree(rp, CRED());
		mutex_enter(&rpfreelist_lock);
	}
	mutex_exit(&rpfreelist_lock);
	return (freed);
}

/*ARGSUSED*/
static void
nfs_reclaim(void *cdrarg)
{

#ifdef DEBUG
	clstat_debug.reclaim.value.ui64++;
#endif
	if (nfs_free_reclaim())
		return;

	if (nfs_active_reclaim())
		return;

	(void) nfs_rnode_reclaim();
}

/*
 * NFS client failover support
 *
 * Routines to copy filehandles
 */
void
nfscopyfh(caddr_t fhp, vnode_t *vp)
{
	fhandle_t *dest = (fhandle_t *)fhp;

	if (dest != NULL)
		*dest = *VTOFH(vp);
}

void
nfs3copyfh(caddr_t fhp, vnode_t *vp)
{
	nfs_fh3 *dest = (nfs_fh3 *)fhp;

	if (dest != NULL)
		*dest = *VTOFH3(vp);
}

/*
 * NFS client failover support
 *
 * failover_safe() will test various conditions to ensure that
 * failover is permitted for this vnode.  It will be denied
 * if:
 *	1) the operation in progress does not support failover (NULL fi)
 *	2) there are no available replicas (NULL mi_servers->sv_next)
 *	3) any locks are outstanding on this file
 */
static int
failover_safe(failinfo_t *fi)
{

	/*
	 * Does this op permit failover?
	 */
	if (fi == NULL || fi->vp == NULL)
		return (0);

	/*
	 * Are there any alternates to failover to?
	 */
	if (VTOMI(fi->vp)->mi_servers->sv_next == NULL)
		return (0);

	/*
	 * Disable check; we've forced local locking
	 *
	 * if (flk_has_remote_locks(fi->vp))
	 *	return (0);
	 */

	/*
	 * If we have no partial path, we can't do anything
	 */
	if (VTOR(fi->vp)->r_path == NULL)
		return (0);

	return (1);
}

#include <sys/thread.h>

/*
 * NFS client failover support
 *
 * failover_newserver() will start a search for a new server,
 * preferably by starting an async thread to do the work.  If
 * someone is already doing this (recognizable by MI_BINDINPROG
 * being set), it will simply return and the calling thread
 * will queue on the mi_failover_cv condition variable.
 */
static void
failover_newserver(mntinfo_t *mi)
{
	/*
	 * Check if someone else is doing this already
	 */
	mutex_enter(&mi->mi_lock);
	if (mi->mi_flags & MI_BINDINPROG) {
		mutex_exit(&mi->mi_lock);
		return;
	}
	mi->mi_flags |= MI_BINDINPROG;

	/*
	 * Need to hold the vfs struct so that it can't be released
	 * while the failover thread is selecting a new server.
	 */
	VFS_HOLD(mi->mi_vfsp);

	/*
	 * Start a thread to do the real searching.
	 */
	(void) zthread_create(NULL, 0, failover_thread, mi, 0, minclsyspri);

	mutex_exit(&mi->mi_lock);
}

/*
 * NFS client failover support
 *
 * failover_thread() will find a new server to replace the one
 * currently in use, wake up other threads waiting on this mount
 * point, and die.  It will start at the head of the server list
 * and poll servers until it finds one with an NFS server which is
 * registered and responds to a NULL procedure ping.
 *
 * XXX failover_thread is unsafe within the scope of the
 * present model defined for cpr to suspend the system.
 * Specifically, over-the-wire calls made by the thread
 * are unsafe. The thread needs to be reevaluated in case of
 * future updates to the cpr suspend model.
 */
static void
failover_thread(mntinfo_t *mi)
{
	servinfo_t *svp = NULL;
	CLIENT *cl;
	enum clnt_stat status;
	struct timeval tv;
	int error;
	int oncethru = 0;
	callb_cpr_t cprinfo;
	rnode_t *rp;
	int index;
	char *srvnames;
	size_t srvnames_len;
	struct nfs_clnt *nfscl = NULL;
	zoneid_t zoneid = getzoneid();

#ifdef DEBUG
	/*
	 * This is currently only needed to access counters which exist on
	 * DEBUG kernels, hence we don't want to pay the penalty of the lookup
	 * on non-DEBUG kernels.
	 */
	nfscl = zone_getspecific(nfsclnt_zone_key, nfs_zone());
	ASSERT(nfscl != NULL);
#endif

	/*
	 * Its safe to piggyback on the mi_lock since failover_newserver()
	 * code guarantees that there will be only one failover thread
	 * per mountinfo at any instance.
	 */
	CALLB_CPR_INIT(&cprinfo, &mi->mi_lock, callb_generic_cpr,
	    "failover_thread");

	mutex_enter(&mi->mi_lock);
	while (mi->mi_readers) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&mi->mi_failover_cv, &mi->mi_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &mi->mi_lock);
	}
	mutex_exit(&mi->mi_lock);

	tv.tv_sec = 2;
	tv.tv_usec = 0;

	/*
	 * Ping the null NFS procedure of every server in
	 * the list until one responds.  We always start
	 * at the head of the list and always skip the one
	 * that is current, since it's caused us a problem.
	 */
	while (svp == NULL) {
		for (svp = mi->mi_servers; svp; svp = svp->sv_next) {
			if (!oncethru && svp == mi->mi_curr_serv)
				continue;

			/*
			 * If the file system was forcibly umounted
			 * while trying to do a failover, then just
			 * give up on the failover.  It won't matter
			 * what the server is.
			 */
			if (FS_OR_ZONE_GONE(mi->mi_vfsp)) {
				svp = NULL;
				goto done;
			}

			error = clnt_tli_kcreate(svp->sv_knconf, &svp->sv_addr,
			    NFS_PROGRAM, NFS_VERSION, 0, 1, CRED(), &cl);
			if (error)
				continue;

			if (!(mi->mi_flags & MI_INT))
				cl->cl_nosignal = TRUE;
			status = CLNT_CALL(cl, RFS_NULL, xdr_void, NULL,
			    xdr_void, NULL, tv);
			if (!(mi->mi_flags & MI_INT))
				cl->cl_nosignal = FALSE;
			AUTH_DESTROY(cl->cl_auth);
			CLNT_DESTROY(cl);
			if (status == RPC_SUCCESS) {
				if (svp == mi->mi_curr_serv) {
#ifdef DEBUG
					zcmn_err(zoneid, CE_NOTE,
			"NFS%d: failing over: selecting original server %s",
					    mi->mi_vers, svp->sv_hostname);
#else
					zcmn_err(zoneid, CE_NOTE,
			"NFS: failing over: selecting original server %s",
					    svp->sv_hostname);
#endif
				} else {
#ifdef DEBUG
					zcmn_err(zoneid, CE_NOTE,
				    "NFS%d: failing over from %s to %s",
					    mi->mi_vers,
					    mi->mi_curr_serv->sv_hostname,
					    svp->sv_hostname);
#else
					zcmn_err(zoneid, CE_NOTE,
				    "NFS: failing over from %s to %s",
					    mi->mi_curr_serv->sv_hostname,
					    svp->sv_hostname);
#endif
				}
				break;
			}
		}

		if (svp == NULL) {
			if (!oncethru) {
				srvnames = nfs_getsrvnames(mi, &srvnames_len);
#ifdef DEBUG
				zprintf(zoneid,
				    "NFS%d servers %s not responding "
				    "still trying\n", mi->mi_vers, srvnames);
#else
				zprintf(zoneid, "NFS servers %s not responding "
				    "still trying\n", srvnames);
#endif
				oncethru = 1;
			}
			mutex_enter(&mi->mi_lock);
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			mutex_exit(&mi->mi_lock);
			delay(hz);
			mutex_enter(&mi->mi_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &mi->mi_lock);
			mutex_exit(&mi->mi_lock);
		}
	}

	if (oncethru) {
#ifdef DEBUG
		zprintf(zoneid, "NFS%d servers %s ok\n", mi->mi_vers, srvnames);
#else
		zprintf(zoneid, "NFS servers %s ok\n", srvnames);
#endif
	}

	if (svp != mi->mi_curr_serv) {
		(void) dnlc_purge_vfsp(mi->mi_vfsp, 0);
		index = rtablehash(&mi->mi_curr_serv->sv_fhandle);
		rw_enter(&rtable[index].r_lock, RW_WRITER);
		rp = rfind(&rtable[index], &mi->mi_curr_serv->sv_fhandle,
		    mi->mi_vfsp);
		if (rp != NULL) {
			if (rp->r_flags & RHASHED)
				rp_rmhash_locked(rp);
			rw_exit(&rtable[index].r_lock);
			rp->r_server = svp;
			rp->r_fh = svp->sv_fhandle;
			(void) nfs_free_data_reclaim(rp);
			index = rtablehash(&rp->r_fh);
			rp->r_hashq = &rtable[index];
			rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
			vn_exists(RTOV(rp));
			rp_addhash(rp);
			rw_exit(&rp->r_hashq->r_lock);
			VN_RELE(RTOV(rp));
		} else
			rw_exit(&rtable[index].r_lock);
	}

done:
	if (oncethru)
		kmem_free(srvnames, srvnames_len);
	mutex_enter(&mi->mi_lock);
	mi->mi_flags &= ~MI_BINDINPROG;
	if (svp != NULL) {
		mi->mi_curr_serv = svp;
		mi->mi_failover++;
#ifdef DEBUG
	nfscl->nfscl_stat.failover.value.ui64++;
#endif
	}
	cv_broadcast(&mi->mi_failover_cv);
	CALLB_CPR_EXIT(&cprinfo);
	VFS_RELE(mi->mi_vfsp);
	zthread_exit();
	/* NOTREACHED */
}

/*
 * NFS client failover support
 *
 * failover_wait() will put the thread to sleep until MI_BINDINPROG
 * is cleared, meaning that failover is complete.  Called with
 * mi_lock mutex held.
 */
static int
failover_wait(mntinfo_t *mi)
{
	k_sigset_t smask;

	/*
	 * If someone else is hunting for a living server,
	 * sleep until it's done.  After our sleep, we may
	 * be bound to the right server and get off cheaply.
	 */
	while (mi->mi_flags & MI_BINDINPROG) {
		/*
		 * Mask out all signals except SIGHUP, SIGINT, SIGQUIT
		 * and SIGTERM. (Preserving the existing masks).
		 * Mask out SIGINT if mount option nointr is specified.
		 */
		sigintr(&smask, (int)mi->mi_flags & MI_INT);
		if (!cv_wait_sig(&mi->mi_failover_cv, &mi->mi_lock)) {
			/*
			 * restore original signal mask
			 */
			sigunintr(&smask);
			return (EINTR);
		}
		/*
		 * restore original signal mask
		 */
		sigunintr(&smask);
	}
	return (0);
}

/*
 * NFS client failover support
 *
 * failover_remap() will do a partial pathname lookup and find the
 * desired vnode on the current server.  The interim vnode will be
 * discarded after we pilfer the new filehandle.
 *
 * Side effects:
 * - This routine will also update the filehandle in the args structure
 *    pointed to by the fi->fhp pointer if it is non-NULL.
 */

static int
failover_remap(failinfo_t *fi)
{
	vnode_t *vp, *nvp, *rootvp;
	rnode_t *rp, *nrp;
	mntinfo_t *mi;
	int error;
#ifdef DEBUG
	struct nfs_clnt *nfscl;

	nfscl = zone_getspecific(nfsclnt_zone_key, nfs_zone());
	ASSERT(nfscl != NULL);
#endif
	/*
	 * Sanity check
	 */
	if (fi == NULL || fi->vp == NULL || fi->lookupproc == NULL)
		return (EINVAL);
	vp = fi->vp;
	rp = VTOR(vp);
	mi = VTOMI(vp);

	if (!(vp->v_flag & VROOT)) {
		/*
		 * Given the root fh, use the path stored in
		 * the rnode to find the fh for the new server.
		 */
		error = VFS_ROOT(mi->mi_vfsp, &rootvp);
		if (error)
			return (error);

		error = failover_lookup(rp->r_path, rootvp,
		    fi->lookupproc, fi->xattrdirproc, &nvp);

		VN_RELE(rootvp);

		if (error)
			return (error);

		/*
		 * If we found the same rnode, we're done now
		 */
		if (nvp == vp) {
			/*
			 * Failed and the new server may physically be same
			 * OR may share a same disk subsystem. In this case
			 * file handle for a particular file path is not going
			 * to change, given the same filehandle lookup will
			 * always locate the same rnode as the existing one.
			 * All we might need to do is to update the r_server
			 * with the current servinfo.
			 */
			if (!VALID_FH(fi)) {
				rp->r_server = mi->mi_curr_serv;
			}
			VN_RELE(nvp);
			return (0);
		}

		/*
		 * Try to make it so that no one else will find this
		 * vnode because it is just a temporary to hold the
		 * new file handle until that file handle can be
		 * copied to the original vnode/rnode.
		 */
		nrp = VTOR(nvp);
		mutex_enter(&mi->mi_remap_lock);
		/*
		 * Some other thread could have raced in here and could
		 * have done the remap for this particular rnode before
		 * this thread here. Check for rp->r_server and
		 * mi->mi_curr_serv and return if they are same.
		 */
		if (VALID_FH(fi)) {
			mutex_exit(&mi->mi_remap_lock);
			VN_RELE(nvp);
			return (0);
		}

		if (nrp->r_flags & RHASHED)
			rp_rmhash(nrp);

		/*
		 * As a heuristic check on the validity of the new
		 * file, check that the size and type match against
		 * that we remember from the old version.
		 */
		if (rp->r_size != nrp->r_size || vp->v_type != nvp->v_type) {
			mutex_exit(&mi->mi_remap_lock);
			zcmn_err(mi->mi_zone->zone_id, CE_WARN,
			    "NFS replicas %s and %s: file %s not same.",
			    rp->r_server->sv_hostname,
			    nrp->r_server->sv_hostname, rp->r_path);
			VN_RELE(nvp);
			return (EINVAL);
		}

		/*
		 * snarf the filehandle from the new rnode
		 * then release it, again while updating the
		 * hash queues for the rnode.
		 */
		if (rp->r_flags & RHASHED)
			rp_rmhash(rp);
		rp->r_server = mi->mi_curr_serv;
		rp->r_fh = nrp->r_fh;
		rp->r_hashq = nrp->r_hashq;
		/*
		 * Copy the attributes from the new rnode to the old
		 * rnode.  This will help to reduce unnecessary page
		 * cache flushes.
		 */
		rp->r_attr = nrp->r_attr;
		rp->r_attrtime = nrp->r_attrtime;
		rp->r_mtime = nrp->r_mtime;
		(void) nfs_free_data_reclaim(rp);
		nfs_setswaplike(vp, &rp->r_attr);
		rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
		rp_addhash(rp);
		rw_exit(&rp->r_hashq->r_lock);
		mutex_exit(&mi->mi_remap_lock);
		VN_RELE(nvp);
	}

	/*
	 * Update successful failover remap count
	 */
	mutex_enter(&mi->mi_lock);
	mi->mi_remap++;
	mutex_exit(&mi->mi_lock);
#ifdef DEBUG
	nfscl->nfscl_stat.remap.value.ui64++;
#endif

	/*
	 * If we have a copied filehandle to update, do it now.
	 */
	if (fi->fhp != NULL && fi->copyproc != NULL)
		(*fi->copyproc)(fi->fhp, vp);

	return (0);
}

/*
 * NFS client failover support
 *
 * We want a simple pathname lookup routine to parse the pieces
 * of path in rp->r_path.  We know that the path was a created
 * as rnodes were made, so we know we have only to deal with
 * paths that look like:
 *	dir1/dir2/dir3/file
 * Any evidence of anything like .., symlinks, and ENOTDIR
 * are hard errors, because they mean something in this filesystem
 * is different from the one we came from, or has changed under
 * us in some way.  If this is true, we want the failure.
 *
 * Extended attributes: if the filesystem is mounted with extended
 * attributes enabled (-o xattr), the attribute directory will be
 * represented in the r_path as the magic name XATTR_RPATH. So if
 * we see that name in the pathname, is must be because this node
 * is an extended attribute.  Therefore, look it up that way.
 */
static int
failover_lookup(char *path, vnode_t *root,
    int (*lookupproc)(vnode_t *, char *, vnode_t **, struct pathname *, int,
    vnode_t *, cred_t *, int),
    int (*xattrdirproc)(vnode_t *, vnode_t **, bool_t, cred_t *, int),
    vnode_t **new)
{
	vnode_t *dvp, *nvp;
	int error = EINVAL;
	char *s, *p, *tmppath;
	size_t len;
	mntinfo_t *mi;
	bool_t xattr;

	/* Make local copy of path */
	len = strlen(path) + 1;
	tmppath = kmem_alloc(len, KM_SLEEP);
	(void) strcpy(tmppath, path);
	s = tmppath;

	dvp = root;
	VN_HOLD(dvp);
	mi = VTOMI(root);
	xattr = mi->mi_flags & MI_EXTATTR;

	do {
		p = strchr(s, '/');
		if (p != NULL)
			*p = '\0';
		if (xattr && strcmp(s, XATTR_RPATH) == 0) {
			error = (*xattrdirproc)(dvp, &nvp, FALSE, CRED(),
			    RFSCALL_SOFT);
		} else {
			error = (*lookupproc)(dvp, s, &nvp, NULL, 0, NULL,
			    CRED(), RFSCALL_SOFT);
		}
		if (p != NULL)
			*p++ = '/';
		if (error) {
			VN_RELE(dvp);
			kmem_free(tmppath, len);
			return (error);
		}
		s = p;
		VN_RELE(dvp);
		dvp = nvp;
	} while (p != NULL);

	if (nvp != NULL && new != NULL)
		*new = nvp;
	kmem_free(tmppath, len);
	return (0);
}

/*
 * NFS client failover support
 *
 * sv_free() frees the malloc'd portion of a "servinfo_t".
 */
void
sv_free(servinfo_t *svp)
{
	servinfo_t *next;
	struct knetconfig *knconf;

	while (svp != NULL) {
		next = svp->sv_next;
		if (svp->sv_secdata)
			sec_clnt_freeinfo(svp->sv_secdata);
		if (svp->sv_hostname && svp->sv_hostnamelen > 0)
			kmem_free(svp->sv_hostname, svp->sv_hostnamelen);
		knconf = svp->sv_knconf;
		if (knconf != NULL) {
			if (knconf->knc_protofmly != NULL)
				kmem_free(knconf->knc_protofmly, KNC_STRSIZE);
			if (knconf->knc_proto != NULL)
				kmem_free(knconf->knc_proto, KNC_STRSIZE);
			kmem_free(knconf, sizeof (*knconf));
		}
		knconf = svp->sv_origknconf;
		if (knconf != NULL) {
			if (knconf->knc_protofmly != NULL)
				kmem_free(knconf->knc_protofmly, KNC_STRSIZE);
			if (knconf->knc_proto != NULL)
				kmem_free(knconf->knc_proto, KNC_STRSIZE);
			kmem_free(knconf, sizeof (*knconf));
		}
		if (svp->sv_addr.buf != NULL && svp->sv_addr.maxlen != 0)
			kmem_free(svp->sv_addr.buf, svp->sv_addr.maxlen);
		mutex_destroy(&svp->sv_lock);
		kmem_free(svp, sizeof (*svp));
		svp = next;
	}
}

/*
 * Only can return non-zero if intr != 0.
 */
int
nfs_rw_enter_sig(nfs_rwlock_t *l, krw_t rw, int intr)
{

	mutex_enter(&l->lock);

	/*
	 * If this is a nested enter, then allow it.  There
	 * must be as many exits as enters through.
	 */
	if (l->owner == curthread) {
		/* lock is held for writing by current thread */
		ASSERT(rw == RW_READER || rw == RW_WRITER);
		l->count--;
	} else if (rw == RW_READER) {
		/*
		 * While there is a writer active or writers waiting,
		 * then wait for them to finish up and move on.  Then,
		 * increment the count to indicate that a reader is
		 * active.
		 */
		while (l->count < 0 || l->waiters > 0) {
			if (intr) {
				klwp_t *lwp = ttolwp(curthread);

				if (lwp != NULL)
					lwp->lwp_nostop++;
				if (cv_wait_sig(&l->cv_rd, &l->lock) == 0) {
					if (lwp != NULL)
						lwp->lwp_nostop--;
					mutex_exit(&l->lock);
					return (EINTR);
				}
				if (lwp != NULL)
					lwp->lwp_nostop--;
			} else
				cv_wait(&l->cv_rd, &l->lock);
		}
		ASSERT(l->count < INT_MAX);
#ifdef	DEBUG
		if ((l->count % 10000) == 9999)
			cmn_err(CE_WARN, "nfs_rw_enter_sig: count %d on"
			    "rwlock @ %p\n", l->count, (void *)&l);
#endif
		l->count++;
	} else {
		ASSERT(rw == RW_WRITER);
		/*
		 * While there are readers active or a writer
		 * active, then wait for all of the readers
		 * to finish or for the writer to finish.
		 * Then, set the owner field to curthread and
		 * decrement count to indicate that a writer
		 * is active.
		 */
		while (l->count != 0) {
			l->waiters++;
			if (intr) {
				klwp_t *lwp = ttolwp(curthread);

				if (lwp != NULL)
					lwp->lwp_nostop++;
				if (cv_wait_sig(&l->cv, &l->lock) == 0) {
					if (lwp != NULL)
						lwp->lwp_nostop--;
					l->waiters--;
					/*
					 * If there are readers active and no
					 * writers waiting then wake up all of
					 * the waiting readers (if any).
					 */
					if (l->count > 0 && l->waiters == 0)
						cv_broadcast(&l->cv_rd);
					mutex_exit(&l->lock);
					return (EINTR);
				}
				if (lwp != NULL)
					lwp->lwp_nostop--;
			} else
				cv_wait(&l->cv, &l->lock);
			l->waiters--;
		}
		ASSERT(l->owner == NULL);
		l->owner = curthread;
		l->count--;
	}

	mutex_exit(&l->lock);

	return (0);
}

/*
 * If the lock is available, obtain it and return non-zero.  If there is
 * already a conflicting lock, return 0 immediately.
 */

int
nfs_rw_tryenter(nfs_rwlock_t *l, krw_t rw)
{
	mutex_enter(&l->lock);

	/*
	 * If this is a nested enter, then allow it.  There
	 * must be as many exits as enters through.
	 */
	if (l->owner == curthread) {
		/* lock is held for writing by current thread */
		ASSERT(rw == RW_READER || rw == RW_WRITER);
		l->count--;
	} else if (rw == RW_READER) {
		/*
		 * If there is a writer active or writers waiting, deny the
		 * lock.  Otherwise, bump the count of readers.
		 */
		if (l->count < 0 || l->waiters > 0) {
			mutex_exit(&l->lock);
			return (0);
		}
		l->count++;
	} else {
		ASSERT(rw == RW_WRITER);
		/*
		 * If there are readers active or a writer active, deny the
		 * lock.  Otherwise, set the owner field to curthread and
		 * decrement count to indicate that a writer is active.
		 */
		if (l->count != 0) {
			mutex_exit(&l->lock);
			return (0);
		}
		ASSERT(l->owner == NULL);
		l->owner = curthread;
		l->count--;
	}

	mutex_exit(&l->lock);

	return (1);
}

void
nfs_rw_exit(nfs_rwlock_t *l)
{

	mutex_enter(&l->lock);

	if (l->owner != NULL) {
		ASSERT(l->owner == curthread);

		/*
		 * To release a writer lock increment count to indicate that
		 * there is one less writer active.  If this was the last of
		 * possibly nested writer locks, then clear the owner field as
		 * well to indicate that there is no writer active.
		 */
		ASSERT(l->count < 0);
		l->count++;
		if (l->count == 0) {
			l->owner = NULL;

			/*
			 * If there are no writers waiting then wakeup all of
			 * the waiting readers (if any).
			 */
			if (l->waiters == 0)
				cv_broadcast(&l->cv_rd);
		}
	} else {
		/*
		 * To release a reader lock just decrement count to indicate
		 * that there is one less reader active.
		 */
		ASSERT(l->count > 0);
		l->count--;
	}

	/*
	 * If there are no readers active nor a writer active and there is a
	 * writer waiting we need to wake up it.
	 */
	if (l->count == 0 && l->waiters > 0)
		cv_signal(&l->cv);
	mutex_exit(&l->lock);
}

int
nfs_rw_lock_held(nfs_rwlock_t *l, krw_t rw)
{

	if (rw == RW_READER)
		return (l->count > 0);
	ASSERT(rw == RW_WRITER);
	return (l->count < 0);
}

/* ARGSUSED */
void
nfs_rw_init(nfs_rwlock_t *l, char *name, krw_type_t type, void *arg)
{

	l->count = 0;
	l->waiters = 0;
	l->owner = NULL;
	mutex_init(&l->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&l->cv, NULL, CV_DEFAULT, NULL);
	cv_init(&l->cv_rd, NULL, CV_DEFAULT, NULL);
}

void
nfs_rw_destroy(nfs_rwlock_t *l)
{

	mutex_destroy(&l->lock);
	cv_destroy(&l->cv);
	cv_destroy(&l->cv_rd);
}

int
nfs3_rddir_compar(const void *x, const void *y)
{
	rddir_cache *a = (rddir_cache *)x;
	rddir_cache *b = (rddir_cache *)y;

	if (a->nfs3_cookie == b->nfs3_cookie) {
		if (a->buflen == b->buflen)
			return (0);
		if (a->buflen < b->buflen)
			return (-1);
		return (1);
	}

	if (a->nfs3_cookie < b->nfs3_cookie)
		return (-1);

	return (1);
}

int
nfs_rddir_compar(const void *x, const void *y)
{
	rddir_cache *a = (rddir_cache *)x;
	rddir_cache *b = (rddir_cache *)y;

	if (a->nfs_cookie == b->nfs_cookie) {
		if (a->buflen == b->buflen)
			return (0);
		if (a->buflen < b->buflen)
			return (-1);
		return (1);
	}

	if (a->nfs_cookie < b->nfs_cookie)
		return (-1);

	return (1);
}

static char *
nfs_getsrvnames(mntinfo_t *mi, size_t *len)
{
	servinfo_t *s;
	char *srvnames;
	char *namep;
	size_t length;

	/*
	 * Calculate the length of the string required to hold all
	 * of the server names plus either a comma or a null
	 * character following each individual one.
	 */
	length = 0;
	for (s = mi->mi_servers; s != NULL; s = s->sv_next)
		length += s->sv_hostnamelen;

	srvnames = kmem_alloc(length, KM_SLEEP);

	namep = srvnames;
	for (s = mi->mi_servers; s != NULL; s = s->sv_next) {
		(void) strcpy(namep, s->sv_hostname);
		namep += s->sv_hostnamelen - 1;
		*namep++ = ',';
	}
	*--namep = '\0';

	*len = length;

	return (srvnames);
}

/*
 * These two functions are temporary and designed for the upgrade-workaround
 * only.  They cannot be used for general zone-crossing NFS client support, and
 * will be removed shortly.
 *
 * When the workaround is enabled, all NFS traffic is forced into the global
 * zone.  These functions are called when the code needs to refer to the state
 * of the underlying network connection.  They're not called when the function
 * needs to refer to the state of the process that invoked the system call.
 * (E.g., when checking whether the zone is shutting down during the mount()
 * call.)
 */

struct zone *
nfs_zone(void)
{
	return (nfs_global_client_only != 0 ? global_zone : curproc->p_zone);
}

zoneid_t
nfs_zoneid(void)
{
	return (nfs_global_client_only != 0 ? GLOBAL_ZONEID : getzoneid());
}

/*
 * nfs_mount_label_policy:
 *	Determine whether the mount is allowed according to MAC check,
 *	by comparing (where appropriate) label of the remote server
 *	against the label of the zone being mounted into.
 *
 *	Returns:
 *		 0 :	access allowed
 *		-1 :	read-only access allowed (i.e., read-down)
 *		>0 :	error code, such as EACCES
 */
int
nfs_mount_label_policy(vfs_t *vfsp, struct netbuf *addr,
    struct knetconfig *knconf, cred_t *cr)
{
	int		addr_type;
	void		*ipaddr;
	bslabel_t	*server_sl, *mntlabel;
	zone_t		*mntzone = NULL;
	ts_label_t	*zlabel;
	tsol_tpc_t	*tp;
	ts_label_t	*tsl = NULL;
	int		retv;

	/*
	 * Get the zone's label.  Each zone on a labeled system has a label.
	 */
	mntzone = zone_find_by_any_path(refstr_value(vfsp->vfs_mntpt), B_FALSE);
	zlabel = mntzone->zone_slabel;
	ASSERT(zlabel != NULL);
	label_hold(zlabel);

	if (strcmp(knconf->knc_protofmly, NC_INET) == 0) {
		addr_type = IPV4_VERSION;
		ipaddr = &((struct sockaddr_in *)addr->buf)->sin_addr;
	} else if (strcmp(knconf->knc_protofmly, NC_INET6) == 0) {
		addr_type = IPV6_VERSION;
		ipaddr = &((struct sockaddr_in6 *)addr->buf)->sin6_addr;
	} else {
		retv = 0;
		goto out;
	}

	retv = EACCES;				/* assume the worst */

	/*
	 * Next, get the assigned label of the remote server.
	 */
	tp = find_tpc(ipaddr, addr_type, B_FALSE);
	if (tp == NULL)
		goto out;			/* error getting host entry */

	if (tp->tpc_tp.tp_doi != zlabel->tsl_doi)
		goto rel_tpc;			/* invalid domain */
	if ((tp->tpc_tp.host_type != SUN_CIPSO) &&
	    (tp->tpc_tp.host_type != UNLABELED))
		goto rel_tpc;			/* invalid hosttype */

	if (tp->tpc_tp.host_type == SUN_CIPSO) {
		tsl = getflabel_cipso(vfsp);
		if (tsl == NULL)
			goto rel_tpc;		/* error getting server lbl */

		server_sl = label2bslabel(tsl);
	} else {	/* UNLABELED */
		server_sl = &tp->tpc_tp.tp_def_label;
	}

	mntlabel = label2bslabel(zlabel);

	/*
	 * Now compare labels to complete the MAC check.  If the labels
	 * are equal or if the requestor is in the global zone and has
	 * NET_MAC_AWARE, then allow read-write access.   (Except for
	 * mounts into the global zone itself; restrict these to
	 * read-only.)
	 *
	 * If the requestor is in some other zone, but their label
	 * dominates the server, then allow read-down.
	 *
	 * Otherwise, access is denied.
	 */
	if (blequal(mntlabel, server_sl) ||
	    (crgetzoneid(cr) == GLOBAL_ZONEID &&
	    getpflags(NET_MAC_AWARE, cr) != 0)) {
		if ((mntzone == global_zone) ||
		    !blequal(mntlabel, server_sl))
			retv = -1;		/* read-only */
		else
			retv = 0;		/* access OK */
	} else if (bldominates(mntlabel, server_sl)) {
		retv = -1;			/* read-only */
	} else {
		retv = EACCES;
	}

	if (tsl != NULL)
		label_rele(tsl);

rel_tpc:
	TPC_RELE(tp);
out:
	if (mntzone)
		zone_rele(mntzone);
	label_rele(zlabel);
	return (retv);
}

boolean_t
nfs_has_ctty(void)
{
	boolean_t rv;
	mutex_enter(&curproc->p_splock);
	rv = (curproc->p_sessp->s_vp != NULL);
	mutex_exit(&curproc->p_splock);
	return (rv);
}

/*
 * See if xattr directory to see if it has any generic user attributes
 */
int
do_xattr_exists_check(vnode_t *vp, ulong_t *valp, cred_t *cr)
{
	struct uio uio;
	struct iovec iov;
	char *dbuf;
	struct dirent64 *dp;
	size_t dlen = 8 * 1024;
	size_t dbuflen;
	int eof = 0;
	int error;

	*valp = 0;
	dbuf = kmem_alloc(dlen, KM_SLEEP);
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_loffset = 0;
	uio.uio_resid = dlen;
	iov.iov_base = dbuf;
	iov.iov_len = dlen;
	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
	error = VOP_READDIR(vp, &uio, cr, &eof, NULL, 0);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);

	dbuflen = dlen - uio.uio_resid;

	if (error || dbuflen == 0) {
		kmem_free(dbuf, dlen);
		return (error);
	}

	dp = (dirent64_t *)dbuf;

	while ((intptr_t)dp < (intptr_t)dbuf + dbuflen) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0 || strcmp(dp->d_name,
		    VIEW_READWRITE) == 0 || strcmp(dp->d_name,
		    VIEW_READONLY) == 0) {
			dp = (dirent64_t *)((intptr_t)dp + dp->d_reclen);
			continue;
		}

		*valp = 1;
		break;
	}
	kmem_free(dbuf, dlen);
	return (0);
}
