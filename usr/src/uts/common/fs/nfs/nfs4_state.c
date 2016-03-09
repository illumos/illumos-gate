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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <sys/clconf.h>
#include <sys/cladm.h>
#include <sys/flock.h>
#include <nfs/export.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfssys.h>
#include <nfs/lm.h>
#include <sys/pathname.h>
#include <sys/sdt.h>
#include <sys/nvpair.h>

extern u_longlong_t nfs4_srv_caller_id;

extern time_t rfs4_start_time;
extern uint_t nfs4_srv_vkey;

stateid4 special0 = {
	0,
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

stateid4 special1 = {
	0xffffffff,
	{
		(char)0xff, (char)0xff, (char)0xff, (char)0xff,
		(char)0xff, (char)0xff, (char)0xff, (char)0xff,
		(char)0xff, (char)0xff, (char)0xff, (char)0xff
	}
};


#define	ISSPECIAL(id)  (stateid4_cmp(id, &special0) || \
			stateid4_cmp(id, &special1))

/* For embedding the cluster nodeid into our clientid */
#define	CLUSTER_NODEID_SHIFT	24
#define	CLUSTER_MAX_NODEID	255

#ifdef DEBUG
int rfs4_debug;
#endif

static uint32_t rfs4_database_debug = 0x00;

static void rfs4_ss_clid_write(rfs4_client_t *cp, char *leaf);
static void rfs4_ss_clid_write_one(rfs4_client_t *cp, char *dir, char *leaf);
static void rfs4_dss_clear_oldstate(rfs4_servinst_t *sip);
static void rfs4_ss_chkclid_sip(rfs4_client_t *cp, rfs4_servinst_t *sip);

/*
 * Couple of simple init/destroy functions for a general waiter
 */
void
rfs4_sw_init(rfs4_state_wait_t *swp)
{
	mutex_init(swp->sw_cv_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(swp->sw_cv, NULL, CV_DEFAULT, NULL);
	swp->sw_active = FALSE;
	swp->sw_wait_count = 0;
}

void
rfs4_sw_destroy(rfs4_state_wait_t *swp)
{
	mutex_destroy(swp->sw_cv_lock);
	cv_destroy(swp->sw_cv);
}

void
rfs4_sw_enter(rfs4_state_wait_t *swp)
{
	mutex_enter(swp->sw_cv_lock);
	while (swp->sw_active) {
		swp->sw_wait_count++;
		cv_wait(swp->sw_cv, swp->sw_cv_lock);
		swp->sw_wait_count--;
	}
	ASSERT(swp->sw_active == FALSE);
	swp->sw_active = TRUE;
	mutex_exit(swp->sw_cv_lock);
}

void
rfs4_sw_exit(rfs4_state_wait_t *swp)
{
	mutex_enter(swp->sw_cv_lock);
	ASSERT(swp->sw_active == TRUE);
	swp->sw_active = FALSE;
	if (swp->sw_wait_count != 0)
		cv_broadcast(swp->sw_cv);
	mutex_exit(swp->sw_cv_lock);
}

/*
 * CPR callback id -- not related to v4 callbacks
 */
static callb_id_t cpr_id = 0;

static void
deep_lock_copy(LOCK4res *dres, LOCK4res *sres)
{
	lock_owner4 *slo = &sres->LOCK4res_u.denied.owner;
	lock_owner4 *dlo = &dres->LOCK4res_u.denied.owner;

	if (sres->status == NFS4ERR_DENIED) {
		dlo->owner_val = kmem_alloc(slo->owner_len, KM_SLEEP);
		bcopy(slo->owner_val, dlo->owner_val, slo->owner_len);
	}
}

static void
deep_lock_free(LOCK4res *res)
{
	lock_owner4 *lo = &res->LOCK4res_u.denied.owner;

	if (res->status == NFS4ERR_DENIED)
		kmem_free(lo->owner_val, lo->owner_len);
}

static void
deep_open_copy(OPEN4res *dres, OPEN4res *sres)
{
	nfsace4 *sacep, *dacep;

	if (sres->status != NFS4_OK) {
		return;
	}

	dres->attrset = sres->attrset;

	switch (sres->delegation.delegation_type) {
	case OPEN_DELEGATE_NONE:
		return;
	case OPEN_DELEGATE_READ:
		sacep = &sres->delegation.open_delegation4_u.read.permissions;
		dacep = &dres->delegation.open_delegation4_u.read.permissions;
		break;
	case OPEN_DELEGATE_WRITE:
		sacep = &sres->delegation.open_delegation4_u.write.permissions;
		dacep = &dres->delegation.open_delegation4_u.write.permissions;
		break;
	}
	dacep->who.utf8string_val =
	    kmem_alloc(sacep->who.utf8string_len, KM_SLEEP);
	bcopy(sacep->who.utf8string_val, dacep->who.utf8string_val,
	    sacep->who.utf8string_len);
}

static void
deep_open_free(OPEN4res *res)
{
	nfsace4 *acep;
	if (res->status != NFS4_OK)
		return;

	switch (res->delegation.delegation_type) {
	case OPEN_DELEGATE_NONE:
		return;
	case OPEN_DELEGATE_READ:
		acep = &res->delegation.open_delegation4_u.read.permissions;
		break;
	case OPEN_DELEGATE_WRITE:
		acep = &res->delegation.open_delegation4_u.write.permissions;
		break;
	}

	if (acep->who.utf8string_val) {
		kmem_free(acep->who.utf8string_val, acep->who.utf8string_len);
		acep->who.utf8string_val = NULL;
	}
}

void
rfs4_free_reply(nfs_resop4 *rp)
{
	switch (rp->resop) {
	case OP_LOCK:
		deep_lock_free(&rp->nfs_resop4_u.oplock);
		break;
	case OP_OPEN:
		deep_open_free(&rp->nfs_resop4_u.opopen);
	default:
		break;
	}
}

void
rfs4_copy_reply(nfs_resop4 *dst, nfs_resop4 *src)
{
	*dst = *src;

	/* Handle responses that need deep copy */
	switch (src->resop) {
	case OP_LOCK:
		deep_lock_copy(&dst->nfs_resop4_u.oplock,
		    &src->nfs_resop4_u.oplock);
		break;
	case OP_OPEN:
		deep_open_copy(&dst->nfs_resop4_u.opopen,
		    &src->nfs_resop4_u.opopen);
		break;
	default:
		break;
	};
}

/*
 * This is the implementation of the underlying state engine. The
 * public interface to this engine is described by
 * nfs4_state.h. Callers to the engine should hold no state engine
 * locks when they call in to it. If the protocol needs to lock data
 * structures it should do so after acquiring all references to them
 * first and then follow the following lock order:
 *
 *	client > openowner > state > lo_state > lockowner > file.
 *
 * Internally we only allow a thread to hold one hash bucket lock at a
 * time and the lock is higher in the lock order (must be acquired
 * first) than the data structure that is on that hash list.
 *
 * If a new reference was acquired by the caller, that reference needs
 * to be released after releasing all acquired locks with the
 * corresponding rfs4_*_rele routine.
 */

/*
 * This code is some what prototypical for now. Its purpose currently is to
 * implement the interfaces sufficiently to finish the higher protocol
 * elements. This will be replaced by a dynamically resizeable tables
 * backed by kmem_cache allocator. However synchronization is handled
 * correctly (I hope) and will not change by much.  The mutexes for
 * the hash buckets that can be used to create new instances of data
 * structures  might be good candidates to evolve into reader writer
 * locks. If it has to do a creation, it would be holding the
 * mutex across a kmem_alloc with KM_SLEEP specified.
 */

#ifdef DEBUG
#define	TABSIZE 17
#else
#define	TABSIZE 2047
#endif

#define	ADDRHASH(key) ((unsigned long)(key) >> 3)

/* Used to serialize create/destroy of rfs4_server_state database */
kmutex_t	rfs4_state_lock;
static rfs4_database_t *rfs4_server_state = NULL;

/* Used to serialize lookups of clientids */
static	krwlock_t	rfs4_findclient_lock;

/*
 * For now this "table" is exposed so that the CPR callback
 * function can tromp through it..
 */
rfs4_table_t *rfs4_client_tab;

static rfs4_index_t *rfs4_clientid_idx;
static rfs4_index_t *rfs4_nfsclnt_idx;
static rfs4_table_t *rfs4_clntip_tab;
static rfs4_index_t *rfs4_clntip_idx;
static rfs4_table_t *rfs4_openowner_tab;
static rfs4_index_t *rfs4_openowner_idx;
static rfs4_table_t *rfs4_state_tab;
static rfs4_index_t *rfs4_state_idx;
static rfs4_index_t *rfs4_state_owner_file_idx;
static rfs4_index_t *rfs4_state_file_idx;
static rfs4_table_t *rfs4_lo_state_tab;
static rfs4_index_t *rfs4_lo_state_idx;
static rfs4_index_t *rfs4_lo_state_owner_idx;
static rfs4_table_t *rfs4_lockowner_tab;
static rfs4_index_t *rfs4_lockowner_idx;
static rfs4_index_t *rfs4_lockowner_pid_idx;
static rfs4_table_t *rfs4_file_tab;
static rfs4_index_t *rfs4_file_idx;
static rfs4_table_t *rfs4_deleg_state_tab;
static rfs4_index_t *rfs4_deleg_idx;
static rfs4_index_t *rfs4_deleg_state_idx;

#define	MAXTABSZ 1024*1024

/* The values below are rfs4_lease_time units */

#ifdef DEBUG
#define	CLIENT_CACHE_TIME 1
#define	OPENOWNER_CACHE_TIME 1
#define	STATE_CACHE_TIME 1
#define	LO_STATE_CACHE_TIME 1
#define	LOCKOWNER_CACHE_TIME 1
#define	FILE_CACHE_TIME 3
#define	DELEG_STATE_CACHE_TIME 1
#else
#define	CLIENT_CACHE_TIME 10
#define	OPENOWNER_CACHE_TIME 5
#define	STATE_CACHE_TIME 1
#define	LO_STATE_CACHE_TIME 1
#define	LOCKOWNER_CACHE_TIME 3
#define	FILE_CACHE_TIME 40
#define	DELEG_STATE_CACHE_TIME 1
#endif


static time_t rfs4_client_cache_time = 0;
static time_t rfs4_clntip_cache_time = 0;
static time_t rfs4_openowner_cache_time = 0;
static time_t rfs4_state_cache_time = 0;
static time_t rfs4_lo_state_cache_time = 0;
static time_t rfs4_lockowner_cache_time = 0;
static time_t rfs4_file_cache_time = 0;
static time_t rfs4_deleg_state_cache_time = 0;

static bool_t rfs4_client_create(rfs4_entry_t, void *);
static void rfs4_dss_remove_cpleaf(rfs4_client_t *);
static void rfs4_dss_remove_leaf(rfs4_servinst_t *, char *, char *);
static void rfs4_client_destroy(rfs4_entry_t);
static bool_t rfs4_client_expiry(rfs4_entry_t);
static uint32_t clientid_hash(void *);
static bool_t clientid_compare(rfs4_entry_t, void *);
static void *clientid_mkkey(rfs4_entry_t);
static uint32_t nfsclnt_hash(void *);
static bool_t nfsclnt_compare(rfs4_entry_t, void *);
static void *nfsclnt_mkkey(rfs4_entry_t);
static bool_t rfs4_clntip_expiry(rfs4_entry_t);
static void rfs4_clntip_destroy(rfs4_entry_t);
static bool_t rfs4_clntip_create(rfs4_entry_t, void *);
static uint32_t clntip_hash(void *);
static bool_t clntip_compare(rfs4_entry_t, void *);
static void *clntip_mkkey(rfs4_entry_t);
static bool_t rfs4_openowner_create(rfs4_entry_t, void *);
static void rfs4_openowner_destroy(rfs4_entry_t);
static bool_t rfs4_openowner_expiry(rfs4_entry_t);
static uint32_t openowner_hash(void *);
static bool_t openowner_compare(rfs4_entry_t, void *);
static void *openowner_mkkey(rfs4_entry_t);
static bool_t rfs4_state_create(rfs4_entry_t, void *);
static void rfs4_state_destroy(rfs4_entry_t);
static bool_t rfs4_state_expiry(rfs4_entry_t);
static uint32_t state_hash(void *);
static bool_t state_compare(rfs4_entry_t, void *);
static void *state_mkkey(rfs4_entry_t);
static uint32_t state_owner_file_hash(void *);
static bool_t state_owner_file_compare(rfs4_entry_t, void *);
static void *state_owner_file_mkkey(rfs4_entry_t);
static uint32_t state_file_hash(void *);
static bool_t state_file_compare(rfs4_entry_t, void *);
static void *state_file_mkkey(rfs4_entry_t);
static bool_t rfs4_lo_state_create(rfs4_entry_t, void *);
static void rfs4_lo_state_destroy(rfs4_entry_t);
static bool_t rfs4_lo_state_expiry(rfs4_entry_t);
static uint32_t lo_state_hash(void *);
static bool_t lo_state_compare(rfs4_entry_t, void *);
static void *lo_state_mkkey(rfs4_entry_t);
static uint32_t lo_state_lo_hash(void *);
static bool_t lo_state_lo_compare(rfs4_entry_t, void *);
static void *lo_state_lo_mkkey(rfs4_entry_t);
static bool_t rfs4_lockowner_create(rfs4_entry_t, void *);
static void rfs4_lockowner_destroy(rfs4_entry_t);
static bool_t rfs4_lockowner_expiry(rfs4_entry_t);
static uint32_t lockowner_hash(void *);
static bool_t lockowner_compare(rfs4_entry_t, void *);
static void *lockowner_mkkey(rfs4_entry_t);
static uint32_t pid_hash(void *);
static bool_t pid_compare(rfs4_entry_t, void *);
static void *pid_mkkey(rfs4_entry_t);
static bool_t rfs4_file_create(rfs4_entry_t, void *);
static void rfs4_file_destroy(rfs4_entry_t);
static uint32_t file_hash(void *);
static bool_t file_compare(rfs4_entry_t, void *);
static void *file_mkkey(rfs4_entry_t);
static bool_t rfs4_deleg_state_create(rfs4_entry_t, void *);
static void rfs4_deleg_state_destroy(rfs4_entry_t);
static bool_t rfs4_deleg_state_expiry(rfs4_entry_t);
static uint32_t deleg_hash(void *);
static bool_t deleg_compare(rfs4_entry_t, void *);
static void *deleg_mkkey(rfs4_entry_t);
static uint32_t deleg_state_hash(void *);
static bool_t deleg_state_compare(rfs4_entry_t, void *);
static void *deleg_state_mkkey(rfs4_entry_t);

static void rfs4_state_rele_nounlock(rfs4_state_t *);

static int rfs4_ss_enabled = 0;

extern void (*rfs4_client_clrst)(struct nfs4clrst_args *);

void
rfs4_ss_pnfree(rfs4_ss_pn_t *ss_pn)
{
	kmem_free(ss_pn, sizeof (rfs4_ss_pn_t));
}

static rfs4_ss_pn_t *
rfs4_ss_pnalloc(char *dir, char *leaf)
{
	rfs4_ss_pn_t *ss_pn;
	int 	dir_len, leaf_len;

	/*
	 * validate we have a resonable path
	 * (account for the '/' and trailing null)
	 */
	if ((dir_len = strlen(dir)) > MAXPATHLEN ||
	    (leaf_len = strlen(leaf)) > MAXNAMELEN ||
	    (dir_len + leaf_len + 2) > MAXPATHLEN) {
		return (NULL);
	}

	ss_pn = kmem_alloc(sizeof (rfs4_ss_pn_t), KM_SLEEP);

	(void) snprintf(ss_pn->pn, MAXPATHLEN, "%s/%s", dir, leaf);
	/* Handy pointer to just the leaf name */
	ss_pn->leaf = ss_pn->pn + dir_len + 1;
	return (ss_pn);
}


/*
 * Move the "leaf" filename from "sdir" directory
 * to the "ddir" directory. Return the pathname of
 * the destination unless the rename fails in which
 * case we need to return the source pathname.
 */
static rfs4_ss_pn_t *
rfs4_ss_movestate(char *sdir, char *ddir, char *leaf)
{
	rfs4_ss_pn_t *src, *dst;

	if ((src = rfs4_ss_pnalloc(sdir, leaf)) == NULL)
		return (NULL);

	if ((dst = rfs4_ss_pnalloc(ddir, leaf)) == NULL) {
		rfs4_ss_pnfree(src);
		return (NULL);
	}

	/*
	 * If the rename fails we shall return the src
	 * pathname and free the dst. Otherwise we need
	 * to free the src and return the dst pathanme.
	 */
	if (vn_rename(src->pn, dst->pn, UIO_SYSSPACE)) {
		rfs4_ss_pnfree(dst);
		return (src);
	}
	rfs4_ss_pnfree(src);
	return (dst);
}


static rfs4_oldstate_t *
rfs4_ss_getstate(vnode_t *dvp, rfs4_ss_pn_t *ss_pn)
{
	struct uio uio;
	struct iovec iov[3];

	rfs4_oldstate_t *cl_ss = NULL;
	vnode_t *vp;
	vattr_t va;
	uint_t id_len;
	int err, kill_file, file_vers;

	if (ss_pn == NULL)
		return (NULL);

	/*
	 * open the state file.
	 */
	if (vn_open(ss_pn->pn, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0) != 0) {
		return (NULL);
	}

	if (vp->v_type != VREG) {
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		return (NULL);
	}

	err = VOP_ACCESS(vp, VREAD, 0, CRED(), NULL);
	if (err) {
		/*
		 * We don't have read access? better get the heck out.
		 */
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		return (NULL);
	}

	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
	/*
	 * get the file size to do some basic validation
	 */
	va.va_mask = AT_SIZE;
	err = VOP_GETATTR(vp, &va, 0, CRED(), NULL);

	kill_file = (va.va_size == 0 || va.va_size <
	    (NFS4_VERIFIER_SIZE + sizeof (uint_t)+1));

	if (err || kill_file) {
		VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		if (kill_file) {
			(void) VOP_REMOVE(dvp, ss_pn->leaf, CRED(), NULL, 0);
		}
		return (NULL);
	}

	cl_ss = kmem_alloc(sizeof (rfs4_oldstate_t), KM_SLEEP);

	/*
	 * build iovecs to read in the file_version, verifier and id_len
	 */
	iov[0].iov_base = (caddr_t)&file_vers;
	iov[0].iov_len = sizeof (int);
	iov[1].iov_base = (caddr_t)&cl_ss->cl_id4.verifier;
	iov[1].iov_len = NFS4_VERIFIER_SIZE;
	iov[2].iov_base = (caddr_t)&id_len;
	iov[2].iov_len = sizeof (uint_t);

	uio.uio_iov = iov;
	uio.uio_iovcnt = 3;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_loffset = 0;
	uio.uio_resid = sizeof (int) + NFS4_VERIFIER_SIZE + sizeof (uint_t);

	if (err = VOP_READ(vp, &uio, FREAD, CRED(), NULL)) {
		VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		kmem_free(cl_ss, sizeof (rfs4_oldstate_t));
		return (NULL);
	}

	/*
	 * if the file_version doesn't match or if the
	 * id_len is zero or the combination of the verifier,
	 * id_len and id_val is bigger than the file we have
	 * a problem. If so ditch the file.
	 */
	kill_file = (file_vers != NFS4_SS_VERSION || id_len == 0 ||
	    (id_len + NFS4_VERIFIER_SIZE + sizeof (uint_t)) > va.va_size);

	if (err || kill_file) {
		VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		kmem_free(cl_ss, sizeof (rfs4_oldstate_t));
		if (kill_file) {
			(void) VOP_REMOVE(dvp, ss_pn->leaf, CRED(), NULL, 0);
		}
		return (NULL);
	}

	/*
	 * now get the client id value
	 */
	cl_ss->cl_id4.id_val = kmem_alloc(id_len, KM_SLEEP);
	iov[0].iov_base = cl_ss->cl_id4.id_val;
	iov[0].iov_len = id_len;

	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_resid = cl_ss->cl_id4.id_len = id_len;

	if (err = VOP_READ(vp, &uio, FREAD, CRED(), NULL)) {
		VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		kmem_free(cl_ss->cl_id4.id_val, id_len);
		kmem_free(cl_ss, sizeof (rfs4_oldstate_t));
		return (NULL);
	}

	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);
	return (cl_ss);
}

#ifdef	nextdp
#undef nextdp
#endif
#define	nextdp(dp)	((struct dirent64 *)((char *)(dp) + (dp)->d_reclen))

/*
 * Add entries from statedir to supplied oldstate list.
 * Optionally, move all entries from statedir -> destdir.
 */
void
rfs4_ss_oldstate(rfs4_oldstate_t *oldstate, char *statedir, char *destdir)
{
	rfs4_ss_pn_t *ss_pn;
	rfs4_oldstate_t *cl_ss = NULL;
	char	*dirt = NULL;
	int	err, dir_eof = 0, size = 0;
	vnode_t *dvp;
	struct iovec iov;
	struct uio uio;
	struct dirent64 *dep;
	offset_t dirchunk_offset = 0;

	/*
	 * open the state directory
	 */
	if (vn_open(statedir, UIO_SYSSPACE, FREAD, 0, &dvp, 0, 0))
		return;

	if (dvp->v_type != VDIR || VOP_ACCESS(dvp, VREAD, 0, CRED(), NULL))
		goto out;

	dirt = kmem_alloc(RFS4_SS_DIRSIZE, KM_SLEEP);

	/*
	 * Get and process the directory entries
	 */
	while (!dir_eof) {
		(void) VOP_RWLOCK(dvp, V_WRITELOCK_FALSE, NULL);
		iov.iov_base = dirt;
		iov.iov_len = RFS4_SS_DIRSIZE;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_loffset = dirchunk_offset;
		uio.uio_resid = RFS4_SS_DIRSIZE;

		err = VOP_READDIR(dvp, &uio, CRED(), &dir_eof, NULL, 0);
		VOP_RWUNLOCK(dvp, V_WRITELOCK_FALSE, NULL);
		if (err)
			goto out;

		size = RFS4_SS_DIRSIZE - uio.uio_resid;

		/*
		 * Process all the directory entries in this
		 * readdir chunk
		 */
		for (dep = (struct dirent64 *)dirt; size > 0;
		    dep = nextdp(dep)) {

			size -= dep->d_reclen;
			dirchunk_offset = dep->d_off;

			/*
			 * Skip '.' and '..'
			 */
			if (NFS_IS_DOTNAME(dep->d_name))
				continue;

			ss_pn = rfs4_ss_pnalloc(statedir, dep->d_name);
			if (ss_pn == NULL)
				continue;

			if (cl_ss = rfs4_ss_getstate(dvp, ss_pn)) {
				if (destdir != NULL) {
					rfs4_ss_pnfree(ss_pn);
					cl_ss->ss_pn = rfs4_ss_movestate(
					    statedir, destdir, dep->d_name);
				} else {
					cl_ss->ss_pn = ss_pn;
				}
				insque(cl_ss, oldstate);
			} else {
				rfs4_ss_pnfree(ss_pn);
			}
		}
	}

out:
	(void) VOP_CLOSE(dvp, FREAD, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(dvp);
	if (dirt)
		kmem_free((caddr_t)dirt, RFS4_SS_DIRSIZE);
}

static void
rfs4_ss_init(void)
{
	int npaths = 1;
	char *default_dss_path = NFS4_DSS_VAR_DIR;

	/* read the default stable storage state */
	rfs4_dss_readstate(npaths, &default_dss_path);

	rfs4_ss_enabled = 1;
}

static void
rfs4_ss_fini(void)
{
	rfs4_servinst_t *sip;

	mutex_enter(&rfs4_servinst_lock);
	sip = rfs4_cur_servinst;
	while (sip != NULL) {
		rfs4_dss_clear_oldstate(sip);
		sip = sip->next;
	}
	mutex_exit(&rfs4_servinst_lock);
}

/*
 * Remove all oldstate files referenced by this servinst.
 */
static void
rfs4_dss_clear_oldstate(rfs4_servinst_t *sip)
{
	rfs4_oldstate_t *os_head, *osp;

	rw_enter(&sip->oldstate_lock, RW_WRITER);
	os_head = sip->oldstate;

	if (os_head == NULL) {
		rw_exit(&sip->oldstate_lock);
		return;
	}

	/* skip dummy entry */
	osp = os_head->next;
	while (osp != os_head) {
		char *leaf = osp->ss_pn->leaf;
		rfs4_oldstate_t *os_next;

		rfs4_dss_remove_leaf(sip, NFS4_DSS_OLDSTATE_LEAF, leaf);

		if (osp->cl_id4.id_val)
			kmem_free(osp->cl_id4.id_val, osp->cl_id4.id_len);
		rfs4_ss_pnfree(osp->ss_pn);

		os_next = osp->next;
		remque(osp);
		kmem_free(osp, sizeof (rfs4_oldstate_t));
		osp = os_next;
	}

	rw_exit(&sip->oldstate_lock);
}

/*
 * Form the state and oldstate paths, and read in the stable storage files.
 */
void
rfs4_dss_readstate(int npaths, char **paths)
{
	int i;
	char *state, *oldstate;

	state = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	oldstate = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	for (i = 0; i < npaths; i++) {
		char *path = paths[i];

		(void) sprintf(state, "%s/%s", path, NFS4_DSS_STATE_LEAF);
		(void) sprintf(oldstate, "%s/%s", path, NFS4_DSS_OLDSTATE_LEAF);

		/*
		 * Populate the current server instance's oldstate list.
		 *
		 * 1. Read stable storage data from old state directory,
		 *    leaving its contents alone.
		 *
		 * 2. Read stable storage data from state directory,
		 *    and move the latter's contents to old state
		 *    directory.
		 */
		rfs4_ss_oldstate(rfs4_cur_servinst->oldstate, oldstate, NULL);
		rfs4_ss_oldstate(rfs4_cur_servinst->oldstate, state, oldstate);
	}

	kmem_free(state, MAXPATHLEN);
	kmem_free(oldstate, MAXPATHLEN);
}


/*
 * Check if we are still in grace and if the client can be
 * granted permission to perform reclaims.
 */
void
rfs4_ss_chkclid(rfs4_client_t *cp)
{
	rfs4_servinst_t *sip;

	/*
	 * It should be sufficient to check the oldstate data for just
	 * this client's instance. However, since our per-instance
	 * client grouping is solely temporal, HA-NFSv4 RG failover
	 * might result in clients of the same RG being partitioned into
	 * separate instances.
	 *
	 * Until the client grouping is improved, we must check the
	 * oldstate data for all instances with an active grace period.
	 *
	 * This also serves as the mechanism to remove stale oldstate data.
	 * The first time we check an instance after its grace period has
	 * expired, the oldstate data should be cleared.
	 *
	 * Start at the current instance, and walk the list backwards
	 * to the first.
	 */
	mutex_enter(&rfs4_servinst_lock);
	for (sip = rfs4_cur_servinst; sip != NULL; sip = sip->prev) {
		rfs4_ss_chkclid_sip(cp, sip);

		/* if the above check found this client, we're done */
		if (cp->rc_can_reclaim)
			break;
	}
	mutex_exit(&rfs4_servinst_lock);
}

static void
rfs4_ss_chkclid_sip(rfs4_client_t *cp, rfs4_servinst_t *sip)
{
	rfs4_oldstate_t *osp, *os_head;

	/* short circuit everything if this server instance has no oldstate */
	rw_enter(&sip->oldstate_lock, RW_READER);
	os_head = sip->oldstate;
	rw_exit(&sip->oldstate_lock);
	if (os_head == NULL)
		return;

	/*
	 * If this server instance is no longer in a grace period then
	 * the client won't be able to reclaim. No further need for this
	 * instance's oldstate data, so it can be cleared.
	 */
	if (!rfs4_servinst_in_grace(sip))
		return;

	/* this instance is still in grace; search for the clientid */

	rw_enter(&sip->oldstate_lock, RW_READER);

	os_head = sip->oldstate;
	/* skip dummy entry */
	osp = os_head->next;
	while (osp != os_head) {
		if (osp->cl_id4.id_len == cp->rc_nfs_client.id_len) {
			if (bcmp(osp->cl_id4.id_val, cp->rc_nfs_client.id_val,
			    osp->cl_id4.id_len) == 0) {
				cp->rc_can_reclaim = 1;
				break;
			}
		}
		osp = osp->next;
	}

	rw_exit(&sip->oldstate_lock);
}

/*
 * Place client information into stable storage: 1/3.
 * First, generate the leaf filename, from the client's IP address and
 * the server-generated short-hand clientid.
 */
void
rfs4_ss_clid(rfs4_client_t *cp)
{
	const char *kinet_ntop6(uchar_t *, char *, size_t);
	char leaf[MAXNAMELEN], buf[INET6_ADDRSTRLEN];
	struct sockaddr *ca;
	uchar_t *b;

	if (rfs4_ss_enabled == 0) {
		return;
	}

	buf[0] = 0;

	ca = (struct sockaddr *)&cp->rc_addr;

	/*
	 * Convert the caller's IP address to a dotted string
	 */
	if (ca->sa_family == AF_INET) {
		b = (uchar_t *)&((struct sockaddr_in *)ca)->sin_addr;
		(void) sprintf(buf, "%03d.%03d.%03d.%03d", b[0] & 0xFF,
		    b[1] & 0xFF, b[2] & 0xFF, b[3] & 0xFF);
	} else if (ca->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)ca;
		(void) kinet_ntop6((uchar_t *)&sin6->sin6_addr,
		    buf, INET6_ADDRSTRLEN);
	}

	(void) snprintf(leaf, MAXNAMELEN, "%s-%llx", buf,
	    (longlong_t)cp->rc_clientid);
	rfs4_ss_clid_write(cp, leaf);
}

/*
 * Place client information into stable storage: 2/3.
 * DSS: distributed stable storage: the file may need to be written to
 * multiple directories.
 */
static void
rfs4_ss_clid_write(rfs4_client_t *cp, char *leaf)
{
	rfs4_servinst_t *sip;

	/*
	 * It should be sufficient to write the leaf file to (all) DSS paths
	 * associated with just this client's instance. However, since our
	 * per-instance client grouping is solely temporal, HA-NFSv4 RG
	 * failover might result in us losing DSS data.
	 *
	 * Until the client grouping is improved, we must write the DSS data
	 * to all instances' paths. Start at the current instance, and
	 * walk the list backwards to the first.
	 */
	mutex_enter(&rfs4_servinst_lock);
	for (sip = rfs4_cur_servinst; sip != NULL; sip = sip->prev) {
		int i, npaths = sip->dss_npaths;

		/* write the leaf file to all DSS paths */
		for (i = 0; i < npaths; i++) {
			rfs4_dss_path_t *dss_path = sip->dss_paths[i];

			/* HA-NFSv4 path might have been failed-away from us */
			if (dss_path == NULL)
				continue;

			rfs4_ss_clid_write_one(cp, dss_path->path, leaf);
		}
	}
	mutex_exit(&rfs4_servinst_lock);
}

/*
 * Place client information into stable storage: 3/3.
 * Write the stable storage data to the requested file.
 */
static void
rfs4_ss_clid_write_one(rfs4_client_t *cp, char *dss_path, char *leaf)
{
	int ioflag;
	int file_vers = NFS4_SS_VERSION;
	size_t dirlen;
	struct uio uio;
	struct iovec iov[4];
	char *dir;
	rfs4_ss_pn_t *ss_pn;
	vnode_t *vp;
	nfs_client_id4 *cl_id4 = &(cp->rc_nfs_client);

	/* allow 2 extra bytes for '/' & NUL */
	dirlen = strlen(dss_path) + strlen(NFS4_DSS_STATE_LEAF) + 2;
	dir = kmem_alloc(dirlen, KM_SLEEP);
	(void) sprintf(dir, "%s/%s", dss_path, NFS4_DSS_STATE_LEAF);

	ss_pn = rfs4_ss_pnalloc(dir, leaf);
	/* rfs4_ss_pnalloc takes its own copy */
	kmem_free(dir, dirlen);
	if (ss_pn == NULL)
		return;

	if (vn_open(ss_pn->pn, UIO_SYSSPACE, FCREAT|FWRITE, 0600, &vp,
	    CRCREAT, 0)) {
		rfs4_ss_pnfree(ss_pn);
		return;
	}

	/*
	 * We need to record leaf - i.e. the filename - so that we know
	 * what to remove, in the future. However, the dir part of cp->ss_pn
	 * should never be referenced directly, since it's potentially only
	 * one of several paths with this leaf in it.
	 */
	if (cp->rc_ss_pn != NULL) {
		if (strcmp(cp->rc_ss_pn->leaf, leaf) == 0) {
			/* we've already recorded *this* leaf */
			rfs4_ss_pnfree(ss_pn);
		} else {
			/* replace with this leaf */
			rfs4_ss_pnfree(cp->rc_ss_pn);
			cp->rc_ss_pn = ss_pn;
		}
	} else {
		cp->rc_ss_pn = ss_pn;
	}

	/*
	 * Build a scatter list that points to the nfs_client_id4
	 */
	iov[0].iov_base = (caddr_t)&file_vers;
	iov[0].iov_len = sizeof (int);
	iov[1].iov_base = (caddr_t)&(cl_id4->verifier);
	iov[1].iov_len = NFS4_VERIFIER_SIZE;
	iov[2].iov_base = (caddr_t)&(cl_id4->id_len);
	iov[2].iov_len = sizeof (uint_t);
	iov[3].iov_base = (caddr_t)cl_id4->id_val;
	iov[3].iov_len = cl_id4->id_len;

	uio.uio_iov = iov;
	uio.uio_iovcnt = 4;
	uio.uio_loffset = 0;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_llimit = (rlim64_t)MAXOFFSET_T;
	uio.uio_resid = cl_id4->id_len + sizeof (int) +
	    NFS4_VERIFIER_SIZE + sizeof (uint_t);

	ioflag = uio.uio_fmode = (FWRITE|FSYNC);
	uio.uio_extflg = UIO_COPY_DEFAULT;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
	/* write the full client id to the file. */
	(void) VOP_WRITE(vp, &uio, ioflag, CRED(), NULL);
	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);

	(void) VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);
}

/*
 * DSS: distributed stable storage.
 * Unpack the list of paths passed by nfsd.
 * Use nvlist_alloc(9F) to manage the data.
 * The caller is responsible for allocating and freeing the buffer.
 */
int
rfs4_dss_setpaths(char *buf, size_t buflen)
{
	int error;

	/*
	 * If this is a "warm start", i.e. we previously had DSS paths,
	 * preserve the old paths.
	 */
	if (rfs4_dss_paths != NULL) {
		/*
		 * Before we lose the ptr, destroy the nvlist and pathnames
		 * array from the warm start before this one.
		 */
		nvlist_free(rfs4_dss_oldpaths);
		rfs4_dss_oldpaths = rfs4_dss_paths;
	}

	/* unpack the buffer into a searchable nvlist */
	error = nvlist_unpack(buf, buflen, &rfs4_dss_paths, KM_SLEEP);
	if (error)
		return (error);

	/*
	 * Search the nvlist for the pathnames nvpair (which is the only nvpair
	 * in the list, and record its location.
	 */
	error = nvlist_lookup_string_array(rfs4_dss_paths, NFS4_DSS_NVPAIR_NAME,
	    &rfs4_dss_newpaths, &rfs4_dss_numnewpaths);
	return (error);
}

/*
 * Ultimately the nfssys() call NFS4_CLR_STATE endsup here
 * to find and mark the client for forced expire.
 */
static void
rfs4_client_scrub(rfs4_entry_t ent, void *arg)
{
	rfs4_client_t *cp = (rfs4_client_t *)ent;
	struct nfs4clrst_args *clr = arg;
	struct sockaddr_in6 *ent_sin6;
	struct in6_addr  clr_in6;
	struct sockaddr_in  *ent_sin;
	struct in_addr   clr_in;

	if (clr->addr_type != cp->rc_addr.ss_family) {
		return;
	}

	switch (clr->addr_type) {

	case AF_INET6:
		/* copyin the address from user space */
		if (copyin(clr->ap, &clr_in6, sizeof (clr_in6))) {
			break;
		}

		ent_sin6 = (struct sockaddr_in6 *)&cp->rc_addr;

		/*
		 * now compare, and if equivalent mark entry
		 * for forced expiration
		 */
		if (IN6_ARE_ADDR_EQUAL(&ent_sin6->sin6_addr, &clr_in6)) {
			cp->rc_forced_expire = 1;
		}
		break;

	case AF_INET:
		/* copyin the address from user space */
		if (copyin(clr->ap, &clr_in, sizeof (clr_in))) {
			break;
		}

		ent_sin = (struct sockaddr_in *)&cp->rc_addr;

		/*
		 * now compare, and if equivalent mark entry
		 * for forced expiration
		 */
		if (ent_sin->sin_addr.s_addr == clr_in.s_addr) {
			cp->rc_forced_expire = 1;
		}
		break;

	default:
		/* force this assert to fail */
		ASSERT(clr->addr_type != clr->addr_type);
	}
}

/*
 * This is called from nfssys() in order to clear server state
 * for the specified client IP Address.
 */
void
rfs4_clear_client_state(struct nfs4clrst_args *clr)
{
	(void) rfs4_dbe_walk(rfs4_client_tab, rfs4_client_scrub, clr);
}

/*
 * Used to initialize the NFSv4 server's state or database.  All of
 * the tables are created and timers are set. Only called when NFSv4
 * service is provided.
 */
void
rfs4_state_init()
{
	int start_grace;
	extern boolean_t rfs4_cpr_callb(void *, int);
	char *dss_path = NFS4_DSS_VAR_DIR;
	time_t start_time;

	mutex_enter(&rfs4_state_lock);

	/*
	 * If the server state database has already been initialized,
	 * skip it
	 */
	if (rfs4_server_state != NULL) {
		mutex_exit(&rfs4_state_lock);
		return;
	}

	rw_init(&rfs4_findclient_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Set the boot time.  If the server
	 * has been restarted quickly and has had the opportunity to
	 * service clients, then the start_time needs to be bumped
	 * regardless.  A small window but it exists...
	 */
	start_time = gethrestime_sec();
	if (rfs4_start_time < start_time)
		rfs4_start_time = start_time;
	else
		rfs4_start_time++;

	/* DSS: distributed stable storage: initialise served paths list */
	rfs4_dss_pathlist = NULL;

	/*
	 * Create the first server instance, or a new one if the server has
	 * been restarted; see above comments on rfs4_start_time. Don't
	 * start its grace period; that will be done later, to maximise the
	 * clients' recovery window.
	 */
	start_grace = 0;
	rfs4_servinst_create(start_grace, 1, &dss_path);

	/* reset the "first NFSv4 request" status */
	rfs4_seen_first_compound = 0;

	/*
	 * Add a CPR callback so that we can update client
	 * access times to extend the lease after a suspend
	 * and resume (using the same class as rpcmod/connmgr)
	 */
	cpr_id = callb_add(rfs4_cpr_callb, 0, CB_CL_CPR_RPC, "rfs4");

	/* set the various cache timers for table creation */
	if (rfs4_client_cache_time == 0)
		rfs4_client_cache_time = CLIENT_CACHE_TIME;
	if (rfs4_openowner_cache_time == 0)
		rfs4_openowner_cache_time = OPENOWNER_CACHE_TIME;
	if (rfs4_state_cache_time == 0)
		rfs4_state_cache_time = STATE_CACHE_TIME;
	if (rfs4_lo_state_cache_time == 0)
		rfs4_lo_state_cache_time = LO_STATE_CACHE_TIME;
	if (rfs4_lockowner_cache_time == 0)
		rfs4_lockowner_cache_time = LOCKOWNER_CACHE_TIME;
	if (rfs4_file_cache_time == 0)
		rfs4_file_cache_time = FILE_CACHE_TIME;
	if (rfs4_deleg_state_cache_time == 0)
		rfs4_deleg_state_cache_time = DELEG_STATE_CACHE_TIME;

	/* Create the overall database to hold all server state */
	rfs4_server_state = rfs4_database_create(rfs4_database_debug);

	/* Now create the individual tables */
	rfs4_client_cache_time *= rfs4_lease_time;
	rfs4_client_tab = rfs4_table_create(rfs4_server_state,
	    "Client",
	    rfs4_client_cache_time,
	    2,
	    rfs4_client_create,
	    rfs4_client_destroy,
	    rfs4_client_expiry,
	    sizeof (rfs4_client_t),
	    TABSIZE,
	    MAXTABSZ/8, 100);
	rfs4_nfsclnt_idx = rfs4_index_create(rfs4_client_tab,
	    "nfs_client_id4", nfsclnt_hash,
	    nfsclnt_compare, nfsclnt_mkkey,
	    TRUE);
	rfs4_clientid_idx = rfs4_index_create(rfs4_client_tab,
	    "client_id", clientid_hash,
	    clientid_compare, clientid_mkkey,
	    FALSE);

	rfs4_clntip_cache_time = 86400 * 365;	/* about a year */
	rfs4_clntip_tab = rfs4_table_create(rfs4_server_state,
	    "ClntIP",
	    rfs4_clntip_cache_time,
	    1,
	    rfs4_clntip_create,
	    rfs4_clntip_destroy,
	    rfs4_clntip_expiry,
	    sizeof (rfs4_clntip_t),
	    TABSIZE,
	    MAXTABSZ, 100);
	rfs4_clntip_idx = rfs4_index_create(rfs4_clntip_tab,
	    "client_ip", clntip_hash,
	    clntip_compare, clntip_mkkey,
	    TRUE);

	rfs4_openowner_cache_time *= rfs4_lease_time;
	rfs4_openowner_tab = rfs4_table_create(rfs4_server_state,
	    "OpenOwner",
	    rfs4_openowner_cache_time,
	    1,
	    rfs4_openowner_create,
	    rfs4_openowner_destroy,
	    rfs4_openowner_expiry,
	    sizeof (rfs4_openowner_t),
	    TABSIZE,
	    MAXTABSZ, 100);
	rfs4_openowner_idx = rfs4_index_create(rfs4_openowner_tab,
	    "open_owner4", openowner_hash,
	    openowner_compare,
	    openowner_mkkey, TRUE);

	rfs4_state_cache_time *= rfs4_lease_time;
	rfs4_state_tab = rfs4_table_create(rfs4_server_state,
	    "OpenStateID",
	    rfs4_state_cache_time,
	    3,
	    rfs4_state_create,
	    rfs4_state_destroy,
	    rfs4_state_expiry,
	    sizeof (rfs4_state_t),
	    TABSIZE,
	    MAXTABSZ, 100);

	rfs4_state_owner_file_idx = rfs4_index_create(rfs4_state_tab,
	    "Openowner-File",
	    state_owner_file_hash,
	    state_owner_file_compare,
	    state_owner_file_mkkey, TRUE);

	rfs4_state_idx = rfs4_index_create(rfs4_state_tab,
	    "State-id", state_hash,
	    state_compare, state_mkkey, FALSE);

	rfs4_state_file_idx = rfs4_index_create(rfs4_state_tab,
	    "File", state_file_hash,
	    state_file_compare, state_file_mkkey,
	    FALSE);

	rfs4_lo_state_cache_time *= rfs4_lease_time;
	rfs4_lo_state_tab = rfs4_table_create(rfs4_server_state,
	    "LockStateID",
	    rfs4_lo_state_cache_time,
	    2,
	    rfs4_lo_state_create,
	    rfs4_lo_state_destroy,
	    rfs4_lo_state_expiry,
	    sizeof (rfs4_lo_state_t),
	    TABSIZE,
	    MAXTABSZ, 100);

	rfs4_lo_state_owner_idx = rfs4_index_create(rfs4_lo_state_tab,
	    "lockownerxstate",
	    lo_state_lo_hash,
	    lo_state_lo_compare,
	    lo_state_lo_mkkey, TRUE);

	rfs4_lo_state_idx = rfs4_index_create(rfs4_lo_state_tab,
	    "State-id",
	    lo_state_hash, lo_state_compare,
	    lo_state_mkkey, FALSE);

	rfs4_lockowner_cache_time *= rfs4_lease_time;

	rfs4_lockowner_tab = rfs4_table_create(rfs4_server_state,
	    "Lockowner",
	    rfs4_lockowner_cache_time,
	    2,
	    rfs4_lockowner_create,
	    rfs4_lockowner_destroy,
	    rfs4_lockowner_expiry,
	    sizeof (rfs4_lockowner_t),
	    TABSIZE,
	    MAXTABSZ, 100);

	rfs4_lockowner_idx = rfs4_index_create(rfs4_lockowner_tab,
	    "lock_owner4", lockowner_hash,
	    lockowner_compare,
	    lockowner_mkkey, TRUE);

	rfs4_lockowner_pid_idx = rfs4_index_create(rfs4_lockowner_tab,
	    "pid", pid_hash,
	    pid_compare, pid_mkkey,
	    FALSE);

	rfs4_file_cache_time *= rfs4_lease_time;
	rfs4_file_tab = rfs4_table_create(rfs4_server_state,
	    "File",
	    rfs4_file_cache_time,
	    1,
	    rfs4_file_create,
	    rfs4_file_destroy,
	    NULL,
	    sizeof (rfs4_file_t),
	    TABSIZE,
	    MAXTABSZ, -1);

	rfs4_file_idx = rfs4_index_create(rfs4_file_tab,
	    "Filehandle", file_hash,
	    file_compare, file_mkkey, TRUE);

	rfs4_deleg_state_cache_time *= rfs4_lease_time;
	rfs4_deleg_state_tab = rfs4_table_create(rfs4_server_state,
	    "DelegStateID",
	    rfs4_deleg_state_cache_time,
	    2,
	    rfs4_deleg_state_create,
	    rfs4_deleg_state_destroy,
	    rfs4_deleg_state_expiry,
	    sizeof (rfs4_deleg_state_t),
	    TABSIZE,
	    MAXTABSZ, 100);
	rfs4_deleg_idx = rfs4_index_create(rfs4_deleg_state_tab,
	    "DelegByFileClient",
	    deleg_hash,
	    deleg_compare,
	    deleg_mkkey, TRUE);

	rfs4_deleg_state_idx = rfs4_index_create(rfs4_deleg_state_tab,
	    "DelegState",
	    deleg_state_hash,
	    deleg_state_compare,
	    deleg_state_mkkey, FALSE);

	/*
	 * Init the stable storage.
	 */
	rfs4_ss_init();

	rfs4_client_clrst = rfs4_clear_client_state;

	mutex_exit(&rfs4_state_lock);
}


/*
 * Used at server shutdown to cleanup all of the NFSv4 server's structures
 * and other state.
 */
void
rfs4_state_fini()
{
	rfs4_database_t *dbp;

	mutex_enter(&rfs4_state_lock);

	if (rfs4_server_state == NULL) {
		mutex_exit(&rfs4_state_lock);
		return;
	}

	rfs4_client_clrst = NULL;

	rfs4_set_deleg_policy(SRV_NEVER_DELEGATE);
	dbp = rfs4_server_state;
	rfs4_server_state = NULL;

	/*
	 * Cleanup the CPR callback.
	 */
	if (cpr_id)
		(void) callb_delete(cpr_id);

	rw_destroy(&rfs4_findclient_lock);

	/* First stop all of the reaper threads in the database */
	rfs4_database_shutdown(dbp);
	/* clean up any dangling stable storage structures */
	rfs4_ss_fini();
	/* Now actually destroy/release the database and its tables */
	rfs4_database_destroy(dbp);

	/* Reset the cache timers for next time */
	rfs4_client_cache_time = 0;
	rfs4_openowner_cache_time = 0;
	rfs4_state_cache_time = 0;
	rfs4_lo_state_cache_time = 0;
	rfs4_lockowner_cache_time = 0;
	rfs4_file_cache_time = 0;
	rfs4_deleg_state_cache_time = 0;

	mutex_exit(&rfs4_state_lock);

	/* destroy server instances and current instance ptr */
	rfs4_servinst_destroy_all();

	/* reset the "first NFSv4 request" status */
	rfs4_seen_first_compound = 0;

	/* DSS: distributed stable storage */
	nvlist_free(rfs4_dss_oldpaths);
	nvlist_free(rfs4_dss_paths);
	rfs4_dss_paths = rfs4_dss_oldpaths = NULL;
}

typedef union {
	struct {
		uint32_t start_time;
		uint32_t c_id;
	} impl_id;
	clientid4 id4;
} cid;

static int foreign_stateid(stateid_t *id);
static int foreign_clientid(cid *cidp);
static void embed_nodeid(cid *cidp);

typedef union {
	struct {
		uint32_t c_id;
		uint32_t gen_num;
	} cv_impl;
	verifier4	confirm_verf;
} scid_confirm_verf;

static uint32_t
clientid_hash(void *key)
{
	cid *idp = key;

	return (idp->impl_id.c_id);
}

static bool_t
clientid_compare(rfs4_entry_t entry, void *key)
{
	rfs4_client_t *cp = (rfs4_client_t *)entry;
	clientid4 *idp = key;

	return (*idp == cp->rc_clientid);
}

static void *
clientid_mkkey(rfs4_entry_t entry)
{
	rfs4_client_t *cp = (rfs4_client_t *)entry;

	return (&cp->rc_clientid);
}

static uint32_t
nfsclnt_hash(void *key)
{
	nfs_client_id4 *client = key;
	int i;
	uint32_t hash = 0;

	for (i = 0; i < client->id_len; i++) {
		hash <<= 1;
		hash += (uint_t)client->id_val[i];
	}
	return (hash);
}


static bool_t
nfsclnt_compare(rfs4_entry_t entry, void *key)
{
	rfs4_client_t *cp = (rfs4_client_t *)entry;
	nfs_client_id4 *nfs_client = key;

	if (cp->rc_nfs_client.id_len != nfs_client->id_len)
		return (FALSE);

	return (bcmp(cp->rc_nfs_client.id_val, nfs_client->id_val,
	    nfs_client->id_len) == 0);
}

static void *
nfsclnt_mkkey(rfs4_entry_t entry)
{
	rfs4_client_t *cp = (rfs4_client_t *)entry;

	return (&cp->rc_nfs_client);
}

static bool_t
rfs4_client_expiry(rfs4_entry_t u_entry)
{
	rfs4_client_t *cp = (rfs4_client_t *)u_entry;
	bool_t cp_expired;

	if (rfs4_dbe_is_invalid(cp->rc_dbe)) {
		cp->rc_ss_remove = 1;
		return (TRUE);
	}
	/*
	 * If the sysadmin has used clear_locks for this
	 * entry then forced_expire will be set and we
	 * want this entry to be reaped. Or the entry
	 * has exceeded its lease period.
	 */
	cp_expired = (cp->rc_forced_expire ||
	    (gethrestime_sec() - cp->rc_last_access
	    > rfs4_lease_time));

	if (!cp->rc_ss_remove && cp_expired)
		cp->rc_ss_remove = 1;
	return (cp_expired);
}

/*
 * Remove the leaf file from all distributed stable storage paths.
 */
static void
rfs4_dss_remove_cpleaf(rfs4_client_t *cp)
{
	rfs4_servinst_t *sip;
	char *leaf = cp->rc_ss_pn->leaf;

	/*
	 * since the state files are written to all DSS
	 * paths we must remove this leaf file instance
	 * from all server instances.
	 */

	mutex_enter(&rfs4_servinst_lock);
	for (sip = rfs4_cur_servinst; sip != NULL; sip = sip->prev) {
		/* remove the leaf file associated with this server instance */
		rfs4_dss_remove_leaf(sip, NFS4_DSS_STATE_LEAF, leaf);
	}
	mutex_exit(&rfs4_servinst_lock);
}

static void
rfs4_dss_remove_leaf(rfs4_servinst_t *sip, char *dir_leaf, char *leaf)
{
	int i, npaths = sip->dss_npaths;

	for (i = 0; i < npaths; i++) {
		rfs4_dss_path_t *dss_path = sip->dss_paths[i];
		char *path, *dir;
		size_t pathlen;

		/* the HA-NFSv4 path might have been failed-over away from us */
		if (dss_path == NULL)
			continue;

		dir = dss_path->path;

		/* allow 3 extra bytes for two '/' & a NUL */
		pathlen = strlen(dir) + strlen(dir_leaf) + strlen(leaf) + 3;
		path = kmem_alloc(pathlen, KM_SLEEP);
		(void) sprintf(path, "%s/%s/%s", dir, dir_leaf, leaf);

		(void) vn_remove(path, UIO_SYSSPACE, RMFILE);

		kmem_free(path, pathlen);
	}
}

static void
rfs4_client_destroy(rfs4_entry_t u_entry)
{
	rfs4_client_t *cp = (rfs4_client_t *)u_entry;

	mutex_destroy(cp->rc_cbinfo.cb_lock);
	cv_destroy(cp->rc_cbinfo.cb_cv);
	cv_destroy(cp->rc_cbinfo.cb_cv_nullcaller);
	list_destroy(&cp->rc_openownerlist);

	/* free callback info */
	rfs4_cbinfo_free(&cp->rc_cbinfo);

	if (cp->rc_cp_confirmed)
		rfs4_client_rele(cp->rc_cp_confirmed);

	if (cp->rc_ss_pn) {
		/* check if the stable storage files need to be removed */
		if (cp->rc_ss_remove)
			rfs4_dss_remove_cpleaf(cp);
		rfs4_ss_pnfree(cp->rc_ss_pn);
	}

	/* Free the client supplied client id */
	kmem_free(cp->rc_nfs_client.id_val, cp->rc_nfs_client.id_len);

	if (cp->rc_sysidt != LM_NOSYSID)
		lm_free_sysidt(cp->rc_sysidt);
}

static bool_t
rfs4_client_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_client_t *cp = (rfs4_client_t *)u_entry;
	nfs_client_id4 *client = (nfs_client_id4 *)arg;
	struct sockaddr *ca;
	cid *cidp;
	scid_confirm_verf *scvp;

	/* Get a clientid to give to the client */
	cidp = (cid *)&cp->rc_clientid;
	cidp->impl_id.start_time = rfs4_start_time;
	cidp->impl_id.c_id = (uint32_t)rfs4_dbe_getid(cp->rc_dbe);

	/* If we are booted as a cluster node, embed our nodeid */
	if (cluster_bootflags & CLUSTER_BOOTED)
		embed_nodeid(cidp);

	/* Allocate and copy client's client id value */
	cp->rc_nfs_client.id_val = kmem_alloc(client->id_len, KM_SLEEP);
	cp->rc_nfs_client.id_len = client->id_len;
	bcopy(client->id_val, cp->rc_nfs_client.id_val, client->id_len);
	cp->rc_nfs_client.verifier = client->verifier;

	/* Copy client's IP address */
	ca = client->cl_addr;
	if (ca->sa_family == AF_INET)
		bcopy(ca, &cp->rc_addr, sizeof (struct sockaddr_in));
	else if (ca->sa_family == AF_INET6)
		bcopy(ca, &cp->rc_addr, sizeof (struct sockaddr_in6));
	cp->rc_nfs_client.cl_addr = (struct sockaddr *)&cp->rc_addr;

	/* Init the value for the SETCLIENTID_CONFIRM verifier */
	scvp = (scid_confirm_verf *)&cp->rc_confirm_verf;
	scvp->cv_impl.c_id = cidp->impl_id.c_id;
	scvp->cv_impl.gen_num = 0;

	/* An F_UNLKSYS has been done for this client */
	cp->rc_unlksys_completed = FALSE;

	/* We need the client to ack us */
	cp->rc_need_confirm = TRUE;
	cp->rc_cp_confirmed = NULL;

	/* TRUE all the time until the callback path actually fails */
	cp->rc_cbinfo.cb_notified_of_cb_path_down = TRUE;

	/* Initialize the access time to now */
	cp->rc_last_access = gethrestime_sec();

	cp->rc_cr_set = NULL;

	cp->rc_sysidt = LM_NOSYSID;

	list_create(&cp->rc_openownerlist, sizeof (rfs4_openowner_t),
	    offsetof(rfs4_openowner_t, ro_node));

	/* set up the callback control structure */
	cp->rc_cbinfo.cb_state = CB_UNINIT;
	mutex_init(cp->rc_cbinfo.cb_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(cp->rc_cbinfo.cb_cv, NULL, CV_DEFAULT, NULL);
	cv_init(cp->rc_cbinfo.cb_cv_nullcaller, NULL, CV_DEFAULT, NULL);

	/*
	 * Associate the client_t with the current server instance.
	 * The hold is solely to satisfy the calling requirement of
	 * rfs4_servinst_assign(). In this case it's not strictly necessary.
	 */
	rfs4_dbe_hold(cp->rc_dbe);
	rfs4_servinst_assign(cp, rfs4_cur_servinst);
	rfs4_dbe_rele(cp->rc_dbe);

	return (TRUE);
}

/*
 * Caller wants to generate/update the setclientid_confirm verifier
 * associated with a client.  This is done during the SETCLIENTID
 * processing.
 */
void
rfs4_client_scv_next(rfs4_client_t *cp)
{
	scid_confirm_verf *scvp;

	/* Init the value for the SETCLIENTID_CONFIRM verifier */
	scvp = (scid_confirm_verf *)&cp->rc_confirm_verf;
	scvp->cv_impl.gen_num++;
}

void
rfs4_client_rele(rfs4_client_t *cp)
{
	rfs4_dbe_rele(cp->rc_dbe);
}

rfs4_client_t *
rfs4_findclient(nfs_client_id4 *client, bool_t *create,	rfs4_client_t *oldcp)
{
	rfs4_client_t *cp;


	if (oldcp) {
		rw_enter(&rfs4_findclient_lock, RW_WRITER);
		rfs4_dbe_hide(oldcp->rc_dbe);
	} else {
		rw_enter(&rfs4_findclient_lock, RW_READER);
	}

	cp = (rfs4_client_t *)rfs4_dbsearch(rfs4_nfsclnt_idx, client,
	    create, (void *)client, RFS4_DBS_VALID);

	if (oldcp)
		rfs4_dbe_unhide(oldcp->rc_dbe);

	rw_exit(&rfs4_findclient_lock);

	return (cp);
}

rfs4_client_t *
rfs4_findclient_by_id(clientid4 clientid, bool_t find_unconfirmed)
{
	rfs4_client_t *cp;
	bool_t create = FALSE;
	cid *cidp = (cid *)&clientid;

	/* If we're a cluster and the nodeid isn't right, short-circuit */
	if (cluster_bootflags & CLUSTER_BOOTED && foreign_clientid(cidp))
		return (NULL);

	rw_enter(&rfs4_findclient_lock, RW_READER);

	cp = (rfs4_client_t *)rfs4_dbsearch(rfs4_clientid_idx, &clientid,
	    &create, NULL, RFS4_DBS_VALID);

	rw_exit(&rfs4_findclient_lock);

	if (cp && cp->rc_need_confirm && find_unconfirmed == FALSE) {
		rfs4_client_rele(cp);
		return (NULL);
	} else {
		return (cp);
	}
}

static uint32_t
clntip_hash(void *key)
{
	struct sockaddr *addr = key;
	int i, len = 0;
	uint32_t hash = 0;
	char *ptr;

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *a = (struct sockaddr_in *)addr;
		len = sizeof (struct in_addr);
		ptr = (char *)&a->sin_addr;
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)addr;
		len = sizeof (struct in6_addr);
		ptr = (char *)&a->sin6_addr;
	} else
		return (0);

	for (i = 0; i < len; i++) {
		hash <<= 1;
		hash += (uint_t)ptr[i];
	}
	return (hash);
}

static bool_t
clntip_compare(rfs4_entry_t entry, void *key)
{
	rfs4_clntip_t *cp = (rfs4_clntip_t *)entry;
	struct sockaddr *addr = key;
	int len = 0;
	char *p1, *p2;

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *a1 = (struct sockaddr_in *)&cp->ri_addr;
		struct sockaddr_in *a2 = (struct sockaddr_in *)addr;
		len = sizeof (struct in_addr);
		p1 = (char *)&a1->sin_addr;
		p2 = (char *)&a2->sin_addr;
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *a1 = (struct sockaddr_in6 *)&cp->ri_addr;
		struct sockaddr_in6 *a2 = (struct sockaddr_in6 *)addr;
		len = sizeof (struct in6_addr);
		p1 = (char *)&a1->sin6_addr;
		p2 = (char *)&a2->sin6_addr;
	} else
		return (0);

	return (bcmp(p1, p2, len) == 0);
}

static void *
clntip_mkkey(rfs4_entry_t entry)
{
	rfs4_clntip_t *cp = (rfs4_clntip_t *)entry;

	return (&cp->ri_addr);
}

static bool_t
rfs4_clntip_expiry(rfs4_entry_t u_entry)
{
	rfs4_clntip_t *cp = (rfs4_clntip_t *)u_entry;

	if (rfs4_dbe_is_invalid(cp->ri_dbe))
		return (TRUE);
	return (FALSE);
}

/* ARGSUSED */
static void
rfs4_clntip_destroy(rfs4_entry_t u_entry)
{
}

static bool_t
rfs4_clntip_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_clntip_t *cp = (rfs4_clntip_t *)u_entry;
	struct sockaddr *ca = (struct sockaddr *)arg;

	/* Copy client's IP address */
	if (ca->sa_family == AF_INET)
		bcopy(ca, &cp->ri_addr, sizeof (struct sockaddr_in));
	else if (ca->sa_family == AF_INET6)
		bcopy(ca, &cp->ri_addr, sizeof (struct sockaddr_in6));
	else
		return (FALSE);
	cp->ri_no_referrals = 1;

	return (TRUE);
}

rfs4_clntip_t *
rfs4_find_clntip(struct sockaddr *addr, bool_t *create)
{
	rfs4_clntip_t *cp;

	rw_enter(&rfs4_findclient_lock, RW_READER);

	cp = (rfs4_clntip_t *)rfs4_dbsearch(rfs4_clntip_idx, addr,
	    create, addr, RFS4_DBS_VALID);

	rw_exit(&rfs4_findclient_lock);

	return (cp);
}

void
rfs4_invalidate_clntip(struct sockaddr *addr)
{
	rfs4_clntip_t *cp;
	bool_t create = FALSE;

	rw_enter(&rfs4_findclient_lock, RW_READER);

	cp = (rfs4_clntip_t *)rfs4_dbsearch(rfs4_clntip_idx, addr,
	    &create, NULL, RFS4_DBS_VALID);
	if (cp == NULL) {
		rw_exit(&rfs4_findclient_lock);
		return;
	}
	rfs4_dbe_invalidate(cp->ri_dbe);
	rfs4_dbe_rele(cp->ri_dbe);

	rw_exit(&rfs4_findclient_lock);
}

bool_t
rfs4_lease_expired(rfs4_client_t *cp)
{
	bool_t rc;

	rfs4_dbe_lock(cp->rc_dbe);

	/*
	 * If the admin has executed clear_locks for this
	 * client id, force expire will be set, so no need
	 * to calculate anything because it's "outa here".
	 */
	if (cp->rc_forced_expire) {
		rc = TRUE;
	} else {
		rc = (gethrestime_sec() - cp->rc_last_access > rfs4_lease_time);
	}

	/*
	 * If the lease has expired we will also want
	 * to remove any stable storage state data. So
	 * mark the client id accordingly.
	 */
	if (!cp->rc_ss_remove)
		cp->rc_ss_remove = (rc == TRUE);

	rfs4_dbe_unlock(cp->rc_dbe);

	return (rc);
}

void
rfs4_update_lease(rfs4_client_t *cp)
{
	rfs4_dbe_lock(cp->rc_dbe);
	if (!cp->rc_forced_expire)
		cp->rc_last_access = gethrestime_sec();
	rfs4_dbe_unlock(cp->rc_dbe);
}


static bool_t
EQOPENOWNER(open_owner4 *a, open_owner4 *b)
{
	bool_t rc;

	if (a->clientid != b->clientid)
		return (FALSE);

	if (a->owner_len != b->owner_len)
		return (FALSE);

	rc = (bcmp(a->owner_val, b->owner_val, a->owner_len) == 0);

	return (rc);
}

static uint_t
openowner_hash(void *key)
{
	int i;
	open_owner4 *openowner = key;
	uint_t hash = 0;

	for (i = 0; i < openowner->owner_len; i++) {
		hash <<= 4;
		hash += (uint_t)openowner->owner_val[i];
	}
	hash += (uint_t)openowner->clientid;
	hash |= (openowner->clientid >> 32);

	return (hash);
}

static bool_t
openowner_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;
	open_owner4 *arg = key;

	return (EQOPENOWNER(&oo->ro_owner, arg));
}

void *
openowner_mkkey(rfs4_entry_t u_entry)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;

	return (&oo->ro_owner);
}

/* ARGSUSED */
static bool_t
rfs4_openowner_expiry(rfs4_entry_t u_entry)
{
	/* openstateid held us and did all needed delay */
	return (TRUE);
}

static void
rfs4_openowner_destroy(rfs4_entry_t u_entry)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;

	/* Remove open owner from client's lists of open owners */
	rfs4_dbe_lock(oo->ro_client->rc_dbe);
	list_remove(&oo->ro_client->rc_openownerlist, oo);
	rfs4_dbe_unlock(oo->ro_client->rc_dbe);

	/* One less reference to the client */
	rfs4_client_rele(oo->ro_client);
	oo->ro_client = NULL;

	/* Free the last reply for this lock owner */
	rfs4_free_reply(&oo->ro_reply);

	if (oo->ro_reply_fh.nfs_fh4_val) {
		kmem_free(oo->ro_reply_fh.nfs_fh4_val,
		    oo->ro_reply_fh.nfs_fh4_len);
		oo->ro_reply_fh.nfs_fh4_val = NULL;
		oo->ro_reply_fh.nfs_fh4_len = 0;
	}

	rfs4_sw_destroy(&oo->ro_sw);
	list_destroy(&oo->ro_statelist);

	/* Free the lock owner id */
	kmem_free(oo->ro_owner.owner_val, oo->ro_owner.owner_len);
}

void
rfs4_openowner_rele(rfs4_openowner_t *oo)
{
	rfs4_dbe_rele(oo->ro_dbe);
}

static bool_t
rfs4_openowner_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;
	rfs4_openowner_t *argp = (rfs4_openowner_t *)arg;
	open_owner4 *openowner = &argp->ro_owner;
	seqid4 seqid = argp->ro_open_seqid;
	rfs4_client_t *cp;
	bool_t create = FALSE;

	rw_enter(&rfs4_findclient_lock, RW_READER);

	cp = (rfs4_client_t *)rfs4_dbsearch(rfs4_clientid_idx,
	    &openowner->clientid,
	    &create, NULL, RFS4_DBS_VALID);

	rw_exit(&rfs4_findclient_lock);

	if (cp == NULL)
		return (FALSE);

	oo->ro_reply_fh.nfs_fh4_len = 0;
	oo->ro_reply_fh.nfs_fh4_val = NULL;

	oo->ro_owner.clientid = openowner->clientid;
	oo->ro_owner.owner_val =
	    kmem_alloc(openowner->owner_len, KM_SLEEP);

	bcopy(openowner->owner_val,
	    oo->ro_owner.owner_val, openowner->owner_len);

	oo->ro_owner.owner_len = openowner->owner_len;

	oo->ro_need_confirm = TRUE;

	rfs4_sw_init(&oo->ro_sw);

	oo->ro_open_seqid = seqid;
	bzero(&oo->ro_reply, sizeof (nfs_resop4));
	oo->ro_client = cp;
	oo->ro_cr_set = NULL;

	list_create(&oo->ro_statelist, sizeof (rfs4_state_t),
	    offsetof(rfs4_state_t, rs_node));

	/* Insert openowner into client's open owner list */
	rfs4_dbe_lock(cp->rc_dbe);
	list_insert_tail(&cp->rc_openownerlist, oo);
	rfs4_dbe_unlock(cp->rc_dbe);

	return (TRUE);
}

rfs4_openowner_t *
rfs4_findopenowner(open_owner4 *openowner, bool_t *create, seqid4 seqid)
{
	rfs4_openowner_t *oo;
	rfs4_openowner_t arg;

	arg.ro_owner = *openowner;
	arg.ro_open_seqid = seqid;
	oo = (rfs4_openowner_t *)rfs4_dbsearch(rfs4_openowner_idx, openowner,
	    create, &arg, RFS4_DBS_VALID);

	return (oo);
}

void
rfs4_update_open_sequence(rfs4_openowner_t *oo)
{

	rfs4_dbe_lock(oo->ro_dbe);

	oo->ro_open_seqid++;

	rfs4_dbe_unlock(oo->ro_dbe);
}

void
rfs4_update_open_resp(rfs4_openowner_t *oo, nfs_resop4 *resp, nfs_fh4 *fh)
{

	rfs4_dbe_lock(oo->ro_dbe);

	rfs4_free_reply(&oo->ro_reply);

	rfs4_copy_reply(&oo->ro_reply, resp);

	/* Save the filehandle if provided and free if not used */
	if (resp->nfs_resop4_u.opopen.status == NFS4_OK &&
	    fh && fh->nfs_fh4_len) {
		if (oo->ro_reply_fh.nfs_fh4_val == NULL)
			oo->ro_reply_fh.nfs_fh4_val =
			    kmem_alloc(fh->nfs_fh4_len, KM_SLEEP);
		nfs_fh4_copy(fh, &oo->ro_reply_fh);
	} else {
		if (oo->ro_reply_fh.nfs_fh4_val) {
			kmem_free(oo->ro_reply_fh.nfs_fh4_val,
			    oo->ro_reply_fh.nfs_fh4_len);
			oo->ro_reply_fh.nfs_fh4_val = NULL;
			oo->ro_reply_fh.nfs_fh4_len = 0;
		}
	}

	rfs4_dbe_unlock(oo->ro_dbe);
}

static bool_t
lockowner_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;
	lock_owner4 *b = (lock_owner4 *)key;

	if (lo->rl_owner.clientid != b->clientid)
		return (FALSE);

	if (lo->rl_owner.owner_len != b->owner_len)
		return (FALSE);

	return (bcmp(lo->rl_owner.owner_val, b->owner_val,
	    lo->rl_owner.owner_len) == 0);
}

void *
lockowner_mkkey(rfs4_entry_t u_entry)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;

	return (&lo->rl_owner);
}

static uint32_t
lockowner_hash(void *key)
{
	int i;
	lock_owner4 *lockowner = key;
	uint_t hash = 0;

	for (i = 0; i < lockowner->owner_len; i++) {
		hash <<= 4;
		hash += (uint_t)lockowner->owner_val[i];
	}
	hash += (uint_t)lockowner->clientid;
	hash |= (lockowner->clientid >> 32);

	return (hash);
}

static uint32_t
pid_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

static void *
pid_mkkey(rfs4_entry_t u_entry)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;

	return ((void *)(uintptr_t)lo->rl_pid);
}

static bool_t
pid_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;

	return (lo->rl_pid == (pid_t)(uintptr_t)key);
}

static void
rfs4_lockowner_destroy(rfs4_entry_t u_entry)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;

	/* Free the lock owner id */
	kmem_free(lo->rl_owner.owner_val, lo->rl_owner.owner_len);
	rfs4_client_rele(lo->rl_client);
}

void
rfs4_lockowner_rele(rfs4_lockowner_t *lo)
{
	rfs4_dbe_rele(lo->rl_dbe);
}

/* ARGSUSED */
static bool_t
rfs4_lockowner_expiry(rfs4_entry_t u_entry)
{
	/*
	 * Since expiry is called with no other references on
	 * this struct, go ahead and have it removed.
	 */
	return (TRUE);
}

static bool_t
rfs4_lockowner_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;
	lock_owner4 *lockowner = (lock_owner4 *)arg;
	rfs4_client_t *cp;
	bool_t create = FALSE;

	rw_enter(&rfs4_findclient_lock, RW_READER);

	cp = (rfs4_client_t *)rfs4_dbsearch(rfs4_clientid_idx,
	    &lockowner->clientid,
	    &create, NULL, RFS4_DBS_VALID);

	rw_exit(&rfs4_findclient_lock);

	if (cp == NULL)
		return (FALSE);

	/* Reference client */
	lo->rl_client = cp;
	lo->rl_owner.clientid = lockowner->clientid;
	lo->rl_owner.owner_val = kmem_alloc(lockowner->owner_len, KM_SLEEP);
	bcopy(lockowner->owner_val, lo->rl_owner.owner_val,
	    lockowner->owner_len);
	lo->rl_owner.owner_len = lockowner->owner_len;
	lo->rl_pid = rfs4_dbe_getid(lo->rl_dbe);

	return (TRUE);
}

rfs4_lockowner_t *
rfs4_findlockowner(lock_owner4 *lockowner, bool_t *create)
{
	rfs4_lockowner_t *lo;

	lo = (rfs4_lockowner_t *)rfs4_dbsearch(rfs4_lockowner_idx, lockowner,
	    create, lockowner, RFS4_DBS_VALID);

	return (lo);
}

rfs4_lockowner_t *
rfs4_findlockowner_by_pid(pid_t pid)
{
	rfs4_lockowner_t *lo;
	bool_t create = FALSE;

	lo = (rfs4_lockowner_t *)rfs4_dbsearch(rfs4_lockowner_pid_idx,
	    (void *)(uintptr_t)pid, &create, NULL, RFS4_DBS_VALID);

	return (lo);
}


static uint32_t
file_hash(void *key)
{
	return (ADDRHASH(key));
}

static void *
file_mkkey(rfs4_entry_t u_entry)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;

	return (fp->rf_vp);
}

static bool_t
file_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;

	return (fp->rf_vp == (vnode_t *)key);
}

static void
rfs4_file_destroy(rfs4_entry_t u_entry)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;

	list_destroy(&fp->rf_delegstatelist);

	if (fp->rf_filehandle.nfs_fh4_val)
		kmem_free(fp->rf_filehandle.nfs_fh4_val,
		    fp->rf_filehandle.nfs_fh4_len);
	cv_destroy(fp->rf_dinfo.rd_recall_cv);
	if (fp->rf_vp) {
		vnode_t *vp = fp->rf_vp;

		mutex_enter(&vp->v_vsd_lock);
		(void) vsd_set(vp, nfs4_srv_vkey, NULL);
		mutex_exit(&vp->v_vsd_lock);
		VN_RELE(vp);
		fp->rf_vp = NULL;
	}
	rw_destroy(&fp->rf_file_rwlock);
}

/*
 * Used to unlock the underlying dbe struct only
 */
void
rfs4_file_rele(rfs4_file_t *fp)
{
	rfs4_dbe_rele(fp->rf_dbe);
}

typedef struct {
    vnode_t *vp;
    nfs_fh4 *fh;
} rfs4_fcreate_arg;

static bool_t
rfs4_file_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;
	rfs4_fcreate_arg *ap = (rfs4_fcreate_arg *)arg;
	vnode_t *vp = ap->vp;
	nfs_fh4 *fh = ap->fh;

	VN_HOLD(vp);

	fp->rf_filehandle.nfs_fh4_len = 0;
	fp->rf_filehandle.nfs_fh4_val = NULL;
	ASSERT(fh && fh->nfs_fh4_len);
	if (fh && fh->nfs_fh4_len) {
		fp->rf_filehandle.nfs_fh4_val =
		    kmem_alloc(fh->nfs_fh4_len, KM_SLEEP);
		nfs_fh4_copy(fh, &fp->rf_filehandle);
	}
	fp->rf_vp = vp;

	list_create(&fp->rf_delegstatelist, sizeof (rfs4_deleg_state_t),
	    offsetof(rfs4_deleg_state_t, rds_node));

	fp->rf_share_deny = fp->rf_share_access = fp->rf_access_read = 0;
	fp->rf_access_write = fp->rf_deny_read = fp->rf_deny_write = 0;

	mutex_init(fp->rf_dinfo.rd_recall_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(fp->rf_dinfo.rd_recall_cv, NULL, CV_DEFAULT, NULL);

	fp->rf_dinfo.rd_dtype = OPEN_DELEGATE_NONE;

	rw_init(&fp->rf_file_rwlock, NULL, RW_DEFAULT, NULL);

	mutex_enter(&vp->v_vsd_lock);
	VERIFY(vsd_set(vp, nfs4_srv_vkey, (void *)fp) == 0);
	mutex_exit(&vp->v_vsd_lock);

	return (TRUE);
}

rfs4_file_t *
rfs4_findfile(vnode_t *vp, nfs_fh4 *fh, bool_t *create)
{
	rfs4_file_t *fp;
	rfs4_fcreate_arg arg;

	arg.vp = vp;
	arg.fh = fh;

	if (*create == TRUE)
		fp = (rfs4_file_t *)rfs4_dbsearch(rfs4_file_idx, vp, create,
		    &arg, RFS4_DBS_VALID);
	else {
		mutex_enter(&vp->v_vsd_lock);
		fp = (rfs4_file_t *)vsd_get(vp, nfs4_srv_vkey);
		if (fp) {
			rfs4_dbe_lock(fp->rf_dbe);
			if (rfs4_dbe_is_invalid(fp->rf_dbe) ||
			    (rfs4_dbe_refcnt(fp->rf_dbe) == 0)) {
				rfs4_dbe_unlock(fp->rf_dbe);
				fp = NULL;
			} else {
				rfs4_dbe_hold(fp->rf_dbe);
				rfs4_dbe_unlock(fp->rf_dbe);
			}
		}
		mutex_exit(&vp->v_vsd_lock);
	}
	return (fp);
}

/*
 * Find a file in the db and once it is located, take the rw lock.
 * Need to check the vnode pointer and if it does not exist (it was
 * removed between the db location and check) redo the find.  This
 * assumes that a file struct that has a NULL vnode pointer is marked
 * at 'invalid' and will not be found in the db the second time
 * around.
 */
rfs4_file_t *
rfs4_findfile_withlock(vnode_t *vp, nfs_fh4 *fh, bool_t *create)
{
	rfs4_file_t *fp;
	rfs4_fcreate_arg arg;
	bool_t screate = *create;

	if (screate == FALSE) {
		mutex_enter(&vp->v_vsd_lock);
		fp = (rfs4_file_t *)vsd_get(vp, nfs4_srv_vkey);
		if (fp) {
			rfs4_dbe_lock(fp->rf_dbe);
			if (rfs4_dbe_is_invalid(fp->rf_dbe) ||
			    (rfs4_dbe_refcnt(fp->rf_dbe) == 0)) {
				rfs4_dbe_unlock(fp->rf_dbe);
				mutex_exit(&vp->v_vsd_lock);
				fp = NULL;
			} else {
				rfs4_dbe_hold(fp->rf_dbe);
				rfs4_dbe_unlock(fp->rf_dbe);
				mutex_exit(&vp->v_vsd_lock);
				rw_enter(&fp->rf_file_rwlock, RW_WRITER);
				if (fp->rf_vp == NULL) {
					rw_exit(&fp->rf_file_rwlock);
					rfs4_file_rele(fp);
					fp = NULL;
				}
			}
		} else {
			mutex_exit(&vp->v_vsd_lock);
		}
	} else {
retry:
		arg.vp = vp;
		arg.fh = fh;

		fp = (rfs4_file_t *)rfs4_dbsearch(rfs4_file_idx, vp, create,
		    &arg, RFS4_DBS_VALID);
		if (fp != NULL) {
			rw_enter(&fp->rf_file_rwlock, RW_WRITER);
			if (fp->rf_vp == NULL) {
				rw_exit(&fp->rf_file_rwlock);
				rfs4_file_rele(fp);
				*create = screate;
				goto retry;
			}
		}
	}

	return (fp);
}

static uint32_t
lo_state_hash(void *key)
{
	stateid_t *id = key;

	return (id->bits.ident+id->bits.pid);
}

static bool_t
lo_state_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	stateid_t *id = key;
	bool_t rc;

	rc = (lsp->rls_lockid.bits.boottime == id->bits.boottime &&
	    lsp->rls_lockid.bits.type == id->bits.type &&
	    lsp->rls_lockid.bits.ident == id->bits.ident &&
	    lsp->rls_lockid.bits.pid == id->bits.pid);

	return (rc);
}

static void *
lo_state_mkkey(rfs4_entry_t u_entry)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;

	return (&lsp->rls_lockid);
}

static bool_t
rfs4_lo_state_expiry(rfs4_entry_t u_entry)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;

	if (rfs4_dbe_is_invalid(lsp->rls_dbe))
		return (TRUE);
	if (lsp->rls_state->rs_closed)
		return (TRUE);
	return ((gethrestime_sec() -
	    lsp->rls_state->rs_owner->ro_client->rc_last_access
	    > rfs4_lease_time));
}

static void
rfs4_lo_state_destroy(rfs4_entry_t u_entry)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;

	rfs4_dbe_lock(lsp->rls_state->rs_dbe);
	list_remove(&lsp->rls_state->rs_lostatelist, lsp);
	rfs4_dbe_unlock(lsp->rls_state->rs_dbe);

	rfs4_sw_destroy(&lsp->rls_sw);

	/* Make sure to release the file locks */
	if (lsp->rls_locks_cleaned == FALSE) {
		lsp->rls_locks_cleaned = TRUE;
		if (lsp->rls_locker->rl_client->rc_sysidt != LM_NOSYSID) {
			/* Is the PxFS kernel module loaded? */
			if (lm_remove_file_locks != NULL) {
				int new_sysid;

				/* Encode the cluster nodeid in new sysid */
				new_sysid =
				    lsp->rls_locker->rl_client->rc_sysidt;
				lm_set_nlmid_flk(&new_sysid);

				/*
				 * This PxFS routine removes file locks for a
				 * client over all nodes of a cluster.
				 */
				DTRACE_PROBE1(nfss_i_clust_rm_lck,
				    int, new_sysid);
				(*lm_remove_file_locks)(new_sysid);
			} else {
				(void) cleanlocks(
				    lsp->rls_state->rs_finfo->rf_vp,
				    lsp->rls_locker->rl_pid,
				    lsp->rls_locker->rl_client->rc_sysidt);
			}
		}
	}

	/* Free the last reply for this state */
	rfs4_free_reply(&lsp->rls_reply);

	rfs4_lockowner_rele(lsp->rls_locker);
	lsp->rls_locker = NULL;

	rfs4_state_rele_nounlock(lsp->rls_state);
	lsp->rls_state = NULL;
}

static bool_t
rfs4_lo_state_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	rfs4_lo_state_t *argp = (rfs4_lo_state_t *)arg;
	rfs4_lockowner_t *lo = argp->rls_locker;
	rfs4_state_t *sp = argp->rls_state;

	lsp->rls_state = sp;

	lsp->rls_lockid = sp->rs_stateid;
	lsp->rls_lockid.bits.type = LOCKID;
	lsp->rls_lockid.bits.chgseq = 0;
	lsp->rls_lockid.bits.pid = lo->rl_pid;

	lsp->rls_locks_cleaned = FALSE;
	lsp->rls_lock_completed = FALSE;

	rfs4_sw_init(&lsp->rls_sw);

	/* Attached the supplied lock owner */
	rfs4_dbe_hold(lo->rl_dbe);
	lsp->rls_locker = lo;

	rfs4_dbe_lock(sp->rs_dbe);
	list_insert_tail(&sp->rs_lostatelist, lsp);
	rfs4_dbe_hold(sp->rs_dbe);
	rfs4_dbe_unlock(sp->rs_dbe);

	return (TRUE);
}

void
rfs4_lo_state_rele(rfs4_lo_state_t *lsp, bool_t unlock_fp)
{
	if (unlock_fp == TRUE)
		rw_exit(&lsp->rls_state->rs_finfo->rf_file_rwlock);
	rfs4_dbe_rele(lsp->rls_dbe);
}

static rfs4_lo_state_t *
rfs4_findlo_state(stateid_t *id, bool_t lock_fp)
{
	rfs4_lo_state_t *lsp;
	bool_t create = FALSE;

	lsp = (rfs4_lo_state_t *)rfs4_dbsearch(rfs4_lo_state_idx, id,
	    &create, NULL, RFS4_DBS_VALID);
	if (lock_fp == TRUE && lsp != NULL)
		rw_enter(&lsp->rls_state->rs_finfo->rf_file_rwlock, RW_READER);

	return (lsp);
}


static uint32_t
lo_state_lo_hash(void *key)
{
	rfs4_lo_state_t *lsp = key;

	return (ADDRHASH(lsp->rls_locker) ^ ADDRHASH(lsp->rls_state));
}

static bool_t
lo_state_lo_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	rfs4_lo_state_t *keyp = key;

	return (keyp->rls_locker == lsp->rls_locker &&
	    keyp->rls_state == lsp->rls_state);
}

static void *
lo_state_lo_mkkey(rfs4_entry_t u_entry)
{
	return (u_entry);
}

rfs4_lo_state_t *
rfs4_findlo_state_by_owner(rfs4_lockowner_t *lo, rfs4_state_t *sp,
    bool_t *create)
{
	rfs4_lo_state_t *lsp;
	rfs4_lo_state_t arg;

	arg.rls_locker = lo;
	arg.rls_state = sp;

	lsp = (rfs4_lo_state_t *)rfs4_dbsearch(rfs4_lo_state_owner_idx, &arg,
	    create, &arg, RFS4_DBS_VALID);

	return (lsp);
}

static stateid_t
get_stateid(id_t eid)
{
	stateid_t id;

	id.bits.boottime = rfs4_start_time;
	id.bits.ident = eid;
	id.bits.chgseq = 0;
	id.bits.type = 0;
	id.bits.pid = 0;

	/*
	 * If we are booted as a cluster node, embed our nodeid.
	 * We've already done sanity checks in rfs4_client_create() so no
	 * need to repeat them here.
	 */
	id.bits.clnodeid = (cluster_bootflags & CLUSTER_BOOTED) ?
	    clconf_get_nodeid() : 0;

	return (id);
}

/*
 * For use only when booted as a cluster node.
 * Returns TRUE if the embedded nodeid indicates that this stateid was
 * generated on another node.
 */
static int
foreign_stateid(stateid_t *id)
{
	ASSERT(cluster_bootflags & CLUSTER_BOOTED);
	return (id->bits.clnodeid != (uint32_t)clconf_get_nodeid());
}

/*
 * For use only when booted as a cluster node.
 * Returns TRUE if the embedded nodeid indicates that this clientid was
 * generated on another node.
 */
static int
foreign_clientid(cid *cidp)
{
	ASSERT(cluster_bootflags & CLUSTER_BOOTED);
	return (cidp->impl_id.c_id >> CLUSTER_NODEID_SHIFT !=
	    (uint32_t)clconf_get_nodeid());
}

/*
 * For use only when booted as a cluster node.
 * Embed our cluster nodeid into the clientid.
 */
static void
embed_nodeid(cid *cidp)
{
	int clnodeid;
	/*
	 * Currently, our state tables are small enough that their
	 * ids will leave enough bits free for the nodeid. If the
	 * tables become larger, we mustn't overwrite the id.
	 * Equally, we only have room for so many bits of nodeid, so
	 * must check that too.
	 */
	ASSERT(cluster_bootflags & CLUSTER_BOOTED);
	ASSERT(cidp->impl_id.c_id >> CLUSTER_NODEID_SHIFT == 0);
	clnodeid = clconf_get_nodeid();
	ASSERT(clnodeid <= CLUSTER_MAX_NODEID);
	ASSERT(clnodeid != NODEID_UNKNOWN);
	cidp->impl_id.c_id |= (clnodeid << CLUSTER_NODEID_SHIFT);
}

static uint32_t
state_hash(void *key)
{
	stateid_t *ip = (stateid_t *)key;

	return (ip->bits.ident);
}

static bool_t
state_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	stateid_t *id = (stateid_t *)key;
	bool_t rc;

	rc = (sp->rs_stateid.bits.boottime == id->bits.boottime &&
	    sp->rs_stateid.bits.ident == id->bits.ident);

	return (rc);
}

static void *
state_mkkey(rfs4_entry_t u_entry)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;

	return (&sp->rs_stateid);
}

static void
rfs4_state_destroy(rfs4_entry_t u_entry)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;

	/* remove from openowner list */
	rfs4_dbe_lock(sp->rs_owner->ro_dbe);
	list_remove(&sp->rs_owner->ro_statelist, sp);
	rfs4_dbe_unlock(sp->rs_owner->ro_dbe);

	list_destroy(&sp->rs_lostatelist);

	/* release any share locks for this stateid if it's still open */
	if (!sp->rs_closed) {
		rfs4_dbe_lock(sp->rs_dbe);
		(void) rfs4_unshare(sp);
		rfs4_dbe_unlock(sp->rs_dbe);
	}

	/* Were done with the file */
	rfs4_file_rele(sp->rs_finfo);
	sp->rs_finfo = NULL;

	/* And now with the openowner */
	rfs4_openowner_rele(sp->rs_owner);
	sp->rs_owner = NULL;
}

static void
rfs4_state_rele_nounlock(rfs4_state_t *sp)
{
	rfs4_dbe_rele(sp->rs_dbe);
}

void
rfs4_state_rele(rfs4_state_t *sp)
{
	rw_exit(&sp->rs_finfo->rf_file_rwlock);
	rfs4_dbe_rele(sp->rs_dbe);
}

static uint32_t
deleg_hash(void *key)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)key;

	return (ADDRHASH(dsp->rds_client) ^ ADDRHASH(dsp->rds_finfo));
}

static bool_t
deleg_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	rfs4_deleg_state_t *kdsp = (rfs4_deleg_state_t *)key;

	return (dsp->rds_client == kdsp->rds_client &&
	    dsp->rds_finfo == kdsp->rds_finfo);
}

static void *
deleg_mkkey(rfs4_entry_t u_entry)
{
	return (u_entry);
}

static uint32_t
deleg_state_hash(void *key)
{
	stateid_t *ip = (stateid_t *)key;

	return (ip->bits.ident);
}

static bool_t
deleg_state_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	stateid_t *id = (stateid_t *)key;
	bool_t rc;

	if (id->bits.type != DELEGID)
		return (FALSE);

	rc = (dsp->rds_delegid.bits.boottime == id->bits.boottime &&
	    dsp->rds_delegid.bits.ident == id->bits.ident);

	return (rc);
}

static void *
deleg_state_mkkey(rfs4_entry_t u_entry)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;

	return (&dsp->rds_delegid);
}

static bool_t
rfs4_deleg_state_expiry(rfs4_entry_t u_entry)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;

	if (rfs4_dbe_is_invalid(dsp->rds_dbe))
		return (TRUE);

	if (dsp->rds_dtype == OPEN_DELEGATE_NONE)
		return (TRUE);

	if ((gethrestime_sec() - dsp->rds_client->rc_last_access
	    > rfs4_lease_time)) {
		rfs4_dbe_invalidate(dsp->rds_dbe);
		return (TRUE);
	}

	return (FALSE);
}

static bool_t
rfs4_deleg_state_create(rfs4_entry_t u_entry, void *argp)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	rfs4_file_t *fp = ((rfs4_deleg_state_t *)argp)->rds_finfo;
	rfs4_client_t *cp = ((rfs4_deleg_state_t *)argp)->rds_client;

	rfs4_dbe_hold(fp->rf_dbe);
	rfs4_dbe_hold(cp->rc_dbe);

	dsp->rds_delegid = get_stateid(rfs4_dbe_getid(dsp->rds_dbe));
	dsp->rds_delegid.bits.type = DELEGID;
	dsp->rds_finfo = fp;
	dsp->rds_client = cp;
	dsp->rds_dtype = OPEN_DELEGATE_NONE;

	dsp->rds_time_granted = gethrestime_sec();	/* observability */
	dsp->rds_time_revoked = 0;

	list_link_init(&dsp->rds_node);

	return (TRUE);
}

static void
rfs4_deleg_state_destroy(rfs4_entry_t u_entry)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;

	/* return delegation if necessary */
	rfs4_return_deleg(dsp, FALSE);

	/* Were done with the file */
	rfs4_file_rele(dsp->rds_finfo);
	dsp->rds_finfo = NULL;

	/* And now with the openowner */
	rfs4_client_rele(dsp->rds_client);
	dsp->rds_client = NULL;
}

rfs4_deleg_state_t *
rfs4_finddeleg(rfs4_state_t *sp, bool_t *create)
{
	rfs4_deleg_state_t ds, *dsp;

	ds.rds_client = sp->rs_owner->ro_client;
	ds.rds_finfo = sp->rs_finfo;

	dsp = (rfs4_deleg_state_t *)rfs4_dbsearch(rfs4_deleg_idx, &ds,
	    create, &ds, RFS4_DBS_VALID);

	return (dsp);
}

rfs4_deleg_state_t *
rfs4_finddelegstate(stateid_t *id)
{
	rfs4_deleg_state_t *dsp;
	bool_t create = FALSE;

	dsp = (rfs4_deleg_state_t *)rfs4_dbsearch(rfs4_deleg_state_idx, id,
	    &create, NULL, RFS4_DBS_VALID);

	return (dsp);
}

void
rfs4_deleg_state_rele(rfs4_deleg_state_t *dsp)
{
	rfs4_dbe_rele(dsp->rds_dbe);
}

void
rfs4_update_lock_sequence(rfs4_lo_state_t *lsp)
{

	rfs4_dbe_lock(lsp->rls_dbe);

	/*
	 * If we are skipping sequence id checking, this means that
	 * this is the first lock request and therefore the sequence
	 * id does not need to be updated.  This only happens on the
	 * first lock request for a lockowner
	 */
	if (!lsp->rls_skip_seqid_check)
		lsp->rls_seqid++;

	rfs4_dbe_unlock(lsp->rls_dbe);
}

void
rfs4_update_lock_resp(rfs4_lo_state_t *lsp, nfs_resop4 *resp)
{

	rfs4_dbe_lock(lsp->rls_dbe);

	rfs4_free_reply(&lsp->rls_reply);

	rfs4_copy_reply(&lsp->rls_reply, resp);

	rfs4_dbe_unlock(lsp->rls_dbe);
}

void
rfs4_free_opens(rfs4_openowner_t *oo, bool_t invalidate,
    bool_t close_of_client)
{
	rfs4_state_t *sp;

	rfs4_dbe_lock(oo->ro_dbe);

	for (sp = list_head(&oo->ro_statelist); sp != NULL;
	    sp = list_next(&oo->ro_statelist, sp)) {
		rfs4_state_close(sp, FALSE, close_of_client, CRED());
		if (invalidate == TRUE)
			rfs4_dbe_invalidate(sp->rs_dbe);
	}

	rfs4_dbe_invalidate(oo->ro_dbe);
	rfs4_dbe_unlock(oo->ro_dbe);
}

static uint32_t
state_owner_file_hash(void *key)
{
	rfs4_state_t *sp = key;

	return (ADDRHASH(sp->rs_owner) ^ ADDRHASH(sp->rs_finfo));
}

static bool_t
state_owner_file_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	rfs4_state_t *arg = key;

	if (sp->rs_closed == TRUE)
		return (FALSE);

	return (arg->rs_owner == sp->rs_owner && arg->rs_finfo == sp->rs_finfo);
}

static void *
state_owner_file_mkkey(rfs4_entry_t u_entry)
{
	return (u_entry);
}

static uint32_t
state_file_hash(void *key)
{
	return (ADDRHASH(key));
}

static bool_t
state_file_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	rfs4_file_t *fp = key;

	if (sp->rs_closed == TRUE)
		return (FALSE);

	return (fp == sp->rs_finfo);
}

static void *
state_file_mkkey(rfs4_entry_t u_entry)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;

	return (sp->rs_finfo);
}

rfs4_state_t *
rfs4_findstate_by_owner_file(rfs4_openowner_t *oo, rfs4_file_t *fp,
	bool_t *create)
{
	rfs4_state_t *sp;
	rfs4_state_t key;

	key.rs_owner = oo;
	key.rs_finfo = fp;

	sp = (rfs4_state_t *)rfs4_dbsearch(rfs4_state_owner_file_idx, &key,
	    create, &key, RFS4_DBS_VALID);

	return (sp);
}

/* This returns ANY state struct that refers to this file */
static rfs4_state_t *
rfs4_findstate_by_file(rfs4_file_t *fp)
{
	bool_t create = FALSE;

	return ((rfs4_state_t *)rfs4_dbsearch(rfs4_state_file_idx, fp,
	    &create, fp, RFS4_DBS_VALID));
}

static bool_t
rfs4_state_expiry(rfs4_entry_t u_entry)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;

	if (rfs4_dbe_is_invalid(sp->rs_dbe))
		return (TRUE);

	if (sp->rs_closed == TRUE &&
	    ((gethrestime_sec() - rfs4_dbe_get_timerele(sp->rs_dbe))
	    > rfs4_lease_time))
		return (TRUE);

	return ((gethrestime_sec() - sp->rs_owner->ro_client->rc_last_access
	    > rfs4_lease_time));
}

static bool_t
rfs4_state_create(rfs4_entry_t u_entry, void *argp)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	rfs4_file_t *fp = ((rfs4_state_t *)argp)->rs_finfo;
	rfs4_openowner_t *oo = ((rfs4_state_t *)argp)->rs_owner;

	rfs4_dbe_hold(fp->rf_dbe);
	rfs4_dbe_hold(oo->ro_dbe);
	sp->rs_stateid = get_stateid(rfs4_dbe_getid(sp->rs_dbe));
	sp->rs_stateid.bits.type = OPENID;
	sp->rs_owner = oo;
	sp->rs_finfo = fp;

	list_create(&sp->rs_lostatelist, sizeof (rfs4_lo_state_t),
	    offsetof(rfs4_lo_state_t, rls_node));

	/* Insert state on per open owner's list */
	rfs4_dbe_lock(oo->ro_dbe);
	list_insert_tail(&oo->ro_statelist, sp);
	rfs4_dbe_unlock(oo->ro_dbe);

	return (TRUE);
}

static rfs4_state_t *
rfs4_findstate(stateid_t *id, rfs4_dbsearch_type_t find_invalid, bool_t lock_fp)
{
	rfs4_state_t *sp;
	bool_t create = FALSE;

	sp = (rfs4_state_t *)rfs4_dbsearch(rfs4_state_idx, id,
	    &create, NULL, find_invalid);
	if (lock_fp == TRUE && sp != NULL)
		rw_enter(&sp->rs_finfo->rf_file_rwlock, RW_READER);

	return (sp);
}

void
rfs4_state_close(rfs4_state_t *sp, bool_t lock_held, bool_t close_of_client,
    cred_t *cr)
{
	/* Remove the associated lo_state owners */
	if (!lock_held)
		rfs4_dbe_lock(sp->rs_dbe);

	/*
	 * If refcnt == 0, the dbe is about to be destroyed.
	 * lock state will be released by the reaper thread.
	 */

	if (rfs4_dbe_refcnt(sp->rs_dbe) > 0) {
		if (sp->rs_closed == FALSE) {
			rfs4_release_share_lock_state(sp, cr, close_of_client);
			sp->rs_closed = TRUE;
		}
	}

	if (!lock_held)
		rfs4_dbe_unlock(sp->rs_dbe);
}

/*
 * Remove all state associated with the given client.
 */
void
rfs4_client_state_remove(rfs4_client_t *cp)
{
	rfs4_openowner_t *oo;

	rfs4_dbe_lock(cp->rc_dbe);

	for (oo = list_head(&cp->rc_openownerlist); oo != NULL;
	    oo = list_next(&cp->rc_openownerlist, oo)) {
		rfs4_free_opens(oo, TRUE, TRUE);
	}

	rfs4_dbe_unlock(cp->rc_dbe);
}

void
rfs4_client_close(rfs4_client_t *cp)
{
	/* Mark client as going away. */
	rfs4_dbe_lock(cp->rc_dbe);
	rfs4_dbe_invalidate(cp->rc_dbe);
	rfs4_dbe_unlock(cp->rc_dbe);

	rfs4_client_state_remove(cp);

	/* Release the client */
	rfs4_client_rele(cp);
}

nfsstat4
rfs4_check_clientid(clientid4 *cp, int setclid_confirm)
{
	cid *cidp = (cid *) cp;

	/*
	 * If we are booted as a cluster node, check the embedded nodeid.
	 * If it indicates that this clientid was generated on another node,
	 * inform the client accordingly.
	 */
	if (cluster_bootflags & CLUSTER_BOOTED && foreign_clientid(cidp))
		return (NFS4ERR_STALE_CLIENTID);

	/*
	 * If the server start time matches the time provided
	 * by the client (via the clientid) and this is NOT a
	 * setclientid_confirm then return EXPIRED.
	 */
	if (!setclid_confirm && cidp->impl_id.start_time == rfs4_start_time)
		return (NFS4ERR_EXPIRED);

	return (NFS4ERR_STALE_CLIENTID);
}

/*
 * This is used when a stateid has not been found amongst the
 * current server's state.  Check the stateid to see if it
 * was from this server instantiation or not.
 */
static nfsstat4
what_stateid_error(stateid_t *id, stateid_type_t type)
{
	/* If we are booted as a cluster node, was stateid locally generated? */
	if ((cluster_bootflags & CLUSTER_BOOTED) && foreign_stateid(id))
		return (NFS4ERR_STALE_STATEID);

	/* If types don't match then no use checking further */
	if (type != id->bits.type)
		return (NFS4ERR_BAD_STATEID);

	/* From a different server instantiation, return STALE */
	if (id->bits.boottime != rfs4_start_time)
		return (NFS4ERR_STALE_STATEID);

	/*
	 * From this server but the state is most likely beyond lease
	 * timeout: return NFS4ERR_EXPIRED.  However, there is the
	 * case of a delegation stateid.  For delegations, there is a
	 * case where the state can be removed without the client's
	 * knowledge/consent: revocation.  In the case of delegation
	 * revocation, the delegation state will be removed and will
	 * not be found.  If the client does something like a
	 * DELEGRETURN or even a READ/WRITE with a delegatoin stateid
	 * that has been revoked, the server should return BAD_STATEID
	 * instead of the more common EXPIRED error.
	 */
	if (id->bits.boottime == rfs4_start_time) {
		if (type == DELEGID)
			return (NFS4ERR_BAD_STATEID);
		else
			return (NFS4ERR_EXPIRED);
	}

	return (NFS4ERR_BAD_STATEID);
}

/*
 * Used later on to find the various state structs.  When called from
 * rfs4_check_stateid()->rfs4_get_all_state(), no file struct lock is
 * taken (it is not needed) and helps on the read/write path with
 * respect to performance.
 */
static nfsstat4
rfs4_get_state_lockit(stateid4 *stateid, rfs4_state_t **spp,
    rfs4_dbsearch_type_t find_invalid, bool_t lock_fp)
{
	stateid_t *id = (stateid_t *)stateid;
	rfs4_state_t *sp;

	*spp = NULL;

	/* If we are booted as a cluster node, was stateid locally generated? */
	if ((cluster_bootflags & CLUSTER_BOOTED) && foreign_stateid(id))
		return (NFS4ERR_STALE_STATEID);

	sp = rfs4_findstate(id, find_invalid, lock_fp);
	if (sp == NULL) {
		return (what_stateid_error(id, OPENID));
	}

	if (rfs4_lease_expired(sp->rs_owner->ro_client)) {
		if (lock_fp == TRUE)
			rfs4_state_rele(sp);
		else
			rfs4_state_rele_nounlock(sp);
		return (NFS4ERR_EXPIRED);
	}

	*spp = sp;

	return (NFS4_OK);
}

nfsstat4
rfs4_get_state(stateid4 *stateid, rfs4_state_t **spp,
    rfs4_dbsearch_type_t find_invalid)
{
	return (rfs4_get_state_lockit(stateid, spp, find_invalid, TRUE));
}

int
rfs4_check_stateid_seqid(rfs4_state_t *sp, stateid4 *stateid)
{
	stateid_t *id = (stateid_t *)stateid;

	if (rfs4_lease_expired(sp->rs_owner->ro_client))
		return (NFS4_CHECK_STATEID_EXPIRED);

	/* Stateid is some time in the future - that's bad */
	if (sp->rs_stateid.bits.chgseq < id->bits.chgseq)
		return (NFS4_CHECK_STATEID_BAD);

	if (sp->rs_stateid.bits.chgseq == id->bits.chgseq + 1)
		return (NFS4_CHECK_STATEID_REPLAY);

	/* Stateid is some time in the past - that's old */
	if (sp->rs_stateid.bits.chgseq > id->bits.chgseq)
		return (NFS4_CHECK_STATEID_OLD);

	/* Caller needs to know about confirmation before closure */
	if (sp->rs_owner->ro_need_confirm)
		return (NFS4_CHECK_STATEID_UNCONFIRMED);

	if (sp->rs_closed == TRUE)
		return (NFS4_CHECK_STATEID_CLOSED);

	return (NFS4_CHECK_STATEID_OKAY);
}

int
rfs4_check_lo_stateid_seqid(rfs4_lo_state_t *lsp, stateid4 *stateid)
{
	stateid_t *id = (stateid_t *)stateid;

	if (rfs4_lease_expired(lsp->rls_state->rs_owner->ro_client))
		return (NFS4_CHECK_STATEID_EXPIRED);

	/* Stateid is some time in the future - that's bad */
	if (lsp->rls_lockid.bits.chgseq < id->bits.chgseq)
		return (NFS4_CHECK_STATEID_BAD);

	if (lsp->rls_lockid.bits.chgseq == id->bits.chgseq + 1)
		return (NFS4_CHECK_STATEID_REPLAY);

	/* Stateid is some time in the past - that's old */
	if (lsp->rls_lockid.bits.chgseq > id->bits.chgseq)
		return (NFS4_CHECK_STATEID_OLD);

	if (lsp->rls_state->rs_closed == TRUE)
		return (NFS4_CHECK_STATEID_CLOSED);

	return (NFS4_CHECK_STATEID_OKAY);
}

nfsstat4
rfs4_get_deleg_state(stateid4 *stateid, rfs4_deleg_state_t **dspp)
{
	stateid_t *id = (stateid_t *)stateid;
	rfs4_deleg_state_t *dsp;

	*dspp = NULL;

	/* If we are booted as a cluster node, was stateid locally generated? */
	if ((cluster_bootflags & CLUSTER_BOOTED) && foreign_stateid(id))
		return (NFS4ERR_STALE_STATEID);

	dsp = rfs4_finddelegstate(id);
	if (dsp == NULL) {
		return (what_stateid_error(id, DELEGID));
	}

	if (rfs4_lease_expired(dsp->rds_client)) {
		rfs4_deleg_state_rele(dsp);
		return (NFS4ERR_EXPIRED);
	}

	*dspp = dsp;

	return (NFS4_OK);
}

nfsstat4
rfs4_get_lo_state(stateid4 *stateid, rfs4_lo_state_t **lspp, bool_t lock_fp)
{
	stateid_t *id = (stateid_t *)stateid;
	rfs4_lo_state_t *lsp;

	*lspp = NULL;

	/* If we are booted as a cluster node, was stateid locally generated? */
	if ((cluster_bootflags & CLUSTER_BOOTED) && foreign_stateid(id))
		return (NFS4ERR_STALE_STATEID);

	lsp = rfs4_findlo_state(id, lock_fp);
	if (lsp == NULL) {
		return (what_stateid_error(id, LOCKID));
	}

	if (rfs4_lease_expired(lsp->rls_state->rs_owner->ro_client)) {
		rfs4_lo_state_rele(lsp, lock_fp);
		return (NFS4ERR_EXPIRED);
	}

	*lspp = lsp;

	return (NFS4_OK);
}

static nfsstat4
rfs4_get_all_state(stateid4 *sid, rfs4_state_t **spp,
    rfs4_deleg_state_t **dspp, rfs4_lo_state_t **lspp)
{
	rfs4_state_t *sp = NULL;
	rfs4_deleg_state_t *dsp = NULL;
	rfs4_lo_state_t *lsp = NULL;
	stateid_t *id;
	nfsstat4 status;

	*spp = NULL; *dspp = NULL; *lspp = NULL;

	id = (stateid_t *)sid;
	switch (id->bits.type) {
	case OPENID:
		status = rfs4_get_state_lockit(sid, &sp, FALSE, FALSE);
		break;
	case DELEGID:
		status = rfs4_get_deleg_state(sid, &dsp);
		break;
	case LOCKID:
		status = rfs4_get_lo_state(sid, &lsp, FALSE);
		if (status == NFS4_OK) {
			sp = lsp->rls_state;
			rfs4_dbe_hold(sp->rs_dbe);
		}
		break;
	default:
		status = NFS4ERR_BAD_STATEID;
	}

	if (status == NFS4_OK) {
		*spp = sp;
		*dspp = dsp;
		*lspp = lsp;
	}

	return (status);
}

/*
 * Given the I/O mode (FREAD or FWRITE), this checks whether the
 * rfs4_state_t struct has access to do this operation and if so
 * return NFS4_OK; otherwise the proper NFSv4 error is returned.
 */
nfsstat4
rfs4_state_has_access(rfs4_state_t *sp, int mode, vnode_t *vp)
{
	nfsstat4 stat = NFS4_OK;
	rfs4_file_t *fp;
	bool_t create = FALSE;

	rfs4_dbe_lock(sp->rs_dbe);
	if (mode == FWRITE) {
		if (!(sp->rs_share_access & OPEN4_SHARE_ACCESS_WRITE)) {
			stat = NFS4ERR_OPENMODE;
		}
	} else if (mode == FREAD) {
		if (!(sp->rs_share_access & OPEN4_SHARE_ACCESS_READ)) {
			/*
			 * If we have OPENed the file with DENYing access
			 * to both READ and WRITE then no one else could
			 * have OPENed the file, hence no conflicting READ
			 * deny.  This check is merely an optimization.
			 */
			if (sp->rs_share_deny == OPEN4_SHARE_DENY_BOTH)
				goto out;

			/* Check against file struct's DENY mode */
			fp = rfs4_findfile(vp, NULL, &create);
			if (fp != NULL) {
				int deny_read = 0;
				rfs4_dbe_lock(fp->rf_dbe);
				/*
				 * Check if any other open owner has the file
				 * OPENed with deny READ.
				 */
				if (sp->rs_share_deny & OPEN4_SHARE_DENY_READ)
					deny_read = 1;
				ASSERT(fp->rf_deny_read >= deny_read);
				if (fp->rf_deny_read > deny_read)
					stat = NFS4ERR_OPENMODE;
				rfs4_dbe_unlock(fp->rf_dbe);
				rfs4_file_rele(fp);
			}
		}
	} else {
		/* Illegal I/O mode */
		stat = NFS4ERR_INVAL;
	}
out:
	rfs4_dbe_unlock(sp->rs_dbe);
	return (stat);
}

/*
 * Given the I/O mode (FREAD or FWRITE), the vnode, the stateid and whether
 * the file is being truncated, return NFS4_OK if allowed or appropriate
 * V4 error if not. Note NFS4ERR_DELAY will be returned and a recall on
 * the associated file will be done if the I/O is not consistent with any
 * delegation in effect on the file. Should be holding VOP_RWLOCK, either
 * as reader or writer as appropriate. rfs4_op_open will acquire the
 * VOP_RWLOCK as writer when setting up delegation. If the stateid is bad
 * this routine will return NFS4ERR_BAD_STATEID. In addition, through the
 * deleg parameter, we will return whether a write delegation is held by
 * the client associated with this stateid.
 * If the server instance associated with the relevant client is in its
 * grace period, return NFS4ERR_GRACE.
 */

nfsstat4
rfs4_check_stateid(int mode, vnode_t *vp,
    stateid4 *stateid, bool_t trunc, bool_t *deleg,
    bool_t do_access, caller_context_t *ct)
{
	rfs4_file_t *fp;
	bool_t create = FALSE;
	rfs4_state_t *sp;
	rfs4_deleg_state_t *dsp;
	rfs4_lo_state_t *lsp;
	stateid_t *id = (stateid_t *)stateid;
	nfsstat4 stat = NFS4_OK;

	if (ct != NULL) {
		ct->cc_sysid = 0;
		ct->cc_pid = 0;
		ct->cc_caller_id = nfs4_srv_caller_id;
		ct->cc_flags = CC_DONTBLOCK;
	}

	if (ISSPECIAL(stateid)) {
		fp = rfs4_findfile(vp, NULL, &create);
		if (fp == NULL)
			return (NFS4_OK);
		if (fp->rf_dinfo.rd_dtype == OPEN_DELEGATE_NONE) {
			rfs4_file_rele(fp);
			return (NFS4_OK);
		}
		if (mode == FWRITE ||
		    fp->rf_dinfo.rd_dtype == OPEN_DELEGATE_WRITE) {
			rfs4_recall_deleg(fp, trunc, NULL);
			rfs4_file_rele(fp);
			return (NFS4ERR_DELAY);
		}
		rfs4_file_rele(fp);
		return (NFS4_OK);
	} else {
		stat = rfs4_get_all_state(stateid, &sp, &dsp, &lsp);
		if (stat != NFS4_OK)
			return (stat);
		if (lsp != NULL) {
			/* Is associated server instance in its grace period? */
			if (rfs4_clnt_in_grace(lsp->rls_locker->rl_client)) {
				rfs4_lo_state_rele(lsp, FALSE);
				if (sp != NULL)
					rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_GRACE);
			}
			if (id->bits.type == LOCKID) {
				/* Seqid in the future? - that's bad */
				if (lsp->rls_lockid.bits.chgseq <
				    id->bits.chgseq) {
					rfs4_lo_state_rele(lsp, FALSE);
					if (sp != NULL)
						rfs4_state_rele_nounlock(sp);
					return (NFS4ERR_BAD_STATEID);
				}
				/* Seqid in the past? - that's old */
				if (lsp->rls_lockid.bits.chgseq >
				    id->bits.chgseq) {
					rfs4_lo_state_rele(lsp, FALSE);
					if (sp != NULL)
						rfs4_state_rele_nounlock(sp);
					return (NFS4ERR_OLD_STATEID);
				}
				/* Ensure specified filehandle matches */
				if (lsp->rls_state->rs_finfo->rf_vp != vp) {
					rfs4_lo_state_rele(lsp, FALSE);
					if (sp != NULL)
						rfs4_state_rele_nounlock(sp);
					return (NFS4ERR_BAD_STATEID);
				}
			}
			if (ct != NULL) {
				ct->cc_sysid =
				    lsp->rls_locker->rl_client->rc_sysidt;
				ct->cc_pid = lsp->rls_locker->rl_pid;
			}
			rfs4_lo_state_rele(lsp, FALSE);
		}

		/* Stateid provided was an "open" stateid */
		if (sp != NULL) {
			/* Is associated server instance in its grace period? */
			if (rfs4_clnt_in_grace(sp->rs_owner->ro_client)) {
				rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_GRACE);
			}
			if (id->bits.type == OPENID) {
				/* Seqid in the future? - that's bad */
				if (sp->rs_stateid.bits.chgseq <
				    id->bits.chgseq) {
					rfs4_state_rele_nounlock(sp);
					return (NFS4ERR_BAD_STATEID);
				}
				/* Seqid in the past - that's old */
				if (sp->rs_stateid.bits.chgseq >
				    id->bits.chgseq) {
					rfs4_state_rele_nounlock(sp);
					return (NFS4ERR_OLD_STATEID);
				}
			}
			/* Ensure specified filehandle matches */
			if (sp->rs_finfo->rf_vp != vp) {
				rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_BAD_STATEID);
			}

			if (sp->rs_owner->ro_need_confirm) {
				rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_BAD_STATEID);
			}

			if (sp->rs_closed == TRUE) {
				rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_OLD_STATEID);
			}

			if (do_access)
				stat = rfs4_state_has_access(sp, mode, vp);
			else
				stat = NFS4_OK;

			/*
			 * Return whether this state has write
			 * delegation if desired
			 */
			if (deleg && (sp->rs_finfo->rf_dinfo.rd_dtype ==
			    OPEN_DELEGATE_WRITE))
				*deleg = TRUE;

			/*
			 * We got a valid stateid, so we update the
			 * lease on the client. Ideally we would like
			 * to do this after the calling op succeeds,
			 * but for now this will be good
			 * enough. Callers of this routine are
			 * currently insulated from the state stuff.
			 */
			rfs4_update_lease(sp->rs_owner->ro_client);

			/*
			 * If a delegation is present on this file and
			 * this is a WRITE, then update the lastwrite
			 * time to indicate that activity is present.
			 */
			if (sp->rs_finfo->rf_dinfo.rd_dtype ==
			    OPEN_DELEGATE_WRITE &&
			    mode == FWRITE) {
				sp->rs_finfo->rf_dinfo.rd_time_lastwrite =
				    gethrestime_sec();
			}

			rfs4_state_rele_nounlock(sp);

			return (stat);
		}

		if (dsp != NULL) {
			/* Is associated server instance in its grace period? */
			if (rfs4_clnt_in_grace(dsp->rds_client)) {
				rfs4_deleg_state_rele(dsp);
				return (NFS4ERR_GRACE);
			}
			if (dsp->rds_delegid.bits.chgseq != id->bits.chgseq) {
				rfs4_deleg_state_rele(dsp);
				return (NFS4ERR_BAD_STATEID);
			}

			/* Ensure specified filehandle matches */
			if (dsp->rds_finfo->rf_vp != vp) {
				rfs4_deleg_state_rele(dsp);
				return (NFS4ERR_BAD_STATEID);
			}
			/*
			 * Return whether this state has write
			 * delegation if desired
			 */
			if (deleg && (dsp->rds_finfo->rf_dinfo.rd_dtype ==
			    OPEN_DELEGATE_WRITE))
				*deleg = TRUE;

			rfs4_update_lease(dsp->rds_client);

			/*
			 * If a delegation is present on this file and
			 * this is a WRITE, then update the lastwrite
			 * time to indicate that activity is present.
			 */
			if (dsp->rds_finfo->rf_dinfo.rd_dtype ==
			    OPEN_DELEGATE_WRITE && mode == FWRITE) {
				dsp->rds_finfo->rf_dinfo.rd_time_lastwrite =
				    gethrestime_sec();
			}

			/*
			 * XXX - what happens if this is a WRITE and the
			 * delegation type of for READ.
			 */
			rfs4_deleg_state_rele(dsp);

			return (stat);
		}
		/*
		 * If we got this far, something bad happened
		 */
		return (NFS4ERR_BAD_STATEID);
	}
}


/*
 * This is a special function in that for the file struct provided the
 * server wants to remove/close all current state associated with the
 * file.  The prime use of this would be with OP_REMOVE to force the
 * release of state and particularly of file locks.
 *
 * There is an assumption that there is no delegations outstanding on
 * this file at this point.  The caller should have waited for those
 * to be returned or revoked.
 */
void
rfs4_close_all_state(rfs4_file_t *fp)
{
	rfs4_state_t *sp;

	rfs4_dbe_lock(fp->rf_dbe);

#ifdef DEBUG
	/* only applies when server is handing out delegations */
	if (rfs4_deleg_policy != SRV_NEVER_DELEGATE)
		ASSERT(fp->rf_dinfo.rd_hold_grant > 0);
#endif

	/* No delegations for this file */
	ASSERT(list_is_empty(&fp->rf_delegstatelist));

	/* Make sure that it can not be found */
	rfs4_dbe_invalidate(fp->rf_dbe);

	if (fp->rf_vp == NULL) {
		rfs4_dbe_unlock(fp->rf_dbe);
		return;
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	/*
	 * Hold as writer to prevent other server threads from
	 * processing requests related to the file while all state is
	 * being removed.
	 */
	rw_enter(&fp->rf_file_rwlock, RW_WRITER);

	/* Remove ALL state from the file */
	while (sp = rfs4_findstate_by_file(fp)) {
		rfs4_state_close(sp, FALSE, FALSE, CRED());
		rfs4_state_rele_nounlock(sp);
	}

	/*
	 * This is only safe since there are no further references to
	 * the file.
	 */
	rfs4_dbe_lock(fp->rf_dbe);
	if (fp->rf_vp) {
		vnode_t *vp = fp->rf_vp;

		mutex_enter(&vp->v_vsd_lock);
		(void) vsd_set(vp, nfs4_srv_vkey, NULL);
		mutex_exit(&vp->v_vsd_lock);
		VN_RELE(vp);
		fp->rf_vp = NULL;
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	/* Finally let other references to proceed */
	rw_exit(&fp->rf_file_rwlock);
}

/*
 * This function is used as a target for the rfs4_dbe_walk() call
 * below.  The purpose of this function is to see if the
 * lockowner_state refers to a file that resides within the exportinfo
 * export.  If so, then remove the lock_owner state (file locks and
 * share "locks") for this object since the intent is the server is
 * unexporting the specified directory.  Be sure to invalidate the
 * object after the state has been released
 */
static void
rfs4_lo_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs_fh4_fmt_t   fhfmt4, *exi_fhp, *finfo_fhp;
	fhandle_t *efhp;

	efhp = (fhandle_t *)&exi->exi_fh;
	exi_fhp = (nfs_fh4_fmt_t *)&fhfmt4;

	FH_TO_FMT4(efhp, exi_fhp);

	finfo_fhp = (nfs_fh4_fmt_t *)lsp->rls_state->rs_finfo->
	    rf_filehandle.nfs_fh4_val;

	if (EQFSID(&finfo_fhp->fh4_fsid, &exi_fhp->fh4_fsid) &&
	    bcmp(&finfo_fhp->fh4_xdata, &exi_fhp->fh4_xdata,
	    exi_fhp->fh4_xlen) == 0) {
		rfs4_state_close(lsp->rls_state, FALSE, FALSE, CRED());
		rfs4_dbe_invalidate(lsp->rls_dbe);
		rfs4_dbe_invalidate(lsp->rls_state->rs_dbe);
	}
}

/*
 * This function is used as a target for the rfs4_dbe_walk() call
 * below.  The purpose of this function is to see if the state refers
 * to a file that resides within the exportinfo export.  If so, then
 * remove the open state for this object since the intent is the
 * server is unexporting the specified directory.  The main result for
 * this type of entry is to invalidate it such it will not be found in
 * the future.
 */
static void
rfs4_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs_fh4_fmt_t   fhfmt4, *exi_fhp, *finfo_fhp;
	fhandle_t *efhp;

	efhp = (fhandle_t *)&exi->exi_fh;
	exi_fhp = (nfs_fh4_fmt_t *)&fhfmt4;

	FH_TO_FMT4(efhp, exi_fhp);

	finfo_fhp =
	    (nfs_fh4_fmt_t *)sp->rs_finfo->rf_filehandle.nfs_fh4_val;

	if (EQFSID(&finfo_fhp->fh4_fsid, &exi_fhp->fh4_fsid) &&
	    bcmp(&finfo_fhp->fh4_xdata, &exi_fhp->fh4_xdata,
	    exi_fhp->fh4_xlen) == 0) {
		rfs4_state_close(sp, TRUE, FALSE, CRED());
		rfs4_dbe_invalidate(sp->rs_dbe);
	}
}

/*
 * This function is used as a target for the rfs4_dbe_walk() call
 * below.  The purpose of this function is to see if the state refers
 * to a file that resides within the exportinfo export.  If so, then
 * remove the deleg state for this object since the intent is the
 * server is unexporting the specified directory.  The main result for
 * this type of entry is to invalidate it such it will not be found in
 * the future.
 */
static void
rfs4_deleg_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs_fh4_fmt_t   fhfmt4, *exi_fhp, *finfo_fhp;
	fhandle_t *efhp;

	efhp = (fhandle_t *)&exi->exi_fh;
	exi_fhp = (nfs_fh4_fmt_t *)&fhfmt4;

	FH_TO_FMT4(efhp, exi_fhp);

	finfo_fhp =
	    (nfs_fh4_fmt_t *)dsp->rds_finfo->rf_filehandle.nfs_fh4_val;

	if (EQFSID(&finfo_fhp->fh4_fsid, &exi_fhp->fh4_fsid) &&
	    bcmp(&finfo_fhp->fh4_xdata, &exi_fhp->fh4_xdata,
	    exi_fhp->fh4_xlen) == 0) {
		rfs4_dbe_invalidate(dsp->rds_dbe);
	}
}

/*
 * This function is used as a target for the rfs4_dbe_walk() call
 * below.  The purpose of this function is to see if the state refers
 * to a file that resides within the exportinfo export.  If so, then
 * release vnode hold for this object since the intent is the server
 * is unexporting the specified directory.  Invalidation will prevent
 * this struct from being found in the future.
 */
static void
rfs4_file_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs_fh4_fmt_t   fhfmt4, *exi_fhp, *finfo_fhp;
	fhandle_t *efhp;

	efhp = (fhandle_t *)&exi->exi_fh;
	exi_fhp = (nfs_fh4_fmt_t *)&fhfmt4;

	FH_TO_FMT4(efhp, exi_fhp);

	finfo_fhp = (nfs_fh4_fmt_t *)fp->rf_filehandle.nfs_fh4_val;

	if (EQFSID(&finfo_fhp->fh4_fsid, &exi_fhp->fh4_fsid) &&
	    bcmp(&finfo_fhp->fh4_xdata, &exi_fhp->fh4_xdata,
	    exi_fhp->fh4_xlen) == 0) {
		if (fp->rf_vp) {
			vnode_t *vp = fp->rf_vp;

			/*
			 * don't leak monitors and remove the reference
			 * put on the vnode when the delegation was granted.
			 */
			if (fp->rf_dinfo.rd_dtype == OPEN_DELEGATE_READ) {
				(void) fem_uninstall(vp, deleg_rdops,
				    (void *)fp);
				vn_open_downgrade(vp, FREAD);
			} else if (fp->rf_dinfo.rd_dtype ==
			    OPEN_DELEGATE_WRITE) {
				(void) fem_uninstall(vp, deleg_wrops,
				    (void *)fp);
				vn_open_downgrade(vp, FREAD|FWRITE);
			}
			mutex_enter(&vp->v_vsd_lock);
			(void) vsd_set(vp, nfs4_srv_vkey, NULL);
			mutex_exit(&vp->v_vsd_lock);
			VN_RELE(vp);
			fp->rf_vp = NULL;
		}
		rfs4_dbe_invalidate(fp->rf_dbe);
	}
}

/*
 * Given a directory that is being unexported, cleanup/release all
 * state in the server that refers to objects residing underneath this
 * particular export.  The ordering of the release is important.
 * Lock_owner, then state and then file.
 */
void
rfs4_clean_state_exi(struct exportinfo *exi)
{
	mutex_enter(&rfs4_state_lock);

	if (rfs4_server_state == NULL) {
		mutex_exit(&rfs4_state_lock);
		return;
	}

	rfs4_dbe_walk(rfs4_lo_state_tab, rfs4_lo_state_walk_callout, exi);
	rfs4_dbe_walk(rfs4_state_tab, rfs4_state_walk_callout, exi);
	rfs4_dbe_walk(rfs4_deleg_state_tab, rfs4_deleg_state_walk_callout, exi);
	rfs4_dbe_walk(rfs4_file_tab, rfs4_file_walk_callout, exi);

	mutex_exit(&rfs4_state_lock);
}
