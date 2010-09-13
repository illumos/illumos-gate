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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	All Rights Reserved					*/


/*
 * Common Inter-Process Communication routines.
 *
 * Overview
 * --------
 *
 * The System V inter-process communication (IPC) facilities provide
 * three services, message queues, semaphore arrays, and shared memory
 * segments, which are mananged using filesystem-like namespaces.
 * Unlike a filesystem, these namespaces aren't mounted and accessible
 * via a path -- a special API is used to interact with the different
 * facilities (nothing precludes a VFS-based interface, but the
 * standards require the special APIs).  Furthermore, these special
 * APIs don't use file descriptors, nor do they have an equivalent.
 * This means that every operation which acts on an object needs to
 * perform the quivalent of a lookup, which in turn means that every
 * operation can fail if the specified object doesn't exist in the
 * facility's namespace.
 *
 * Objects
 * -------
 *
 * Each object in a namespace has a unique ID, which is assigned by the
 * system and is used to identify the object when performing operations
 * on it.  An object can also have a key, which is selected by the user
 * at allocation time and is used as a primitive rendezvous mechanism.
 * An object without a key is said to have a "private" key.
 *
 * To perform an operation on an object given its key, one must first
 * perform a lookup and obtain its ID.  The ID is then used to identify
 * the object when performing the operation.  If the object has a
 * private key, the ID must be known or obtained by other means.
 *
 * Each object in the namespace has a creator uid and gid, as well as
 * an owner uid and gid.  Both are initialized with the ruid and rgid
 * of the process which created the object.  The creator or current
 * owner has the ability to change the owner of the object.
 *
 * Each object in the namespace has a set of file-like permissions,
 * which, in conjunction with the creator and owner uid and gid,
 * control read and write access to the object (execute is ignored).
 *
 * Each object also has a creator project and zone, which are used to
 * account for its resource usage.
 *
 * Operations
 * ----------
 *
 * There are five operations which all three facilities have in
 * common: GET, SET, STAT, RMID, and IDS.
 *
 * GET, like open, is used to allocate a new object or obtain an
 * existing one (using its key).  It takes a key, a set of flags and
 * mode bits, and optionally facility-specific arguments.  If the key
 * is IPC_PRIVATE, a new object with the requested mode bits and
 * facility-specific attributes is created.  If the key isn't
 * IPC_PRIVATE, the GET will attempt to look up the specified key and
 * either return that or create a new key depending on the state of the
 * IPC_CREAT and IPC_EXCL flags, much like open.  If GET needs to
 * allocate an object, it can fail if there is insufficient space in
 * the namespace (the maximum number of ids for the facility has been
 * exceeded) or if the facility-specific initialization fails.  If GET
 * finds an object it can return, it can still fail if that object's
 * permissions or facility-specific attributes are less than those
 * requested.
 *
 * SET is used to adjust facility-specific parameters of an object, in
 * addition to the owner uid and gid, and mode bits.  It can fail if
 * the caller isn't the creator or owner.
 *
 * STAT is used to obtain information about an object including the
 * general attributes object described as well as facility-specific
 * information.  It can fail if the caller doesn't have read
 * permission.
 *
 * RMID removes an object from the namespace.  Subsequent operations
 * using the object's ID or key will fail (until another object is
 * created with the same key or ID).  Since an RMID may be performed
 * asynchronously with other operations, it is possible that other
 * threads and/or processes will have references to the object.  While
 * a facility may have actions which need to be performed at RMID time,
 * only when all references are dropped can the object be destroyed.
 * RMID will fail if the caller isn't the creator or owner.
 *
 * IDS obtains a list of all IDs in a facility's namespace.  There are
 * no facility-specific behaviors of IDS.
 *
 * Design
 * ------
 *
 * Because some IPC facilities provide services whose operations must
 * scale, a mechanism which allows fast, concurrent access to
 * individual objects is needed.  Of primary importance is object
 * lookup based on ID (SET, STAT, others).  Allocation (GET),
 * deallocation (RMID), ID enumeration (IDS), and key lookups (GET) are
 * lesser concerns, but should be implemented in such a way that ID
 * lookup isn't affected (at least not in the common case).
 *
 * Starting from the bottom up, each object is represented by a
 * structure, the first member of which must be a kipc_perm_t.  The
 * kipc_perm_t contains the information described above in "Objects", a
 * reference count (since the object may continue to exist after it has
 * been removed from the namespace), as well as some additional
 * metadata used to manage data structure membership.  These objects
 * are dynamically allocated.
 *
 * Above the objects is a power-of-two sized table of ID slots.  Each
 * slot contains a pointer to an object, a sequence number, and a
 * lock.  An object's ID is a function of its slot's index in the table
 * and its slot's sequence number.  Every time a slot is released (via
 * RMID) its sequence number is increased.  Strictly speaking, the
 * sequence number is unnecessary.  However, checking the sequence
 * number after a lookup provides a certain degree of robustness
 * against the use of stale IDs (useful since nothing else does).  When
 * the table fills up, it is resized (see Locking, below).
 *
 * Of an ID's 31 bits (an ID is, as defined by the standards, a signed
 * int) the top IPC_SEQ_BITS are used for the sequence number with the
 * remainder holding the index into the table.  The size of the table
 * is therefore bounded at 2 ^ (31 - IPC_SEQ_BITS) slots.
 *
 * Managing this table is the ipc_service structure.  It contains a
 * pointer to the dynamically allocated ID table, a namespace-global
 * lock, an id_space for managing the free space in the table, and
 * sundry other metadata necessary for the maintenance of the
 * namespace.  An AVL tree of all keyed objects in the table (sorted by
 * key) is used for key lookups.  An unordered doubly linked list of
 * all objects in the namespace (keyed or not) is maintained to
 * facilitate ID enumeration.
 *
 * To help visualize these relationships, here's a picture of a
 * namespace with a table of size 8 containing three objects
 * (IPC_SEQ_BITS = 28):
 *
 *
 * +-ipc_service_t--+
 * | table          *---\
 * | keys           *---+----------------------\
 * | all ids        *--\|                      |
 * |                |  ||                      |
 * +----------------+  ||                      |
 *                     ||                      |
 * /-------------------/|                      |
 * |    /---------------/                      |
 * |    |                                      |
 * |    v                                      |
 * |  +-0------+-1------+-2------+-3------+-4--+---+-5------+-6------+-7------+
 * |  | Seq=3  |        |        | Seq=1  |    :   |        |        | Seq=6  |
 * |  |        |        |        |        |    :   |        |        |        |
 * |  +-*------+--------+--------+-*------+----+---+--------+--------+-*------+
 * |    |                          |           |                       |
 * |    |                      /---/           |      /----------------/
 * |    |                      |               |      |
 * |    v                      v               |      v
 * |  +-kipc_perm_t-+        +-kipc_perm_t-+   |    +-kipc_perm_t-+
 * |  | id=0x30     |        | id=0x13     |   |    | id=0x67     |
 * |  | key=0xfeed  |        | key=0xbeef  |   |    | key=0xcafe  |
 * \->| [list]      |<------>| [list]      |<------>| [list]      |
 * /->| [avl left]  x   /--->| [avl left]  x   \--->| [avl left]  *---\
 * |  | [avl right] x   |    | [avl right] x        | [avl right] *---+-\
 * |  |             |   |    |             |        |             |   | |
 * |  +-------------+   |    +-------------+        +-------------+   | |
 * |                    \---------------------------------------------/ |
 * \--------------------------------------------------------------------/
 *
 * Locking
 * -------
 *
 * There are three locks (or sets of locks) which are used to ensure
 * correctness: the slot locks, the namespace lock, and p_lock (needed
 * when checking resource controls).  Their ordering is
 *
 *   namespace lock -> slot lock 0 -> ... -> slot lock t -> p_lock
 *
 * Generally speaking, the namespace lock is used to protect allocation
 * and removal from the namespace, ID enumeration, and resizing the ID
 * table.  Specifically:
 *
 * - write access to all fields of the ipc_service structure
 * - read access to all variable fields of ipc_service except
 *   ipcs_tabsz (table size) and ipcs_table (the table pointer)
 * - read/write access to ipc_avl, ipc_list in visible objects'
 *   kipc_perm structures (i.e. objects which have been removed from
 *   the namespace don't have this restriction)
 * - write access to ipct_seq and ipct_data in the table entries
 *
 * A slot lock by itself is meaningless (except when resizing).  Of
 * greater interest conceptually is the notion of an ID lock -- a
 * "virtual lock" which refers to whichever slot lock an object's ID
 * currently hashes to.
 *
 * An ID lock protects all objects with that ID.  Normally there will
 * only be one such object: the one pointed to by the locked slot.
 * However, if an object is removed from the namespace but retains
 * references (e.g. an attached shared memory segment which has been
 * RMIDed), it continues to use the lock associated with its original
 * ID.  While this can result in increased contention, operations which
 * require taking the ID lock of removed objects are infrequent.
 *
 * Specifically, an ID lock protects the contents of an object's
 * structure, including the contents of the embedded kipc_perm
 * structure (but excluding those fields protected by the namespace
 * lock).  It also protects the ipct_seq and ipct_data fields in its
 * slot (it is really a slot lock, after all).
 *
 * Recall that the table is resizable.  To avoid requiring every ID
 * lookup to take a global lock, a scheme much like that employed for
 * file descriptors (see the comment above UF_ENTER in user.h) is
 * used.  Note that the sequence number and data pointer are protected
 * by both the namespace lock and their slot lock.  When the table is
 * resized, the following operations take place:
 *
 *   1) A new table is allocated.
 *   2) The global lock is taken.
 *   3) All old slots are locked, in order.
 *   4) The first half of the new slots are locked.
 *   5) All table entries are copied to the new table, and cleared from
 *	the old table.
 *   6) The ipc_service structure is updated to point to the new table.
 *   7) The ipc_service structure is updated with the new table size.
 *   8) All slot locks (old and new) are dropped.
 *
 * Because the slot locks are embedded in the table, ID lookups and
 * other operations which require taking an slot lock need to verify
 * that the lock taken wasn't part of a stale table.  This is
 * accomplished by checking the table size before and after
 * dereferencing the table pointer and taking the lock: if the size
 * changes, the lock must be dropped and reacquired.  It is this
 * additional work which distinguishes an ID lock from a slot lock.
 *
 * Because we can't guarantee that threads aren't accessing the old
 * tables' locks, they are never deallocated.  To prevent spurious
 * reports of memory leaks, a pointer to the discarded table is stored
 * in the new one in step 5.  (Theoretically ipcs_destroy will delete
 * the discarded tables, but it is only ever called from a failed _init
 * invocation; i.e. when there aren't any.)
 *
 * Interfaces
 * ----------
 *
 * The following interfaces are provided by the ipc module for use by
 * the individual IPC facilities:
 *
 * ipcperm_access
 *
 *   Given an object and a cred structure, determines if the requested
 *   access type is allowed.
 *
 * ipcperm_set, ipcperm_stat,
 * ipcperm_set64, ipcperm_stat64
 *
 *   Performs the common portion of an STAT or SET operation.  All
 *   (except stat and stat64) can fail, so they should be called before
 *   any facility-specific non-reversible changes are made to an
 *   object.  Similarly, the set operations have side effects, so they
 *   should only be called once the possibility of a facility-specific
 *   failure is eliminated.
 *
 * ipcs_create
 *
 *   Creates an IPC namespace for use by an IPC facility.
 *
 * ipcs_destroy
 *
 *   Destroys an IPC namespace.
 *
 * ipcs_lock, ipcs_unlock
 *
 *   Takes the namespace lock.  Ideally such access wouldn't be
 *   necessary, but there may be facility-specific data protected by
 *   this lock (e.g. project-wide resource consumption).
 *
 * ipc_lock
 *
 *   Takes the lock associated with an ID.  Can't fail.
 *
 * ipc_relock
 *
 *   Like ipc_lock, but takes a pointer to a held lock.  Drops the lock
 *   unless it is the one that would have been returned by ipc_lock.
 *   Used after calls to cv_wait.
 *
 * ipc_lookup
 *
 *   Performs an ID lookup, returns with the ID lock held.  Fails if
 *   the ID doesn't exist in the namespace.
 *
 * ipc_hold
 *
 *   Takes a reference on an object.
 *
 * ipc_rele
 *
 *   Releases a reference on an object, and drops the object's lock.
 *   Calls the object's destructor if last reference is being
 *   released.
 *
 * ipc_rele_locked
 *
 *   Releases a reference on an object.  Doesn't drop lock, and may
 *   only be called when there is more than one reference to the
 *   object.
 *
 * ipc_get, ipc_commit_begin, ipc_commit_end, ipc_cleanup
 *
 *   Components of a GET operation.  ipc_get performs a key lookup,
 *   allocating an object if the key isn't found (returning with the
 *   namespace lock and p_lock held), and returning the existing object
 *   if it is (with the object lock held).  ipc_get doesn't modify the
 *   namespace.
 *
 *   ipc_commit_begin begins the process of inserting an object
 *   allocated by ipc_get into the namespace, and can fail.  If
 *   successful, it returns with the namespace lock and p_lock held.
 *   ipc_commit_end completes the process of inserting an object into
 *   the namespace and can't fail.  The facility can call ipc_cleanup
 *   at any time following a successful ipc_get and before
 *   ipc_commit_end or a failed ipc_commit_begin to fail the
 *   allocation.  Pseudocode for the suggested GET implementation:
 *
 *   top:
 *
 *     ipc_get
 *
 *     if failure
 *       return
 *
 *     if found {
 *
 *	 if object meets criteria
 *	   unlock object and return success
 *       else
 *	   unlock object and return failure
 *
 *     } else {
 *
 *	 perform resource control tests
 *	 drop namespace lock, p_lock
 *	 if failure
 *	   ipc_cleanup
 *
 *       perform facility-specific initialization
 *	 if failure {
 *	   facility-specific cleanup
 *	   ipc_cleanup
 *       }
 *
 *	 ( At this point the object should be destructible using the
 *	   destructor given to ipcs_create )
 *
 *       ipc_commit_begin
 *	 if retry
 *	   goto top
 *       else if failure
 *         return
 *
 *       perform facility-specific resource control tests/allocations
 *	 if failure
 *	   ipc_cleanup
 *
 *	 ipc_commit_end
 *	 perform any infallible post-creation actions, unlock, and return
 *
 *     }
 *
 * ipc_rmid
 *
 *   Performs the common portion of an RMID operation -- looks up an ID
 *   removes it, and calls the a facility-specific function to do
 *   RMID-time cleanup on the private portions of the object.
 *
 * ipc_ids
 *
 *   Performs the common portion of an IDS operation.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/list.h>
#include <sys/atomic.h>
#include <sys/zone.h>
#include <sys/task.h>
#include <sys/modctl.h>

#include <c2/audit.h>

static struct modlmisc modlmisc = {
	&mod_miscops,
	"common ipc code",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Check message, semaphore, or shared memory access permissions.
 *
 * This routine verifies the requested access permission for the current
 * process.  The zone ids are compared, and the appropriate bits are
 * checked corresponding to owner, group (including the list of
 * supplementary groups), or everyone.  Zero is returned on success.
 * On failure, the security policy is asked to check to override the
 * permissions check; the policy will either return 0 for access granted
 * or EACCES.
 *
 * Access to objects in other zones requires that the caller be in the
 * global zone and have the appropriate IPC_DAC_* privilege, regardless
 * of whether the uid or gid match those of the object.  Note that
 * cross-zone accesses will normally never get here since they'll
 * fail in ipc_lookup or ipc_get.
 *
 * The arguments must be set up as follows:
 * 	p - Pointer to permission structure to verify
 * 	mode - Desired access permissions
 */
int
ipcperm_access(kipc_perm_t *p, int mode, cred_t *cr)
{
	int shifts = 0;
	uid_t uid = crgetuid(cr);
	zoneid_t zoneid = getzoneid();

	if (p->ipc_zoneid == zoneid) {
		if (uid != p->ipc_uid && uid != p->ipc_cuid) {
			shifts += 3;
			if (!groupmember(p->ipc_gid, cr) &&
			    !groupmember(p->ipc_cgid, cr))
				shifts += 3;
		}

		mode &= ~(p->ipc_mode << shifts);

		if (mode == 0)
			return (0);
	} else if (zoneid != GLOBAL_ZONEID)
		return (EACCES);

	return (secpolicy_ipc_access(cr, p, mode));
}

/*
 * There are two versions of the ipcperm_set/stat functions:
 *   ipcperm_???        - for use with IPC_SET/STAT
 *   ipcperm_???_64     - for use with IPC_SET64/STAT64
 *
 * These functions encapsulate the common portions (copying, permission
 * checks, and auditing) of the set/stat operations.  All, except for
 * stat and stat_64 which are void, return 0 on success or a non-zero
 * errno value on error.
 */

int
ipcperm_set(ipc_service_t *service, struct cred *cr,
    kipc_perm_t *kperm, struct ipc_perm *perm, model_t model)
{
	STRUCT_HANDLE(ipc_perm, lperm);
	uid_t uid;
	gid_t gid;
	mode_t mode;
	zone_t *zone;

	ASSERT(IPC_LOCKED(service, kperm));

	STRUCT_SET_HANDLE(lperm, model, perm);
	uid = STRUCT_FGET(lperm, uid);
	gid = STRUCT_FGET(lperm, gid);
	mode = STRUCT_FGET(lperm, mode);

	if (secpolicy_ipc_owner(cr, kperm) != 0)
		return (EPERM);

	zone = crgetzone(cr);
	if (!VALID_UID(uid, zone) || !VALID_GID(gid, zone))
		return (EINVAL);

	kperm->ipc_uid = uid;
	kperm->ipc_gid = gid;
	kperm->ipc_mode = (mode & 0777) | (kperm->ipc_mode & ~0777);

	if (AU_AUDITING())
		audit_ipcget(service->ipcs_atype, kperm);

	return (0);
}

void
ipcperm_stat(struct ipc_perm *perm, kipc_perm_t *kperm, model_t model)
{
	STRUCT_HANDLE(ipc_perm, lperm);

	STRUCT_SET_HANDLE(lperm, model, perm);
	STRUCT_FSET(lperm, uid, kperm->ipc_uid);
	STRUCT_FSET(lperm, gid, kperm->ipc_gid);
	STRUCT_FSET(lperm, cuid, kperm->ipc_cuid);
	STRUCT_FSET(lperm, cgid, kperm->ipc_cgid);
	STRUCT_FSET(lperm, mode, kperm->ipc_mode);
	STRUCT_FSET(lperm, seq, 0);
	STRUCT_FSET(lperm, key, kperm->ipc_key);
}

int
ipcperm_set64(ipc_service_t *service, struct cred *cr,
    kipc_perm_t *kperm, ipc_perm64_t *perm64)
{
	zone_t *zone;

	ASSERT(IPC_LOCKED(service, kperm));

	if (secpolicy_ipc_owner(cr, kperm) != 0)
		return (EPERM);

	zone = crgetzone(cr);
	if (!VALID_UID(perm64->ipcx_uid, zone) ||
	    !VALID_GID(perm64->ipcx_gid, zone))
		return (EINVAL);

	kperm->ipc_uid = perm64->ipcx_uid;
	kperm->ipc_gid = perm64->ipcx_gid;
	kperm->ipc_mode = (perm64->ipcx_mode & 0777) |
	    (kperm->ipc_mode & ~0777);

	if (AU_AUDITING())
		audit_ipcget(service->ipcs_atype, kperm);

	return (0);
}

void
ipcperm_stat64(ipc_perm64_t *perm64, kipc_perm_t *kperm)
{
	perm64->ipcx_uid = kperm->ipc_uid;
	perm64->ipcx_gid = kperm->ipc_gid;
	perm64->ipcx_cuid = kperm->ipc_cuid;
	perm64->ipcx_cgid = kperm->ipc_cgid;
	perm64->ipcx_mode = kperm->ipc_mode;
	perm64->ipcx_key = kperm->ipc_key;
	perm64->ipcx_projid = kperm->ipc_proj->kpj_id;
	perm64->ipcx_zoneid = kperm->ipc_zoneid;
}


/*
 * ipc key comparator.
 */
static int
ipc_key_compar(const void *a, const void *b)
{
	kipc_perm_t *aperm = (kipc_perm_t *)a;
	kipc_perm_t *bperm = (kipc_perm_t *)b;
	int ak = aperm->ipc_key;
	int bk = bperm->ipc_key;
	zoneid_t az;
	zoneid_t bz;

	ASSERT(ak != IPC_PRIVATE);
	ASSERT(bk != IPC_PRIVATE);

	/*
	 * Compare key first, then zoneid.  This optimizes performance for
	 * systems with only one zone, since the zone checks will only be
	 * made when the keys match.
	 */
	if (ak < bk)
		return (-1);
	if (ak > bk)
		return (1);

	/* keys match */
	az = aperm->ipc_zoneid;
	bz = bperm->ipc_zoneid;
	if (az < bz)
		return (-1);
	if (az > bz)
		return (1);
	return (0);
}

/*
 * Create an ipc service.
 */
ipc_service_t *
ipcs_create(const char *name, rctl_hndl_t proj_rctl, rctl_hndl_t zone_rctl,
    size_t size, ipc_func_t *dtor, ipc_func_t *rmid, int audit_type,
    size_t rctl_offset)
{
	ipc_service_t *result;

	result = kmem_alloc(sizeof (ipc_service_t), KM_SLEEP);

	mutex_init(&result->ipcs_lock, NULL, MUTEX_ADAPTIVE, NULL);
	result->ipcs_count = 0;
	avl_create(&result->ipcs_keys, ipc_key_compar, size, 0);
	result->ipcs_tabsz = IPC_IDS_MIN;
	result->ipcs_table =
	    kmem_zalloc(IPC_IDS_MIN * sizeof (ipc_slot_t), KM_SLEEP);
	result->ipcs_ssize = size;
	result->ipcs_ids = id_space_create(name, 0, IPC_IDS_MIN);
	result->ipcs_dtor = dtor;
	result->ipcs_rmid = rmid;
	result->ipcs_proj_rctl = proj_rctl;
	result->ipcs_zone_rctl = zone_rctl;
	result->ipcs_atype = audit_type;
	ASSERT(rctl_offset < sizeof (ipc_rqty_t));
	result->ipcs_rctlofs = rctl_offset;
	list_create(&result->ipcs_usedids, sizeof (kipc_perm_t),
	    offsetof(kipc_perm_t, ipc_list));

	return (result);
}

/*
 * Destroy an ipc service.
 */
void
ipcs_destroy(ipc_service_t *service)
{
	ipc_slot_t *slot, *next;

	mutex_enter(&service->ipcs_lock);

	ASSERT(service->ipcs_count == 0);
	avl_destroy(&service->ipcs_keys);
	list_destroy(&service->ipcs_usedids);
	id_space_destroy(service->ipcs_ids);

	for (slot = service->ipcs_table; slot; slot = next) {
		next = slot[0].ipct_chain;
		kmem_free(slot, service->ipcs_tabsz * sizeof (ipc_slot_t));
		service->ipcs_tabsz >>= 1;
	}

	mutex_destroy(&service->ipcs_lock);
	kmem_free(service, sizeof (ipc_service_t));
}

/*
 * Takes the service lock.
 */
void
ipcs_lock(ipc_service_t *service)
{
	mutex_enter(&service->ipcs_lock);
}

/*
 * Releases the service lock.
 */
void
ipcs_unlock(ipc_service_t *service)
{
	mutex_exit(&service->ipcs_lock);
}


/*
 * Locks the specified ID.  Returns the ID's ID table index.
 */
static int
ipc_lock_internal(ipc_service_t *service, uint_t id)
{
	uint_t	tabsz;
	uint_t	index;
	kmutex_t *mutex;

	for (;;) {
		tabsz = service->ipcs_tabsz;
		membar_consumer();
		index = id & (tabsz - 1);
		mutex = &service->ipcs_table[index].ipct_lock;
		mutex_enter(mutex);
		if (tabsz == service->ipcs_tabsz)
			break;
		mutex_exit(mutex);
	}

	return (index);
}

/*
 * Locks the specified ID.  Returns a pointer to the ID's lock.
 */
kmutex_t *
ipc_lock(ipc_service_t *service, int id)
{
	uint_t index;

	/*
	 * These assertions don't reflect requirements of the code
	 * which follows, but they should never fail nonetheless.
	 */
	ASSERT(id >= 0);
	ASSERT(IPC_INDEX(id) < service->ipcs_tabsz);
	index = ipc_lock_internal(service, id);

	return (&service->ipcs_table[index].ipct_lock);
}

/*
 * Checks to see if the held lock provided is the current lock for the
 * specified id.  If so, we return it instead of dropping it and
 * returning the result of ipc_lock.  This is intended to speed up cv
 * wakeups where we are left holding a lock which could be stale, but
 * probably isn't.
 */
kmutex_t *
ipc_relock(ipc_service_t *service, int id, kmutex_t *lock)
{
	ASSERT(id >= 0);
	ASSERT(IPC_INDEX(id) < service->ipcs_tabsz);
	ASSERT(MUTEX_HELD(lock));

	if (&service->ipcs_table[IPC_INDEX(id)].ipct_lock == lock)
		return (lock);

	mutex_exit(lock);
	return (ipc_lock(service, id));
}

/*
 * Performs an ID lookup.  If the ID doesn't exist or has been removed,
 * or isn't visible to the caller (because of zones), NULL is returned.
 * Otherwise, a pointer to the ID's perm structure and held ID lock are
 * returned.
 */
kmutex_t *
ipc_lookup(ipc_service_t *service, int id, kipc_perm_t **perm)
{
	kipc_perm_t *result;
	uint_t index;

	/*
	 * There is no need to check to see if id is in-range (i.e.
	 * positive and fits into the table).  If it is out-of-range,
	 * the id simply won't match the object's.
	 */

	index = ipc_lock_internal(service, id);
	result = service->ipcs_table[index].ipct_data;
	if (result == NULL || result->ipc_id != (uint_t)id ||
	    !HASZONEACCESS(curproc, result->ipc_zoneid)) {
		mutex_exit(&service->ipcs_table[index].ipct_lock);
		return (NULL);
	}

	ASSERT(IPC_SEQ(id) == service->ipcs_table[index].ipct_seq);

	*perm = result;
	if (AU_AUDITING())
		audit_ipc(service->ipcs_atype, id, result);

	return (&service->ipcs_table[index].ipct_lock);
}

/*
 * Increase the reference count on an ID.
 */
/*ARGSUSED*/
void
ipc_hold(ipc_service_t *s, kipc_perm_t *perm)
{
	ASSERT(IPC_INDEX(perm->ipc_id) < s->ipcs_tabsz);
	ASSERT(IPC_LOCKED(s, perm));
	perm->ipc_ref++;
}

/*
 * Decrease the reference count on an ID and drops the ID's lock.
 * Destroys the ID if the new reference count is zero.
 */
void
ipc_rele(ipc_service_t *s, kipc_perm_t *perm)
{
	int nref;

	ASSERT(IPC_INDEX(perm->ipc_id) < s->ipcs_tabsz);
	ASSERT(IPC_LOCKED(s, perm));
	ASSERT(perm->ipc_ref > 0);

	nref = --perm->ipc_ref;
	mutex_exit(&s->ipcs_table[IPC_INDEX(perm->ipc_id)].ipct_lock);

	if (nref == 0) {
		ASSERT(IPC_FREE(perm));		/* ipc_rmid clears IPC_ALLOC */
		s->ipcs_dtor(perm);
		project_rele(perm->ipc_proj);
		zone_rele_ref(&perm->ipc_zone_ref, ZONE_REF_IPC);
		kmem_free(perm, s->ipcs_ssize);
	}
}

/*
 * Decrease the reference count on an ID, but don't drop the ID lock.
 * Used in cases where one thread needs to remove many references (on
 * behalf of other parties).
 */
void
ipc_rele_locked(ipc_service_t *s, kipc_perm_t *perm)
{
	ASSERT(perm->ipc_ref > 1);
	ASSERT(IPC_INDEX(perm->ipc_id) < s->ipcs_tabsz);
	ASSERT(IPC_LOCKED(s, perm));

	perm->ipc_ref--;
}


/*
 * Internal function to grow the service ID table.
 */
static int
ipc_grow(ipc_service_t *service)
{
	ipc_slot_t *new, *old;
	int i, oldsize, newsize;

	ASSERT(MUTEX_HELD(&service->ipcs_lock));
	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	if (service->ipcs_tabsz == IPC_IDS_MAX)
		return (ENOSPC);

	oldsize = service->ipcs_tabsz;
	newsize = oldsize << 1;
	new = kmem_zalloc(newsize * sizeof (ipc_slot_t), KM_NOSLEEP);
	if (new == NULL)
		return (ENOSPC);

	old = service->ipcs_table;
	for (i = 0; i < oldsize; i++) {
		mutex_enter(&old[i].ipct_lock);
		mutex_enter(&new[i].ipct_lock);

		new[i].ipct_seq = old[i].ipct_seq;
		new[i].ipct_data = old[i].ipct_data;
		old[i].ipct_data = NULL;
	}

	new[0].ipct_chain = old;
	service->ipcs_table = new;
	membar_producer();
	service->ipcs_tabsz = newsize;

	for (i = 0; i < oldsize; i++) {
		mutex_exit(&old[i].ipct_lock);
		mutex_exit(&new[i].ipct_lock);
	}

	id_space_extend(service->ipcs_ids, oldsize, service->ipcs_tabsz);

	return (0);
}


static int
ipc_keylookup(ipc_service_t *service, key_t key, int flag, kipc_perm_t **permp)
{
	kipc_perm_t *perm = NULL;
	avl_index_t where;
	kipc_perm_t template;

	ASSERT(MUTEX_HELD(&service->ipcs_lock));

	template.ipc_key = key;
	template.ipc_zoneid = getzoneid();
	if (perm = avl_find(&service->ipcs_keys, &template, &where)) {
		ASSERT(!IPC_FREE(perm));
		if ((flag & (IPC_CREAT | IPC_EXCL)) == (IPC_CREAT | IPC_EXCL))
			return (EEXIST);
		if ((flag & 0777) & ~perm->ipc_mode) {
			if (AU_AUDITING())
				audit_ipcget(NULL, (void *)perm);
			return (EACCES);
		}
		*permp = perm;
		return (0);
	} else if (flag & IPC_CREAT) {
		*permp = NULL;
		return (0);
	}
	return (ENOENT);
}

static int
ipc_alloc_test(ipc_service_t *service, proc_t *pp)
{
	ASSERT(MUTEX_HELD(&service->ipcs_lock));

	/*
	 * Resizing the table first would result in a cleaner code
	 * path, but would also allow a user to (permanently) double
	 * the id table size in cases where the allocation would be
	 * denied.  Hence we test the rctl first.
	 */
retry:
	mutex_enter(&pp->p_lock);
	if ((rctl_test(service->ipcs_proj_rctl, pp->p_task->tk_proj->kpj_rctls,
	    pp, 1, RCA_SAFE) & RCT_DENY) ||
	    (rctl_test(service->ipcs_zone_rctl, pp->p_zone->zone_rctls,
	    pp, 1, RCA_SAFE) & RCT_DENY)) {
		mutex_exit(&pp->p_lock);
		return (ENOSPC);
	}

	if (service->ipcs_count == service->ipcs_tabsz) {
		int error;

		mutex_exit(&pp->p_lock);
		if (error = ipc_grow(service))
			return (error);
		goto retry;
	}

	return (0);
}

/*
 * Given a key, search for or create the associated identifier.
 *
 * If IPC_CREAT is specified and the key isn't found, or if the key is
 * equal to IPC_PRIVATE, we return 0 and place a pointer to a newly
 * allocated object structure in permp.  A pointer to the held service
 * lock is placed in lockp.  ipc_mode's IPC_ALLOC bit is clear.
 *
 * If the key is found and no error conditions arise, we return 0 and
 * place a pointer to the existing object structure in permp.  A
 * pointer to the held ID lock is placed in lockp.  ipc_mode's
 * IPC_ALLOC bit is set.
 *
 * Otherwise, a non-zero errno value is returned.
 */
int
ipc_get(ipc_service_t *service, key_t key, int flag, kipc_perm_t **permp,
    kmutex_t **lockp)
{
	kipc_perm_t	*perm = NULL;
	proc_t		*pp = curproc;
	int		error, index;
	cred_t		*cr = CRED();

	if (key != IPC_PRIVATE) {

		mutex_enter(&service->ipcs_lock);
		error = ipc_keylookup(service, key, flag, &perm);
		if (perm != NULL)
			index = ipc_lock_internal(service, perm->ipc_id);
		mutex_exit(&service->ipcs_lock);

		if (error) {
			ASSERT(perm == NULL);
			return (error);
		}

		if (perm) {
			ASSERT(!IPC_FREE(perm));
			*permp = perm;
			*lockp = &service->ipcs_table[index].ipct_lock;
			return (0);
		}

		/* Key not found; fall through */
	}

	perm = kmem_zalloc(service->ipcs_ssize, KM_SLEEP);

	mutex_enter(&service->ipcs_lock);
	if (error = ipc_alloc_test(service, pp)) {
		mutex_exit(&service->ipcs_lock);
		kmem_free(perm, service->ipcs_ssize);
		return (error);
	}

	perm->ipc_cuid = perm->ipc_uid = crgetuid(cr);
	perm->ipc_cgid = perm->ipc_gid = crgetgid(cr);
	perm->ipc_zoneid = getzoneid();
	perm->ipc_mode = flag & 0777;
	perm->ipc_key = key;
	perm->ipc_ref = 1;
	perm->ipc_id = IPC_ID_INVAL;
	*permp = perm;
	*lockp = &service->ipcs_lock;

	return (0);
}

/*
 * Attempts to add the a newly created ID to the global namespace.  If
 * creating it would cause an error, we return the error.  If there is
 * the possibility that we could obtain the existing ID and return it
 * to the user, we return EAGAIN.  Otherwise, we return 0 with p_lock
 * and the service lock held.
 *
 * Since this should be only called after all initialization has been
 * completed, on failure we automatically invoke the destructor for the
 * object and deallocate the memory associated with it.
 */
int
ipc_commit_begin(ipc_service_t *service, key_t key, int flag,
    kipc_perm_t *newperm)
{
	kipc_perm_t *perm;
	int error;
	proc_t *pp = curproc;

	ASSERT(newperm->ipc_ref == 1);
	ASSERT(IPC_FREE(newperm));

	/*
	 * Set ipc_proj and ipc_zone_ref so that future calls to ipc_cleanup()
	 * clean up the necessary state.  This must be done before the
	 * potential call to ipcs_dtor() below.
	 */
	newperm->ipc_proj = pp->p_task->tk_proj;
	zone_init_ref(&newperm->ipc_zone_ref);
	zone_hold_ref(pp->p_zone, &newperm->ipc_zone_ref, ZONE_REF_IPC);

	mutex_enter(&service->ipcs_lock);
	/*
	 * Ensure that no-one has raced with us and created the key.
	 */
	if ((key != IPC_PRIVATE) &&
	    (((error = ipc_keylookup(service, key, flag, &perm)) != 0) ||
	    (perm != NULL))) {
		error = error ? error : EAGAIN;
		goto errout;
	}

	/*
	 * Ensure that no-one has raced with us and used the last of
	 * the permissible ids, or the last of the free spaces in the
	 * id table.
	 */
	if (error = ipc_alloc_test(service, pp))
		goto errout;

	ASSERT(MUTEX_HELD(&service->ipcs_lock));
	ASSERT(MUTEX_HELD(&pp->p_lock));

	return (0);
errout:
	mutex_exit(&service->ipcs_lock);
	service->ipcs_dtor(newperm);
	zone_rele_ref(&newperm->ipc_zone_ref, ZONE_REF_IPC);
	kmem_free(newperm, service->ipcs_ssize);
	return (error);
}

/*
 * Commit the ID allocation transaction.  Called with p_lock and the
 * service lock held, both of which are dropped.  Returns the held ID
 * lock so the caller can extract the ID and perform ipcget auditing.
 */
kmutex_t *
ipc_commit_end(ipc_service_t *service, kipc_perm_t *perm)
{
	ipc_slot_t *slot;
	avl_index_t where;
	int index;
	void *loc;

	ASSERT(MUTEX_HELD(&service->ipcs_lock));
	ASSERT(MUTEX_HELD(&curproc->p_lock));

	(void) project_hold(perm->ipc_proj);
	mutex_exit(&curproc->p_lock);

	/*
	 * Pick out our slot.
	 */
	service->ipcs_count++;
	index = id_alloc(service->ipcs_ids);
	ASSERT(index < service->ipcs_tabsz);
	slot = &service->ipcs_table[index];
	mutex_enter(&slot->ipct_lock);
	ASSERT(slot->ipct_data == NULL);

	/*
	 * Update the perm structure.
	 */
	perm->ipc_mode |= IPC_ALLOC;
	perm->ipc_id = (slot->ipct_seq << IPC_SEQ_SHIFT) | index;

	/*
	 * Push into global visibility.
	 */
	slot->ipct_data = perm;
	if (perm->ipc_key != IPC_PRIVATE) {
		loc = avl_find(&service->ipcs_keys, perm, &where);
		ASSERT(loc == NULL);
		avl_insert(&service->ipcs_keys, perm, where);
	}
	list_insert_head(&service->ipcs_usedids, perm);

	/*
	 * Update resource consumption.
	 */
	IPC_PROJ_USAGE(perm, service) += 1;
	IPC_ZONE_USAGE(perm, service) += 1;

	mutex_exit(&service->ipcs_lock);
	return (&slot->ipct_lock);
}

/*
 * Clean up function, in case the allocation fails.  If called between
 * ipc_lookup and ipc_commit_begin, perm->ipc_proj will be 0 and we
 * merely free the perm structure.  If called after ipc_commit_begin,
 * we also drop locks and call the ID's destructor.
 */
void
ipc_cleanup(ipc_service_t *service, kipc_perm_t *perm)
{
	ASSERT(IPC_FREE(perm));
	if (perm->ipc_proj) {
		mutex_exit(&curproc->p_lock);
		mutex_exit(&service->ipcs_lock);
		service->ipcs_dtor(perm);
	}
	if (perm->ipc_zone_ref.zref_zone != NULL)
		zone_rele_ref(&perm->ipc_zone_ref, ZONE_REF_IPC);
	kmem_free(perm, service->ipcs_ssize);
}


/*
 * Common code to remove an IPC object.  This should be called after
 * all permissions checks have been performed, and with the service
 * and ID locked.  Note that this does not remove the object from
 * the ipcs_usedids list (this needs to be done by the caller before
 * dropping the service lock).
 */
static void
ipc_remove(ipc_service_t *service, kipc_perm_t *perm)
{
	int id = perm->ipc_id;
	int index;

	ASSERT(MUTEX_HELD(&service->ipcs_lock));
	ASSERT(IPC_LOCKED(service, perm));

	index = IPC_INDEX(id);

	service->ipcs_table[index].ipct_data = NULL;

	if (perm->ipc_key != IPC_PRIVATE)
		avl_remove(&service->ipcs_keys, perm);
	list_remove(&service->ipcs_usedids, perm);
	perm->ipc_mode &= ~IPC_ALLOC;

	id_free(service->ipcs_ids, index);

	if (service->ipcs_table[index].ipct_seq++ == IPC_SEQ_MASK)
		service->ipcs_table[index].ipct_seq = 0;
	service->ipcs_count--;
	ASSERT(IPC_PROJ_USAGE(perm, service) > 0);
	ASSERT(IPC_ZONE_USAGE(perm, service) > 0);
	IPC_PROJ_USAGE(perm, service) -= 1;
	IPC_ZONE_USAGE(perm, service) -= 1;
	ASSERT(service->ipcs_count || ((IPC_PROJ_USAGE(perm, service) == 0) &&
	    (IPC_ZONE_USAGE(perm, service) == 0)));
}


/*
 * Common code to perform an IPC_RMID.  Returns an errno value on
 * failure, 0 on success.
 */
int
ipc_rmid(ipc_service_t *service, int id, cred_t *cr)
{
	kipc_perm_t *perm;
	kmutex_t *lock;

	mutex_enter(&service->ipcs_lock);

	lock = ipc_lookup(service, id, &perm);
	if (lock == NULL) {
		mutex_exit(&service->ipcs_lock);
		return (EINVAL);
	}

	ASSERT(service->ipcs_count > 0);

	if (secpolicy_ipc_owner(cr, perm) != 0) {
		mutex_exit(lock);
		mutex_exit(&service->ipcs_lock);
		return (EPERM);
	}

	/*
	 * Nothing can fail from this point on.
	 */
	ipc_remove(service, perm);
	mutex_exit(&service->ipcs_lock);

	/* perform any per-service removal actions */
	service->ipcs_rmid(perm);

	ipc_rele(service, perm);

	return (0);
}

/*
 * Implementation for shmids, semids, and msgids.  buf is the address
 * of the user buffer, nids is the size, and pnids is a pointer to
 * where we write the actual number of ids that [would] have been
 * copied out.
 */
int
ipc_ids(ipc_service_t *service, int *buf, uint_t nids, uint_t *pnids)
{
	kipc_perm_t *perm;
	size_t	idsize = 0;
	int	error = 0;
	int	idcount;
	int	*ids;
	int	numids = 0;
	zoneid_t zoneid = getzoneid();
	int	global = INGLOBALZONE(curproc);

	if (buf == NULL)
		nids = 0;

	/*
	 * Get an accurate count of the total number of ids, and allocate a
	 * staging buffer.  Since ipcs_count is always sane, we don't have
	 * to take ipcs_lock for our first guess.  If there are no ids, or
	 * we're in the global zone and the number of ids is greater than
	 * the size of the specified buffer, we shunt to the end.  Otherwise,
	 * we go through the id list looking for (and counting) what is
	 * visible in the specified zone.
	 */
	idcount = service->ipcs_count;
	for (;;) {
		if ((global && idcount > nids) || idcount == 0) {
			numids = idcount;
			nids = 0;
			goto out;
		}

		idsize = idcount * sizeof (int);
		ids = kmem_alloc(idsize, KM_SLEEP);

		mutex_enter(&service->ipcs_lock);
		if (idcount >= service->ipcs_count)
			break;
		idcount = service->ipcs_count;
		mutex_exit(&service->ipcs_lock);

		if (idsize != 0) {
			kmem_free(ids, idsize);
			idsize = 0;
		}
	}

	for (perm = list_head(&service->ipcs_usedids); perm != NULL;
	    perm = list_next(&service->ipcs_usedids, perm)) {
		ASSERT(!IPC_FREE(perm));
		if (global || perm->ipc_zoneid == zoneid)
			ids[numids++] = perm->ipc_id;
	}
	mutex_exit(&service->ipcs_lock);

	/*
	 * If there isn't enough space to hold all of the ids, just
	 * return the number of ids without copying out any of them.
	 */
	if (nids < numids)
		nids = 0;

out:
	if (suword32(pnids, (uint32_t)numids) ||
	    (nids != 0 && copyout(ids, buf, numids * sizeof (int))))
		error = EFAULT;
	if (idsize != 0)
		kmem_free(ids, idsize);
	return (error);
}

/*
 * Destroy IPC objects from the given service that are associated with
 * the given zone.
 *
 * We can't hold on to the service lock when freeing objects, so we
 * first search the service and move all the objects to a private
 * list, then walk through and free them after dropping the lock.
 */
void
ipc_remove_zone(ipc_service_t *service, zoneid_t zoneid)
{
	kipc_perm_t *perm, *next;
	list_t rmlist;
	kmutex_t *lock;

	list_create(&rmlist, sizeof (kipc_perm_t),
	    offsetof(kipc_perm_t, ipc_list));

	mutex_enter(&service->ipcs_lock);
	for (perm = list_head(&service->ipcs_usedids); perm != NULL;
	    perm = next) {
		next = list_next(&service->ipcs_usedids, perm);
		if (perm->ipc_zoneid != zoneid)
			continue;

		/*
		 * Remove the object from the service, then put it on
		 * the removal list so we can defer the call to
		 * ipc_rele (which will actually free the structure).
		 * We need to do this since the destructor may grab
		 * the service lock.
		 */
		ASSERT(!IPC_FREE(perm));
		lock = ipc_lock(service, perm->ipc_id);
		ipc_remove(service, perm);
		mutex_exit(lock);
		list_insert_tail(&rmlist, perm);
	}
	mutex_exit(&service->ipcs_lock);

	/*
	 * Now that we've dropped the service lock, loop through the
	 * private list freeing removed objects.
	 */
	for (perm = list_head(&rmlist); perm != NULL; perm = next) {
		next = list_next(&rmlist, perm);
		list_remove(&rmlist, perm);

		(void) ipc_lock(service, perm->ipc_id);

		/* perform any per-service removal actions */
		service->ipcs_rmid(perm);

		/* release reference */
		ipc_rele(service, perm);
	}

	list_destroy(&rmlist);
}
