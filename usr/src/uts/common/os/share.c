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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/share.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/t_lock.h>
#include <sys/errno.h>
#include <sys/nbmlock.h>

int share_debug = 0;

#ifdef DEBUG
static void print_shares(struct vnode *);
static void print_share(struct shrlock *);
#endif

static int isreadonly(struct vnode *);
static void do_cleanshares(struct vnode *, pid_t, int32_t);


/*
 * Add the share reservation shr to vp.
 */
int
add_share(struct vnode *vp, struct shrlock *shr)
{
	struct shrlocklist *shrl;

	/*
	 * An access of zero is not legal, however some older clients
	 * generate it anyways.  Allow the request only if it is
	 * coming from a remote system.  Be generous in what you
	 * accept and strict in what you send.
	 */
	if ((shr->s_access == 0) && (GETSYSID(shr->s_sysid) == 0)) {
		return (EINVAL);
	}

	/*
	 * Sanity check to make sure we have valid options.
	 * There is known overlap but it doesn't hurt to be careful.
	 */
	if (shr->s_access & ~(F_RDACC|F_WRACC|F_RWACC|F_RMACC|F_MDACC)) {
		return (EINVAL);
	}
	if (shr->s_deny & ~(F_NODNY|F_RDDNY|F_WRDNY|F_RWDNY|F_COMPAT|
	    F_MANDDNY|F_RMDNY)) {
		return (EINVAL);
	}

	mutex_enter(&vp->v_lock);
	for (shrl = vp->v_shrlocks; shrl != NULL; shrl = shrl->next) {
		/*
		 * If the share owner matches previous request
		 * do special handling.
		 */
		if ((shrl->shr->s_sysid == shr->s_sysid) &&
		    (shrl->shr->s_pid == shr->s_pid) &&
		    (shrl->shr->s_own_len == shr->s_own_len) &&
		    bcmp(shrl->shr->s_owner, shr->s_owner,
		    shr->s_own_len) == 0) {

			/*
			 * If the existing request is F_COMPAT and
			 * is the first share then allow any F_COMPAT
			 * from the same process.  Trick:  If the existing
			 * F_COMPAT is write access then it must have
			 * the same owner as the first.
			 */
			if ((shrl->shr->s_deny & F_COMPAT) &&
			    (shr->s_deny & F_COMPAT) &&
			    ((shrl->next == NULL) ||
			    (shrl->shr->s_access & F_WRACC)))
				break;
		}

		/*
		 * If a first share has been done in compatibility mode
		 * handle the special cases.
		 */
		if ((shrl->shr->s_deny & F_COMPAT) && (shrl->next == NULL)) {

			if (!(shr->s_deny & F_COMPAT)) {
				/*
				 * If not compat and want write access or
				 * want to deny read or
				 * write exists, fails
				 */
				if ((shr->s_access & F_WRACC) ||
				    (shr->s_deny & F_RDDNY) ||
				    (shrl->shr->s_access & F_WRACC)) {
					mutex_exit(&vp->v_lock);
					return (EAGAIN);
				}
				/*
				 * If read only file allow, this may allow
				 * a deny write but that is meaningless on
				 * a read only file.
				 */
				if (isreadonly(vp))
					break;
				mutex_exit(&vp->v_lock);
				return (EAGAIN);
			}
			/*
			 * This is a compat request and read access
			 * and the first was also read access
			 * we always allow it, otherwise we reject because
			 * we have handled the only valid write case above.
			 */
			if ((shr->s_access == F_RDACC) &&
			    (shrl->shr->s_access == F_RDACC))
				break;
			mutex_exit(&vp->v_lock);
			return (EAGAIN);
		}

		/*
		 * If we are trying to share in compatibility mode
		 * and the current share is compat (and not the first)
		 * we don't know enough.
		 */
		if ((shrl->shr->s_deny & F_COMPAT) && (shr->s_deny & F_COMPAT))
			continue;

		/*
		 * If this is a compat we check for what can't succeed.
		 */
		if (shr->s_deny & F_COMPAT) {
			/*
			 * If we want write access or
			 * if anyone is denying read or
			 * if anyone has write access we fail
			 */
			if ((shr->s_access & F_WRACC) ||
			    (shrl->shr->s_deny & F_RDDNY) ||
			    (shrl->shr->s_access & F_WRACC)) {
				mutex_exit(&vp->v_lock);
				return (EAGAIN);
			}
			/*
			 * If the first was opened with only read access
			 * and is a read only file we allow.
			 */
			if (shrl->next == NULL) {
				if ((shrl->shr->s_access == F_RDACC) &&
				    isreadonly(vp)) {
					break;
				}
				mutex_exit(&vp->v_lock);
				return (EAGAIN);
			}
			/*
			 * We still can't determine our fate so continue
			 */
			continue;
		}

		/*
		 * Simple bitwise test, if we are trying to access what
		 * someone else is denying or we are trying to deny
		 * what someone else is accessing we fail.
		 */
		if ((shr->s_access & shrl->shr->s_deny) ||
		    (shr->s_deny & shrl->shr->s_access)) {
			mutex_exit(&vp->v_lock);
			return (EAGAIN);
		}
	}

	shrl = kmem_alloc(sizeof (struct shrlocklist), KM_SLEEP);
	shrl->shr = kmem_alloc(sizeof (struct shrlock), KM_SLEEP);
	shrl->shr->s_access = shr->s_access;
	shrl->shr->s_deny = shr->s_deny;

	/*
	 * Make sure no other deny modes are also set with F_COMPAT
	 */
	if (shrl->shr->s_deny & F_COMPAT)
		shrl->shr->s_deny = F_COMPAT;
	shrl->shr->s_sysid = shr->s_sysid;		/* XXX ref cnt? */
	shrl->shr->s_pid = shr->s_pid;
	shrl->shr->s_own_len = shr->s_own_len;
	shrl->shr->s_owner = kmem_alloc(shr->s_own_len, KM_SLEEP);
	bcopy(shr->s_owner, shrl->shr->s_owner, shr->s_own_len);
	shrl->next = vp->v_shrlocks;
	vp->v_shrlocks = shrl;
#ifdef DEBUG
	if (share_debug)
		print_shares(vp);
#endif

	mutex_exit(&vp->v_lock);

	return (0);
}

/*
 *	nlmid	sysid	pid
 *	=====	=====	===
 *	!=0	!=0	=0	in cluster; NLM lock
 *	!=0	=0	=0	in cluster; special case for NLM lock
 *	!=0	=0	!=0	in cluster; PXFS local lock
 *	!=0	!=0	!=0	cannot happen
 *	=0	!=0	=0	not in cluster; NLM lock
 *	=0	=0	!=0	not in cluster; local lock
 *	=0	=0	=0	cannot happen
 *	=0	!=0	!=0	cannot happen
 */
static int
is_match_for_del(struct shrlock *shr, struct shrlock *element)
{
	int nlmid1, nlmid2;
	int result = 0;

	nlmid1 = GETNLMID(shr->s_sysid);
	nlmid2 = GETNLMID(element->s_sysid);

	if (nlmid1 != 0) {		/* in a cluster */
		if (GETSYSID(shr->s_sysid) != 0 && shr->s_pid == 0) {
			/*
			 * Lock obtained through nlm server.  Just need to
			 * compare whole sysids.  pid will always = 0.
			 */
			result = shr->s_sysid == element->s_sysid;
		} else if (GETSYSID(shr->s_sysid) == 0 && shr->s_pid == 0) {
			/*
			 * This is a special case.  The NLM server wishes to
			 * delete all share locks obtained through nlmid1.
			 */
			result = (nlmid1 == nlmid2);
		} else if (GETSYSID(shr->s_sysid) == 0 && shr->s_pid != 0) {
			/*
			 * Lock obtained locally through PXFS.  Match nlmids
			 * and pids.
			 */
			result = (nlmid1 == nlmid2 &&
			    shr->s_pid == element->s_pid);
		}
	} else {			/* not in a cluster */
		result = ((shr->s_sysid == 0 &&
		    shr->s_pid == element->s_pid) ||
		    (shr->s_sysid != 0 &&
		    shr->s_sysid == element->s_sysid));
	}
	return (result);
}

/*
 * Delete the given share reservation.  Returns 0 if okay, EINVAL if the
 * share could not be found.  If the share reservation is an NBMAND share
 * reservation, signal anyone waiting for the share to go away (e.g.,
 * blocking lock requests).
 */

int
del_share(struct vnode *vp, struct shrlock *shr)
{
	struct shrlocklist *shrl;
	struct shrlocklist **shrlp;
	int found = 0;
	int is_nbmand = 0;

	mutex_enter(&vp->v_lock);
	/*
	 * Delete the shares with the matching sysid and owner
	 * But if own_len == 0 and sysid == 0 delete all with matching pid
	 * But if own_len == 0 delete all with matching sysid.
	 */
	shrlp = &vp->v_shrlocks;
	while (*shrlp) {
		if ((shr->s_own_len == (*shrlp)->shr->s_own_len &&
		    (bcmp(shr->s_owner, (*shrlp)->shr->s_owner,
		    shr->s_own_len) == 0)) ||

		    (shr->s_own_len == 0 &&
		    is_match_for_del(shr, (*shrlp)->shr))) {

			shrl = *shrlp;
			*shrlp = shrl->next;

			if (shrl->shr->s_deny & F_MANDDNY)
				is_nbmand = 1;

			/* XXX deref sysid */
			kmem_free(shrl->shr->s_owner, shrl->shr->s_own_len);
			kmem_free(shrl->shr, sizeof (struct shrlock));
			kmem_free(shrl, sizeof (struct shrlocklist));
			found++;
			continue;
		}
		shrlp = &(*shrlp)->next;
	}

	if (is_nbmand)
		cv_broadcast(&vp->v_cv);

	mutex_exit(&vp->v_lock);
	return (found ? 0 : EINVAL);
}

/*
 * Clean up all local share reservations that the given process has with
 * the given file.
 */
void
cleanshares(struct vnode *vp, pid_t pid)
{
	do_cleanshares(vp, pid, 0);
}

/*
 * Cleanup all remote share reservations that
 * were made by the given sysid on given vnode.
 */
void
cleanshares_by_sysid(struct vnode *vp, int32_t sysid)
{
	if (sysid == 0)
		return;

	do_cleanshares(vp, 0, sysid);
}

/*
 * Cleanup share reservations on given vnode made
 * by the either given pid or sysid.
 * If sysid is 0, remove all shares made by given pid,
 * otherwise all shares made by the given sysid will
 * be removed.
 */
static void
do_cleanshares(struct vnode *vp, pid_t pid, int32_t sysid)
{
	struct shrlock shr;

	if (vp->v_shrlocks == NULL)
		return;

	shr.s_access = 0;
	shr.s_deny = 0;
	shr.s_pid = pid;
	shr.s_sysid = sysid;
	shr.s_own_len = 0;
	shr.s_owner = NULL;

	(void) del_share(vp, &shr);
}

static int
is_match_for_has_remote(int32_t sysid1, int32_t sysid2)
{
	int result = 0;

	if (GETNLMID(sysid1) != 0) { /* in a cluster */
		if (GETSYSID(sysid1) != 0) {
			/*
			 * Lock obtained through nlm server.  Just need to
			 * compare whole sysids.
			 */
			result = (sysid1 == sysid2);
		} else if (GETSYSID(sysid1) == 0) {
			/*
			 * This is a special case.  The NLM server identified
			 * by nlmid1 wishes to find out if it has obtained
			 * any share locks on the vnode.
			 */
			result = (GETNLMID(sysid1) == GETNLMID(sysid2));
		}
	} else {			/* not in a cluster */
		result = ((sysid1 != 0 && sysid1 == sysid2) ||
		    (sysid1 == 0 && sysid2 != 0));
	}
	return (result);
}


/*
 * Determine whether there are any shares for the given vnode
 * with a remote sysid. Returns zero if not, non-zero if there are.
 * If sysid is non-zero then determine if this sysid has a share.
 *
 * Note that the return value from this function is potentially invalid
 * once it has been returned.  The caller is responsible for providing its
 * own synchronization mechanism to ensure that the return value is useful.
 */
int
shr_has_remote_shares(vnode_t *vp, int32_t sysid)
{
	struct shrlocklist *shrl;
	int result = 0;

	mutex_enter(&vp->v_lock);
	shrl = vp->v_shrlocks;
	while (shrl) {
		if (is_match_for_has_remote(sysid, shrl->shr->s_sysid)) {

			result = 1;
			break;
		}
		shrl = shrl->next;
	}
	mutex_exit(&vp->v_lock);
	return (result);
}

static int
isreadonly(struct vnode *vp)
{
	return (vp->v_type != VCHR && vp->v_type != VBLK &&
	    vp->v_type != VFIFO && vn_is_readonly(vp));
}

#ifdef DEBUG
static void
print_shares(struct vnode *vp)
{
	struct shrlocklist *shrl;

	if (vp->v_shrlocks == NULL) {
		printf("<NULL>\n");
		return;
	}

	shrl = vp->v_shrlocks;
	while (shrl) {
		print_share(shrl->shr);
		shrl = shrl->next;
	}
}

static void
print_share(struct shrlock *shr)
{
	int i;

	if (shr == NULL) {
		printf("<NULL>\n");
		return;
	}

	printf("    access(%d):	", shr->s_access);
	if (shr->s_access & F_RDACC)
		printf("R");
	if (shr->s_access & F_WRACC)
		printf("W");
	if ((shr->s_access & (F_RDACC|F_WRACC)) == 0)
		printf("N");
	printf("\n");
	printf("    deny:	");
	if (shr->s_deny & F_COMPAT)
		printf("C");
	if (shr->s_deny & F_RDDNY)
		printf("R");
	if (shr->s_deny & F_WRDNY)
		printf("W");
	if (shr->s_deny == F_NODNY)
		printf("N");
	printf("\n");
	printf("    sysid:	%d\n", shr->s_sysid);
	printf("    pid:	%d\n", shr->s_pid);
	printf("    owner:	[%d]", shr->s_own_len);
	printf("'");
	for (i = 0; i < shr->s_own_len; i++)
		printf("%02x", (unsigned)shr->s_owner[i]);
	printf("'\n");
}
#endif

/*
 * Return non-zero if the given I/O request conflicts with a registered
 * share reservation.  Note: These are Windows-compatible semantics, but
 * windows would do these checks only when opening a file.  Details in:
 *	[MS-FSA] 2.1.5.1.2.2 Algorithm to check sharing access...
 *
 * A process is identified by the tuple (sysid, pid). When the caller
 * context is passed to nbl_share_conflict, the sysid and pid in the
 * caller context are used. Otherwise the sysid is zero, and the pid is
 * taken from the current process.
 *
 * Conflict Algorithm:
 *   1. An op request of NBL_READ will fail if a different
 *      process has a mandatory share reservation with deny read.
 *
 *   2. An op request of NBL_WRITE will fail if a different
 *      process has a mandatory share reservation with deny write.
 *
 *   3. An op request of NBL_READWRITE will fail if a different
 *      process has a mandatory share reservation with deny read
 *      or deny write.
 *
 *   4. An op request of NBL_REMOVE will fail if there is
 *      a mandatory share reservation with deny remove.
 *
 *   5. An op request of NBL_RENAME ... (same as NBL_REMOVE)
 *
 *   Otherwise there is no conflict and the op request succeeds.
 *
 * This behavior is required for interoperability between
 * the nfs server, cifs server, and local access.
 * This behavior can result in non-posix semantics.
 *
 * When mandatory share reservations are enabled, a process
 * should call nbl_share_conflict to determine if the
 * desired operation would conflict with an existing share
 * reservation.
 *
 * The call to nbl_share_conflict may be skipped if the
 * process has an existing share reservation and the operation
 * is being performed in the context of that existing share
 * reservation.
 */
int
nbl_share_conflict(vnode_t *vp, nbl_op_t op, caller_context_t *ct)
{
	struct shrlocklist *shrl;
	int conflict = 0;
	pid_t pid;
	int sysid;

	ASSERT(nbl_in_crit(vp));

	if (ct == NULL) {
		pid = curproc->p_pid;
		sysid = 0;
	} else {
		pid = ct->cc_pid;
		sysid = ct->cc_sysid;
	}

	mutex_enter(&vp->v_lock);
	for (shrl = vp->v_shrlocks; shrl != NULL; shrl = shrl->next) {
		if (!(shrl->shr->s_deny & F_MANDDNY))
			continue;
		/*
		 * Share deny reservations apply to _subsequent_ opens
		 * and therefore only to I/O on _other_ handles.
		 */
		if (shrl->shr->s_sysid == sysid &&
		    shrl->shr->s_pid == pid)
			continue;

		/*
		 * NBL_READ, NBL_WRITE, and NBL_READWRITE need to
		 * check if the share reservation being examined
		 * belongs to the current process.
		 * NBL_REMOVE and NBL_RENAME do not.
		 * This behavior is required by the conflict
		 * algorithm described above.
		 */
		switch (op) {
		case NBL_READ:
			if (shrl->shr->s_deny & F_RDDNY)
				conflict = 1;
			break;
		case NBL_WRITE:
			if (shrl->shr->s_deny & F_WRDNY)
				conflict = 1;
			break;
		case NBL_READWRITE:
			if (shrl->shr->s_deny & F_RWDNY)
				conflict = 1;
			break;
		case NBL_REMOVE:
		case NBL_RENAME:
			if (shrl->shr->s_deny & F_RMDNY)
				conflict = 1;
			break;
#ifdef DEBUG
		default:
			cmn_err(CE_PANIC,
			    "nbl_share_conflict: bogus op (%d)",
			    op);
			break;
#endif
		}
		if (conflict)
			break;
	}

	mutex_exit(&vp->v_lock);
	return (conflict);
}

/*
 * Determine if the given process has a NBMAND share reservation on the
 * given vnode. Returns 1 if the process has such a share reservation,
 * returns 0 otherwise.
 */
int
proc_has_nbmand_share_on_vp(vnode_t *vp, pid_t pid)
{
	struct shrlocklist *shrl;

	/*
	 * Any NBMAND share reservation on the vp for this process?
	 */
	mutex_enter(&vp->v_lock);
	for (shrl = vp->v_shrlocks; shrl != NULL; shrl = shrl->next) {
		if (shrl->shr->s_sysid == 0 &&
		    (shrl->shr->s_deny & F_MANDDNY) &&
		    (shrl->shr->s_pid == pid)) {
			mutex_exit(&vp->v_lock);
			return (1);
		}
	}
	mutex_exit(&vp->v_lock);

	return (0);
}
