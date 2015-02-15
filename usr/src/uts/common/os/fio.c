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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/conf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/var.h>
#include <sys/cpuvar.h>
#include <sys/open.h>
#include <sys/cmn_err.h>
#include <sys/priocntl.h>
#include <sys/procset.h>
#include <sys/prsystm.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/rctl.h>
#include <sys/port_impl.h>
#include <sys/dtrace.h>

#include <c2/audit.h>
#include <sys/nbmlock.h>

#ifdef DEBUG

static uint32_t afd_maxfd;	/* # of entries in maximum allocated array */
static uint32_t afd_alloc;	/* count of kmem_alloc()s */
static uint32_t afd_free;	/* count of kmem_free()s */
static uint32_t afd_wait;	/* count of waits on non-zero ref count */
#define	MAXFD(x)	(afd_maxfd = ((afd_maxfd >= (x))? afd_maxfd : (x)))
#define	COUNT(x)	atomic_inc_32(&x)

#else	/* DEBUG */

#define	MAXFD(x)
#define	COUNT(x)

#endif	/* DEBUG */

kmem_cache_t *file_cache;

static void port_close_fd(portfd_t *);

/*
 * File descriptor allocation.
 *
 * fd_find(fip, minfd) finds the first available descriptor >= minfd.
 * The most common case is open(2), in which minfd = 0, but we must also
 * support fcntl(fd, F_DUPFD, minfd).
 *
 * The algorithm is as follows: we keep all file descriptors in an infix
 * binary tree in which each node records the number of descriptors
 * allocated in its right subtree, including itself.  Starting at minfd,
 * we ascend the tree until we find a non-fully allocated right subtree.
 * We then descend that subtree in a binary search for the smallest fd.
 * Finally, we ascend the tree again to increment the allocation count
 * of every subtree containing the newly-allocated fd.  Freeing an fd
 * requires only the last step: we ascend the tree to decrement allocation
 * counts.  Each of these three steps (ascent to find non-full subtree,
 * descent to find lowest fd, ascent to update allocation counts) is
 * O(log n), thus the algorithm as a whole is O(log n).
 *
 * We don't implement the fd tree using the customary left/right/parent
 * pointers, but instead take advantage of the glorious mathematics of
 * full infix binary trees.  For reference, here's an illustration of the
 * logical structure of such a tree, rooted at 4 (binary 100), covering
 * the range 1-7 (binary 001-111).  Our canonical trees do not include
 * fd 0; we'll deal with that later.
 *
 *	      100
 *	     /	 \
 *	    /	  \
 *	  010	  110
 *	  / \	  / \
 *	001 011 101 111
 *
 * We make the following observations, all of which are easily proven by
 * induction on the depth of the tree:
 *
 * (T1) The least-significant bit (LSB) of any node is equal to its level
 *      in the tree.  In our example, nodes 001, 011, 101 and 111 are at
 *      level 0; nodes 010 and 110 are at level 1; and node 100 is at level 2.
 *
 * (T2) The child size (CSIZE) of node N -- that is, the total number of
 *	right-branch descendants in a child of node N, including itself -- is
 *	given by clearing all but the least significant bit of N.  This
 *	follows immediately from (T1).  Applying this rule to our example, we
 *	see that CSIZE(100) = 100, CSIZE(x10) = 10, and CSIZE(xx1) = 1.
 *
 * (T3) The nearest left ancestor (LPARENT) of node N -- that is, the nearest
 *	ancestor containing node N in its right child -- is given by clearing
 *	the LSB of N.  For example, LPARENT(111) = 110 and LPARENT(110) = 100.
 *	Clearing the LSB of nodes 001, 010 or 100 yields zero, reflecting
 *	the fact that these are leftmost nodes.  Note that this algorithm
 *	automatically skips generations as necessary.  For example, the parent
 *      of node 101 is 110, which is a *right* ancestor (not what we want);
 *      but its grandparent is 100, which is a left ancestor. Clearing the LSB
 *      of 101 gets us to 100 directly, skipping right past the uninteresting
 *      generation (110).
 *
 *      Note that since LPARENT clears the LSB, whereas CSIZE clears all *but*
 *	the LSB, we can express LPARENT() nicely in terms of CSIZE():
 *
 *	LPARENT(N) = N - CSIZE(N)
 *
 * (T4) The nearest right ancestor (RPARENT) of node N is given by:
 *
 *	RPARENT(N) = N + CSIZE(N)
 *
 * (T5) For every interior node, the children differ from their parent by
 *	CSIZE(parent) / 2.  In our example, CSIZE(100) / 2 = 2 = 10 binary,
 *      and indeed, the children of 100 are 100 +/- 10 = 010 and 110.
 *
 * Next, we'll need a few two's-complement math tricks.  Suppose a number,
 * N, has the following form:
 *
 *		N = xxxx10...0
 *
 * That is, the binary representation of N consists of some string of bits,
 * then a 1, then all zeroes.  This amounts to nothing more than saying that
 * N has a least-significant bit, which is true for any N != 0.  If we look
 * at N and N - 1 together, we see that we can combine them in useful ways:
 *
 *		  N = xxxx10...0
 *	      N - 1 = xxxx01...1
 *	------------------------
 *	N & (N - 1) = xxxx000000
 *	N | (N - 1) = xxxx111111
 *	N ^ (N - 1) =     111111
 *
 * In particular, this suggests several easy ways to clear all but the LSB,
 * which by (T2) is exactly what we need to determine CSIZE(N) = 10...0.
 * We'll opt for this formulation:
 *
 *	(C1) CSIZE(N) = (N - 1) ^ (N | (N - 1))
 *
 * Similarly, we have an easy way to determine LPARENT(N), which requires
 * that we clear the LSB of N:
 *
 *	(L1) LPARENT(N) = N & (N - 1)
 *
 * We note in the above relations that (N | (N - 1)) - N = CSIZE(N) - 1.
 * When combined with (T4), this yields an easy way to compute RPARENT(N):
 *
 *	(R1) RPARENT(N) = (N | (N - 1)) + 1
 *
 * Finally, to accommodate fd 0 we must adjust all of our results by +/-1 to
 * move the fd range from [1, 2^n) to [0, 2^n - 1).  This is straightforward,
 * so there's no need to belabor the algebra; the revised relations become:
 *
 *	(C1a) CSIZE(N) = N ^ (N | (N + 1))
 *
 *	(L1a) LPARENT(N) = (N & (N + 1)) - 1
 *
 *	(R1a) RPARENT(N) = N | (N + 1)
 *
 * This completes the mathematical framework.  We now have all the tools
 * we need to implement fd_find() and fd_reserve().
 *
 * fd_find(fip, minfd) finds the smallest available file descriptor >= minfd.
 * It does not actually allocate the descriptor; that's done by fd_reserve().
 * fd_find() proceeds in two steps:
 *
 * (1) Find the leftmost subtree that contains a descriptor >= minfd.
 *     We start at the right subtree rooted at minfd.  If this subtree is
 *     not full -- if fip->fi_list[minfd].uf_alloc != CSIZE(minfd) -- then
 *     step 1 is done.  Otherwise, we know that all fds in this subtree
 *     are taken, so we ascend to RPARENT(minfd) using (R1a).  We repeat
 *     this process until we either find a candidate subtree or exceed
 *     fip->fi_nfiles.  We use (C1a) to compute CSIZE().
 *
 * (2) Find the smallest fd in the subtree discovered by step 1.
 *     Starting at the root of this subtree, we descend to find the
 *     smallest available fd.  Since the left children have the smaller
 *     fds, we will descend rightward only when the left child is full.
 *
 *     We begin by comparing the number of allocated fds in the root
 *     to the number of allocated fds in its right child; if they differ
 *     by exactly CSIZE(child), we know the left subtree is full, so we
 *     descend right; that is, the right child becomes the search root.
 *     Otherwise we leave the root alone and start following the right
 *     child's left children.  As fortune would have it, this is very
 *     simple computationally: by (T5), the right child of fd is just
 *     fd + size, where size = CSIZE(fd) / 2.  Applying (T5) again,
 *     we find that the right child's left child is fd + size - (size / 2) =
 *     fd + (size / 2); *its* left child is fd + (size / 2) - (size / 4) =
 *     fd + (size / 4), and so on.  In general, fd's right child's
 *     leftmost nth descendant is fd + (size >> n).  Thus, to follow
 *     the right child's left descendants, we just halve the size in
 *     each iteration of the search.
 *
 *     When we descend leftward, we must keep track of the number of fds
 *     that were allocated in all the right subtrees we rejected, so we
 *     know how many of the root fd's allocations are in the remaining
 *     (as yet unexplored) leftmost part of its right subtree.  When we
 *     encounter a fully-allocated left child -- that is, when we find
 *     that fip->fi_list[fd].uf_alloc == ralloc + size -- we descend right
 *     (as described earlier), resetting ralloc to zero.
 *
 * fd_reserve(fip, fd, incr) either allocates or frees fd, depending
 * on whether incr is 1 or -1.  Starting at fd, fd_reserve() ascends
 * the leftmost ancestors (see (T3)) and updates the allocation counts.
 * At each step we use (L1a) to compute LPARENT(), the next left ancestor.
 *
 * flist_minsize() finds the minimal tree that still covers all
 * used fds; as long as the allocation count of a root node is zero, we
 * don't need that node or its right subtree.
 *
 * flist_nalloc() counts the number of allocated fds in the tree, by starting
 * at the top of the tree and summing the right-subtree allocation counts as
 * it descends leftwards.
 *
 * Note: we assume that flist_grow() will keep fip->fi_nfiles of the form
 * 2^n - 1.  This ensures that the fd trees are always full, which saves
 * quite a bit of boundary checking.
 */
static int
fd_find(uf_info_t *fip, int minfd)
{
	int size, ralloc, fd;

	ASSERT(MUTEX_HELD(&fip->fi_lock));
	ASSERT((fip->fi_nfiles & (fip->fi_nfiles + 1)) == 0);

	for (fd = minfd; (uint_t)fd < fip->fi_nfiles; fd |= fd + 1) {
		size = fd ^ (fd | (fd + 1));
		if (fip->fi_list[fd].uf_alloc == size)
			continue;
		for (ralloc = 0, size >>= 1; size != 0; size >>= 1) {
			ralloc += fip->fi_list[fd + size].uf_alloc;
			if (fip->fi_list[fd].uf_alloc == ralloc + size) {
				fd += size;
				ralloc = 0;
			}
		}
		return (fd);
	}
	return (-1);
}

static void
fd_reserve(uf_info_t *fip, int fd, int incr)
{
	int pfd;
	uf_entry_t *ufp = &fip->fi_list[fd];

	ASSERT((uint_t)fd < fip->fi_nfiles);
	ASSERT((ufp->uf_busy == 0 && incr == 1) ||
	    (ufp->uf_busy == 1 && incr == -1));
	ASSERT(MUTEX_HELD(&ufp->uf_lock));
	ASSERT(MUTEX_HELD(&fip->fi_lock));

	for (pfd = fd; pfd >= 0; pfd = (pfd & (pfd + 1)) - 1)
		fip->fi_list[pfd].uf_alloc += incr;

	ufp->uf_busy += incr;
}

static int
flist_minsize(uf_info_t *fip)
{
	int fd;

	/*
	 * We'd like to ASSERT(MUTEX_HELD(&fip->fi_lock)), but we're called
	 * by flist_fork(), which relies on other mechanisms for mutual
	 * exclusion.
	 */
	ASSERT((fip->fi_nfiles & (fip->fi_nfiles + 1)) == 0);

	for (fd = fip->fi_nfiles; fd != 0; fd >>= 1)
		if (fip->fi_list[fd >> 1].uf_alloc != 0)
			break;

	return (fd);
}

static int
flist_nalloc(uf_info_t *fip)
{
	int fd;
	int nalloc = 0;

	ASSERT(MUTEX_HELD(&fip->fi_lock));
	ASSERT((fip->fi_nfiles & (fip->fi_nfiles + 1)) == 0);

	for (fd = fip->fi_nfiles; fd != 0; fd >>= 1)
		nalloc += fip->fi_list[fd >> 1].uf_alloc;

	return (nalloc);
}

/*
 * Increase size of the fi_list array to accommodate at least maxfd.
 * We keep the size of the form 2^n - 1 for benefit of fd_find().
 */
static void
flist_grow(int maxfd)
{
	uf_info_t *fip = P_FINFO(curproc);
	int newcnt, oldcnt;
	uf_entry_t *src, *dst, *newlist, *oldlist, *newend, *oldend;
	uf_rlist_t *urp;

	for (newcnt = 1; newcnt <= maxfd; newcnt = (newcnt << 1) | 1)
		continue;

	newlist = kmem_zalloc(newcnt * sizeof (uf_entry_t), KM_SLEEP);

	mutex_enter(&fip->fi_lock);
	oldcnt = fip->fi_nfiles;
	if (newcnt <= oldcnt) {
		mutex_exit(&fip->fi_lock);
		kmem_free(newlist, newcnt * sizeof (uf_entry_t));
		return;
	}
	ASSERT((newcnt & (newcnt + 1)) == 0);
	oldlist = fip->fi_list;
	oldend = oldlist + oldcnt;
	newend = newlist + oldcnt;	/* no need to lock beyond old end */

	/*
	 * fi_list and fi_nfiles cannot change while any uf_lock is held,
	 * so we must grab all the old locks *and* the new locks up to oldcnt.
	 * (Locks beyond the end of oldcnt aren't visible until we store
	 * the new fi_nfiles, which is the last thing we do before dropping
	 * all the locks, so there's no need to acquire these locks).
	 * Holding the new locks is necessary because when fi_list changes
	 * to point to the new list, fi_nfiles won't have been stored yet.
	 * If we *didn't* hold the new locks, someone doing a UF_ENTER()
	 * could see the new fi_list, grab the new uf_lock, and then see
	 * fi_nfiles change while the lock is held -- in violation of
	 * UF_ENTER() semantics.
	 */
	for (src = oldlist; src < oldend; src++)
		mutex_enter(&src->uf_lock);

	for (dst = newlist; dst < newend; dst++)
		mutex_enter(&dst->uf_lock);

	for (src = oldlist, dst = newlist; src < oldend; src++, dst++) {
		dst->uf_file = src->uf_file;
		dst->uf_fpollinfo = src->uf_fpollinfo;
		dst->uf_refcnt = src->uf_refcnt;
		dst->uf_alloc = src->uf_alloc;
		dst->uf_flag = src->uf_flag;
		dst->uf_busy = src->uf_busy;
		dst->uf_portfd = src->uf_portfd;
	}

	/*
	 * As soon as we store the new flist, future locking operations
	 * will use it.  Therefore, we must ensure that all the state
	 * we've just established reaches global visibility before the
	 * new flist does.
	 */
	membar_producer();
	fip->fi_list = newlist;

	/*
	 * Routines like getf() make an optimistic check on the validity
	 * of the supplied file descriptor: if it's less than the current
	 * value of fi_nfiles -- examined without any locks -- then it's
	 * safe to attempt a UF_ENTER() on that fd (which is a valid
	 * assumption because fi_nfiles only increases).  Therefore, it
	 * is critical that the new value of fi_nfiles not reach global
	 * visibility until after the new fi_list: if it happened the
	 * other way around, getf() could see the new fi_nfiles and attempt
	 * a UF_ENTER() on the old fi_list, which would write beyond its
	 * end if the fd exceeded the old fi_nfiles.
	 */
	membar_producer();
	fip->fi_nfiles = newcnt;

	/*
	 * The new state is consistent now, so we can drop all the locks.
	 */
	for (dst = newlist; dst < newend; dst++)
		mutex_exit(&dst->uf_lock);

	for (src = oldlist; src < oldend; src++) {
		/*
		 * If any threads are blocked on the old cvs, wake them.
		 * This will force them to wake up, discover that fi_list
		 * has changed, and go back to sleep on the new cvs.
		 */
		cv_broadcast(&src->uf_wanted_cv);
		cv_broadcast(&src->uf_closing_cv);
		mutex_exit(&src->uf_lock);
	}

	mutex_exit(&fip->fi_lock);

	/*
	 * Retire the old flist.  We can't actually kmem_free() it now
	 * because someone may still have a pointer to it.  Instead,
	 * we link it onto a list of retired flists.  The new flist
	 * is at least double the size of the previous flist, so the
	 * total size of all retired flists will be less than the size
	 * of the current one (to prove, consider the sum of a geometric
	 * series in powers of 2).  exit() frees the retired flists.
	 */
	urp = kmem_zalloc(sizeof (uf_rlist_t), KM_SLEEP);
	urp->ur_list = oldlist;
	urp->ur_nfiles = oldcnt;

	mutex_enter(&fip->fi_lock);
	urp->ur_next = fip->fi_rlist;
	fip->fi_rlist = urp;
	mutex_exit(&fip->fi_lock);
}

/*
 * Utility functions for keeping track of the active file descriptors.
 */
void
clear_stale_fd()		/* called from post_syscall() */
{
	afd_t *afd = &curthread->t_activefd;
	int i;

	/* uninitialized is ok here, a_nfd is then zero */
	for (i = 0; i < afd->a_nfd; i++) {
		/* assert that this should not be necessary */
		ASSERT(afd->a_fd[i] == -1);
		afd->a_fd[i] = -1;
	}
	afd->a_stale = 0;
}

void
free_afd(afd_t *afd)		/* called below and from thread_free() */
{
	int i;

	/* free the buffer if it was kmem_alloc()ed */
	if (afd->a_nfd > sizeof (afd->a_buf) / sizeof (afd->a_buf[0])) {
		COUNT(afd_free);
		kmem_free(afd->a_fd, afd->a_nfd * sizeof (afd->a_fd[0]));
	}

	/* (re)initialize the structure */
	afd->a_fd = &afd->a_buf[0];
	afd->a_nfd = sizeof (afd->a_buf) / sizeof (afd->a_buf[0]);
	afd->a_stale = 0;
	for (i = 0; i < afd->a_nfd; i++)
		afd->a_fd[i] = -1;
}

static void
set_active_fd(int fd)
{
	afd_t *afd = &curthread->t_activefd;
	int i;
	int *old_fd;
	int old_nfd;
	int *new_fd;
	int new_nfd;

	if (afd->a_nfd == 0) {	/* first time initialization */
		ASSERT(fd == -1);
		mutex_enter(&afd->a_fdlock);
		free_afd(afd);
		mutex_exit(&afd->a_fdlock);
	}

	/* insert fd into vacant slot, if any */
	for (i = 0; i < afd->a_nfd; i++) {
		if (afd->a_fd[i] == -1) {
			afd->a_fd[i] = fd;
			return;
		}
	}

	/*
	 * Reallocate the a_fd[] array to add one more slot.
	 */
	ASSERT(fd == -1);
	old_nfd = afd->a_nfd;
	old_fd = afd->a_fd;
	new_nfd = old_nfd + 1;
	new_fd = kmem_alloc(new_nfd * sizeof (afd->a_fd[0]), KM_SLEEP);
	MAXFD(new_nfd);
	COUNT(afd_alloc);

	mutex_enter(&afd->a_fdlock);
	afd->a_fd = new_fd;
	afd->a_nfd = new_nfd;
	for (i = 0; i < old_nfd; i++)
		afd->a_fd[i] = old_fd[i];
	afd->a_fd[i] = fd;
	mutex_exit(&afd->a_fdlock);

	if (old_nfd > sizeof (afd->a_buf) / sizeof (afd->a_buf[0])) {
		COUNT(afd_free);
		kmem_free(old_fd, old_nfd * sizeof (afd->a_fd[0]));
	}
}

void
clear_active_fd(int fd)		/* called below and from aio.c */
{
	afd_t *afd = &curthread->t_activefd;
	int i;

	for (i = 0; i < afd->a_nfd; i++) {
		if (afd->a_fd[i] == fd) {
			afd->a_fd[i] = -1;
			break;
		}
	}
	ASSERT(i < afd->a_nfd);		/* not found is not ok */
}

/*
 * Does this thread have this fd active?
 */
static int
is_active_fd(kthread_t *t, int fd)
{
	afd_t *afd = &t->t_activefd;
	int i;

	ASSERT(t != curthread);
	mutex_enter(&afd->a_fdlock);
	/* uninitialized is ok here, a_nfd is then zero */
	for (i = 0; i < afd->a_nfd; i++) {
		if (afd->a_fd[i] == fd) {
			mutex_exit(&afd->a_fdlock);
			return (1);
		}
	}
	mutex_exit(&afd->a_fdlock);
	return (0);
}

/*
 * Convert a user supplied file descriptor into a pointer to a file
 * structure.  Only task is to check range of the descriptor (soft
 * resource limit was enforced at open time and shouldn't be checked
 * here).
 */
file_t *
getf(int fd)
{
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;
	file_t *fp;

	if ((uint_t)fd >= fip->fi_nfiles)
		return (NULL);

	/*
	 * Reserve a slot in the active fd array now so we can call
	 * set_active_fd(fd) for real below, while still inside UF_ENTER().
	 */
	set_active_fd(-1);

	UF_ENTER(ufp, fip, fd);

	if ((fp = ufp->uf_file) == NULL) {
		UF_EXIT(ufp);

		if (fd == fip->fi_badfd && fip->fi_action > 0)
			tsignal(curthread, fip->fi_action);

		return (NULL);
	}
	ufp->uf_refcnt++;

	set_active_fd(fd);	/* record the active file descriptor */

	UF_EXIT(ufp);

	return (fp);
}

/*
 * Close whatever file currently occupies the file descriptor slot
 * and install the new file, usually NULL, in the file descriptor slot.
 * The close must complete before we release the file descriptor slot.
 * If newfp != NULL we only return an error if we can't allocate the
 * slot so the caller knows that it needs to free the filep;
 * in the other cases we return the error number from closef().
 */
int
closeandsetf(int fd, file_t *newfp)
{
	proc_t *p = curproc;
	uf_info_t *fip = P_FINFO(p);
	uf_entry_t *ufp;
	file_t *fp;
	fpollinfo_t *fpip;
	portfd_t *pfd;
	int error;

	if ((uint_t)fd >= fip->fi_nfiles) {
		if (newfp == NULL)
			return (EBADF);
		flist_grow(fd);
	}

	if (newfp != NULL) {
		/*
		 * If ufp is reserved but has no file pointer, it's in the
		 * transition between ufalloc() and setf().  We must wait
		 * for this transition to complete before assigning the
		 * new non-NULL file pointer.
		 */
		mutex_enter(&fip->fi_lock);
		if (fd == fip->fi_badfd) {
			mutex_exit(&fip->fi_lock);
			if (fip->fi_action > 0)
				tsignal(curthread, fip->fi_action);
			return (EBADF);
		}
		UF_ENTER(ufp, fip, fd);
		while (ufp->uf_busy && ufp->uf_file == NULL) {
			mutex_exit(&fip->fi_lock);
			cv_wait_stop(&ufp->uf_wanted_cv, &ufp->uf_lock, 250);
			UF_EXIT(ufp);
			mutex_enter(&fip->fi_lock);
			UF_ENTER(ufp, fip, fd);
		}
		if ((fp = ufp->uf_file) == NULL) {
			ASSERT(ufp->uf_fpollinfo == NULL);
			ASSERT(ufp->uf_flag == 0);
			fd_reserve(fip, fd, 1);
			ufp->uf_file = newfp;
			UF_EXIT(ufp);
			mutex_exit(&fip->fi_lock);
			return (0);
		}
		mutex_exit(&fip->fi_lock);
	} else {
		UF_ENTER(ufp, fip, fd);
		if ((fp = ufp->uf_file) == NULL) {
			UF_EXIT(ufp);
			return (EBADF);
		}
	}

	ASSERT(ufp->uf_busy);
	ufp->uf_file = NULL;
	ufp->uf_flag = 0;

	/*
	 * If the file descriptor reference count is non-zero, then
	 * some other lwp in the process is performing system call
	 * activity on the file.  To avoid blocking here for a long
	 * time (the other lwp might be in a long term sleep in its
	 * system call), we scan all other lwps in the process to
	 * find the ones with this fd as one of their active fds,
	 * set their a_stale flag, and set them running if they
	 * are in an interruptible sleep so they will emerge from
	 * their system calls immediately.  post_syscall() will
	 * test the a_stale flag and set errno to EBADF.
	 */
	ASSERT(ufp->uf_refcnt == 0 || p->p_lwpcnt > 1);
	if (ufp->uf_refcnt > 0) {
		kthread_t *t;

		/*
		 * We call sprlock_proc(p) to ensure that the thread
		 * list will not change while we are scanning it.
		 * To do this, we must drop ufp->uf_lock and then
		 * reacquire it (so we are not holding both p->p_lock
		 * and ufp->uf_lock at the same time).  ufp->uf_lock
		 * must be held for is_active_fd() to be correct
		 * (set_active_fd() is called while holding ufp->uf_lock).
		 *
		 * This is a convoluted dance, but it is better than
		 * the old brute-force method of stopping every thread
		 * in the process by calling holdlwps(SHOLDFORK1).
		 */

		UF_EXIT(ufp);
		COUNT(afd_wait);

		mutex_enter(&p->p_lock);
		sprlock_proc(p);
		mutex_exit(&p->p_lock);

		UF_ENTER(ufp, fip, fd);
		ASSERT(ufp->uf_file == NULL);

		if (ufp->uf_refcnt > 0) {
			for (t = curthread->t_forw;
			    t != curthread;
			    t = t->t_forw) {
				if (is_active_fd(t, fd)) {
					thread_lock(t);
					t->t_activefd.a_stale = 1;
					t->t_post_sys = 1;
					if (ISWAKEABLE(t))
						setrun_locked(t);
					thread_unlock(t);
				}
			}
		}

		UF_EXIT(ufp);

		mutex_enter(&p->p_lock);
		sprunlock(p);

		UF_ENTER(ufp, fip, fd);
		ASSERT(ufp->uf_file == NULL);
	}

	/*
	 * Wait for other lwps to stop using this file descriptor.
	 */
	while (ufp->uf_refcnt > 0) {
		cv_wait_stop(&ufp->uf_closing_cv, &ufp->uf_lock, 250);
		/*
		 * cv_wait_stop() drops ufp->uf_lock, so the file list
		 * can change.  Drop the lock on our (possibly) stale
		 * ufp and let UF_ENTER() find and lock the current ufp.
		 */
		UF_EXIT(ufp);
		UF_ENTER(ufp, fip, fd);
	}

#ifdef DEBUG
	/*
	 * catch a watchfd on device's pollhead list but not on fpollinfo list
	 */
	if (ufp->uf_fpollinfo != NULL)
		checkwfdlist(fp->f_vnode, ufp->uf_fpollinfo);
#endif	/* DEBUG */

	/*
	 * We may need to cleanup some cached poll states in t_pollstate
	 * before the fd can be reused. It is important that we don't
	 * access a stale thread structure. We will do the cleanup in two
	 * phases to avoid deadlock and holding uf_lock for too long.
	 * In phase 1, hold the uf_lock and call pollblockexit() to set
	 * state in t_pollstate struct so that a thread does not exit on
	 * us. In phase 2, we drop the uf_lock and call pollcacheclean().
	 */
	pfd = ufp->uf_portfd;
	ufp->uf_portfd = NULL;
	fpip = ufp->uf_fpollinfo;
	ufp->uf_fpollinfo = NULL;
	if (fpip != NULL)
		pollblockexit(fpip);
	UF_EXIT(ufp);
	if (fpip != NULL)
		pollcacheclean(fpip, fd);
	if (pfd)
		port_close_fd(pfd);

	/*
	 * Keep the file descriptor entry reserved across the closef().
	 */
	error = closef(fp);

	setf(fd, newfp);

	/* Only return closef() error when closing is all we do */
	return (newfp == NULL ? error : 0);
}

/*
 * Decrement uf_refcnt; wakeup anyone waiting to close the file.
 */
void
releasef(int fd)
{
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;

	UF_ENTER(ufp, fip, fd);
	ASSERT(ufp->uf_refcnt > 0);
	clear_active_fd(fd);	/* clear the active file descriptor */
	if (--ufp->uf_refcnt == 0)
		cv_broadcast(&ufp->uf_closing_cv);
	UF_EXIT(ufp);
}

/*
 * Identical to releasef() but can be called from another process.
 */
void
areleasef(int fd, uf_info_t *fip)
{
	uf_entry_t *ufp;

	UF_ENTER(ufp, fip, fd);
	ASSERT(ufp->uf_refcnt > 0);
	if (--ufp->uf_refcnt == 0)
		cv_broadcast(&ufp->uf_closing_cv);
	UF_EXIT(ufp);
}

/*
 * Duplicate all file descriptors across a fork.
 */
void
flist_fork(uf_info_t *pfip, uf_info_t *cfip)
{
	int fd, nfiles;
	uf_entry_t *pufp, *cufp;

	mutex_init(&cfip->fi_lock, NULL, MUTEX_DEFAULT, NULL);
	cfip->fi_rlist = NULL;

	/*
	 * We don't need to hold fi_lock because all other lwp's in the
	 * parent have been held.
	 */
	cfip->fi_nfiles = nfiles = flist_minsize(pfip);

	cfip->fi_list = kmem_zalloc(nfiles * sizeof (uf_entry_t), KM_SLEEP);

	for (fd = 0, pufp = pfip->fi_list, cufp = cfip->fi_list; fd < nfiles;
	    fd++, pufp++, cufp++) {
		cufp->uf_file = pufp->uf_file;
		cufp->uf_alloc = pufp->uf_alloc;
		cufp->uf_flag = pufp->uf_flag;
		cufp->uf_busy = pufp->uf_busy;
		if (pufp->uf_file == NULL) {
			ASSERT(pufp->uf_flag == 0);
			if (pufp->uf_busy) {
				/*
				 * Grab locks to appease ASSERTs in fd_reserve
				 */
				mutex_enter(&cfip->fi_lock);
				mutex_enter(&cufp->uf_lock);
				fd_reserve(cfip, fd, -1);
				mutex_exit(&cufp->uf_lock);
				mutex_exit(&cfip->fi_lock);
			}
		}
	}
}

/*
 * Close all open file descriptors for the current process.
 * This is only called from exit(), which is single-threaded,
 * so we don't need any locking.
 */
void
closeall(uf_info_t *fip)
{
	int fd;
	file_t *fp;
	uf_entry_t *ufp;

	ufp = fip->fi_list;
	for (fd = 0; fd < fip->fi_nfiles; fd++, ufp++) {
		if ((fp = ufp->uf_file) != NULL) {
			ufp->uf_file = NULL;
			if (ufp->uf_portfd != NULL) {
				portfd_t *pfd;
				/* remove event port association */
				pfd = ufp->uf_portfd;
				ufp->uf_portfd = NULL;
				port_close_fd(pfd);
			}
			ASSERT(ufp->uf_fpollinfo == NULL);
			(void) closef(fp);
		}
	}

	kmem_free(fip->fi_list, fip->fi_nfiles * sizeof (uf_entry_t));
	fip->fi_list = NULL;
	fip->fi_nfiles = 0;
	while (fip->fi_rlist != NULL) {
		uf_rlist_t *urp = fip->fi_rlist;
		fip->fi_rlist = urp->ur_next;
		kmem_free(urp->ur_list, urp->ur_nfiles * sizeof (uf_entry_t));
		kmem_free(urp, sizeof (uf_rlist_t));
	}
}

/*
 * Internal form of close.  Decrement reference count on file
 * structure.  Decrement reference count on the vnode following
 * removal of the referencing file structure.
 */
int
closef(file_t *fp)
{
	vnode_t *vp;
	int error;
	int count;
	int flag;
	offset_t offset;

	/*
	 * audit close of file (may be exit)
	 */
	if (AU_AUDITING())
		audit_closef(fp);
	ASSERT(MUTEX_NOT_HELD(&P_FINFO(curproc)->fi_lock));

	mutex_enter(&fp->f_tlock);

	ASSERT(fp->f_count > 0);

	count = fp->f_count--;
	flag = fp->f_flag;
	offset = fp->f_offset;

	vp = fp->f_vnode;

	error = VOP_CLOSE(vp, flag, count, offset, fp->f_cred, NULL);

	if (count > 1) {
		mutex_exit(&fp->f_tlock);
		return (error);
	}
	ASSERT(fp->f_count == 0);
	mutex_exit(&fp->f_tlock);

	/*
	 * If DTrace has getf() subroutines active, it will set dtrace_closef
	 * to point to code that implements a barrier with respect to probe
	 * context.  This must be called before the file_t is freed (and the
	 * vnode that it refers to is released) -- but it must be after the
	 * file_t has been removed from the uf_entry_t.  That is, there must
	 * be no way for a racing getf() in probe context to yield the fp that
	 * we're operating upon.
	 */
	if (dtrace_closef != NULL)
		(*dtrace_closef)();

	VN_RELE(vp);
	/*
	 * deallocate resources to audit_data
	 */
	if (audit_active)
		audit_unfalloc(fp);
	crfree(fp->f_cred);
	kmem_cache_free(file_cache, fp);
	return (error);
}

/*
 * This is a combination of ufalloc() and setf().
 */
int
ufalloc_file(int start, file_t *fp)
{
	proc_t *p = curproc;
	uf_info_t *fip = P_FINFO(p);
	int filelimit;
	uf_entry_t *ufp;
	int nfiles;
	int fd;

	/*
	 * Assertion is to convince the correctness of the following
	 * assignment for filelimit after casting to int.
	 */
	ASSERT(p->p_fno_ctl <= INT_MAX);
	filelimit = (int)p->p_fno_ctl;

	for (;;) {
		mutex_enter(&fip->fi_lock);
		fd = fd_find(fip, start);
		if (fd >= 0 && fd == fip->fi_badfd) {
			start = fd + 1;
			mutex_exit(&fip->fi_lock);
			continue;
		}
		if ((uint_t)fd < filelimit)
			break;
		if (fd >= filelimit) {
			mutex_exit(&fip->fi_lock);
			mutex_enter(&p->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_NOFILE],
			    p->p_rctls, p, RCA_SAFE);
			mutex_exit(&p->p_lock);
			return (-1);
		}
		/* fd_find() returned -1 */
		nfiles = fip->fi_nfiles;
		mutex_exit(&fip->fi_lock);
		flist_grow(MAX(start, nfiles));
	}

	UF_ENTER(ufp, fip, fd);
	fd_reserve(fip, fd, 1);
	ASSERT(ufp->uf_file == NULL);
	ufp->uf_file = fp;
	UF_EXIT(ufp);
	mutex_exit(&fip->fi_lock);
	return (fd);
}

/*
 * Allocate a user file descriptor greater than or equal to "start".
 */
int
ufalloc(int start)
{
	return (ufalloc_file(start, NULL));
}

/*
 * Check that a future allocation of count fds on proc p has a good
 * chance of succeeding.  If not, do rctl processing as if we'd failed
 * the allocation.
 *
 * Our caller must guarantee that p cannot disappear underneath us.
 */
int
ufcanalloc(proc_t *p, uint_t count)
{
	uf_info_t *fip = P_FINFO(p);
	int filelimit;
	int current;

	if (count == 0)
		return (1);

	ASSERT(p->p_fno_ctl <= INT_MAX);
	filelimit = (int)p->p_fno_ctl;

	mutex_enter(&fip->fi_lock);
	current = flist_nalloc(fip);		/* # of in-use descriptors */
	mutex_exit(&fip->fi_lock);

	/*
	 * If count is a positive integer, the worst that can happen is
	 * an overflow to a negative value, which is caught by the >= 0 check.
	 */
	current += count;
	if (count <= INT_MAX && current >= 0 && current <= filelimit)
		return (1);

	mutex_enter(&p->p_lock);
	(void) rctl_action(rctlproc_legacy[RLIMIT_NOFILE],
	    p->p_rctls, p, RCA_SAFE);
	mutex_exit(&p->p_lock);
	return (0);
}

/*
 * Allocate a user file descriptor and a file structure.
 * Initialize the descriptor to point at the file structure.
 * If fdp is NULL, the user file descriptor will not be allocated.
 */
int
falloc(vnode_t *vp, int flag, file_t **fpp, int *fdp)
{
	file_t *fp;
	int fd;

	if (fdp) {
		if ((fd = ufalloc(0)) == -1)
			return (EMFILE);
	}
	fp = kmem_cache_alloc(file_cache, KM_SLEEP);
	/*
	 * Note: falloc returns the fp locked
	 */
	mutex_enter(&fp->f_tlock);
	fp->f_count = 1;
	fp->f_flag = (ushort_t)flag;
	fp->f_flag2 = (flag & (FSEARCH|FEXEC)) >> 16;
	fp->f_vnode = vp;
	fp->f_offset = 0;
	fp->f_audit_data = 0;
	crhold(fp->f_cred = CRED());
	/*
	 * allocate resources to audit_data
	 */
	if (audit_active)
		audit_falloc(fp);
	*fpp = fp;
	if (fdp)
		*fdp = fd;
	return (0);
}

/*ARGSUSED*/
static int
file_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	file_t *fp = buf;

	mutex_init(&fp->f_tlock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
file_cache_destructor(void *buf, void *cdrarg)
{
	file_t *fp = buf;

	mutex_destroy(&fp->f_tlock);
}

void
finit()
{
	file_cache = kmem_cache_create("file_cache", sizeof (file_t), 0,
	    file_cache_constructor, file_cache_destructor, NULL, NULL, NULL, 0);
}

void
unfalloc(file_t *fp)
{
	ASSERT(MUTEX_HELD(&fp->f_tlock));
	if (--fp->f_count <= 0) {
		/*
		 * deallocate resources to audit_data
		 */
		if (audit_active)
			audit_unfalloc(fp);
		crfree(fp->f_cred);
		mutex_exit(&fp->f_tlock);
		kmem_cache_free(file_cache, fp);
	} else
		mutex_exit(&fp->f_tlock);
}

/*
 * Given a file descriptor, set the user's
 * file pointer to the given parameter.
 */
void
setf(int fd, file_t *fp)
{
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;

	if (AU_AUDITING())
		audit_setf(fp, fd);

	if (fp == NULL) {
		mutex_enter(&fip->fi_lock);
		UF_ENTER(ufp, fip, fd);
		fd_reserve(fip, fd, -1);
		mutex_exit(&fip->fi_lock);
	} else {
		UF_ENTER(ufp, fip, fd);
		ASSERT(ufp->uf_busy);
	}
	ASSERT(ufp->uf_fpollinfo == NULL);
	ASSERT(ufp->uf_flag == 0);
	ufp->uf_file = fp;
	cv_broadcast(&ufp->uf_wanted_cv);
	UF_EXIT(ufp);
}

/*
 * Given a file descriptor, return the file table flags, plus,
 * if this is a socket in asynchronous mode, the FASYNC flag.
 * getf() may or may not have been called before calling f_getfl().
 */
int
f_getfl(int fd, int *flagp)
{
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;
	file_t *fp;
	int error;

	if ((uint_t)fd >= fip->fi_nfiles)
		error = EBADF;
	else {
		UF_ENTER(ufp, fip, fd);
		if ((fp = ufp->uf_file) == NULL)
			error = EBADF;
		else {
			vnode_t *vp = fp->f_vnode;
			int flag = fp->f_flag |
			    ((fp->f_flag2 & ~FEPOLLED) << 16);

			/*
			 * BSD fcntl() FASYNC compatibility.
			 */
			if (vp->v_type == VSOCK)
				flag |= sock_getfasync(vp);
			*flagp = flag;
			error = 0;
		}
		UF_EXIT(ufp);
	}

	return (error);
}

/*
 * Given a file descriptor, return the user's file flags.
 * Force the FD_CLOEXEC flag for writable self-open /proc files.
 * getf() may or may not have been called before calling f_getfd_error().
 */
int
f_getfd_error(int fd, int *flagp)
{
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;
	file_t *fp;
	int flag;
	int error;

	if ((uint_t)fd >= fip->fi_nfiles)
		error = EBADF;
	else {
		UF_ENTER(ufp, fip, fd);
		if ((fp = ufp->uf_file) == NULL)
			error = EBADF;
		else {
			flag = ufp->uf_flag;
			if ((fp->f_flag & FWRITE) && pr_isself(fp->f_vnode))
				flag |= FD_CLOEXEC;
			*flagp = flag;
			error = 0;
		}
		UF_EXIT(ufp);
	}

	return (error);
}

/*
 * getf() must have been called before calling f_getfd().
 */
char
f_getfd(int fd)
{
	int flag = 0;
	(void) f_getfd_error(fd, &flag);
	return ((char)flag);
}

/*
 * Given a file descriptor and file flags, set the user's file flags.
 * At present, the only valid flag is FD_CLOEXEC.
 * getf() may or may not have been called before calling f_setfd_error().
 */
int
f_setfd_error(int fd, int flags)
{
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;
	int error;

	if ((uint_t)fd >= fip->fi_nfiles)
		error = EBADF;
	else {
		UF_ENTER(ufp, fip, fd);
		if (ufp->uf_file == NULL)
			error = EBADF;
		else {
			ufp->uf_flag = flags & FD_CLOEXEC;
			error = 0;
		}
		UF_EXIT(ufp);
	}
	return (error);
}

void
f_setfd(int fd, char flags)
{
	(void) f_setfd_error(fd, flags);
}

#define	BADFD_MIN	3
#define	BADFD_MAX	255

/*
 * Attempt to allocate a file descriptor which is bad and which
 * is "poison" to the application.  It cannot be closed (except
 * on exec), allocated for a different use, etc.
 */
int
f_badfd(int start, int *fdp, int action)
{
	int fdr;
	int badfd;
	uf_info_t *fip = P_FINFO(curproc);

#ifdef _LP64
	/* No restrictions on 64 bit _file */
	if (get_udatamodel() != DATAMODEL_ILP32)
		return (EINVAL);
#endif

	if (start > BADFD_MAX || start < BADFD_MIN)
		return (EINVAL);

	if (action >= NSIG || action < 0)
		return (EINVAL);

	mutex_enter(&fip->fi_lock);
	badfd = fip->fi_badfd;
	mutex_exit(&fip->fi_lock);

	if (badfd != -1)
		return (EAGAIN);

	fdr = ufalloc(start);

	if (fdr > BADFD_MAX) {
		setf(fdr, NULL);
		return (EMFILE);
	}
	if (fdr < 0)
		return (EMFILE);

	mutex_enter(&fip->fi_lock);
	if (fip->fi_badfd != -1) {
		/* Lost race */
		mutex_exit(&fip->fi_lock);
		setf(fdr, NULL);
		return (EAGAIN);
	}
	fip->fi_action = action;
	fip->fi_badfd = fdr;
	mutex_exit(&fip->fi_lock);
	setf(fdr, NULL);

	*fdp = fdr;

	return (0);
}

/*
 * Allocate a file descriptor and assign it to the vnode "*vpp",
 * performing the usual open protocol upon it and returning the
 * file descriptor allocated.  It is the responsibility of the
 * caller to dispose of "*vpp" if any error occurs.
 */
int
fassign(vnode_t **vpp, int mode, int *fdp)
{
	file_t *fp;
	int error;
	int fd;

	if (error = falloc((vnode_t *)NULL, mode, &fp, &fd))
		return (error);
	if (error = VOP_OPEN(vpp, mode, fp->f_cred, NULL)) {
		setf(fd, NULL);
		unfalloc(fp);
		return (error);
	}
	fp->f_vnode = *vpp;
	mutex_exit(&fp->f_tlock);
	/*
	 * Fill in the slot falloc reserved.
	 */
	setf(fd, fp);
	*fdp = fd;
	return (0);
}

/*
 * When a process forks it must increment the f_count of all file pointers
 * since there is a new process pointing at them.  fcnt_add(fip, 1) does this.
 * Since we are called when there is only 1 active lwp we don't need to
 * hold fi_lock or any uf_lock.  If the fork fails, fork_fail() calls
 * fcnt_add(fip, -1) to restore the counts.
 */
void
fcnt_add(uf_info_t *fip, int incr)
{
	int i;
	uf_entry_t *ufp;
	file_t *fp;

	ufp = fip->fi_list;
	for (i = 0; i < fip->fi_nfiles; i++, ufp++) {
		if ((fp = ufp->uf_file) != NULL) {
			mutex_enter(&fp->f_tlock);
			ASSERT((incr == 1 && fp->f_count >= 1) ||
			    (incr == -1 && fp->f_count >= 2));
			fp->f_count += incr;
			mutex_exit(&fp->f_tlock);
		}
	}
}

/*
 * This is called from exec to close all fd's that have the FD_CLOEXEC flag
 * set and also to close all self-open for write /proc file descriptors.
 */
void
close_exec(uf_info_t *fip)
{
	int fd;
	file_t *fp;
	fpollinfo_t *fpip;
	uf_entry_t *ufp;
	portfd_t *pfd;

	ufp = fip->fi_list;
	for (fd = 0; fd < fip->fi_nfiles; fd++, ufp++) {
		if ((fp = ufp->uf_file) != NULL &&
		    ((ufp->uf_flag & FD_CLOEXEC) ||
		    ((fp->f_flag & FWRITE) && pr_isself(fp->f_vnode)))) {
			fpip = ufp->uf_fpollinfo;
			mutex_enter(&fip->fi_lock);
			mutex_enter(&ufp->uf_lock);
			fd_reserve(fip, fd, -1);
			mutex_exit(&fip->fi_lock);
			ufp->uf_file = NULL;
			ufp->uf_fpollinfo = NULL;
			ufp->uf_flag = 0;
			/*
			 * We may need to cleanup some cached poll states
			 * in t_pollstate before the fd can be reused. It
			 * is important that we don't access a stale thread
			 * structure. We will do the cleanup in two
			 * phases to avoid deadlock and holding uf_lock for
			 * too long. In phase 1, hold the uf_lock and call
			 * pollblockexit() to set state in t_pollstate struct
			 * so that a thread does not exit on us. In phase 2,
			 * we drop the uf_lock and call pollcacheclean().
			 */
			pfd = ufp->uf_portfd;
			ufp->uf_portfd = NULL;
			if (fpip != NULL)
				pollblockexit(fpip);
			mutex_exit(&ufp->uf_lock);
			if (fpip != NULL)
				pollcacheclean(fpip, fd);
			if (pfd)
				port_close_fd(pfd);
			(void) closef(fp);
		}
	}

	/* Reset bad fd */
	fip->fi_badfd = -1;
	fip->fi_action = -1;
}

/*
 * Utility function called by most of the *at() system call interfaces.
 *
 * Generate a starting vnode pointer for an (fd, path) pair where 'fd'
 * is an open file descriptor for a directory to be used as the starting
 * point for the lookup of the relative pathname 'path' (or, if path is
 * NULL, generate a vnode pointer for the direct target of the operation).
 *
 * If we successfully return a non-NULL startvp, it has been the target
 * of VN_HOLD() and the caller must call VN_RELE() on it.
 */
int
fgetstartvp(int fd, char *path, vnode_t **startvpp)
{
	vnode_t		*startvp;
	file_t 		*startfp;
	char 		startchar;

	if (fd == AT_FDCWD && path == NULL)
		return (EFAULT);

	if (fd == AT_FDCWD) {
		/*
		 * Start from the current working directory.
		 */
		startvp = NULL;
	} else {
		if (path == NULL)
			startchar = '\0';
		else if (copyin(path, &startchar, sizeof (char)))
			return (EFAULT);

		if (startchar == '/') {
			/*
			 * 'path' is an absolute pathname.
			 */
			startvp = NULL;
		} else {
			/*
			 * 'path' is a relative pathname or we will
			 * be applying the operation to 'fd' itself.
			 */
			if ((startfp = getf(fd)) == NULL)
				return (EBADF);
			startvp = startfp->f_vnode;
			VN_HOLD(startvp);
			releasef(fd);
		}
	}
	*startvpp = startvp;
	return (0);
}

/*
 * Called from fchownat() and fchmodat() to set ownership and mode.
 * The contents of *vap must be set before calling here.
 */
int
fsetattrat(int fd, char *path, int flags, struct vattr *vap)
{
	vnode_t		*startvp;
	vnode_t		*vp;
	int 		error;

	/*
	 * Since we are never called to set the size of a file, we don't
	 * need to check for non-blocking locks (via nbl_need_check(vp)).
	 */
	ASSERT(!(vap->va_mask & AT_SIZE));

	if ((error = fgetstartvp(fd, path, &startvp)) != 0)
		return (error);
	if (AU_AUDITING() && startvp != NULL)
		audit_setfsat_path(1);

	/*
	 * Do lookup for fchownat/fchmodat when path not NULL
	 */
	if (path != NULL) {
		if (error = lookupnameat(path, UIO_USERSPACE,
		    (flags == AT_SYMLINK_NOFOLLOW) ?
		    NO_FOLLOW : FOLLOW,
		    NULLVPP, &vp, startvp)) {
			if (startvp != NULL)
				VN_RELE(startvp);
			return (error);
		}
	} else {
		vp = startvp;
		ASSERT(vp);
		VN_HOLD(vp);
	}

	if (vn_is_readonly(vp)) {
		error = EROFS;
	} else {
		error = VOP_SETATTR(vp, vap, 0, CRED(), NULL);
	}

	if (startvp != NULL)
		VN_RELE(startvp);
	VN_RELE(vp);

	return (error);
}

/*
 * Return true if the given vnode is referenced by any
 * entry in the current process's file descriptor table.
 */
int
fisopen(vnode_t *vp)
{
	int fd;
	file_t *fp;
	vnode_t *ovp;
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;

	mutex_enter(&fip->fi_lock);
	for (fd = 0; fd < fip->fi_nfiles; fd++) {
		UF_ENTER(ufp, fip, fd);
		if ((fp = ufp->uf_file) != NULL &&
		    (ovp = fp->f_vnode) != NULL && VN_CMP(vp, ovp)) {
			UF_EXIT(ufp);
			mutex_exit(&fip->fi_lock);
			return (1);
		}
		UF_EXIT(ufp);
	}
	mutex_exit(&fip->fi_lock);
	return (0);
}

/*
 * Return zero if at least one file currently open (by curproc) shouldn't be
 * allowed to change zones.
 */
int
files_can_change_zones(void)
{
	int fd;
	file_t *fp;
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;

	mutex_enter(&fip->fi_lock);
	for (fd = 0; fd < fip->fi_nfiles; fd++) {
		UF_ENTER(ufp, fip, fd);
		if ((fp = ufp->uf_file) != NULL &&
		    !vn_can_change_zones(fp->f_vnode)) {
			UF_EXIT(ufp);
			mutex_exit(&fip->fi_lock);
			return (0);
		}
		UF_EXIT(ufp);
	}
	mutex_exit(&fip->fi_lock);
	return (1);
}

#ifdef DEBUG

/*
 * The following functions are only used in ASSERT()s elsewhere.
 * They do not modify the state of the system.
 */

/*
 * Return true (1) if the current thread is in the fpollinfo
 * list for this file descriptor, else false (0).
 */
static int
curthread_in_plist(uf_entry_t *ufp)
{
	fpollinfo_t *fpip;

	ASSERT(MUTEX_HELD(&ufp->uf_lock));
	for (fpip = ufp->uf_fpollinfo; fpip; fpip = fpip->fp_next)
		if (fpip->fp_thread == curthread)
			return (1);
	return (0);
}

/*
 * Sanity check to make sure that after lwp_exit(),
 * curthread does not appear on any fd's fpollinfo list.
 */
void
checkfpollinfo(void)
{
	int fd;
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;

	mutex_enter(&fip->fi_lock);
	for (fd = 0; fd < fip->fi_nfiles; fd++) {
		UF_ENTER(ufp, fip, fd);
		ASSERT(!curthread_in_plist(ufp));
		UF_EXIT(ufp);
	}
	mutex_exit(&fip->fi_lock);
}

/*
 * Return true (1) if the current thread is in the fpollinfo
 * list for this file descriptor, else false (0).
 * This is the same as curthread_in_plist(),
 * but is called w/o holding uf_lock.
 */
int
infpollinfo(int fd)
{
	uf_info_t *fip = P_FINFO(curproc);
	uf_entry_t *ufp;
	int rc;

	UF_ENTER(ufp, fip, fd);
	rc = curthread_in_plist(ufp);
	UF_EXIT(ufp);
	return (rc);
}

#endif	/* DEBUG */

/*
 * Add the curthread to fpollinfo list, meaning this fd is currently in the
 * thread's poll cache. Each lwp polling this file descriptor should call
 * this routine once.
 */
void
addfpollinfo(int fd)
{
	struct uf_entry *ufp;
	fpollinfo_t *fpip;
	uf_info_t *fip = P_FINFO(curproc);

	fpip = kmem_zalloc(sizeof (fpollinfo_t), KM_SLEEP);
	fpip->fp_thread = curthread;
	UF_ENTER(ufp, fip, fd);
	/*
	 * Assert we are not already on the list, that is, that
	 * this lwp did not call addfpollinfo twice for the same fd.
	 */
	ASSERT(!curthread_in_plist(ufp));
	/*
	 * addfpollinfo is always done inside the getf/releasef pair.
	 */
	ASSERT(ufp->uf_refcnt >= 1);
	fpip->fp_next = ufp->uf_fpollinfo;
	ufp->uf_fpollinfo = fpip;
	UF_EXIT(ufp);
}

/*
 * Delete curthread from fpollinfo list if it is there.
 */
void
delfpollinfo(int fd)
{
	struct uf_entry *ufp;
	struct fpollinfo *fpip;
	struct fpollinfo **fpipp;
	uf_info_t *fip = P_FINFO(curproc);

	UF_ENTER(ufp, fip, fd);
	for (fpipp = &ufp->uf_fpollinfo;
	    (fpip = *fpipp) != NULL;
	    fpipp = &fpip->fp_next) {
		if (fpip->fp_thread == curthread) {
			*fpipp = fpip->fp_next;
			kmem_free(fpip, sizeof (fpollinfo_t));
			break;
		}
	}
	/*
	 * Assert that we are not still on the list, that is, that
	 * this lwp did not call addfpollinfo twice for the same fd.
	 */
	ASSERT(!curthread_in_plist(ufp));
	UF_EXIT(ufp);
}

/*
 * fd is associated with a port. pfd is a pointer to the fd entry in the
 * cache of the port.
 */

void
addfd_port(int fd, portfd_t *pfd)
{
	struct uf_entry *ufp;
	uf_info_t *fip = P_FINFO(curproc);

	UF_ENTER(ufp, fip, fd);
	/*
	 * addfd_port is always done inside the getf/releasef pair.
	 */
	ASSERT(ufp->uf_refcnt >= 1);
	if (ufp->uf_portfd == NULL) {
		/* first entry */
		ufp->uf_portfd = pfd;
		pfd->pfd_next = NULL;
	} else {
		pfd->pfd_next = ufp->uf_portfd;
		ufp->uf_portfd = pfd;
		pfd->pfd_next->pfd_prev = pfd;
	}
	UF_EXIT(ufp);
}

void
delfd_port(int fd, portfd_t *pfd)
{
	struct uf_entry *ufp;
	uf_info_t *fip = P_FINFO(curproc);

	UF_ENTER(ufp, fip, fd);
	/*
	 * delfd_port is always done inside the getf/releasef pair.
	 */
	ASSERT(ufp->uf_refcnt >= 1);
	if (ufp->uf_portfd == pfd) {
		/* remove first entry */
		ufp->uf_portfd = pfd->pfd_next;
	} else {
		pfd->pfd_prev->pfd_next = pfd->pfd_next;
		if (pfd->pfd_next != NULL)
			pfd->pfd_next->pfd_prev = pfd->pfd_prev;
	}
	UF_EXIT(ufp);
}

static void
port_close_fd(portfd_t *pfd)
{
	portfd_t	*pfdn;

	/*
	 * At this point, no other thread should access
	 * the portfd_t list for this fd. The uf_file, uf_portfd
	 * pointers in the uf_entry_t struct for this fd would
	 * be set to NULL.
	 */
	for (; pfd != NULL; pfd = pfdn) {
		pfdn = pfd->pfd_next;
		port_close_pfd(pfd);
	}
}
