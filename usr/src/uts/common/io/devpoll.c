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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/devops.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/poll_impl.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/devpoll.h>
#include <sys/rctl.h>
#include <sys/resource.h>
#include <sys/schedctl.h>
#include <sys/epoll.h>

#define	RESERVED	1

/* local data struct */
static	dp_entry_t	**devpolltbl;	/* dev poll entries */
static	size_t		dptblsize;

static	kmutex_t	devpoll_lock;	/* lock protecting dev tbl */
int			devpoll_init;	/* is /dev/poll initialized already */

/* device local functions */

static int dpopen(dev_t *devp, int flag, int otyp, cred_t *credp);
static int dpwrite(dev_t dev, struct uio *uiop, cred_t *credp);
static int dpioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp);
static int dppoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp);
static int dpclose(dev_t dev, int flag, int otyp, cred_t *credp);
static dev_info_t *dpdevi;


static struct cb_ops    dp_cb_ops = {
	dpopen,			/* open */
	dpclose,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	dpwrite,		/* write */
	dpioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	dppoll,			/* poll */
	ddi_prop_op,		/* prop_op */
	(struct streamtab *)0,	/* streamtab */
	D_MP,			/* flags */
	CB_REV,			/* cb_ops revision */
	nodev,			/* aread */
	nodev			/* awrite */
};

static int dpattach(dev_info_t *, ddi_attach_cmd_t);
static int dpdetach(dev_info_t *, ddi_detach_cmd_t);
static int dpinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

static struct dev_ops dp_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	dpinfo,			/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	dpattach,		/* attach */
	dpdetach,		/* detach */
	nodev,			/* reset */
	&dp_cb_ops,		/* driver operations */
	(struct bus_ops *)NULL, /* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};


static struct modldrv modldrv = {
	&mod_driverops,		/* type of module - a driver */
	"/dev/poll driver",
	&dp_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * Locking Design
 *
 * The /dev/poll driver shares most of its code with poll sys call whose
 * code is in common/syscall/poll.c. In poll(2) design, the pollcache
 * structure is per lwp. An implicit assumption is made there that some
 * portion of pollcache will never be touched by other lwps. E.g., in
 * poll(2) design, no lwp will ever need to grow bitmap of other lwp.
 * This assumption is not true for /dev/poll; hence the need for extra
 * locking.
 *
 * To allow more parallelism, each /dev/poll file descriptor (indexed by
 * minor number) has its own lock. Since read (dpioctl) is a much more
 * frequent operation than write, we want to allow multiple reads on same
 * /dev/poll fd. However, we prevent writes from being starved by giving
 * priority to write operation. Theoretically writes can starve reads as
 * well. But in practical sense this is not important because (1) writes
 * happens less often than reads, and (2) write operation defines the
 * content of poll fd a cache set. If writes happens so often that they
 * can starve reads, that means the cached set is very unstable. It may
 * not make sense to read an unstable cache set anyway. Therefore, the
 * writers starving readers case is not handled in this design.
 */

int
_init()
{
	int	error;

	dptblsize = DEVPOLLSIZE;
	devpolltbl = kmem_zalloc(sizeof (caddr_t) * dptblsize, KM_SLEEP);
	mutex_init(&devpoll_lock, NULL, MUTEX_DEFAULT, NULL);
	devpoll_init = 1;
	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&devpoll_lock);
		kmem_free(devpolltbl, sizeof (caddr_t) * dptblsize);
		devpoll_init = 0;
	}
	return (error);
}

int
_fini()
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0) {
		return (error);
	}
	mutex_destroy(&devpoll_lock);
	kmem_free(devpolltbl, sizeof (caddr_t) * dptblsize);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
dpattach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (ddi_create_minor_node(devi, "poll", S_IFCHR, 0, DDI_PSEUDO, NULL)
	    == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	dpdevi = devi;
	return (DDI_SUCCESS);
}

static int
dpdetach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
dpinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)dpdevi;
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

/*
 * dp_pcache_poll has similar logic to pcache_poll() in poll.c. The major
 * differences are: (1) /dev/poll requires scanning the bitmap starting at
 * where it was stopped last time, instead of always starting from 0,
 * (2) since user may not have cleaned up the cached fds when they are
 * closed, some polldats in cache may refer to closed or reused fds. We
 * need to check for those cases.
 *
 * NOTE: Upon closing an fd, automatic poll cache cleanup is done for
 *	 poll(2) caches but NOT for /dev/poll caches. So expect some
 *	 stale entries!
 */
static int
dp_pcache_poll(dp_entry_t *dpep, void *dpbuf,
    pollcache_t *pcp, nfds_t nfds, int *fdcntp)
{
	int		start, ostart, end;
	int		fdcnt, fd;
	boolean_t	done;
	file_t		*fp;
	short		revent;
	boolean_t	no_wrap;
	pollhead_t	*php;
	polldat_t	*pdp;
	pollfd_t	*pfdp;
	epoll_event_t	*epoll;
	int		error = 0;
	short		mask = POLLRDHUP | POLLWRBAND;

	ASSERT(MUTEX_HELD(&pcp->pc_lock));
	if (pcp->pc_bitmap == NULL) {
		/*
		 * No Need to search because no poll fd
		 * has been cached.
		 */
		return (error);
	}

	if (dpep->dpe_flag & DP_ISEPOLLCOMPAT) {
		pfdp = NULL;
		epoll = (epoll_event_t *)dpbuf;
	} else {
		pfdp = (pollfd_t *)dpbuf;
		epoll = NULL;
	}
retry:
	start = ostart = pcp->pc_mapstart;
	end = pcp->pc_mapend;
	php = NULL;

	if (start == 0) {
		/*
		 * started from every begining, no need to wrap around.
		 */
		no_wrap = B_TRUE;
	} else {
		no_wrap = B_FALSE;
	}
	done = B_FALSE;
	fdcnt = 0;
	while ((fdcnt < nfds) && !done) {
		php = NULL;
		revent = 0;
		/*
		 * Examine the bit map in a circular fashion
		 * to avoid starvation. Always resume from
		 * last stop. Scan till end of the map. Then
		 * wrap around.
		 */
		fd = bt_getlowbit(pcp->pc_bitmap, start, end);
		ASSERT(fd <= end);
		if (fd >= 0) {
			if (fd == end) {
				if (no_wrap) {
					done = B_TRUE;
				} else {
					start = 0;
					end = ostart - 1;
					no_wrap = B_TRUE;
				}
			} else {
				start = fd + 1;
			}
			pdp = pcache_lookup_fd(pcp, fd);
repoll:
			ASSERT(pdp != NULL);
			ASSERT(pdp->pd_fd == fd);
			if (pdp->pd_fp == NULL) {
				/*
				 * The fd is POLLREMOVed. This fd is
				 * logically no longer cached. So move
				 * on to the next one.
				 */
				continue;
			}
			if ((fp = getf(fd)) == NULL) {
				/*
				 * The fd has been closed, but user has not
				 * done a POLLREMOVE on this fd yet. Instead
				 * of cleaning it here implicitly, we return
				 * POLLNVAL. This is consistent with poll(2)
				 * polling a closed fd. Hope this will remind
				 * user to do a POLLREMOVE.
				 */
				if (pfdp != NULL) {
					pfdp[fdcnt].fd = fd;
					pfdp[fdcnt].revents = POLLNVAL;
					fdcnt++;
					continue;
				}

				/*
				 * In the epoll compatibility case, we actually
				 * perform the implicit removal to remain
				 * closer to the epoll semantics.
				 */
				ASSERT(epoll != NULL);

				pdp->pd_fp = NULL;
				pdp->pd_events = 0;

				if (php != NULL) {
					pollhead_delete(php, pdp);
					pdp->pd_php = NULL;
				}

				BT_CLEAR(pcp->pc_bitmap, fd);
				continue;
			}

			if (fp != pdp->pd_fp) {
				/*
				 * user is polling on a cached fd which was
				 * closed and then reused. Unfortunately
				 * there is no good way to inform user.
				 * If the file struct is also reused, we
				 * may not be able to detect the fd reuse
				 * at all.  As long as this does not
				 * cause system failure and/or memory leak,
				 * we will play along. Man page states if
				 * user does not clean up closed fds, polling
				 * results will be indeterministic.
				 *
				 * XXX - perhaps log the detection of fd
				 *	 reuse?
				 */
				pdp->pd_fp = fp;
			}
			/*
			 * XXX - pollrelock() logic needs to know which
			 * which pollcache lock to grab. It'd be a
			 * cleaner solution if we could pass pcp as
			 * an arguement in VOP_POLL interface instead
			 * of implicitly passing it using thread_t
			 * struct. On the other hand, changing VOP_POLL
			 * interface will require all driver/file system
			 * poll routine to change. May want to revisit
			 * the tradeoff later.
			 */
			curthread->t_pollcache = pcp;
			error = VOP_POLL(fp->f_vnode, pdp->pd_events, 0,
			    &revent, &php, NULL);
			curthread->t_pollcache = NULL;
			releasef(fd);
			if (error != 0) {
				break;
			}
			/*
			 * layered devices (e.g. console driver)
			 * may change the vnode and thus the pollhead
			 * pointer out from underneath us.
			 */
			if (php != NULL && pdp->pd_php != NULL &&
			    php != pdp->pd_php) {
				pollhead_delete(pdp->pd_php, pdp);
				pdp->pd_php = php;
				pollhead_insert(php, pdp);
				/*
				 * The bit should still be set.
				 */
				ASSERT(BT_TEST(pcp->pc_bitmap, fd));
				goto retry;
			}

			if (revent != 0) {
				if (pfdp != NULL) {
					pfdp[fdcnt].fd = fd;
					pfdp[fdcnt].events = pdp->pd_events;
					pfdp[fdcnt].revents = revent;
				} else {
					epoll_event_t *ep = &epoll[fdcnt];

					ASSERT(epoll != NULL);
					ep->data.u64 = pdp->pd_epolldata;

					/*
					 * If any of the event bits are set for
					 * which poll and epoll representations
					 * differ, swizzle in the native epoll
					 * values.
					 */
					if (revent & mask) {
						ep->events = (revent & ~mask) |
						    ((revent & POLLRDHUP) ?
						    EPOLLRDHUP : 0) |
						    ((revent & POLLWRBAND) ?
						    EPOLLWRBAND : 0);
					} else {
						ep->events = revent;
					}

					/*
					 * We define POLLWRNORM to be POLLOUT,
					 * but epoll has separate definitions
					 * for them; if POLLOUT is set and the
					 * user has asked for EPOLLWRNORM, set
					 * that as well.
					 */
					if ((revent & POLLOUT) &&
					    (pdp->pd_events & EPOLLWRNORM)) {
						ep->events |= EPOLLWRNORM;
					}
				}

				/*
				 * If POLLET is set, clear the bit in the
				 * bitmap -- which effectively latches the
				 * edge on a pollwakeup() from the driver.
				 */
				if (pdp->pd_events & POLLET)
					BT_CLEAR(pcp->pc_bitmap, fd);

				/*
				 * If POLLONESHOT is set, perform the implicit
				 * POLLREMOVE.
				 */
				if (pdp->pd_events & POLLONESHOT) {
					pdp->pd_fp = NULL;
					pdp->pd_events = 0;

					if (php != NULL) {
						pollhead_delete(php, pdp);
						pdp->pd_php = NULL;
					}

					BT_CLEAR(pcp->pc_bitmap, fd);
				}

				fdcnt++;
			} else if (php != NULL) {
				/*
				 * We clear a bit or cache a poll fd if
				 * the driver returns a poll head ptr,
				 * which is expected in the case of 0
				 * revents. Some buggy driver may return
				 * NULL php pointer with 0 revents. In
				 * this case, we just treat the driver as
				 * "noncachable" and not clearing the bit
				 * in bitmap.
				 */
				if ((pdp->pd_php != NULL) &&
				    ((pcp->pc_flag & PC_POLLWAKE) == 0)) {
					BT_CLEAR(pcp->pc_bitmap, fd);
				}
				if (pdp->pd_php == NULL) {
					pollhead_insert(php, pdp);
					pdp->pd_php = php;
					/*
					 * An event of interest may have
					 * arrived between the VOP_POLL() and
					 * the pollhead_insert(); check again.
					 */
					goto repoll;
				}
			}
		} else {
			/*
			 * No bit set in the range. Check for wrap around.
			 */
			if (!no_wrap) {
				start = 0;
				end = ostart - 1;
				no_wrap = B_TRUE;
			} else {
				done = B_TRUE;
			}
		}
	}

	if (!done) {
		pcp->pc_mapstart = start;
	}
	ASSERT(*fdcntp == 0);
	*fdcntp = fdcnt;
	return (error);
}

/*ARGSUSED*/
static int
dpopen(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t		minordev;
	dp_entry_t	*dpep;
	pollcache_t	*pcp;

	ASSERT(devpoll_init);
	ASSERT(dptblsize <= MAXMIN);
	mutex_enter(&devpoll_lock);
	for (minordev = 0; minordev < dptblsize; minordev++) {
		if (devpolltbl[minordev] == NULL) {
			devpolltbl[minordev] = (dp_entry_t *)RESERVED;
			break;
		}
	}
	if (minordev == dptblsize) {
		dp_entry_t	**newtbl;
		size_t		oldsize;

		/*
		 * Used up every entry in the existing devpoll table.
		 * Grow the table by DEVPOLLSIZE.
		 */
		if ((oldsize = dptblsize) >= MAXMIN) {
			mutex_exit(&devpoll_lock);
			return (ENXIO);
		}
		dptblsize += DEVPOLLSIZE;
		if (dptblsize > MAXMIN) {
			dptblsize = MAXMIN;
		}
		newtbl = kmem_zalloc(sizeof (caddr_t) * dptblsize, KM_SLEEP);
		bcopy(devpolltbl, newtbl, sizeof (caddr_t) * oldsize);
		kmem_free(devpolltbl, sizeof (caddr_t) * oldsize);
		devpolltbl = newtbl;
		devpolltbl[minordev] = (dp_entry_t *)RESERVED;
	}
	mutex_exit(&devpoll_lock);

	dpep = kmem_zalloc(sizeof (dp_entry_t), KM_SLEEP);
	/*
	 * allocate a pollcache skeleton here. Delay allocating bitmap
	 * structures until dpwrite() time, since we don't know the
	 * optimal size yet.  We also delay setting the pid until either
	 * dpwrite() or attempt to poll on the instance, allowing parents
	 * to create instances of /dev/poll for their children.  (In the
	 * epoll compatibility case, this check isn't performed to maintain
	 * semantic compatibility.)
	 */
	pcp = pcache_alloc();
	dpep->dpe_pcache = pcp;
	pcp->pc_pid = -1;
	*devp = makedevice(getmajor(*devp), minordev);  /* clone the driver */
	mutex_enter(&devpoll_lock);
	ASSERT(minordev < dptblsize);
	ASSERT(devpolltbl[minordev] == (dp_entry_t *)RESERVED);
	devpolltbl[minordev] = dpep;
	mutex_exit(&devpoll_lock);
	return (0);
}

/*
 * Write to dev/poll add/remove fd's to/from a cached poll fd set,
 * or change poll events for a watched fd.
 */
/*ARGSUSED*/
static int
dpwrite(dev_t dev, struct uio *uiop, cred_t *credp)
{
	minor_t		minor;
	dp_entry_t	*dpep;
	pollcache_t	*pcp;
	pollfd_t	*pollfdp, *pfdp;
	dvpoll_epollfd_t *epfdp;
	uintptr_t	limit;
	int		error, size;
	ssize_t		uiosize;
	nfds_t		pollfdnum;
	struct pollhead	*php = NULL;
	polldat_t	*pdp;
	int		fd;
	file_t		*fp;

	minor = getminor(dev);

	mutex_enter(&devpoll_lock);
	ASSERT(minor < dptblsize);
	dpep = devpolltbl[minor];
	ASSERT(dpep != NULL);
	mutex_exit(&devpoll_lock);
	pcp = dpep->dpe_pcache;

	if (!(dpep->dpe_flag & DP_ISEPOLLCOMPAT) &&
	    curproc->p_pid != pcp->pc_pid) {
		if (pcp->pc_pid != -1)
			return (EACCES);

		pcp->pc_pid = curproc->p_pid;
	}

	if (dpep->dpe_flag & DP_ISEPOLLCOMPAT) {
		size = sizeof (dvpoll_epollfd_t);
	} else {
		size = sizeof (pollfd_t);
	}

	uiosize = uiop->uio_resid;
	pollfdnum = uiosize / size;
	mutex_enter(&curproc->p_lock);
	if (pollfdnum > (uint_t)rctl_enforced_value(
	    rctlproc_legacy[RLIMIT_NOFILE], curproc->p_rctls, curproc)) {
		(void) rctl_action(rctlproc_legacy[RLIMIT_NOFILE],
		    curproc->p_rctls, curproc, RCA_SAFE);
		mutex_exit(&curproc->p_lock);
		return (set_errno(EINVAL));
	}
	mutex_exit(&curproc->p_lock);
	/*
	 * Copy in the pollfd array.  Walk through the array and add
	 * each polled fd to the cached set.
	 */
	pollfdp = kmem_alloc(uiosize, KM_SLEEP);
	limit = (uintptr_t)pollfdp + (pollfdnum * size);

	/*
	 * Although /dev/poll uses the write(2) interface to cache fds, it's
	 * not supposed to function as a seekable device. To prevent offset
	 * from growing and eventually exceed the maximum, reset the offset
	 * here for every call.
	 */
	uiop->uio_loffset = 0;
	if ((error = uiomove((caddr_t)pollfdp, uiosize, UIO_WRITE, uiop))
	    != 0) {
		kmem_free(pollfdp, uiosize);
		return (error);
	}
	/*
	 * We are about to enter the core portion of dpwrite(). Make sure this
	 * write has exclusive access in this portion of the code, i.e., no
	 * other writers in this code and no other readers in dpioctl.
	 */
	mutex_enter(&dpep->dpe_lock);
	dpep->dpe_writerwait++;
	while (dpep->dpe_refcnt != 0) {
		/*
		 * We need to do a bit of a dance here:  we need to drop
		 * our dpe_lock and grab the pc_lock to broadcast the pc_cv to
		 * kick any DP_POLL/DP_PPOLL sleepers.
		 */
		mutex_exit(&dpep->dpe_lock);
		mutex_enter(&pcp->pc_lock);
		pcp->pc_flag |= PC_WRITEWANTED;
		cv_broadcast(&pcp->pc_cv);
		mutex_exit(&pcp->pc_lock);
		mutex_enter(&dpep->dpe_lock);

		if (dpep->dpe_refcnt == 0)
			break;

		if (!cv_wait_sig_swap(&dpep->dpe_cv, &dpep->dpe_lock)) {
			dpep->dpe_writerwait--;
			mutex_exit(&dpep->dpe_lock);
			mutex_enter(&pcp->pc_lock);
			pcp->pc_flag &= ~PC_WRITEWANTED;
			mutex_exit(&pcp->pc_lock);
			kmem_free(pollfdp, uiosize);
			return (set_errno(EINTR));
		}
	}
	dpep->dpe_writerwait--;
	dpep->dpe_flag |= DP_WRITER_PRESENT;
	dpep->dpe_refcnt++;

	mutex_exit(&dpep->dpe_lock);

	mutex_enter(&pcp->pc_lock);
	pcp->pc_flag &= ~PC_WRITEWANTED;

	if (pcp->pc_bitmap == NULL) {
		pcache_create(pcp, pollfdnum);
	}
	for (pfdp = pollfdp; (uintptr_t)pfdp < limit;
	    pfdp = (pollfd_t *)((uintptr_t)pfdp + size)) {
		fd = pfdp->fd;
		if ((uint_t)fd >= P_FINFO(curproc)->fi_nfiles)
			continue;
		pdp = pcache_lookup_fd(pcp, fd);
		if (pfdp->events != POLLREMOVE) {
			if (pdp == NULL) {
				pdp = pcache_alloc_fd(0);
				pdp->pd_fd = fd;

				if (dpep->dpe_flag & DP_ISEPOLLCOMPAT) {
					/* LINTED pointer alignment */
					epfdp = (dvpoll_epollfd_t *)pfdp;
					pdp->pd_epolldata = epfdp->dpep_data;
				}

				pdp->pd_pcache = pcp;
				pcache_insert_fd(pcp, pdp, pollfdnum);
			} else {
				if ((dpep->dpe_flag & DP_ISEPOLLCOMPAT) &&
				    pdp->pd_fp != NULL) {
					/*
					 * epoll semantics demand that we error
					 * out in this case.
					 */
					error = EEXIST;
					break;
				}
			}

			ASSERT(pdp->pd_fd == fd);
			ASSERT(pdp->pd_pcache == pcp);
			if (fd >= pcp->pc_mapsize) {
				mutex_exit(&pcp->pc_lock);
				pcache_grow_map(pcp, fd);
				mutex_enter(&pcp->pc_lock);
			}
			if (fd > pcp->pc_mapend) {
				pcp->pc_mapend = fd;
			}
			if ((fp = getf(fd)) == NULL) {
				/*
				 * The fd is not valid. Since we can't pass
				 * this error back in the write() call, set
				 * the bit in bitmap to force DP_POLL ioctl
				 * to examine it.
				 */
				BT_SET(pcp->pc_bitmap, fd);
				pdp->pd_events |= pfdp->events;
				continue;
			}
			/*
			 * Don't do VOP_POLL for an already cached fd with
			 * same poll events.
			 */
			if ((pdp->pd_events == pfdp->events) &&
			    (pdp->pd_fp != NULL)) {
				/*
				 * the events are already cached
				 */
				releasef(fd);
				continue;
			}

			/*
			 * do VOP_POLL and cache this poll fd.
			 */
			/*
			 * XXX - pollrelock() logic needs to know which
			 * which pollcache lock to grab. It'd be a
			 * cleaner solution if we could pass pcp as
			 * an arguement in VOP_POLL interface instead
			 * of implicitly passing it using thread_t
			 * struct. On the other hand, changing VOP_POLL
			 * interface will require all driver/file system
			 * poll routine to change. May want to revisit
			 * the tradeoff later.
			 */
			curthread->t_pollcache = pcp;
			error = VOP_POLL(fp->f_vnode, pfdp->events, 0,
			    &pfdp->revents, &php, NULL);
			curthread->t_pollcache = NULL;
			/*
			 * We always set the bit when this fd is cached;
			 * this forces the first DP_POLL to poll this fd.
			 * Real performance gain comes from subsequent
			 * DP_POLL.  We also attempt a pollhead_insert();
			 * if it's not possible, we'll do it in dpioctl().
			 */
			BT_SET(pcp->pc_bitmap, fd);
			if (error != 0) {
				releasef(fd);
				break;
			}
			pdp->pd_fp = fp;
			pdp->pd_events |= pfdp->events;
			if (php != NULL) {
				if (pdp->pd_php == NULL) {
					pollhead_insert(php, pdp);
					pdp->pd_php = php;
				} else {
					if (pdp->pd_php != php) {
						pollhead_delete(pdp->pd_php,
						    pdp);
						pollhead_insert(php, pdp);
						pdp->pd_php = php;
					}
				}

			}
			releasef(fd);
		} else {
			if (pdp == NULL || pdp->pd_fp == NULL) {
				if (dpep->dpe_flag & DP_ISEPOLLCOMPAT) {
					/*
					 * As with the add case (above), epoll
					 * semantics demand that we error out
					 * in this case.
					 */
					error = ENOENT;
					break;
				}

				continue;
			}
			ASSERT(pdp->pd_fd == fd);
			pdp->pd_fp = NULL;
			pdp->pd_events = 0;
			ASSERT(pdp->pd_thread == NULL);
			if (pdp->pd_php != NULL) {
				pollhead_delete(pdp->pd_php, pdp);
				pdp->pd_php = NULL;
			}
			BT_CLEAR(pcp->pc_bitmap, fd);
		}
	}
	mutex_exit(&pcp->pc_lock);
	mutex_enter(&dpep->dpe_lock);
	dpep->dpe_flag &= ~DP_WRITER_PRESENT;
	ASSERT(dpep->dpe_refcnt == 1);
	dpep->dpe_refcnt--;
	cv_broadcast(&dpep->dpe_cv);
	mutex_exit(&dpep->dpe_lock);
	kmem_free(pollfdp, uiosize);
	return (error);
}

#define	DP_SIGMASK_RESTORE(ksetp) {					\
	if (ksetp != NULL) {						\
		mutex_enter(&p->p_lock);				\
		if (lwp->lwp_cursig == 0) {				\
			t->t_hold = lwp->lwp_sigoldmask;		\
			t->t_flag &= ~T_TOMASK;				\
		}							\
		mutex_exit(&p->p_lock);					\
	}								\
}

/*ARGSUSED*/
static int
dpioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	minor_t		minor;
	dp_entry_t	*dpep;
	pollcache_t	*pcp;
	hrtime_t	now;
	int		error = 0;
	STRUCT_DECL(dvpoll, dvpoll);

	if (cmd == DP_POLL || cmd == DP_PPOLL) {
		/* do this now, before we sleep on DP_WRITER_PRESENT */
		now = gethrtime();
	}

	minor = getminor(dev);
	mutex_enter(&devpoll_lock);
	ASSERT(minor < dptblsize);
	dpep = devpolltbl[minor];
	mutex_exit(&devpoll_lock);
	ASSERT(dpep != NULL);
	pcp = dpep->dpe_pcache;

	mutex_enter(&dpep->dpe_lock);

	if (cmd == DP_EPOLLCOMPAT) {
		if (dpep->dpe_refcnt != 0) {
			/*
			 * We can't turn on epoll compatibility while there
			 * are outstanding operations.
			 */
			mutex_exit(&dpep->dpe_lock);
			return (EBUSY);
		}

		/*
		 * epoll compatibility is a one-way street: there's no way
		 * to turn it off for a particular open.
		 */
		dpep->dpe_flag |= DP_ISEPOLLCOMPAT;
		mutex_exit(&dpep->dpe_lock);

		return (0);
	}

	if (!(dpep->dpe_flag & DP_ISEPOLLCOMPAT) &&
	    curproc->p_pid != pcp->pc_pid) {
		if (pcp->pc_pid != -1)
			return (EACCES);

		pcp->pc_pid = curproc->p_pid;
	}

	while ((dpep->dpe_flag & DP_WRITER_PRESENT) ||
	    (dpep->dpe_writerwait != 0)) {
		if (!cv_wait_sig_swap(&dpep->dpe_cv, &dpep->dpe_lock)) {
			mutex_exit(&dpep->dpe_lock);
			return (EINTR);
		}
	}
	dpep->dpe_refcnt++;
	mutex_exit(&dpep->dpe_lock);

	switch (cmd) {
	case	DP_POLL:
	case	DP_PPOLL:
	{
		pollstate_t	*ps;
		nfds_t		nfds;
		int		fdcnt = 0;
		size_t		size, fdsize, dpsize;
		hrtime_t	deadline = 0;
		k_sigset_t	*ksetp = NULL;
		k_sigset_t	kset;
		sigset_t	set;
		kthread_t	*t = curthread;
		klwp_t		*lwp = ttolwp(t);
		struct proc	*p = ttoproc(curthread);

		STRUCT_INIT(dvpoll, mode);

		/*
		 * The dp_setp member is only required/consumed for DP_PPOLL,
		 * which otherwise uses the same structure as DP_POLL.
		 */
		if (cmd == DP_POLL) {
			dpsize = (uintptr_t)STRUCT_FADDR(dvpoll, dp_setp) -
			    (uintptr_t)STRUCT_FADDR(dvpoll, dp_fds);
		} else {
			ASSERT(cmd == DP_PPOLL);
			dpsize = STRUCT_SIZE(dvpoll);
		}

		error = copyin((caddr_t)arg, STRUCT_BUF(dvpoll), dpsize);

		if (error) {
			DP_REFRELE(dpep);
			return (EFAULT);
		}

		deadline = STRUCT_FGET(dvpoll, dp_timeout);
		if (deadline > 0) {
			/*
			 * Convert the deadline from relative milliseconds
			 * to absolute nanoseconds.  They must wait for at
			 * least a tick.
			 */
			deadline = MSEC2NSEC(deadline);
			deadline = MAX(deadline, nsec_per_tick);
			deadline += now;
		}

		if (cmd == DP_PPOLL) {
			void *setp = STRUCT_FGETP(dvpoll, dp_setp);

			if (setp != NULL) {
				if (copyin(setp, &set, sizeof (set))) {
					DP_REFRELE(dpep);
					return (EFAULT);
				}

				sigutok(&set, &kset);
				ksetp = &kset;

				mutex_enter(&p->p_lock);
				schedctl_finish_sigblock(t);
				lwp->lwp_sigoldmask = t->t_hold;
				t->t_hold = *ksetp;
				t->t_flag |= T_TOMASK;

				/*
				 * Like ppoll() with a non-NULL sigset, we'll
				 * call cv_reltimedwait_sig() just to check for
				 * signals.  This call will return immediately
				 * with either 0 (signalled) or -1 (no signal).
				 * There are some conditions whereby we can
				 * get 0 from cv_reltimedwait_sig() without
				 * a true signal (e.g., a directed stop), so
				 * we restore our signal mask in the unlikely
				 * event that lwp_cursig is 0.
				 */
				if (!cv_reltimedwait_sig(&t->t_delay_cv,
				    &p->p_lock, 0, TR_CLOCK_TICK)) {
					if (lwp->lwp_cursig == 0) {
						t->t_hold = lwp->lwp_sigoldmask;
						t->t_flag &= ~T_TOMASK;
					}

					mutex_exit(&p->p_lock);

					DP_REFRELE(dpep);
					return (EINTR);
				}

				mutex_exit(&p->p_lock);
			}
		}

		if ((nfds = STRUCT_FGET(dvpoll, dp_nfds)) == 0) {
			/*
			 * We are just using DP_POLL to sleep, so
			 * we don't any of the devpoll apparatus.
			 * Do not check for signals if we have a zero timeout.
			 */
			DP_REFRELE(dpep);
			if (deadline == 0) {
				DP_SIGMASK_RESTORE(ksetp);
				return (0);
			}

			mutex_enter(&curthread->t_delay_lock);
			while ((error =
			    cv_timedwait_sig_hrtime(&curthread->t_delay_cv,
			    &curthread->t_delay_lock, deadline)) > 0)
				continue;
			mutex_exit(&curthread->t_delay_lock);

			DP_SIGMASK_RESTORE(ksetp);

			return (error == 0 ? EINTR : 0);
		}

		if (dpep->dpe_flag & DP_ISEPOLLCOMPAT) {
			size = nfds * (fdsize = sizeof (epoll_event_t));
		} else {
			size = nfds * (fdsize = sizeof (pollfd_t));
		}

		/*
		 * XXX It would be nice not to have to alloc each time, but it
		 * requires another per thread structure hook. This can be
		 * implemented later if data suggests that it's necessary.
		 */
		if ((ps = curthread->t_pollstate) == NULL) {
			curthread->t_pollstate = pollstate_create();
			ps = curthread->t_pollstate;
		}
		if (ps->ps_dpbufsize < size) {
			/*
			 * The maximum size should be no large than
			 * current maximum open file count.
			 */
			mutex_enter(&p->p_lock);
			if (nfds > p->p_fno_ctl) {
				mutex_exit(&p->p_lock);
				DP_REFRELE(dpep);
				DP_SIGMASK_RESTORE(ksetp);
				return (EINVAL);
			}
			mutex_exit(&p->p_lock);
			kmem_free(ps->ps_dpbuf, ps->ps_dpbufsize);
			ps->ps_dpbuf = kmem_zalloc(size, KM_SLEEP);
			ps->ps_dpbufsize = size;
		}

		mutex_enter(&pcp->pc_lock);
		for (;;) {
			pcp->pc_flag &= ~PC_POLLWAKE;

			error = dp_pcache_poll(dpep, ps->ps_dpbuf,
			    pcp, nfds, &fdcnt);
			if (fdcnt > 0 || error != 0)
				break;

			/*
			 * A pollwake has happened since we polled cache.
			 */
			if (pcp->pc_flag & PC_POLLWAKE)
				continue;

			/*
			 * Sleep until we are notified, signaled, or timed out.
			 */
			if (deadline == 0) {
				/* immediate timeout; do not check signals */
				break;
			}

			if (!(pcp->pc_flag & PC_WRITEWANTED)) {
				error = cv_timedwait_sig_hrtime(&pcp->pc_cv,
				    &pcp->pc_lock, deadline);
			} else {
				error = 1;
			}

			if (error > 0 && (pcp->pc_flag & PC_WRITEWANTED)) {
				/*
				 * We've been kicked off of our cv because a
				 * writer wants in.  We're going to drop our
				 * reference count and then wait until the
				 * writer is gone -- at which point we'll
				 * reacquire the pc_lock and call into
				 * dp_pcache_poll() to get the updated state.
				 */
				mutex_exit(&pcp->pc_lock);

				mutex_enter(&dpep->dpe_lock);
				dpep->dpe_refcnt--;
				cv_broadcast(&dpep->dpe_cv);

				while ((dpep->dpe_flag & DP_WRITER_PRESENT) ||
				    (dpep->dpe_writerwait != 0)) {
					error = cv_wait_sig_swap(&dpep->dpe_cv,
					    &dpep->dpe_lock);
				}

				dpep->dpe_refcnt++;
				mutex_exit(&dpep->dpe_lock);
				mutex_enter(&pcp->pc_lock);
			}

			/*
			 * If we were awakened by a signal or timeout
			 * then break the loop, else poll again.
			 */
			if (error <= 0) {
				error = (error == 0) ? EINTR : 0;
				break;
			} else {
				error = 0;
			}
		}
		mutex_exit(&pcp->pc_lock);

		DP_SIGMASK_RESTORE(ksetp);

		if (error == 0 && fdcnt > 0) {
			if (copyout(ps->ps_dpbuf,
			    STRUCT_FGETP(dvpoll, dp_fds), fdcnt * fdsize)) {
				DP_REFRELE(dpep);
				return (EFAULT);
			}
			*rvalp = fdcnt;
		}
		break;
	}

	case	DP_ISPOLLED:
	{
		pollfd_t	pollfd;
		polldat_t	*pdp;

		STRUCT_INIT(dvpoll, mode);
		error = copyin((caddr_t)arg, &pollfd, sizeof (pollfd_t));
		if (error) {
			DP_REFRELE(dpep);
			return (EFAULT);
		}
		mutex_enter(&pcp->pc_lock);
		if (pcp->pc_hash == NULL) {
			/*
			 * No Need to search because no poll fd
			 * has been cached.
			 */
			mutex_exit(&pcp->pc_lock);
			DP_REFRELE(dpep);
			return (0);
		}
		if (pollfd.fd < 0) {
			mutex_exit(&pcp->pc_lock);
			break;
		}
		pdp = pcache_lookup_fd(pcp, pollfd.fd);
		if ((pdp != NULL) && (pdp->pd_fd == pollfd.fd) &&
		    (pdp->pd_fp != NULL)) {
			pollfd.revents = pdp->pd_events;
			if (copyout(&pollfd, (caddr_t)arg, sizeof (pollfd_t))) {
				mutex_exit(&pcp->pc_lock);
				DP_REFRELE(dpep);
				return (EFAULT);
			}
			*rvalp = 1;
		}
		mutex_exit(&pcp->pc_lock);
		break;
	}

	default:
		DP_REFRELE(dpep);
		return (EINVAL);
	}
	DP_REFRELE(dpep);
	return (error);
}

/*ARGSUSED*/
static int
dppoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	minor_t		minor;
	dp_entry_t	*dpep;

	minor = getminor(dev);

	mutex_enter(&devpoll_lock);
	dpep = devpolltbl[minor];
	ASSERT(dpep != NULL);
	mutex_exit(&devpoll_lock);

	/*
	 * Polling on a /dev/poll fd is not fully supported yet.
	 */
	if (dpep->dpe_flag & DP_ISEPOLLCOMPAT) {
		/* no error in epoll compat. mode */
		*reventsp = 0;
	} else {
		*reventsp = POLLERR;
	}
	return (0);
}

/*
 * devpoll close should do enough clean up before the pollcache is deleted,
 * i.e., it should ensure no one still references the pollcache later.
 * There is no "permission" check in here. Any process having the last
 * reference of this /dev/poll fd can close.
 */
/*ARGSUSED*/
static int
dpclose(dev_t dev, int flag, int otyp, cred_t *credp)
{
	minor_t		minor;
	dp_entry_t	*dpep;
	pollcache_t	*pcp;
	int		i;
	polldat_t	**hashtbl;
	polldat_t	*pdp;

	minor = getminor(dev);

	mutex_enter(&devpoll_lock);
	dpep = devpolltbl[minor];
	ASSERT(dpep != NULL);
	devpolltbl[minor] = NULL;
	mutex_exit(&devpoll_lock);
	pcp = dpep->dpe_pcache;
	ASSERT(pcp != NULL);
	/*
	 * At this point, no other lwp can access this pollcache via the
	 * /dev/poll fd. This pollcache is going away, so do the clean
	 * up without the pc_lock.
	 */
	hashtbl = pcp->pc_hash;
	for (i = 0; i < pcp->pc_hashsize; i++) {
		for (pdp = hashtbl[i]; pdp; pdp = pdp->pd_hashnext) {
			if (pdp->pd_php != NULL) {
				pollhead_delete(pdp->pd_php, pdp);
				pdp->pd_php = NULL;
				pdp->pd_fp = NULL;
			}
		}
	}
	/*
	 * pollwakeup() may still interact with this pollcache. Wait until
	 * it is done.
	 */
	mutex_enter(&pcp->pc_no_exit);
	ASSERT(pcp->pc_busy >= 0);
	while (pcp->pc_busy > 0)
		cv_wait(&pcp->pc_busy_cv, &pcp->pc_no_exit);
	mutex_exit(&pcp->pc_no_exit);
	pcache_destroy(pcp);
	ASSERT(dpep->dpe_refcnt == 0);
	kmem_free(dpep, sizeof (dp_entry_t));
	return (0);
}
