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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <vm/as.h>
#include <vm/page.h>

#include <sys/dcopy.h>

int64_t uioa_maxpoll = -1;	/* <0 = noblock, 0 = block, >0 = block after */
#define	UIO_DCOPY_CHANNEL	0
#define	UIO_DCOPY_CMD		1

/*
 * Move "n" bytes at byte address "p"; "rw" indicates the direction
 * of the move, and the I/O parameters are provided in "uio", which is
 * update to reflect the data which was moved.  Returns 0 on success or
 * a non-zero errno on failure.
 */
int
uiomove(void *p, size_t n, enum uio_rw rw, struct uio *uio)
{
	struct iovec *iov;
	ulong_t cnt;
	int error;

	while (n && uio->uio_resid) {
		iov = uio->uio_iov;
		cnt = MIN(iov->iov_len, n);
		if (cnt == 0l) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		switch (uio->uio_segflg) {

		case UIO_USERSPACE:
		case UIO_USERISPACE:
			if (rw == UIO_READ) {
				error = xcopyout_nta(p, iov->iov_base, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			} else {
				error = xcopyin_nta(iov->iov_base, p, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			}

			if (error)
				return (error);
			break;

		case UIO_SYSSPACE:
			if (rw == UIO_READ)
				error = kcopy_nta(p, iov->iov_base, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			else
				error = kcopy_nta(iov->iov_base, p, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			if (error)
				return (error);
			break;
		}
		iov->iov_base += cnt;
		iov->iov_len -= cnt;
		uio->uio_resid -= cnt;
		uio->uio_loffset += cnt;
		p = (caddr_t)p + cnt;
		n -= cnt;
	}
	return (0);
}

/*
 * Fault in the pages of the first n bytes specified by the uio structure.
 * 1 byte in each page is touched and the uio struct is unmodified. Any
 * error will terminate the process as this is only a best attempt to get
 * the pages resident.
 */
void
uio_prefaultpages(ssize_t n, struct uio *uio)
{
	struct iovec *iov;
	ulong_t cnt, incr;
	caddr_t p;
	uint8_t tmp;
	int iovcnt;

	iov = uio->uio_iov;
	iovcnt = uio->uio_iovcnt;

	while ((n > 0) && (iovcnt > 0)) {
		cnt = MIN(iov->iov_len, n);
		if (cnt == 0) {
			/* empty iov entry */
			iov++;
			iovcnt--;
			continue;
		}
		n -= cnt;
		/*
		 * touch each page in this segment.
		 */
		p = iov->iov_base;
		while (cnt) {
			switch (uio->uio_segflg) {
			case UIO_USERSPACE:
			case UIO_USERISPACE:
				if (fuword8(p, &tmp))
					return;
				break;
			case UIO_SYSSPACE:
				if (kcopy(p, &tmp, 1))
					return;
				break;
			}
			incr = MIN(cnt, PAGESIZE);
			p += incr;
			cnt -= incr;
		}
		/*
		 * touch the last byte in case it straddles a page.
		 */
		p--;
		switch (uio->uio_segflg) {
		case UIO_USERSPACE:
		case UIO_USERISPACE:
			if (fuword8(p, &tmp))
				return;
			break;
		case UIO_SYSSPACE:
			if (kcopy(p, &tmp, 1))
				return;
			break;
		}
		iov++;
		iovcnt--;
	}
}

/*
 * same as uiomove() but doesn't modify uio structure.
 * return in cbytes how many bytes were copied.
 */
int
uiocopy(void *p, size_t n, enum uio_rw rw, struct uio *uio, size_t *cbytes)
{
	struct iovec *iov;
	ulong_t cnt;
	int error;
	int iovcnt;

	iovcnt = uio->uio_iovcnt;
	*cbytes = 0;

	for (iov = uio->uio_iov; n && iovcnt; iov++, iovcnt--) {
		cnt = MIN(iov->iov_len, n);
		if (cnt == 0)
			continue;

		switch (uio->uio_segflg) {

		case UIO_USERSPACE:
		case UIO_USERISPACE:
			if (rw == UIO_READ) {
				error = xcopyout_nta(p, iov->iov_base, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			} else {
				error = xcopyin_nta(iov->iov_base, p, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			}

			if (error)
				return (error);
			break;

		case UIO_SYSSPACE:
			if (rw == UIO_READ)
				error = kcopy_nta(p, iov->iov_base, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			else
				error = kcopy_nta(iov->iov_base, p, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			if (error)
				return (error);
			break;
		}
		p = (caddr_t)p + cnt;
		n -= cnt;
		*cbytes += cnt;
	}
	return (0);
}

/*
 * transfer a character value into the address space
 * delineated by a uio and update fields within the
 * uio for next character. Return 0 for success, EFAULT
 * for error.
 */
int
ureadc(int val, struct uio *uiop)
{
	struct iovec *iovp;
	unsigned char c;

	/*
	 * first determine if uio is valid.  uiop should be
	 * non-NULL and the resid count > 0.
	 */
	if (!(uiop && uiop->uio_resid > 0))
		return (EFAULT);

	/*
	 * scan through iovecs until one is found that is non-empty.
	 * Return EFAULT if none found.
	 */
	while (uiop->uio_iovcnt > 0) {
		iovp = uiop->uio_iov;
		if (iovp->iov_len <= 0) {
			uiop->uio_iovcnt--;
			uiop->uio_iov++;
		} else
			break;
	}

	if (uiop->uio_iovcnt <= 0)
		return (EFAULT);

	/*
	 * Transfer character to uio space.
	 */

	c = (unsigned char) (val & 0xFF);

	switch (uiop->uio_segflg) {

	case UIO_USERISPACE:
	case UIO_USERSPACE:
		if (copyout(&c, iovp->iov_base, sizeof (unsigned char)))
			return (EFAULT);
		break;

	case UIO_SYSSPACE: /* can do direct copy since kernel-kernel */
		*iovp->iov_base = c;
		break;

	default:
		return (EFAULT); /* invalid segflg value */
	}

	/*
	 * bump up/down iovec and uio members to reflect transfer.
	 */
	iovp->iov_base++;
	iovp->iov_len--;
	uiop->uio_resid--;
	uiop->uio_loffset++;
	return (0); /* success */
}

/*
 * return a character value from the address space
 * delineated by a uio and update fields within the
 * uio for next character. Return the character for success,
 * -1 for error.
 */
int
uwritec(struct uio *uiop)
{
	struct iovec *iovp;
	unsigned char c;

	/*
	 * verify we were passed a valid uio structure.
	 * (1) non-NULL uiop, (2) positive resid count
	 * (3) there is an iovec with positive length
	 */

	if (!(uiop && uiop->uio_resid > 0))
		return (-1);

	while (uiop->uio_iovcnt > 0) {
		iovp = uiop->uio_iov;
		if (iovp->iov_len <= 0) {
			uiop->uio_iovcnt--;
			uiop->uio_iov++;
		} else
			break;
	}

	if (uiop->uio_iovcnt <= 0)
		return (-1);

	/*
	 * Get the character from the uio address space.
	 */
	switch (uiop->uio_segflg) {

	case UIO_USERISPACE:
	case UIO_USERSPACE:
		if (copyin(iovp->iov_base, &c, sizeof (unsigned char)))
			return (-1);
		break;

	case UIO_SYSSPACE:
		c = *iovp->iov_base;
		break;

	default:
		return (-1); /* invalid segflg */
	}

	/*
	 * Adjust fields of iovec and uio appropriately.
	 */
	iovp->iov_base++;
	iovp->iov_len--;
	uiop->uio_resid--;
	uiop->uio_loffset++;
	return ((int)c & 0xFF); /* success */
}

/*
 * Drop the next n chars out of *uiop.
 */
void
uioskip(uio_t *uiop, size_t n)
{
	if (n > uiop->uio_resid)
		return;
	while (n != 0) {
		register iovec_t	*iovp = uiop->uio_iov;
		register size_t		niovb = MIN(iovp->iov_len, n);

		if (niovb == 0) {
			uiop->uio_iov++;
			uiop->uio_iovcnt--;
			continue;
		}
		iovp->iov_base += niovb;
		uiop->uio_loffset += niovb;
		iovp->iov_len -= niovb;
		uiop->uio_resid -= niovb;
		n -= niovb;
	}
}

/*
 * Dup the suio into the duio and diovec of size diov_cnt. If diov
 * is too small to dup suio then an error will be returned, else 0.
 */
int
uiodup(uio_t *suio, uio_t *duio, iovec_t *diov, int diov_cnt)
{
	int ix;
	iovec_t *siov = suio->uio_iov;

	*duio = *suio;
	for (ix = 0; ix < suio->uio_iovcnt; ix++) {
		diov[ix] = siov[ix];
		if (ix >= diov_cnt)
			return (1);
	}
	duio->uio_iov = diov;
	return (0);
}

/*
 * Shadow state for checking if a platform has hardware asynchronous
 * copy capability and minimum copy size, e.g. Intel's I/OAT dma engine,
 *
 * Dcopy does a call-back to uioa_dcopy_enable() when a dma device calls
 * into dcopy to register and uioa_dcopy_disable() when the device calls
 * into dcopy to unregister.
 */
uioasync_t uioasync = {B_FALSE, 1024};

void
uioa_dcopy_enable()
{
	uioasync.enabled = B_TRUE;
}

void
uioa_dcopy_disable()
{
	uioasync.enabled = B_FALSE;
}

/*
 * Schedule an asynchronous move of "n" bytes at byte address "p",
 * "rw" indicates the direction of the move, I/O parameters and
 * async state are provided in "uioa" which is update to reflect
 * the data which is to be moved.
 *
 * Returns 0 on success or a non-zero errno on failure.
 *
 * Note, while the uioasync APIs are general purpose in design
 * the current implementation is Intel I/OAT specific.
 */
int
uioamove(void *p, size_t n, enum uio_rw rw, uioa_t *uioa)
{
	int		soff, doff;
	uint64_t	pa;
	int		cnt;
	iovec_t		*iov;
	dcopy_handle_t	channel;
	dcopy_cmd_t	cmd;
	int		ret = 0;
	int		dcopy_flags;

	if (!(uioa->uioa_state & UIOA_ENABLED)) {
		/* The uioa_t isn't enabled */
		return (ENXIO);
	}

	if (uioa->uio_segflg != UIO_USERSPACE || rw != UIO_READ) {
		/* Only support to user-land from kernel */
		return (ENOTSUP);
	}


	channel = uioa->uioa_hwst[UIO_DCOPY_CHANNEL];
	cmd = uioa->uioa_hwst[UIO_DCOPY_CMD];
	dcopy_flags = DCOPY_NOSLEEP;

	/*
	 * While source bytes and destination bytes.
	 */
	while (n > 0 && uioa->uio_resid > 0) {
		iov = uioa->uio_iov;
		if (iov->iov_len == 0l) {
			uioa->uio_iov++;
			uioa->uio_iovcnt--;
			uioa->uioa_lcur++;
			uioa->uioa_lppp = uioa->uioa_lcur->uioa_ppp;
			continue;
		}
		/*
		 * While source bytes schedule an async
		 * dma for destination page by page.
		 */
		while (n > 0) {
			/* Addr offset in page src/dst */
			soff = (uintptr_t)p & PAGEOFFSET;
			doff = (uintptr_t)iov->iov_base & PAGEOFFSET;
			/* Min copy count src and dst and page sized */
			cnt = MIN(n, iov->iov_len);
			cnt = MIN(cnt, PAGESIZE - soff);
			cnt = MIN(cnt, PAGESIZE - doff);
			/* XXX if next page(s) contiguous could use multipage */

			/*
			 * if we have an old command, we want to link all
			 * other commands to the next command we alloced so
			 * we only need to track the last command but can
			 * still free them all.
			 */
			if (cmd != NULL) {
				dcopy_flags |= DCOPY_ALLOC_LINK;
			}
			ret = dcopy_cmd_alloc(channel, dcopy_flags, &cmd);
			if (ret != DCOPY_SUCCESS) {
				/* Error of some sort */
				return (EIO);
			}
			uioa->uioa_hwst[UIO_DCOPY_CMD] = cmd;

			ASSERT(cmd->dp_version == DCOPY_CMD_V0);
			if (uioa_maxpoll >= 0) {
				/* Blocking (>0 may be) used in uioafini() */
				cmd->dp_flags = DCOPY_CMD_INTR;
			} else {
				/* Non blocking uioafini() so no intr */
				cmd->dp_flags = DCOPY_CMD_NOFLAGS;
			}
			cmd->dp_cmd = DCOPY_CMD_COPY;
			pa = ptob((uint64_t)hat_getpfnum(kas.a_hat, p));
			cmd->dp.copy.cc_source = pa + soff;
			if (uioa->uioa_lcur->uioa_pfncnt == 0) {
				/* Have a (page_t **) */
				pa = ptob((uint64_t)(
				    *(page_t **)uioa->uioa_lppp)->p_pagenum);
			} else {
				/* Have a (pfn_t *) */
				pa = ptob((uint64_t)(
				    *(pfn_t *)uioa->uioa_lppp));
			}
			cmd->dp.copy.cc_dest = pa + doff;
			cmd->dp.copy.cc_size = cnt;
			ret = dcopy_cmd_post(cmd);
			if (ret != DCOPY_SUCCESS) {
				/* Error of some sort */
				return (EIO);
			}
			ret = 0;

			/* If UIOA_POLL not set, set it */
			if (!(uioa->uioa_state & UIOA_POLL))
				uioa->uioa_state |= UIOA_POLL;

			/* Update iov, uio, and local pointers/counters */
			iov->iov_base += cnt;
			iov->iov_len -= cnt;
			uioa->uio_resid -= cnt;
			uioa->uioa_mbytes += cnt;
			uioa->uio_loffset += cnt;
			p = (caddr_t)p + cnt;
			n -= cnt;

			/* End of iovec? */
			if (iov->iov_len == 0) {
				/* Yup, next iovec */
				break;
			}

			/* Next dst addr page? */
			if (doff + cnt == PAGESIZE) {
				/* Yup, next page_t */
				uioa->uioa_lppp++;
			}
		}
	}

	return (ret);
}

/*
 * Initialize a uioa_t for a given uio_t for the current user context,
 * copy the common uio_t to the uioa_t, walk the shared iovec_t and
 * lock down the user-land page(s) containing iovec_t data, then mapin
 * user-land pages using segkpm.
 */
int
uioainit(uio_t *uiop, uioa_t *uioap)
{
	caddr_t	addr;
	page_t		**pages;
	int		off;
	int		len;
	proc_t		*procp = ttoproc(curthread);
	struct as	*as = procp->p_as;
	iovec_t		*iov = uiop->uio_iov;
	int32_t		iovcnt = uiop->uio_iovcnt;
	uioa_page_t	*locked = uioap->uioa_locked;
	dcopy_handle_t	channel;
	int		error;

	if (! (uioap->uioa_state & UIOA_ALLOC)) {
		/* Can only init() a freshly allocated uioa_t */
		return (EINVAL);
	}

	error = dcopy_alloc(DCOPY_NOSLEEP, &channel);
	if (error == DCOPY_NORESOURCES) {
		/* Turn off uioa */
		uioasync.enabled = B_FALSE;
		return (ENODEV);
	}
	if (error != DCOPY_SUCCESS) {
		/* Alloc failed */
		return (EIO);
	}

	uioap->uioa_hwst[UIO_DCOPY_CHANNEL] = channel;
	uioap->uioa_hwst[UIO_DCOPY_CMD] = NULL;

	/* Indicate uioa_t (will be) initialized */
	uioap->uioa_state = UIOA_INIT;

	uioap->uioa_mbytes = 0;

	/* uio_t/uioa_t uio_t common struct copy */
	*((uio_t *)uioap) = *uiop;

	/* initialize *uiop->uio_iov */
	if (iovcnt > UIOA_IOV_MAX) {
		/* Too big? */
		return (E2BIG);
	}
	uioap->uio_iov = iov;
	uioap->uio_iovcnt = iovcnt;

	/* Mark the uioap as such */
	uioap->uio_extflg |= UIO_ASYNC;

	/*
	 * For each iovec_t, lock-down the page(s) backing the iovec_t
	 * and save the page_t list for phys addr use in uioamove().
	 */
	iov = uiop->uio_iov;
	iovcnt = uiop->uio_iovcnt;
	while (iovcnt > 0) {
		addr = iov->iov_base;
		off = (uintptr_t)addr & PAGEOFFSET;
		addr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
		len = iov->iov_len + off;

		/* Lock down page(s) for the iov span */
		if ((error = as_pagelock(as, &pages,
		    iov->iov_base, iov->iov_len, S_WRITE)) != 0) {
			/* Error */
			goto cleanup;
		}

		if (pages == NULL) {
			/*
			 * Need page_t list, really only need
			 * a pfn list so build one.
			 */
			pfn_t   *pfnp;
			int	pcnt = len >> PAGESHIFT;

			if (off)
				pcnt++;
			if ((pfnp = kmem_alloc(pcnt * sizeof (pfnp),
			    KM_NOSLEEP)) == NULL) {
				error = ENOMEM;
				goto cleanup;
			}
			locked->uioa_ppp = (void **)pfnp;
			locked->uioa_pfncnt = pcnt;
			AS_LOCK_ENTER(as, RW_READER);
			while (pcnt-- > 0) {
				*pfnp++ = hat_getpfnum(as->a_hat, addr);
				addr += PAGESIZE;
			}
			AS_LOCK_EXIT(as);
		} else {
			/* Have a page_t list, save it */
			locked->uioa_ppp = (void **)pages;
			locked->uioa_pfncnt = 0;
		}
		/* Save for as_pageunlock() in uioafini() */
		locked->uioa_base = iov->iov_base;
		locked->uioa_len = iov->iov_len;
		locked++;

		/* Next iovec_t */
		iov++;
		iovcnt--;
	}
	/* Initialize curret pointer into uioa_locked[] and it's uioa_ppp */
	uioap->uioa_lcur = uioap->uioa_locked;
	uioap->uioa_lppp = uioap->uioa_lcur->uioa_ppp;
	return (0);

cleanup:
	/* Unlock any previously locked page_t(s) */
	while (locked > uioap->uioa_locked) {
		locked--;
		as_pageunlock(as, (page_t **)locked->uioa_ppp,
		    locked->uioa_base, locked->uioa_len, S_WRITE);
	}

	/* Last indicate uioa_t still in alloc state */
	uioap->uioa_state = UIOA_ALLOC;
	uioap->uioa_mbytes = 0;

	return (error);
}

/*
 * Finish processing of a uioa_t by cleanup any pending "uioap" actions.
 */
int
uioafini(uio_t *uiop, uioa_t *uioap)
{
	int32_t		iovcnt = uiop->uio_iovcnt;
	uioa_page_t	*locked = uioap->uioa_locked;
	struct as	*as = ttoproc(curthread)->p_as;
	dcopy_handle_t	channel;
	dcopy_cmd_t	cmd;
	int		ret = 0;

	ASSERT(uioap->uio_extflg & UIO_ASYNC);

	if (!(uioap->uioa_state & (UIOA_ENABLED|UIOA_FINI))) {
		/* Must be an active uioa_t */
		return (EINVAL);
	}

	channel = uioap->uioa_hwst[UIO_DCOPY_CHANNEL];
	cmd = uioap->uioa_hwst[UIO_DCOPY_CMD];

	/* XXX - why do we get cmd == NULL sometimes? */
	if (cmd != NULL) {
		if (uioap->uioa_state & UIOA_POLL) {
			/* Wait for last dcopy() to finish */
			int64_t poll = 1;
			int poll_flag = DCOPY_POLL_NOFLAGS;

			do {
				if (uioa_maxpoll == 0 ||
				    (uioa_maxpoll > 0 &&
				    poll >= uioa_maxpoll)) {
					/* Always block or after maxpoll */
					poll_flag = DCOPY_POLL_BLOCK;
				} else {
					/* No block, poll */
					poll++;
				}
				ret = dcopy_cmd_poll(cmd, poll_flag);
			} while (ret == DCOPY_PENDING);

			if (ret == DCOPY_COMPLETED) {
				/* Poll/block succeeded */
				ret = 0;
			} else {
				/* Poll/block failed */
				ret = EIO;
			}
		}
		dcopy_cmd_free(&cmd);
	}

	dcopy_free(&channel);

	/* Unlock all page(s) iovec_t by iovec_t */
	while (iovcnt-- > 0) {
		page_t **pages;

		if (locked->uioa_pfncnt == 0) {
			/* A as_pagelock() returned (page_t **) */
			pages = (page_t **)locked->uioa_ppp;
		} else {
			/* Our pfn_t array */
			pages = NULL;
			kmem_free(locked->uioa_ppp, locked->uioa_pfncnt *
			    sizeof (pfn_t *));
		}
		as_pageunlock(as, pages, locked->uioa_base, locked->uioa_len,
		    S_WRITE);

		locked++;
	}
	/* uioa_t->uio_t common struct copy */
	*uiop = *((uio_t *)uioap);

	/*
	 * Last, reset uioa state to alloc.
	 *
	 * Note, we only initialize the state here, all other members
	 * will be initialized in a subsequent uioainit().
	 */
	uioap->uioa_state = UIOA_ALLOC;
	uioap->uioa_mbytes = 0;

	uioap->uioa_hwst[UIO_DCOPY_CMD] = NULL;
	uioap->uioa_hwst[UIO_DCOPY_CHANNEL] = NULL;

	return (ret);
}
