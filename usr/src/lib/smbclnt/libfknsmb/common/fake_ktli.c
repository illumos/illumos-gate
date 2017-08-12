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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
/*
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Kernel TLI-like functions
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>

#include <errno.h>
#include <stropts.h>
#include <unistd.h>

#include "fake_xti.h"

/* Size of mblks for tli_recv */
#define	FKTLI_RCV_SZ	4096

/*
 * Translate a TLI error into a system error as best we can.
 */
static const int tli_errs[] = {
	0,		/* no error	*/
	EADDRNOTAVAIL,  /* TBADADDR	*/
	ENOPROTOOPT,    /* TBADOPT	*/
	EACCES,		/* TACCES	*/
	EBADF,		/* TBADF	*/
	EADDRNOTAVAIL,	/* TNOADDR	*/
	EPROTO,		/* TOUTSTATE	*/
	EPROTO,		/* TBADSEQ	*/
	ENOSYS,		/* TSYSERR	*/
	EPROTO,		/* TLOOK	*/
	EMSGSIZE,	/* TBADDATA	*/
	EMSGSIZE,	/* TBUFOVFLW	*/
	EPROTO,		/* TFLOW	*/
	EWOULDBLOCK,    /* TNODATA	*/
	EPROTO,		/* TNODIS	*/
	EPROTO,		/* TNOUDERR	*/
	EINVAL,		/* TBADFLAG	*/
	EPROTO,		/* TNOREL	*/
	EOPNOTSUPP,	/* TNOTSUPPORT	*/
	EPROTO,		/* TSTATECHNG	*/
};

static int
tlitosyserr(int terr)
{
	if (terr < 0 || (terr >= (sizeof (tli_errs) / sizeof (tli_errs[0]))))
		return (EPROTO);
	else
		return (tli_errs[terr]);
}

/*
 * Note: This implementation is specific to the needs of the callers in
 * uts/common/fs/smbclnt/netsmb/smb_trantcp.c
 */
/* ARGSUSED */
int
t_kopen(file_t *fp, dev_t rdev, int flags, TIUSER **tiptr, cred_t *cr)
{
	boolean_t madefp = B_FALSE;
	vnode_t	*vp;
	TIUSER *tiu;
	int fd;
	int rc;

	*tiptr = NULL;

	if (fp == NULL) {
		/*
		 * create a socket endpoint
		 * dev is actualy AF
		 */
		char *devnm;
		switch (rdev) {
		case AF_INET:
			devnm = "/dev/tcp";
			break;
		case AF_INET6:
			devnm = "/dev/tcp6";
			break;
		default:
			cmn_err(CE_NOTE, "t_kopen: bad device");
			return (EINVAL);
		}

		fd = t_open(devnm, O_RDWR, NULL);
		if (fd < 0) {
			rc = t_errno;
			cmn_err(CE_NOTE, "t_kopen: t_open terr=%d", rc);
			return (tlitosyserr(rc));
		}

		/*
		 * allocate a file pointer...
		 */
		fp = getf(fd);
		madefp = B_TRUE;
	}
	vp = fp->f_vnode;
	fd = vp->v_fd;

	tiu = kmem_zalloc(sizeof (*tiu), KM_SLEEP);
	rc = t_getinfo(fd, &tiu->tp_info);
	if (rc < 0) {
		rc = t_errno;
		cmn_err(CE_NOTE, "t_kopen: t_getinfo terr=%d", rc);
		kmem_free(tiu, sizeof (*tiu));
		if (madefp) {
			releasef(fd);
			(void) t_close(fd);
		}
		return (tlitosyserr(rc));
	}

	tiu->fp = fp;
	tiu->flags = madefp ? MADE_FP : 0;
	*tiptr = tiu;

	return (0);
}

/* ARGSUSED */
int
t_kclose(TIUSER *tiptr, int callclosef)
{
	file_t	*fp;

	fp = (tiptr->flags & MADE_FP) ? tiptr->fp : NULL;

	kmem_free(tiptr, TIUSERSZ);

	if (fp != NULL) {
		vnode_t *vp = fp->f_vnode;
		int fd = vp->v_fd;
		releasef(fd);
		(void) t_close(fd);
	}

	return (0);
}

int
t_kbind(TIUSER *tiptr, struct t_bind *req, struct t_bind *ret)
{
	file_t		*fp = tiptr->fp;
	vnode_t		*vp = fp->f_vnode;
	int		rc;

	if (t_bind(vp->v_fd, req, ret) < 0) {
		rc = t_errno;
		cmn_err(CE_NOTE, "t_kbind: t_bind terr=%d", rc);
		return (tlitosyserr(rc));
	}
	return (0);
}

int
t_kunbind(TIUSER *tiptr)
{
	file_t		*fp = tiptr->fp;
	vnode_t		*vp = fp->f_vnode;
	int		rc;

	if (t_unbind(vp->v_fd) < 0) {
		rc = t_errno;
		cmn_err(CE_NOTE, "t_kunbind: t_unbind terr=%d", rc);
		return (tlitosyserr(rc));
	}
	return (0);
}

int
t_kconnect(TIUSER *tiptr, struct t_call *sndcall, struct t_call *rcvcall)
{
	file_t		*fp = tiptr->fp;
	vnode_t		*vp = fp->f_vnode;
	int		rc;

	if (t_connect(vp->v_fd, sndcall, rcvcall) < 0) {
		rc = t_errno;
		cmn_err(CE_NOTE, "t_kconnect: t_connect terr=%d", rc);
		if (rc == TLOOK) {
			/* Probably got a RST. */
			rc = ECONNREFUSED;
		} else {
			rc = tlitosyserr(rc);
		}
		return (rc);
	}
	return (0);
}

int
t_koptmgmt(TIUSER *tiptr, struct t_optmgmt *req, struct t_optmgmt *ret)
{
	file_t		*fp = tiptr->fp;
	vnode_t		*vp = fp->f_vnode;
	int		rc;

	if (t_optmgmt(vp->v_fd, req, ret) < 0) {
		rc = t_errno;
		cmn_err(CE_NOTE, "t_koptmgmt: t_optmgmt terr=%d", rc);
		return (tlitosyserr(rc));
	}
	return (0);
}

/*
 * Poll for an input event.
 *
 * timo is measured in ticks
 */
int
t_kspoll(TIUSER *tiptr, int timo, int waitflg, int *events)
{
	struct pollfd	pfds[1];
	file_t		*fp;
	vnode_t		*vp;
	clock_t		timout;	/* milliseconds */
	int		n;

	fp = tiptr->fp;
	vp = fp->f_vnode;

	if (events == NULL || ((waitflg & READWAIT) == 0))
		return (EINVAL);

	/* Convert from ticks to milliseconds */
	if (timo < 0)
		timout = -1;
	else
		timout = TICK_TO_MSEC(timo);

	pfds[0].fd = vp->v_fd;
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;

	errno = 0;
	n = poll(pfds, 1, timout);
	if (n < 0)
		return (errno);
	if (n == 0)
		return (ETIME);
	*events = pfds[0].revents;
	return (0);
}

/*
 * Send the message, return zero or errno.
 * Always free's the message, even on error.
 */
int
tli_send(TIUSER *tiptr, mblk_t *bp, int fmode)
{
	struct strbuf ctlbuf;
	struct strbuf databuf;
	mblk_t	*m;
	int	flg, n, rc;
	vnode_t	*vp;

	if (bp == NULL)
		return (0);
	vp = tiptr->fp->f_vnode;

	switch (bp->b_datap->db_type) {
	case M_DATA:
		for (m = bp; m != NULL; m = m->b_cont) {
			n = MBLKL(m);
			flg = (m->b_cont != NULL) ? T_MORE : 0;
			rc = t_snd(vp->v_fd, (void *) m->b_rptr, n, flg);
			if (rc != n) {
				rc = EIO;
				goto out;
			}
		}
		rc = 0;
		break;

	/*
	 * May get M_PROTO/T_DISCON_REQ from nb_snddis()
	 */
	case M_PROTO:
	case M_PCPROTO:
		ctlbuf.len = MBLKL(bp);
		ctlbuf.maxlen = MBLKL(bp);
		ctlbuf.buf = (char *)bp->b_rptr;
		if (bp->b_cont == NULL) {
			bzero(&databuf, sizeof (databuf));
		} else {
			m = bp->b_cont;
			databuf.len = MBLKL(m);
			databuf.maxlen = MBLKL(m);
			databuf.buf = (char *)m->b_rptr;
		}
		if (putmsg(vp->v_fd, &ctlbuf, &databuf, 0) < 0) {
			rc = errno;
			cmn_err(CE_NOTE, "tli_send: putmsg err=%d", rc);
		} else {
			rc = 0;
		}
		break;

	default:
		rc = EIO;
		break;
	}

out:
	freemsg(bp);
	return (rc);
}

int
tli_recv(TIUSER *tiptr, mblk_t **bp, int fmode)
{
	mblk_t		*mtop = NULL;
	mblk_t		*m;
	vnode_t		*vp;
	int		error;
	int		flags;
	int		nread;
	int		n;

	vp = tiptr->fp->f_vnode;



	/*
	 * Get an mblk for the data
	 */
	nread = FKTLI_RCV_SZ;
	m = allocb_wait(nread, 0, 0, &error);
	ASSERT(m != NULL);

	if (mtop == NULL)
		mtop = m;

again:
	flags = 0;
	n = t_rcv(vp->v_fd, (void *) m->b_rptr, nread, &flags);
	if (n < 0) {
		n = t_errno;
		cmn_err(CE_NOTE, "tli_recv: t_rcv terr=%d", n);
		error = tlitosyserr(n);
		goto errout;
	}
	if (n == 0) {
		error = ENOTCONN;
		goto errout;
	}
	ASSERT(n > 0 && n <= nread);
	m->b_wptr = m->b_rptr + n;

	if (flags & T_MORE) {
		mblk_t	*mtail = m;
		m = allocb_wait(nread, 0, 0, &error);
		ASSERT(m != NULL);
		mtail->b_cont = m;
		goto again;
	}

	*bp = mtop;
	return (0);

errout:
	if (m == mtop) {
		freemsg(mtop);
		return (error);
	}

	/* got some data, so return it. */
	return (0);
}
