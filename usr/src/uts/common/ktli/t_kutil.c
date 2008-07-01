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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains the following utility functions:
 * 	tli_send:
 * 	tli_recv:
 * 	get_ok_ack:
 *
 * Returns:
 * 	See individual functions.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <sys/strsun.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <netinet/ip6.h>
#include <inet/ip.h>

extern int getiocseqno(void);

int
tli_send(TIUSER *tiptr, mblk_t *bp, int fmode)
{
	vnode_t	*vp;
	int	error;

	vp = tiptr->fp->f_vnode;

	/*
	 * Send data honoring flow control and errors
	 */
	error = kstrputmsg(vp, bp, NULL, 0, 0, MSG_BAND | MSG_HOLDSIG, fmode);
	return (error);
}

int
tli_recv(TIUSER *tiptr, mblk_t **bp, int fmode)
{
	vnode_t		*vp;
	int		error;
	uchar_t 	pri;
	int 		pflag;
	rval_t		rval;
	clock_t		timout;

	vp = tiptr->fp->f_vnode;
	if (fmode & (FNDELAY|FNONBLOCK))
		timout = 0;
	else
		timout = -1;

	pflag = MSG_ANY;
	pri = 0;
	*bp = NULL;
	error = kstrgetmsg(vp, bp, NULL, &pri, &pflag, timout, &rval);
	if (error == ETIME)
		error = EAGAIN;

	return (error);
}

int
get_ok_ack(TIUSER *tiptr, int type, int fmode)
{
	int			msgsz;
	union T_primitives	*pptr;
	mblk_t			*bp;
	int			error;

	error = 0;

	/*
	 * wait for ack
	 */
	bp = NULL;
	if ((error = tli_recv(tiptr, &bp, fmode)) != 0)
		return (error);

	if ((msgsz = (int)MBLKL(bp)) < sizeof (int)) {
		freemsg(bp);
		return (EPROTO);
	}

	pptr = (void *)bp->b_rptr;
	switch (pptr->type) {
	case T_OK_ACK:
		if (msgsz < TOKACKSZ || pptr->ok_ack.CORRECT_prim != type)
			error = EPROTO;
		break;

	case T_ERROR_ACK:
		if (msgsz < TERRORACKSZ) {
			error = EPROTO;
			break;
		}

		if (pptr->error_ack.TLI_error == TSYSERR)
			error = pptr->error_ack.UNIX_error;
		else
			error = t_tlitosyserr(pptr->error_ack.TLI_error);
		break;

	default:
		error = EPROTO;
		break;
	}
	freemsg(bp);
	return (error);
}

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
	0,		/* TSYSERR - will never get */
	EPROTO,		/* TLOOK - should never be sent by transport */
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

int
t_tlitosyserr(int terr)
{
	if (terr < 0 || (terr >= (sizeof (tli_errs) / sizeof (tli_errs[0]))))
		return (EPROTO);
	else
		return (tli_errs[terr]);
}

/*
 * Notify transport that we are having trouble with this connection.
 * If transport is TCP/IP, IP should delete the IRE and start over.
 */
void
t_kadvise(TIUSER *tiptr, uchar_t *addr, int addr_len)
{
	file_t		*fp;
	vnode_t		*vp;
	struct iocblk	*iocp;
	ipid_t		*ipid;
	mblk_t		*mp;

	fp = tiptr->fp;
	vp = fp->f_vnode;

	mp = mkiocb(IP_IOCTL);
	if (!mp)
		return;

	iocp = (void *)mp->b_rptr;
	iocp->ioc_count = sizeof (ipid_t) + addr_len;

	mp->b_cont = allocb(iocp->ioc_count, BPRI_HI);
	if (!mp->b_cont) {
		freeb(mp);
		return;
	}

	ipid = (void *)mp->b_cont->b_rptr;
	mp->b_cont->b_wptr += iocp->ioc_count;

	bzero(ipid, sizeof (*ipid));
	ipid->ipid_cmd = IP_IOC_IRE_DELETE_NO_REPLY;
	ipid->ipid_ire_type = IRE_CACHE;
	ipid->ipid_addr_offset = sizeof (ipid_t);
	ipid->ipid_addr_length = addr_len;

	bcopy(addr, &ipid[1], addr_len);

	/* Ignore flow control, signals and errors */
	(void) kstrputmsg(vp, mp, NULL, 0, 0,
	    MSG_BAND | MSG_IGNFLOW | MSG_HOLDSIG | MSG_IGNERROR, 0);
}

#ifdef KTLIDEBUG
int ktlilog = 0;

/*
 * Kernel level debugging aid. The global variable "ktlilog" is a bit
 * mask which allows various types of debugging messages to be printed
 * out.
 *
 *	ktlilog & 1 	will cause actual failures to be printed.
 *	ktlilog & 2	will cause informational messages to be
 *			printed.
 */
int
ktli_log(int level, char *str, int a1)
{
	if (level & ktlilog)
		printf(str, a1);
}
#endif
