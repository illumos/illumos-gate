/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _TTYMUX_IMPL_H
#define	_TTYMUX_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types32.h>
#include <sys/param.h>

/*
 * Local definitions.
 */
#define	SM_TRBIT(code)		(1 << (code)-'@')

extern uint_t  sm_max_units;

#define	MAX_LQS	(sm_max_units)
#define	NLUNITS	(MAX_LQS + 2)

/*
 * Re-use minor device encoding used by the se(7D) driver.
 */
#define	ASYNC_DEVICE	(0)
#define	OUTLINE		(1 << (NBITSMINOR32 - 1))
#define	NULL_PROTOCOL	0
#define	ASYN_PROTOCOL	1
#define	OUTD_PROTOCOL	2

#define	DEV_TO_UNIT(dev)	(getminor(dev) & ~OUTLINE)
#define	DEV_TO_PROTOBITS(dev)	(getminor(dev) & OUTLINE)

/*
 * Driver id
 */
#define	SM_MOD_ID	0x534d

/*
 * Access modes of the two halves to each others flags
 * Q	uq->flags lq->flags
 * uq	rw		r
 * lq	-		 rw
 */
/*
 * A lower queue is associated with an upper queue
 * (used for synchronising dissasociate reqests with the lower half)
 * A lower q will not forward messages if SM_UQVALID is set in uqflags.
 */
#define	SM_UQVALID	(0x1)	/* written by an upper q read by a lower q */
#define	SM_OBPCNDEV	(0x2)	/* set when this device is an OBP console */

/*
 * unused flags
 */
#define	FLUSHR_PEND	(0x1)	/* M_FLUSH is expected on all the lr q's */

/*
 * An open has completed on this stream.
 */
#define	FULLY_OPEN	(0x2)
#define	EXCL_OPEN	(0x4)

#define	SM_CARON	(0x8)
/*
 * Flags to disable queues controlled from below.
 */
#define	HANGUP_MODE	(0x10) /* not used (sets WERROR_MODE instead) */
#define	RERROR_MODE	(0x20) /* read error on stream (unset by closing) */
#define	WERROR_MODE	(0x40) /* write side error on the stream (set by */
				/* M_HANGUP/M_ERROR */
				/* unset by M_UNHANGUP/M_ERROR) */
#define	ERROR_MODE	(0x60)	/* read error on stream (unset by M_ERROR) */

/*
 * Flags to disable queues controlled from above.
 * Also used by set on queues which are OBP consoles
 */
#define	SM_STOPPED	(0x080)	/* M_STOP has been seen */
#define	SM_ISTOPPED	(0x100)	/* M_STOPI has been seen */

/*
 * A stream wants something.
 */
#define	WANT_SC		(0x200) /* carrier status of a stream required */
#define	WANT_CL		(0x400) /* CLOCAL status of a stream required */
#define	WANT_CD		(0x800) /* CD modem status of a line required */
#define	WANT_CDSTAT	(0xe00)
#define	WANT_TCSET	(0x20000) /* send down initial termios settings */

#define	WANT_RENB	(0x40000) /* read q is flowcontrolled */

#define	SM_IOCPENDING	(0x80000)
#define	SM_CLOSE	(0x100000)
#define	SM_INTERNALIOC	(0x200000)

#define	SM_LOGINREQ	(0x400000)

#define	LOCK_UNIT(u)	(mutex_enter(u->sm_umutex)) /* Lock per-stream data */
#define	UNLOCK_UNIT(u)	(mutex_exit(u->sm_umutex)) /* Unlock per-stream data */

/*
 * Checks whether an open could potentially block.
 */
#define	BLOCKING(unitp, proto, flag)	\
	(!(flag & (FNDELAY|FNONBLOCK)) &&	\
	!(proto == OUTLINE) &&			\
	unitp->sm_lqs &&				\
	(unitp->sm_flags & SM_CARON) == 0)

/*
 * Update termios style control flag with a termio style flag.
 */
#define	SM_SETCFLAG(qi, tc)	\
	qi->sm_ttycommon->t_cflag = \
	(qi->sm_ttycommon->t_cflag & 0xffff0000 | (tc)->c_cflag)
#define	SM_SETLFLAG(qi, tc)	\
	qi->sm_ttycommon->t_iflag = \
	(qi->sm_ttycommon->t_iflag & 0xffff0000 | (tc)->c_iflag)

#define	SM_WQ(qi)	(qi->sm_ttycommon->t_writeq)
#define	SM_RQ(qi)	(qi->sm_ttycommon->t_readq)

/*
 *
 */
struct sm_iocinfo {
	int	sm_id;
	int	sm_cmd;
	void	*sm_data;
};

/*
 * Perform a per instance search for a specified per stream structure.
 */
#define	get_lqi(ssp, unit)	\
	((unit < MAX_LQS) ? &ssp->sm_lqs[unit] : 0)

#define	get_uqi(ssp, unit)	\
	((unit < NLUNITS) ? &ssp->sm_uqs[unit] : NULL)

#define	CNTRL(c)	((c)&037)

#define	sm_allocb(size, pri)	allocb(size, pri)
#define	sm_copymsg(mp)	((DB_TYPE(mp) == M_DATA) ? dupmsg(mp) : copymsg(mp))
#define	sm_freemsg(mp)	freemsg(mp)

/*
 * macro to improve performance. The cond is checked before deciding whether
 * to create a new stack frame for the debug call
 * Calls to sm_dbg should not occur in hanging statements - alternatively
 * bracket SM_CMD with a do .... while (0)
 */

#define	SM_CMD(cond, stmt)	{ if (cond) stmt; }
#define	sm_dbg(lvl, args)	SM_CMD(sm_ssp->sm_trflag & SM_TRBIT(lvl), \
	sm_debug args)

#define	SM_SLOT_RED	3
#define	SM_MAX_SLOT_WAIT	3

#define	sm_dev2unit(dev)	(getminor(dev) & ~OUTLINE)

#define	LQI2ASSOC(a, l)				\
	(a)->ttymux_linkid = (l)->sm_linkid;	\
	(a)->ttymux_tag = (l)->sm_tag;		\
	(a)->ttymux_ioflag = (l)->sm_ioflag;	\
	(a)->ttymux_ldev = (l)->sm_dev;		\
	(a)->ttymux_udev = ((l)->sm_uqi == 0) ? NODEV :	\
	    makedevice(ddi_driver_major(sm_ssp->sm_dip), \
	    (l)->sm_uqi->sm_lunit); 			 \
	(void) strncpy((a)->ttymux_path, (l)->sm_path, MAXPATHLEN)

#define	LQI2ASSOC32(a, l)				\
	(a)->ttymux32_linkid = (l)->sm_linkid;		\
	(a)->ttymux32_tag = (uint32_t)(l)->sm_tag;	\
	(a)->ttymux32_ioflag = (l)->sm_ioflag;		\
	(void) cmpldev(&(a)->ttymux32_ldev, (l)->sm_dev);\
	(a)->ttymux32_udev = ((l)->sm_uqi == 0) ? NODEV32 :	\
	    ((void) cmpldev(&(a)->ttymux32_udev,		\
	    makedevice(ddi_driver_major(sm_ssp->sm_dip), \
	    (l)->sm_uqi->sm_lunit)), \
	    (a)->ttymux32_udev);	\
	(void) strncpy((a)->ttymux32_path, (l)->sm_path, MAXPATHLEN)

#define	CNTRL(c)	((c)&037)

/*
 * 32 bit eqivalents of structures defined in sys/ttymuxuser.h
 */
typedef struct ttymux_association32 {

	dev32_t		ttymux32_udev; /* the upper device to be associated */
	dev32_t		ttymux32_ldev;
				/* the device type of a linked lower stream */
	int		ttymux32_linkid;
				/* the linkid of a linked lower stream */
	uint32_t	ttymux32_tag;	/* tagged association */
	uint_t		ttymux32_ioflag;	/* FORINPUT FOROUTPUT FORIO */
	char		ttymux32_path[MAXPATHLEN];	/* device path */
} ttymux_assoc32_t;

typedef struct ttymux_associations32 {
	uint32_t	ttymux32_nlinks;
	caddr32_t	ttymux32_assocs;
} ttymux_assocs32_t;

#ifdef	__cplusplus
}
#endif

#endif /* _TTYMUX_IMPL_H */
