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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Transport Interface Library read/write module - issue 1
 */

#include	<sys/types.h>
#include	<sys/param.h>
#include	<sys/stream.h>
#include	<sys/stropts.h>
#include	<sys/tihdr.h>
#include	<sys/debug.h>
#include	<sys/errno.h>
#include	<sys/kmem.h>
#include	<sys/tirdwr.h>
#include	<sys/conf.h>
#include	<sys/modctl.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>

#define	ORDREL		002
#define	DISCON		004
#define	FATAL		010
#define	WAITACK		020
#define	TIRDWR_ID	4

/*
 * Per-Stream private data structure.
 */
struct trw_trw {
	queue_t	*trw_rdq;
	uint_t	trw_flags;
};

/*
 * stream data structure definitions
 */
static	int tirdwropen(queue_t *q, dev_t *dev,
    int flag, int sflag, cred_t	*cr);

static	int tirdwrclose(queue_t *q, int flag, cred_t *cr);

static	int check_strhead(queue_t *q);

/*
 * To save instructions, since STREAMS ignores the return value
 * from these functions, they are defined as void here. Kind of icky, but...
 */
static int tirdwrrput(queue_t *q, mblk_t *mp);
static int tirdwrwput(queue_t *q, mblk_t *mp);

static struct module_info tirdwr_info = {
	TIRDWR_ID,
	"tirdwr",
	0,
	INFPSZ,
	4096,
	1024
};

static struct qinit tirdwrrinit = {
	tirdwrrput,
	NULL,
	tirdwropen,
	tirdwrclose,
	nulldev,
	&tirdwr_info,
	NULL
};

static struct qinit tirdwrwinit = {
	tirdwrwput,
	NULL,
	tirdwropen,
	tirdwrclose,
	nulldev,
	&tirdwr_info,
	NULL
};

static struct streamtab trwinfo = {
	&tirdwrrinit,
	&tirdwrwinit,
	NULL,
	NULL
};

static struct fmodsw fsw = {
	"tirdwr",
	&trwinfo,
	D_NEW|D_MTQPAIR|D_MP
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "xport interface rd/wr str mod", &fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
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

static void send_fatal(queue_t *q, mblk_t *mp);
static void strip_strhead(queue_t *q);


/*
 * tirdwropen - open routine gets called when the
 *		module gets pushed onto the stream.
 */
/*ARGSUSED*/
static int
tirdwropen(
	queue_t *q,
	dev_t	*dev,
	int flag,
	int sflag,
	cred_t	*cr)
{
	struct trw_trw *trwptr;

	/* check if already open */
	if (q->q_ptr) {
		return (0);
	}

	/*
	 * Allocate a new trw_trw struct.
	 */
	trwptr = kmem_alloc(sizeof (struct trw_trw), KM_SLEEP);

	/* initialize data structure */
	trwptr->trw_flags = 0;
	trwptr->trw_rdq = q;
	q->q_ptr = (caddr_t)trwptr;
	WR(q)->q_ptr = (caddr_t)trwptr;
	qprocson(q);

	freezestr(q);

	(void) strqset(WR(q), QMAXPSZ, 0, (uintptr_t)WR(q)->q_next->q_maxpsz);
	(void) strqset(q, QMAXPSZ, 0, (uintptr_t)q->q_next->q_maxpsz);

	if (!check_strhead(q)) {
		unfreezestr(q);
		qprocsoff(q);
		kmem_free(trwptr, sizeof (struct trw_trw));
		return (EPROTO);
	}
	strip_strhead(q);
	unfreezestr(q);

	return (0);
}

/*
 * tirdwrclose - This routine gets called when the module
 *		gets popped off of the stream.
 */

/*ARGSUSED1*/
static int
tirdwrclose(queue_t *q, int flag, cred_t *cr)
{
	struct trw_trw *trwptr;
	mblk_t *mp;
	union T_primitives *pptr;

	qprocsoff(q);
	trwptr = (struct trw_trw *)q->q_ptr;

	ASSERT(trwptr != NULL);

	/*
	 * Send up a T_DISCON_IND if necessary.
	 */
	if ((trwptr->trw_flags & ORDREL) && !(trwptr->trw_flags & FATAL))
		if (mp = allocb(sizeof (struct T_discon_req), BPRI_LO)) {
			pptr = (union T_primitives *)mp->b_rptr;
			mp->b_wptr = mp->b_rptr + sizeof (struct T_ordrel_req);
			pptr->type = T_ORDREL_REQ;
			mp->b_datap->db_type = M_PROTO;
			putnext(WR(q), mp);
		}

	kmem_free(trwptr, sizeof (struct trw_trw));

	return (0);
}

/*
 * tirdwrrput - Module read queue put procedure.
 *		This is called from the module or
 *		driver downstream.
 */

static int
tirdwrrput(queue_t *q, mblk_t *mp)
{
	union T_primitives *pptr;
	struct trw_trw *trwptr;
	mblk_t *tmp;

	trwptr = (struct trw_trw *)q->q_ptr;

	ASSERT(trwptr != NULL);

	if ((trwptr->trw_flags & FATAL) && !(trwptr->trw_flags & WAITACK)) {
		freemsg(mp);
		return (0);
	}

	switch (mp->b_datap->db_type) {

	default:
		putnext(q, mp);
		break;

	case M_DATA:
		putnext(q, mp);
		break;

	case M_PCPROTO:
	case M_PROTO:
		/* is there enough data to check type */
		if ((mp->b_wptr - mp->b_rptr) < sizeof (t_scalar_t)) {
			/* malformed message */
			freemsg(mp);
			break;
		}
		pptr = (union T_primitives *)mp->b_rptr;

		switch (pptr->type) {

		case T_EXDATA_IND:
			send_fatal(q, mp);
			break;
		case T_DATA_IND:
			if (msgdsize(mp) == 0) {
				freemsg(mp);
				break;
			}

			tmp = (mblk_t *)unlinkb(mp);
			freemsg(mp);
			putnext(q, tmp);
			break;

		case T_ORDREL_IND:
			trwptr->trw_flags |= ORDREL;
			mp->b_datap->db_type = M_DATA;
			mp->b_wptr = mp->b_rptr;
			putnext(q, mp);
			break;

		case T_DISCON_IND:
			trwptr->trw_flags |= DISCON;
			trwptr->trw_flags &= ~ORDREL;
			if (msgdsize(mp) != 0) {
				tmp = (mblk_t *)unlinkb(mp);
				putnext(q, tmp);
			}
			mp->b_datap->db_type = M_HANGUP;
			mp->b_wptr = mp->b_rptr;
			putnext(q, mp);
			break;

		default:
			send_fatal(q, mp);
			break;
		}
	}
	return (0);
}


/*
 * tirdwrwput - Module write queue put procedure.
 *		This is called from the module or
 *		stream head upstream.
 */
static int
tirdwrwput(queue_t *q, mblk_t *mp)
{
	struct trw_trw *trwptr;

	trwptr = (struct trw_trw *)q->q_ptr;

	ASSERT(trwptr != NULL);

	if (trwptr->trw_flags & FATAL) {
		freemsg(mp);
		return (0);
	}

	switch (mp->b_datap->db_type) {
	default:
		putnext(q, mp);
		break;

	case M_DATA:
		putnext(q, mp);
		break;

	case M_PROTO:
	case M_PCPROTO:
		send_fatal(q, mp);
		break;
	}
	return (0);
}


static void
send_fatal(queue_t *q, mblk_t *mp)
{
	struct trw_trw *trwptr;

	trwptr = (struct trw_trw *)q->q_ptr;

	trwptr->trw_flags |= FATAL;
	mp->b_datap->db_type = M_ERROR;
	*mp->b_datap->db_base = EPROTO;
	mp->b_rptr = mp->b_datap->db_base;
	mp->b_wptr = mp->b_datap->db_base + sizeof (char);
	freemsg(unlinkb(mp));
	if (q->q_flag&QREADR)
		putnext(q, mp);
	else
		qreply(q, mp);
}

static int
check_strhead(queue_t *q)
{
	mblk_t *mp;
	union T_primitives *pptr;

	for (mp = q->q_next->q_first; mp != NULL; mp = mp->b_next) {

		switch (mp->b_datap->db_type) {
		case M_PROTO:
			pptr = (union T_primitives *)mp->b_rptr;
			if ((mp->b_wptr - mp->b_rptr) < sizeof (t_scalar_t))
				return (0);
			switch (pptr->type) {

			case T_EXDATA_IND:
				return (0);
			case T_DATA_IND:
				if (mp->b_cont &&
				    (mp->b_cont->b_datap->db_type != M_DATA))
					return (0);
				break;
			default:
				return (0);
			}
			break;

		case M_PCPROTO:
			return (0);

		case M_DATA:
		case M_SIG:
			break;
		default:
			return (0);
		}
	}
	return (1);
}

static void
strip_strhead(queue_t *q)
{
	mblk_t *mp;
	mblk_t *emp;
	mblk_t *tmp;
	union T_primitives *pptr;

	q = q->q_next;
	/*CSTYLED*/
	for (mp = q->q_first; mp != NULL; ) {

		switch (mp->b_datap->db_type) {
		case M_PROTO:
			pptr = (union T_primitives *)mp->b_rptr;
			switch (pptr->type) {

			case T_DATA_IND:
				if (msgdsize(mp) == 0) {
strip0:
					tmp = mp->b_next;
					rmvq(q, mp);
					freemsg(mp);
					mp = tmp;
					break;
				}
				emp = mp->b_next;
				rmvq(q, mp);
				tmp = (mblk_t *)unlinkb(mp);
				freeb(mp);
				(void) insq(q, emp, tmp);
				mp = emp;
				break;
			}
			break;

		case M_DATA:
			if (msgdsize(mp) == 0)
				goto strip0;
			mp = mp->b_next;
			break;

		case M_SIG:
			mp = mp->b_next;
			break;
		}
	}
}
