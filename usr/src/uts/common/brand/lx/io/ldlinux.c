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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/ptms.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>

#include <sys/ldlinux.h>


/*
 * ldlinuxopen - open routine gets called when the module gets pushed onto the
 * stream.
 */
/* ARGSUSED */
static int
ldlinuxopen(
	queue_t    *q,		/* pointer to the read side queue */
	dev_t   *devp,		/* pointer to stream tail's dev */
	int	oflag,		/* the user open(2) supplied flags */
	int	sflag,		/* open state flag */
	cred_t *credp)		/* credentials */
{
	struct ldlinux *tp;	/* ldlinux entry for this module */
	mblk_t *mop;
	struct stroptions *sop;
	struct termios *termiosp;
	int len;

	if (sflag != MODOPEN)
		return (EINVAL);

	if (q->q_ptr != NULL) {
		/* It's already attached. */
		return (0);
	}

	mop = allocb(sizeof (struct stroptions), BPRI_MED);
	if (mop == NULL)
		return (ENOSR);
	mop->b_datap->db_type = M_SETOPTS;
	mop->b_wptr += sizeof (struct stroptions);
	sop = (struct stroptions *)mop->b_rptr;
	sop->so_flags = SO_ISTTY;

	/*
	 * Allocate state structure.
	 */
	tp = kmem_alloc(sizeof (*tp), KM_SLEEP);

	/* Stash a pointer to our private data in q_ptr. */
	q->q_ptr = WR(q)->q_ptr = tp;

	/*
	 * Get termios defaults.  These are stored as
	 * a property in the "options" node.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(), 0, "ttymodes",
	    (caddr_t)&termiosp, &len) == DDI_PROP_SUCCESS &&
	    len == sizeof (struct termios)) {
		if (termiosp->c_lflag & ICANON) {
			tp->veof = termiosp->c_cc[VEOF];
			tp->veol = termiosp->c_cc[VEOL];
			tp->vmin = 1;
			tp->vtime = 0;
		} else {
			tp->veof = 0;
			tp->veol = 0;
			tp->vmin = termiosp->c_cc[VMIN];
			tp->vtime = termiosp->c_cc[VTIME];
		}
		kmem_free(termiosp, len);
	} else {
		/*
		 * winge winge winge...
		 */
		cmn_err(CE_WARN,
		    "ldlinuxopen: Couldn't get ttymodes property!");
		bzero(tp, sizeof (*tp));
	}

	tp->state = 0;

	/*
	 * Commit to the open and send the M_SETOPTS off to the stream head.
	 */
	qprocson(q);
	putnext(q, mop);

	return (0);
}


/*
 * ldlinuxclose - This routine gets called when the module gets
 * popped off of the stream.
 */
/* ARGSUSED */
static int
ldlinuxclose(queue_t *q, int flag, cred_t *credp)
{
	struct ldlinux *tp;

	qprocsoff(q);
	tp = q->q_ptr;
	kmem_free(tp, sizeof (*tp));
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}


static void
do_ioctl(queue_t *q, mblk_t *mp)
{
	struct ldlinux	*tp = q->q_ptr;
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	struct lx_cc	*cb;
	mblk_t		*tmp;
	int		error;

	switch (iocp->ioc_cmd) {
	case TIOCSETLD:
		/* prepare caller supplied data for access */
		error = miocpullup(mp, sizeof (struct lx_cc));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		/* get a pointer to the caller supplied data */
		cb = (struct lx_cc *)mp->b_cont->b_rptr;

		/* save caller supplied data in our per-stream cache */
		tp->veof = cb->veof;
		tp->veol = cb->veol;
		tp->vmin = cb->vmin;
		tp->vtime = cb->vtime;

		/* initialize and send a reply indicating that we're done */
		miocack(q, mp, 0, 0);
		return;

	case TIOCGETLD:
		/* allocate a reply message */
		if ((tmp = allocb(sizeof (struct lx_cc), BPRI_MED)) == NULL) {
			miocnak(q, mp, 0, ENOSR);
			return;
		}

		/* initialize the reply message */
		mioc2ack(mp, tmp, sizeof (struct lx_cc), 0);

		/* get a pointer to the reply data */
		cb = (struct lx_cc *)mp->b_cont->b_rptr;

		/* copy data from our per-stream cache into the reply data */
		cb->veof = tp->veof;
		cb->veol = tp->veol;
		cb->vmin = tp->vmin;
		cb->vtime = tp->vtime;

		/* send the reply indicating that we're done */
		qreply(q, mp);
		return;

	case PTSSTTY:
		tp->state |= ISPTSTTY;
		break;

	default:
		break;
	}

	putnext(q, mp);
}


/*
 * ldlinuxput - Module read and write queue put procedure.
 */
static void
ldlinuxput(queue_t *q, mblk_t *mp)
{
	struct ldlinux *tp = q->q_ptr;

	switch (DB_TYPE(mp)) {
	default:
		break;
	case M_IOCTL:
		if ((q->q_flag & QREADR) == 0) {
			do_ioctl(q, mp);
			return;
		}
		break;

	case M_FLUSH:
		/*
		 * Handle read and write flushes.
		 */
		if ((((q->q_flag & QREADR) != 0) && (*mp->b_rptr & FLUSHR)) ||
		    (((q->q_flag & QREADR) == 0) && (*mp->b_rptr & FLUSHW))) {
			if ((tp->state & ISPTSTTY) && (*mp->b_rptr & FLUSHBAND))
				flushband(q, *(mp->b_rptr + 1), FLUSHDATA);
			else
				flushq(q, FLUSHDATA);
		}
		break;
	}
	putnext(q, mp);
}


static struct module_info ldlinux_info = {
	LDLINUX_MODID,
	LDLINUX_MOD,
	0,
	INFPSZ,
	0,
	0
};

static struct qinit ldlinuxinit = {
	(int (*)()) ldlinuxput,
	NULL,
	ldlinuxopen,
	ldlinuxclose,
	NULL,
	&ldlinux_info
};

static struct streamtab ldlinuxinfo = {
	&ldlinuxinit,
	&ldlinuxinit
};

/*
 * Module linkage information for the kernel.
 */
static struct fmodsw fsw = {
	LDLINUX_MOD,
	&ldlinuxinfo,
	D_MTQPAIR | D_MP
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "termios extensions for lx brand", &fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
