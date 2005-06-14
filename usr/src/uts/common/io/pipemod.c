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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module switches the read and write flush bits for each
 * M_FLUSH control message it receives. It's intended usage is to
 * properly flush a STREAMS-based pipe.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/stropts.h>

#include <sys/conf.h>
#include <sys/modctl.h>

/*ARGSUSED*/
static int
pipeopen(queue_t *rqp, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	qprocson(rqp);
	return (0);
}

/*ARGSUSED*/
static int
pipeclose(queue_t *q, int cflag, cred_t *crp)
{
	qprocsoff(q);
	return (0);
}

/*
 * Use same put procedure for write and read queues.
 * If mp is an M_FLUSH message, switch the FLUSHW to FLUSHR and
 * the FLUSHR to FLUSHW and send the message on.  If mp is not an
 * M_FLUSH message, send it on with out processing.
 */
static int
pipeput(queue_t *qp, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		if (!(*mp->b_rptr & FLUSHR && *mp->b_rptr & FLUSHW)) {
			if (*mp->b_rptr & FLUSHW) {
				*mp->b_rptr |= FLUSHR;
				*mp->b_rptr &= ~FLUSHW;
			} else {
				*mp->b_rptr |= FLUSHW;
				*mp->b_rptr &= ~FLUSHR;
			}
		}
		break;

	default:
		break;
	}
	putnext(qp, mp);
	return (0);
}

static struct module_info pipe_info = {
	1003, "pipemod", 0, INFPSZ, STRHIGH, STRLOW
};

static struct qinit piperinit = {
	pipeput, NULL, pipeopen, pipeclose, NULL, &pipe_info, NULL
};

static struct qinit pipewinit = {
	pipeput, NULL, NULL, NULL, NULL, &pipe_info, NULL
};

static struct streamtab pipeinfo = { &piperinit, &pipewinit, NULL, NULL };

static struct fmodsw fsw = {
	"pipemod",
	&pipeinfo,
	D_NEW | D_MP
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "pipe flushing module", &fsw
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
