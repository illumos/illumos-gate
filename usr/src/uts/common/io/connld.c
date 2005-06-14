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
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4 1.8	*/

/*
 * This module establishes a unique connection on
 * a STREAMS-based pipe.
 */
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/fstyp.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fs/fifonode.h>
#include <sys/debug.h>
#include <sys/ddi.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/conf.h>
#include <sys/modctl.h>

extern struct streamtab conninfo;

static struct fmodsw fsw = {
	"connld",
	&conninfo,
	D_NEW | D_MP
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "Streams-based pipes", &fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlstrmod, NULL
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

/*
 * Define local and external routines.
 */
int connopen(queue_t *, dev_t *, int, int, cred_t *);
int connclose(queue_t *, int, cred_t *);
int connput(queue_t *, mblk_t *);

/*
 * Define STREAMS header information.
 */
static struct module_info conn_info = {
	1003,
	"connld",
	0,
	INFPSZ,
	STRHIGH,
	STRLOW
};
static struct qinit connrinit = {
	connput,
	NULL,
	connopen,
	connclose,
	NULL,
	&conn_info,
	NULL
};
static struct qinit connwinit = {
	connput,
	NULL,
	NULL,
	NULL,
	NULL,
	&conn_info,
	NULL
};
struct streamtab conninfo = {
	&connrinit,
	&connwinit
};

/*
 * For each invocation of connopen(), create a new pipe. One end of the pipe
 * is sent to the process on the other end of this STREAM. The vnode for
 * the other end is returned to the open() system call as the vnode for
 * the opened object.
 *
 * On the first invocation of connopen(), a flag is set and the routine
 * returns 0, since the first open corresponds to the pushing of the module.
 */
/*ARGSUSED*/
int
connopen(queue_t *rqp, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	int error = 0;
	vnode_t *streamvp;
	fifonode_t *streamfnp;

	if ((streamvp = strq2vp(rqp)) == NULL) {
		return (EINVAL);
	}

	/*
	 * CONNLD is only allowed to be pushed onto a "pipe" that has both
	 * of its ends open.
	 */
	if (streamvp->v_type != VFIFO) {
		error = EINVAL;
		goto out;
	}

	streamfnp = VTOF(streamvp);

	if (!(streamfnp->fn_flag & ISPIPE) ||
	    streamfnp->fn_dest->fn_open == 0) {
		error = EPIPE;
		goto out;
	}

	/*
	 * If this is the first time CONNLD was opened while on this stream,
	 * it is being pushed. Therefore, set a flag and return 0.
	 */
	if (rqp->q_ptr == 0) {
		if (streamfnp->fn_flag & FIFOCONNLD) {
			error = ENXIO;
			goto out;
		}
		rqp->q_ptr = (caddr_t)1;
		streamfnp->fn_flag |= FIFOCONNLD;
		qprocson(rqp);
	}
out:
	VN_RELE(streamvp);
	return (error);
}

/*ARGSUSED*/
int
connclose(queue_t *q, int cflag, cred_t *crp)
{
	vnode_t *streamvp;
	fifonode_t *streamfnp;

	qprocsoff(q);
	streamvp = strq2vp(q);

	ASSERT(streamvp != NULL);
	ASSERT(streamvp->v_type == VFIFO);

	streamfnp = VTOF(streamvp);
	streamfnp->fn_flag &= ~FIFOCONNLD;
	VN_RELE(streamvp);
	return (0);
}

/*
 * Use same put procedure for write and read queues.
 */
int
connput(queue_t *q, mblk_t *bp)
{
	putnext(q, bp);
	return (0);
}
