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

/*
 * Redirection STREAMS module.
 *
 * This module is intended for use in conjunction with instantiations of the
 * redirection driver.  Its purpose in life is to detect when the stream that
 * it's pushed on is closed, thereupon calling back into the redirection
 * driver so that the driver can cancel redirection to the stream.
 * It passes all messages on unchanged, in both directions.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/debug.h>
#include <sys/strredir.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

/*
 * Forward declarations for private routines.
 */
static int	wcmopen(queue_t	*, dev_t *, int, int, cred_t *);
static int	wcmclose(queue_t *, int, cred_t *);
static int	wcmrput(queue_t *, mblk_t *);
static int	wcmwput(queue_t *, mblk_t *);

static struct module_info	wcminfo = {
	STRREDIR_MODID,
	STRREDIR_MOD,
	0,
	INFPSZ,
	5120,
	1024
};

static struct qinit	wcmrinit = {
	wcmrput,		/* put */
	NULL,			/* service */
	wcmopen,		/* open */
	wcmclose,		/* close */
	NULL,			/* qadmin */
	&wcminfo,
	NULL			/* mstat */
};

static struct qinit	wcmwinit = {
	wcmwput,		/* put */
	NULL,			/* service */
	wcmopen,		/* open */
	wcmclose,		/* close */
	NULL,			/* qadmin */
	&wcminfo,
	NULL			/* mstat */
};

static struct streamtab	redirminfo = {
	&wcmrinit,
	&wcmwinit,
	NULL,
	NULL
};

static struct fmodsw fsw = {
	"redirmod",
	&redirminfo,
	D_MP
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"redirection module",
	&fsw
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
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
wcmopen(queue_t *q, dev_t *dev, int flag, int sflag, cred_t *cred)
{
	if (sflag != MODOPEN)
		return (EINVAL);
	qprocson(q);
	return (0);
}

/* ARGSUSED */
static int
wcmclose(queue_t *q, int flag, cred_t *cred)
{
	qprocsoff(q);
	srpop(q->q_stream->sd_vnode, B_TRUE);
	return (0);
}

/*
 * Upstream messages are passed unchanged.
 * If a hangup occurs the target is no longer usable, so deprecate it.
 */
static int
wcmrput(queue_t *q, mblk_t *mp)
{
	if (DB_TYPE(mp) == M_HANGUP)
		/* Don't block waiting for outstanding operations to complete */
		srpop(q->q_stream->sd_vnode, B_FALSE);
	putnext(q, mp);
	return (0);
}

static int
wcmwput(queue_t *q, mblk_t *mp)
{
	putnext(q, mp);
	return (0);
}
