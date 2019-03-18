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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/zone.h>
#include <inet/common.h>
#include <inet/led.h>
#include <inet/nd.h>
#include <netinet/in.h>

#include "ncaconf.h"

extern caddr_t	nca_g_nd;	/* Head of 'named dispatch' variable list */

#define	INET_NAME	"nca"
#define	INET_MODSTRTAB	ncainfo
#define	INET_DEVSTRTAB	ncainfo
#define	INET_MODDESC	"NCA STREAMS module 1.6"
#define	INET_DEVDESC	"NCA STREAMS driver 1.6"
#define	INET_DEVMINOR	0
#define	INET_DEVMTFLAGS	D_MP
#define	INET_MODMTFLAGS	D_MP

#include "../inetddi.c"

/*ARGSUSED*/
static int
nca_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	/* Reopen supported */
	if (q->q_ptr != NULL)
		return (0);

	/*
	 * NCA is not supported in non-global zones; we enforce this restriction
	 * here.
	 */
	if (credp != NULL && crgetzoneid(credp) != GLOBAL_ZONEID) {
		return (ENOTSUP);
	}

	if (! (sflag & MODOPEN)) {
		/* Device instance */
		RD(q)->q_ptr = (void *)B_TRUE;
		WR(q)->q_ptr = (void *)B_TRUE;
	} else {
		/* Modopen just pass through */
		RD(q)->q_ptr = (void *)B_FALSE;
		WR(q)->q_ptr = (void *)B_FALSE;
	}
	qprocson(q);
	return (0);
}

/* ARGSUSED */
static int
nca_close(queue_t *q, int flags __unused, cred_t *credp __unused)
{
	qprocsoff(q);
	RD(q)->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	return (0);
}

static int
nca_rput(queue_t *q, mblk_t *mp)
{
	/* Passthrough */
	putnext(q, mp);
	return (0);
}

static int
nca_wput(queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocp;

	if (! (boolean_t)q->q_ptr) {
		iocp = (struct iocblk *)mp->b_rptr;
		if (DB_TYPE(mp) == M_IOCTL && iocp->ioc_cmd == NCA_SET_IF) {
			miocnak(q, mp, 0, ENOTSUP);
			return (0);
		}
		/* Module, passthrough */
		putnext(q, mp);
		return (0);
	}

	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case ND_SET:
		case ND_GET:
			if (! nd_getset(q, nca_g_nd, mp)) {
				miocnak(q, mp, 0, ENOENT);
				return (0);
			}
			qreply(q, mp);
			break;
		default:
			miocnak(q, mp, 0, ENOTSUP);
			break;
		}
		break;
	default:
		freemsg(mp);
		break;
	}
	return (0);
}

static struct module_info info = {
	0, "nca", 1, INFPSZ, 65536, 1024
};

static struct qinit rinit = {
	nca_rput, NULL, nca_open, nca_close, NULL, &info
};

static struct qinit winit = {
	nca_wput, NULL, nca_open, nca_close, NULL, &info
};

struct streamtab ncainfo = {
	&rinit, &winit
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
