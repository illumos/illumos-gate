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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/errno.h>

#include <rpc/auth.h>
#include <rpc/svc.h>

#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsvers.h>
#include "rdc_stub.h"

static void null_dispatch(struct svc_req *req, SVCXPRT *xprt);
static void (*dispatch)(struct svc_req *, SVCXPRT *) = null_dispatch;

/*
 * Solaris module setup.
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,   /* Type of module */
	"nws:Remote Mirror kRPC Stub:" ISS_VERSION_STR
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}


int
_fini(void)
{
	/* unload is forbidden */
	return (EBUSY);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * rdcstub_dispatch is the place holder for rdcsrv_dispatch.
 * rdcsrv registers this function as kRPC dispatch function.
 * If rdcsrv is unloaded (uninstall package), then dispatch
 * is set to null_dispatch
 */
void
rdcstub_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	(*dispatch)(req, xprt);
}

/* ARGSUSED */
static void
null_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	svcerr_noproc(xprt);
}

void
rdcstub_set_dispatch(void (*disp)(struct svc_req *, SVCXPRT *))
{
	ASSERT(disp != NULL);
	dispatch = disp;
}

void
rdcstub_unset_dispatch()
{
	dispatch = null_dispatch;
}
