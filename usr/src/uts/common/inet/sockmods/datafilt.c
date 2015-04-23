/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 */

/*
 * This file implements a socketfilter used to deter TCP connections.
 * To defer a connection means to delay the return of accept(3SOCKET)
 * until at least one byte is ready to be read(2). This filter may be
 * applied automatically or programmatically through the use of
 * soconfig(1M) and setsockopt(3SOCKET).
 */

#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/socketvar.h>
#include <sys/sockfilter.h>
#include <sys/note.h>
#include <sys/taskq.h>

#define	DATAFILT_MODULE "datafilt"

static struct modlmisc dataf_modlmisc = {
	&mod_miscops,
	"Kernel data-ready socket filter"
};

static struct modlinkage dataf_modlinkage = {
	MODREV_1,
	&dataf_modlmisc,
	NULL
};

static sof_rval_t
dataf_attach_passive_cb(sof_handle_t handle, sof_handle_t ph,
    void *parg, struct sockaddr *laddr, socklen_t laddrlen,
    struct sockaddr *faddr, socklen_t faddrlen, void **cookiep)
{
	_NOTE(ARGUNUSED(handle, ph, parg, laddr, laddrlen, faddr, faddrlen,
	cookiep));
	return (SOF_RVAL_DEFER);
}

static void
dataf_detach_cb(sof_handle_t handle, void *cookie, cred_t *cr)
{
	_NOTE(ARGUNUSED(handle, cookie, cr));
}

static mblk_t *
dataf_data_in_cb(sof_handle_t handle, void *cookie, mblk_t *mp, int flags,
    size_t *lenp)
{
	_NOTE(ARGUNUSED(cookie, flags, lenp));

	if (mp != NULL && MBLKL(mp) > 0) {
		sof_newconn_ready(handle);
		sof_bypass(handle);
	}

	return (mp);
}

static sof_ops_t dataf_ops = {
	.sofop_attach_passive = dataf_attach_passive_cb,
	.sofop_detach = dataf_detach_cb,
	.sofop_data_in = dataf_data_in_cb
};

int
_init(void)
{
	int err;

	/*
	 * This module is safe to attach even after some preliminary socket
	 * setup calls have taken place. See the comment for SOF_ATT_SAFE.
	 */
	err = sof_register(SOF_VERSION, DATAFILT_MODULE, &dataf_ops,
	    SOF_ATT_SAFE);
	if (err != 0)
		return (err);
	if ((err = mod_install(&dataf_modlinkage)) != 0)
		(void) sof_unregister(DATAFILT_MODULE);

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = sof_unregister(DATAFILT_MODULE)) != 0)
		return (err);

	return (mod_remove(&dataf_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&dataf_modlinkage, modinfop));
}
