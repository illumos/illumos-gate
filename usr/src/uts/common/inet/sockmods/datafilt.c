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
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/socketvar.h>
#include <sys/sockfilter.h>
#include <sys/note.h>
#include <sys/taskq.h>

static struct modlmisc dataf_modlmisc = {
	&mod_miscops,
	"Kernel data-ready socket filter"
};

static struct modlinkage dataf_modlinkage = {
	MODREV_1,
	&dataf_modlmisc,
	NULL
};

#define	DATAFILT_MODULE "datafilt"

/* ARGSUSED */
sof_rval_t
dataf_attach_passive_cb(sof_handle_t handle, sof_handle_t ph,
    void *parg, struct sockaddr *laddr, socklen_t laddrlen,
    struct sockaddr *faddr, socklen_t faddrlen, void **cookiep)
{
	return (SOF_RVAL_DEFER);
}

void
dataf_detach_cb(sof_handle_t handle, void *cookie, cred_t *cr)
{
	_NOTE(ARGUNUSED(handle, cookie, cr));
}

/*
 * Called for each incoming segment.
 */
mblk_t *
dataf_data_in_cb(sof_handle_t handle, void *cookie, mblk_t *mp, int flags,
    size_t *lenp)
{
	_NOTE(ARGUNUSED(cookie, flags, lenp));

	if (mp != NULL && MBLKL(mp) > 0)
		sof_newconn_ready(handle);

	return (mp);
}

sof_ops_t dataf_ops = {
	.sofop_attach_passive = dataf_attach_passive_cb,
	.sofop_detach = dataf_detach_cb,
	.sofop_data_in = dataf_data_in_cb
};

int
_init(void)
{
	int error;

	/*
	 * This module is safe to attach even after some preliminary socket
	 * setup calls have taken place. See the comment for SOF_ATT_SAFE.
	 */
	error = sof_register(SOF_VERSION, DATAFILT_MODULE, &dataf_ops,
	    SOF_ATT_SAFE);
	if (error != 0)
		return (error);
	if ((error = mod_install(&dataf_modlinkage)) != 0)
		(void) sof_unregister(DATAFILT_MODULE);

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = sof_unregister(DATAFILT_MODULE)) != 0)
		return (error);

	return (mod_remove(&dataf_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&dataf_modlinkage, modinfop));
}
