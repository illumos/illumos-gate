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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/vtrace.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/socketvar.h>

#include <inet/kssl/ksslapi.h>


/*
 * This routine is registered with the stream head to be called by kstrgetmsg()
 * with every packet received on the read queue, and before copying its
 * content to user buffers. kstrgetmsg() calls only once with the same
 * message.
 * If the message is successfully procssed, then it is returned.
 * A failed message will be freed.
 */
/* ARGSUSED */
mblk_t *
strsock_kssl_input(vnode_t *vp, mblk_t *mp,
		strwakeup_t *wakeups, strsigset_t *firstmsgsigs,
		strsigset_t *allmsgsigs, strpollset_t *pollwakeups)
{
	struct sonode *so = VTOSO(vp);
	kssl_ctx_t kssl_ctx = so->so_kssl_ctx;
	kssl_cmd_t kssl_cmd;
	mblk_t *out;

	dprintso(so, 1, ("strsock_kssl_input(%p, %p)\n", vp, mp));

	kssl_cmd = kssl_handle_mblk(kssl_ctx, &mp, &out);

	switch (kssl_cmd) {
	case KSSL_CMD_NONE:
		return (NULL);

	case KSSL_CMD_DELIVER_PROXY:
		return (mp);

	case KSSL_CMD_SEND: {
		ASSERT(out != NULL);

		putnext(vp->v_stream->sd_wrq, out);
	}
	/* FALLTHRU */
	default:
		/* transient error. */
		return (NULL);
	}
}

/*
 * This routine is registered with the stream head be called by
 * kstrmakedata() with every packet sent downstreams.
 * If the message is successfully processed, then it is returned.
 */
/* ARGSUSED */
mblk_t *
strsock_kssl_output(vnode_t *vp, mblk_t *mp,
		strwakeup_t *wakeups, strsigset_t *firstmsgsigs,
		strsigset_t *allmsgsigs, strpollset_t *pollwakeups)
{
	struct sonode *so = VTOSO(vp);
	kssl_ctx_t kssl_ctx = so->so_kssl_ctx;
	mblk_t *recmp;

	dprintso(so, 1, ("strsock_kssl_output(%p, %p)\n", vp, mp));

	if ((recmp = kssl_build_record(kssl_ctx, mp)) == NULL) {
		/* The caller will free the bogus message */
		return (NULL);
	}
	return (recmp);
}
