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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/logindmux_impl.h>

/*
 * Print our peer's upper queue pointer, and our lower queue pointer.
 */
void
logdmux_uqinfo(const queue_t *q, char *buf, size_t nbytes)
{
	struct tmx tmx;
	uintptr_t peer, lower;
	queue_t lq;

	/*
	 * First, get the pointer to our lower write queue.
	 */
	(void) mdb_vread(&tmx, sizeof (tmx), (uintptr_t)q->q_ptr);
	lower = (uintptr_t)tmx.muxq;

	/*
	 * Now read in the lower's peer, and follow that to up to our peer.
	 */
	(void) mdb_vread(&lq, sizeof (lq), (uintptr_t)tmx.peerq);
	(void) mdb_vread(&tmx, sizeof (tmx), (uintptr_t)lq.q_ptr);
	peer = (uintptr_t)tmx.rdq;

	(void) mdb_snprintf(buf, nbytes, "peer rq    : %p\nlower wq   : %p",
	    peer, lower);
}

/*
 * Print our peer's lower queue pointer, and our upper queue pointer.
 */
void
logdmux_lqinfo(const queue_t *q, char *buf, size_t nbytes)
{
	struct tmx tmx;

	(void) mdb_vread(&tmx, sizeof (tmx), (uintptr_t)q->q_ptr);
	(void) mdb_snprintf(buf, nbytes, "peer wq    : %p\nupper rq   : %p",
	    (uintptr_t)tmx.peerq, (uintptr_t)tmx.rdq);
}

uintptr_t
logdmux_lrnext(const queue_t *q)
{
	struct tmx tmx;

	(void) mdb_vread(&tmx, sizeof (tmx), (uintptr_t)q->q_ptr);
	return ((uintptr_t)tmx.rdq);
}

uintptr_t
logdmux_uwnext(const queue_t *q)
{
	struct tmx tmx;

	(void) mdb_vread(&tmx, sizeof (tmx), (uintptr_t)q->q_ptr);
	return ((uintptr_t)tmx.muxq);
}

static const mdb_qops_t logdmux_uqops = {
	.q_info = logdmux_uqinfo,
	.q_rnext = mdb_qrnext_default,
	.q_wnext = logdmux_uwnext,
};

static const mdb_qops_t logdmux_lqops = {
	.q_info = logdmux_lqinfo,
	.q_rnext = logdmux_lrnext,
	.q_wnext = mdb_qwnext_default
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION };

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj("logindmux", "logdmuxuwinit", &sym) == 0)
		mdb_qops_install(&logdmux_uqops, (uintptr_t)sym.st_value);
	if (mdb_lookup_by_obj("logindmux", "logdmuxlwinit", &sym) == 0)
		mdb_qops_install(&logdmux_lqops, (uintptr_t)sym.st_value);

	return (&modinfo);
}

void
_mdb_fini(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj("logindmux", "logdmuxuwinit", &sym) == 0)
		mdb_qops_remove(&logdmux_uqops, (uintptr_t)sym.st_value);
	if (mdb_lookup_by_obj("logindmux", "logdmuxlwinit", &sym) == 0)
		mdb_qops_remove(&logdmux_lqops, (uintptr_t)sym.st_value);
}
