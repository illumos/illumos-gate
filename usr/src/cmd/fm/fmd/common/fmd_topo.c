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

/*
 * FMD Topology Handling
 *
 * Fault manager scheme and module plug-ins may need access to the latest
 * libtopo snapshot.  Upon fmd initialization, a snapshot is taken and
 * made available via fmd_fmri_topology() and fmd_hdl_topology().  Each
 * of these routines returns a libtopo snapshot handle back to the caller.
 * New snapshots are taken if and when a DR event causes the DR generation
 * number to increase.  The current snapshot is retained to assure consistency
 * for modules still using older snapshots and the latest snapshot handle is
 * returned to the caller.
 */

#include <fmd_alloc.h>
#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd_topo.h>
#include <fmd.h>

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>

static void
fmd_topo_update(void)
{
	int err;
	topo_hdl_t *tp;
	fmd_topo_t *ftp;
	char *id;
	const char *name;

	ASSERT(MUTEX_HELD(&fmd.d_topo_lock));

	name = fmd.d_rootdir != NULL &&
	    *fmd.d_rootdir != '\0' ? fmd.d_rootdir : NULL;

	/*
	 * Update the topology snapshot.
	 */
	if ((tp = topo_open(TOPO_VERSION, name, &err)) == NULL)
		fmd_panic("failed to open topology library: %s",
		    topo_strerror(err));

	if ((id = topo_snap_hold(tp, NULL, &err)) == NULL)
		fmd_panic("failed to get topology snapshot: %s",
		    topo_strerror(err));

	topo_hdl_strfree(tp, id);

	ftp = fmd_alloc(sizeof (fmd_topo_t), FMD_SLEEP);
	ftp->ft_hdl = tp;
	fmd.d_stats->ds_topo_gen.fmds_value.ui64++;
	fmd_list_prepend(&fmd.d_topo_list, ftp);

}

topo_hdl_t *
fmd_topo_handle(int version)
{
	uint64_t curgen;
	fmd_topo_t *ftp;

	if (version != TOPO_VERSION)
		return (NULL);

	(void) pthread_mutex_lock(&fmd.d_topo_lock);
	if ((curgen = fmd_fmri_get_drgen()) >
	    fmd.d_stats->ds_topo_drgen.fmds_value.ui64) {
		fmd.d_stats->ds_topo_drgen.fmds_value.ui64 = curgen;
		fmd_topo_update();
	}
	ftp = fmd_list_next(&fmd.d_topo_list);
	(void) pthread_mutex_unlock(&fmd.d_topo_lock);

	return ((topo_hdl_t *)ftp->ft_hdl);
}

void
fmd_topo_init(void)
{
	(void) pthread_mutex_lock(&fmd.d_topo_lock);
	fmd_topo_update();
	(void) pthread_mutex_unlock(&fmd.d_topo_lock);
}

void
fmd_topo_fini(void)
{
	fmd_topo_t *ftp;

	(void) pthread_mutex_lock(&fmd.d_topo_lock);
	while ((ftp = fmd_list_next(&fmd.d_topo_list)) != NULL) {
		fmd_list_delete(&fmd.d_topo_list, ftp);
		topo_close(ftp->ft_hdl);
		fmd_free(ftp, sizeof (fmd_topo_t));
	}
	(void) pthread_mutex_unlock(&fmd.d_topo_lock);
}
