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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interfaces that deal with loadobjects (shared objects) in target
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <link.h>
#include <unistd.h>
#include <sys/procfs.h>

#include "tnfctl.h"
#include "prb_proc_int.h"
#include "dbg.h"

/*
 * iterate over all loadobjects calling the callback function "obj_func"
 * for every loadobject with information about the loadobject.
 */
prb_status_t
prb_loadobj_iter(prb_proc_ctl_t *proc_p, prb_loadobj_f *obj_func, void *cd)
{
	prb_status_t	prbstat;
	Elf3264_Dyn	dentry;
	struct r_debug	r_dbg;
	uintptr_t	lmapaddr;
	struct link_map lmap;
	prb_loadobj_t	loadobj;
	int		retval = 0;

	DBG_TNF_PROBE_0(prb_loadobj_iter_start, "libtnfctl",
			"start prb_loadobj_iter; sunw%verbosity 1");

	if (proc_p->dbgaddr == 0) {
		DBG((void) fprintf(stderr,
			"prb_loadobj_iter: dbgaddr not set\n"));
		return (PRB_STATUS_BADARG);
	}

	prbstat = prb_proc_read(proc_p, proc_p->dbgaddr, &dentry,
				sizeof (dentry));
	if (prbstat || !dentry.d_un.d_ptr) {
		DBG((void) fprintf(stderr,
			"prb_lmap_update: error in d_un.d_ptr\n"));
		return (prbstat);
	}
	/* read in the debug struct that it points to */
	prbstat = prb_proc_read(proc_p, dentry.d_un.d_ptr,
		&r_dbg, sizeof (r_dbg));
	if (prbstat)
		return (prbstat);

	DBG_TNF_PROBE_1(prb_loadobj_iter_1, "libtnfctl", "sunw%verbosity 1",
		tnf_string, link_map_state,
		(r_dbg.r_state == RT_CONSISTENT) ? "RT_CONSISTENT" :
			(r_dbg.r_state == RT_ADD) ? "RT_ADD" : "RT_DELETE");

	/* if the link map is not consistent, bail now */
	if (r_dbg.r_state != RT_CONSISTENT)
		return (PRB_STATUS_BADLMAPSTATE);

	lmap.l_next = NULL;			/* makes lint happy */

	for (lmapaddr = (uintptr_t) r_dbg.r_map; lmapaddr;
		lmapaddr = (uintptr_t) lmap.l_next) {

		prbstat = prb_proc_read(proc_p, lmapaddr, &lmap, sizeof (lmap));
		if (prbstat)
			return (prbstat);

		loadobj.text_base = lmap.l_addr;
		loadobj.data_base = lmap.l_addr;
		loadobj.objname = NULL;
		/*
		 * client of this interface should deal with -1 for objfd,
		 * so no error checking is needed on this ioctl
		 */
		loadobj.objfd = ioctl(proc_p->procfd, PIOCOPENM, &lmap.l_addr);

		(void) prb_proc_readstr(proc_p, (uintptr_t) lmap.l_name,
						&loadobj.objname);
		retval = obj_func(proc_p, &loadobj, cd);
		if (loadobj.objname)
			free((char *)loadobj.objname);
		if (loadobj.objfd != -1)
			close(loadobj.objfd);
		/* check for error */
		if (retval == 1)
			return (PRB_STATUS_BADARG);
	}

	DBG_TNF_PROBE_0(prb_loadobj_iter_end, "libtnfctl",
			"end prb_loadobj_iter; sunw%verbosity 1");
	return (PRB_STATUS_OK);
}

/*
 * Return a fd for the main executable and also the address of where
 * it was mapped.
 */
prb_status_t
prb_mainobj_get(prb_proc_ctl_t *proc_p, int *objfd, uintptr_t *baseaddr)
{
	int		procfd;
	int		retfd;


	procfd = proc_p->procfd;
again:
	retfd = ioctl(procfd, PIOCOPENM, 0);
	if (retfd < 0) {
		if (errno == EINTR)
			goto again;
		DBG((void) fprintf(stderr,
			"prb_mainobj_get: PIOCOPENM failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	*objfd = retfd;
	*baseaddr = 0;

	return (PRB_STATUS_OK);
}
