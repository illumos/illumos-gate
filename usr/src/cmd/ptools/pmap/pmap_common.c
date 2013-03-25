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
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <stdio.h>
#include <strings.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pmap_common.h"

/*
 * We compare the high memory addresses since stacks are faulted in from
 * high memory addresses to low memory addresses, and our prmap_t
 * structures identify only the range of addresses that have been faulted
 * in so far.
 */
int
cmpstacks(const void *ap, const void *bp)
{
	const lwpstack_t *as = ap;
	const lwpstack_t *bs = bp;
	uintptr_t a = (uintptr_t)as->lwps_stack.ss_sp + as->lwps_stack.ss_size;
	uintptr_t b = (uintptr_t)bs->lwps_stack.ss_sp + bs->lwps_stack.ss_size;

	if (a < b)
		return (1);
	if (a > b)
		return (-1);
	return (0);
}

/*
 * Create labels for non-anon, non-heap mappings
 */
char *
make_name(struct ps_prochandle *Pr, int lflag, uintptr_t addr,
    const char *mapname, char *buf, size_t bufsz)
{
	const pstatus_t		*Psp = Pstatus(Pr);
	struct stat		statb;
	char			path[PATH_MAX];
	int			len;

	if (lflag || Pstate(Pr) == PS_DEAD) {
		if (Pobjname(Pr, addr, buf, bufsz) != NULL)
			return (buf);
	} else {
		if (Pobjname_resolved(Pr, addr, buf, bufsz) != NULL) {
			/* Verify that the path exists */
			if ((len = resolvepath(buf, buf, bufsz)) > 0) {
				buf[len] = '\0';
				return (buf);
			}
		}
	}

	if (Pstate(Pr) == PS_DEAD || *mapname == '\0')
		return (NULL);

	/* first see if we can find a path via /proc */
	(void) snprintf(path, sizeof (path), "/proc/%d/path/%s",
	    (int)Psp->pr_pid, mapname);
	len = readlink(path, buf, bufsz - 1);
	if (len >= 0) {
		buf[len] = '\0';
		return (buf);
	}

	/* fall back to object information reported by /proc */
	(void) snprintf(path, sizeof (path),
	    "/proc/%d/object/%s", (int)Psp->pr_pid, mapname);
	if (stat(path, &statb) == 0) {
		dev_t dev = statb.st_dev;
		ino_t ino = statb.st_ino;
		(void) snprintf(buf, bufsz, "dev:%lu,%lu ino:%lu",
		    (ulong_t)major(dev), (ulong_t)minor(dev), ino);
		return (buf);
	}

	return (NULL);
}

/*
 * Create label for anon mappings
 */
char *
anon_name(char *name, const pstatus_t *Psp, lwpstack_t *stacks, uint_t nstacks,
    uintptr_t vaddr, size_t size, int mflags, int shmid, int *mtypesp)
{
	int mtypes = 0;

	if (mflags & MA_ISM) {
		if (shmid == -1)
			(void) snprintf(name, PATH_MAX, "  [ %s shmid=null ]",
			    (mflags & MA_NORESERVE) ? "ism" : "dism");
		else
			(void) snprintf(name, PATH_MAX, "  [ %s shmid=0x%x ]",
			    (mflags & MA_NORESERVE) ? "ism" : "dism", shmid);
		mtypes |= (1 << AT_SHARED);
	} else if (mflags & MA_SHM) {
		if (shmid == -1)
			(void) sprintf(name, "  [ shmid=null ]");
		else
			(void) sprintf(name, "  [ shmid=0x%x ]", shmid);
		mtypes |= (1 << AT_SHARED);
	} else if (vaddr + size > Psp->pr_stkbase &&
	    vaddr < Psp->pr_stkbase + Psp->pr_stksize) {
		(void) strcpy(name, "  [ stack ]");
		mtypes |= (1 << AT_STACK);
	} else if ((mflags & MA_ANON) &&
	    vaddr + size > Psp->pr_brkbase &&
	    vaddr < Psp->pr_brkbase + Psp->pr_brksize) {
		(void) strcpy(name, "  [ heap ]");
		mtypes |= (1 << AT_HEAP);
	} else {
		lwpstack_t key, *stk;

		key.lwps_stack.ss_sp = (void *)vaddr;
		key.lwps_stack.ss_size = size;
		if (nstacks > 0 &&
		    (stk = bsearch(&key, stacks, nstacks, sizeof (stacks[0]),
		    cmpstacks)) != NULL) {
			(void) snprintf(name, PATH_MAX, "  [ %s tid=%d ]",
			    (stk->lwps_stack.ss_flags & SS_ONSTACK) ?
			    "altstack" : "stack",
			    stk->lwps_lwpid);
			mtypes |= (1 << AT_STACK);
		} else {
			(void) strcpy(name, "  [ anon ]");
			mtypes |= (1 << AT_PRIVM);
		}
	}

	if (mtypesp)
		*mtypesp = mtypes;
	return (name);
}
