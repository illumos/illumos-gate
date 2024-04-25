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
 * Copyright 2002 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "libproc.h"
#include "Pcontrol.h"
#include "Putil.h"


int
pr_meminfo(struct ps_prochandle *Pr, const uint64_t *addrs,
    int addr_count, const uint_t *info, int info_count,
    uint64_t *outdata, uint_t *validity)
{


	int error;
	sysret_t rval;
	argdes_t argd[7];
	argdes_t *adp = &argd[0];
	struct meminfo m;
#ifdef _LP64
	struct meminfo32 m32;
	int model;
#endif
	int retval = -1;
	uintptr_t inaddr, infoaddr, outaddr, validityaddr;
	size_t outarraysize, infoarraysize;
	size_t inarraysize, validityarraysize;
	size_t totalsize;
	char *totalmap = MAP_FAILED;

	inarraysize = addr_count * sizeof (uint64_t);
	outarraysize = sizeof (uint64_t) * addr_count * info_count;
	infoarraysize = info_count * sizeof (uint_t);
	validityarraysize = sizeof (uint_t) * addr_count;


	totalsize = inarraysize + outarraysize + infoarraysize +
	    validityarraysize;

	if ((totalmap  = pr_zmap(Pr, 0, totalsize, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE)) == MAP_FAILED) {
		Pdprintf("pr_meminfo: mmap failed\n");
		goto out;
	}

	inaddr = (uintptr_t)totalmap;

	outaddr = inaddr + inarraysize;

	infoaddr = outaddr + outarraysize;

	validityaddr = infoaddr + infoarraysize;

	if (Pwrite(Pr, addrs, inarraysize, inaddr) != inarraysize) {
		Pdprintf("pr_meminfo: Pwrite inaddr failed \n");
		goto out;
	}

	if (Pwrite(Pr, info, infoarraysize, infoaddr) !=
	    infoarraysize) {
		Pdprintf("pr_meminfo: Pwrite info failed \n");
		goto out;
	}

#ifdef _LP64
	model = Pr->status.pr_dmodel;
	if (model == PR_MODEL_ILP32) {
		m32.mi_info_count = info_count;
		m32.mi_inaddr = (caddr32_t)inaddr;
		m32.mi_outdata = (caddr32_t)outaddr;
		m32.mi_info_req = (caddr32_t)infoaddr;
		m32.mi_validity = (caddr32_t)validityaddr;
	} else
#endif
	{
		m.mi_info_count = info_count;
		m.mi_inaddr = (uint64_t *)inaddr;
		m.mi_outdata = (uint64_t *)outaddr;
		m.mi_info_req = (uint_t *)infoaddr;
		m.mi_validity = (uint_t *)validityaddr;
	}


	/*
	 * initial command
	 */

	adp->arg_value = MISYS_MEMINFO;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;

	/*
	 * length of input address vector
	 */

	adp->arg_value = addr_count;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;

	/*
	 * information wanted vector
	 */

	adp->arg_value = 0;
#ifdef _LP64
	if (model == PR_MODEL_ILP32) {
		adp->arg_object = &m32;
		adp->arg_size = sizeof (struct meminfo32);
	} else
#endif
	{
		adp->arg_object = &m;
		adp->arg_size = sizeof (struct meminfo);
	}
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;


	error = Psyscall(Pr,  &rval, SYS_meminfosys, 3, &argd[0]);

	if (error) {
		errno = (error > 0) ? error: ENOSYS;
		goto out;
	}

	/* syscall was successful, copy out the data */

	if ((Pread(Pr, outdata, outarraysize, outaddr)) != outarraysize) {
		Pdprintf("pr_meminfo: Pread of outarray failed\n");
		goto out;
	}

	if (Pread(Pr, validity, validityarraysize, validityaddr)
	    != validityarraysize) {
		Pdprintf("pr_meminfo: Pread of validity array failed\n");
		goto out;
	}

	retval = rval.sys_rval1;

out:

	if (totalmap != MAP_FAILED &&
	    pr_munmap(Pr, totalmap, totalsize) == -1) {
			Pdprintf("pr_meminfo: munmap failed\n");
			retval = -1;
		}

	return (retval);

}
