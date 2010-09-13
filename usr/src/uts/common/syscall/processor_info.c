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
 * Copyright (c) 1992, 1994, 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/kstat.h>
#include <sys/uadmin.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/debug.h>

/*
 * processor_info(2) - return information on a processor.
 */
int
processor_info(processorid_t cpun, processor_info_t *infop)
{
	cpu_t *cp;
	processor_info_t temp;

	mutex_enter(&cpu_lock);
	if ((cp = cpu_get(cpun)) == NULL) {
		mutex_exit(&cpu_lock);
		return (set_errno(EINVAL));
	}
	bcopy(&cp->cpu_type_info, &temp, sizeof (temp));
	mutex_exit(&cpu_lock);

	/*
	 * The spec indicates that the rest of the information is meaningless
	 * if the CPU is offline, but if presented by the machine-dependent
	 * layer, it is probably still accurate.  It seems OK to copy it all in
	 * either case.
	 */
	if (copyout((caddr_t)&temp, (caddr_t)infop,
	    sizeof (processor_info_t)))
		return (set_errno(EFAULT));

	return (0);
}
