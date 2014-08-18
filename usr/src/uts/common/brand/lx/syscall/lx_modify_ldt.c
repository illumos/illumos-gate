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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/segments.h>
#include <sys/archsystm.h>
#include <sys/proc.h>
#include <sys/sysi86.h>
#include <sys/cmn_err.h>
#include <sys/lx_ldt.h>

/*
 * Read the ldt_info structure in from the Linux app, convert it to an ssd
 * structure, and then call setdscr() to do all the heavy lifting.
 */
static int
write_ldt(void *data, ulong_t count)
{
	user_desc_t usd;
	struct ssd ssd;
	struct ldt_info ldt_inf;
	proc_t *pp = curthread->t_procp;
	int err;

	if (count != sizeof (ldt_inf))
		return (set_errno(EINVAL));

	if (copyin(data, &ldt_inf, sizeof (ldt_inf)))
		return (set_errno(EFAULT));

	if (ldt_inf.entry_number >= MAXNLDT)
		return (set_errno(EINVAL));

	LDT_INFO_TO_DESC(&ldt_inf, &usd);
	usd_to_ssd(&usd, &ssd, SEL_LDT(ldt_inf.entry_number));

	/*
	 * Get everyone into a safe state before changing the LDT.
	 */
	if (!holdlwps(SHOLDFORK1))
		return (set_errno(EINTR));

	err = setdscr(&ssd);

	/*
	 * Release the hounds!
	 */
	mutex_enter(&pp->p_lock);
	continuelwps(pp);
	mutex_exit(&pp->p_lock);

	return (err ? set_errno(err) : 0);
}

static int
read_ldt(void *uptr, ulong_t count)
{
	proc_t *pp = curproc;
	int bytes;

	if (pp->p_ldt == NULL)
		return (0);

	bytes = (pp->p_ldtlimit + 1) * sizeof (user_desc_t);
	if (bytes > count)
		bytes = count;

	if (copyout(pp->p_ldt, uptr, bytes))
		return (set_errno(EFAULT));

	return (bytes);
}

long
lx_modify_ldt(int op, void *data, ulong_t count)
{
	int rval;

	switch (op) {
	case 0:
		rval = read_ldt(data, count);
		break;

	case 1:
		rval = write_ldt(data, count);
		break;

	default:
		rval = set_errno(ENOSYS);
		break;
	}

	return (rval);
}
