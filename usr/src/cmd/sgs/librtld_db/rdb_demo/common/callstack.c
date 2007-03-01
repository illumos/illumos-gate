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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <procfs.h>

#include "rdb.h"

#ifndef	STACK_BIAS
#define	STACK_BIAS	0
#endif

static int
get_frame(struct ps_prochandle *ph, psaddr_t fp, struct frame *frm)
{
#if	defined(_LP64)
	/*
	 * Use special structures to read a 32-bit process
	 * from a 64-bit process.
	 */
	if (ph->pp_dmodel == PR_MODEL_ILP32) {
		struct frame32	frm32;

		if (ps_pread(ph, (psaddr_t)fp, (char *)&frm32,
		    sizeof (struct frame32)) != PS_OK) {
			printf("stack trace: bad frame pointer: 0x%lx\n",
				fp);
			return (-1);
		}

		frm->fr_savpc = (long)frm32.fr_savpc;
#if	defined(__sparcv9)
		frm->fr_savfp = (struct frame *)(uintptr_t)frm32.fr_savfp;
#elif	defined(__amd64)
		frm->fr_savfp = (long)frm32.fr_savfp;
#endif
		return (0);
	}
#endif	/* defined(_LP64) */

	if (ps_pread(ph, (psaddr_t)fp + STACK_BIAS, (char *)frm,
	    sizeof (struct frame)) != PS_OK) {
		printf("stack trace: bad frame pointer: 0x%lx\n", fp);
		return (-1);
	}
	return (0);
}

/*
 * Relatively architecture neutral routine to display the callstack.
 */
void
CallStack(struct ps_prochandle *ph)
{
	pstatus_t	pstatus;
	greg_t		fp;
	struct frame	frm;
	char		*symstr;

	if (pread(ph->pp_statusfd, &pstatus, sizeof (pstatus), 0) == -1)
		perr("cs: reading status");

	symstr = print_address_ps(ph, (ulong_t)pstatus.pr_lwp.pr_reg[R_PC],
		FLG_PAP_SONAME);
	printf(" 0x%08lx:%-17s\n", pstatus.pr_lwp.pr_reg[R_PC],
		symstr);

	fp = pstatus.pr_lwp.pr_reg[R_FP];

	while (fp) {
		if (get_frame(ph, (psaddr_t)fp, &frm) == -1)
			return;
		if (frm.fr_savpc) {
			symstr = print_address_ps(ph, (ulong_t)frm.fr_savpc,
				FLG_PAP_SONAME);
			printf(" 0x%08lx:%-17s\n", frm.fr_savpc,
				symstr);
		}
		fp = (greg_t)frm.fr_savfp;
	}
}
