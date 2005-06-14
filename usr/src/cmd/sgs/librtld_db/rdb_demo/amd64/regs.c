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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>
#include <sys/reg.h>

#include "rdb.h"

static void
disp_reg_line(struct ps_prochandle *ph, pstatus_t *prst,
	char *r1, int ind1, char *r2, int ind2)
{
	char	str1[MAXPATHLEN];
	char	str2[MAXPATHLEN];
	strcpy(str1, print_address_ps(ph, prst->pr_lwp.pr_reg[ind1],
		FLG_PAP_NOHEXNAME));
	strcpy(str2, print_address_ps(ph, prst->pr_lwp.pr_reg[ind2],
		FLG_PAP_NOHEXNAME));

	printf("%8s: 0x%08x %-16s %8s: 0x%08x %-16s\n",
		r1, prst->pr_lwp.pr_reg[ind1], str1,
		r2, prst->pr_lwp.pr_reg[ind2], str2);
}


retc_t
display_all_regs(struct ps_prochandle *ph)
{
	pstatus_t	pstatus;
	if (pread(ph->pp_statusfd, &pstatus, sizeof (pstatus),
	    0) == -1) {
		perror("dar: reading status");
		return (RET_FAILED);
	}
	printf("registers:\n");
	disp_reg_line(ph, &pstatus, "gs", REG_GS, "fs", REG_FS);
	disp_reg_line(ph, &pstatus, "es", REG_ES, "ds", REG_DS);
	disp_reg_line(ph, &pstatus, "rdi", REG_RDI, "rsi", REG_RSI);
	disp_reg_line(ph, &pstatus, "rbp", REG_RBP, "rsp", REG_RSP);
	disp_reg_line(ph, &pstatus, "rbx", REG_RBX, "rdx", REG_RDX);
	disp_reg_line(ph, &pstatus, "rcx", REG_RCX, "rax", REG_RAX);
	disp_reg_line(ph, &pstatus, "trapno", REG_TRAPNO, "err", REG_ERR);
	disp_reg_line(ph, &pstatus, "rip", REG_RIP, "cs", REG_CS);
	disp_reg_line(ph, &pstatus, "rfl", REG_RFL, "uesp", REG_RSP);
	return (RET_OK);
}
