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

#include	<stdio.h>
#include	<proc_service.h>
#include	<link.h>
#include	<rtld_db.h>
#include	<_rtld_db.h>
#include	<msg.h>


/*
 * A un-initialized PLT look like so:
 *
 * .PLT
 *	sethi	(.-.PLT0), %g1
 *	ba,a	.PLT0
 *	nop
 *
 * To test to see if this is an uninitialized PLT we check
 * the second instruction and confirm that it's a branch.
 */
/* ARGSUSED 2 */
rd_err_e
plt32_resolution(rd_agent_t *rap, psaddr_t pc, lwpid_t lwpid,
	psaddr_t pltbase, rd_plt_info_t *rpi)
{
	unsigned int	instr[4];
	rd_err_e	rerr;
	psaddr_t	destaddr = 0;
	psaddr_t	pltoff, pltaddr;
	int		pltbound = 0;

	pltoff = pc - pltbase;
	pltaddr = pltbase +
		((pltoff / M32_PLT_ENTSIZE) * M32_PLT_ENTSIZE);

	if (ps_pread(rap->rd_psp, pltaddr, (char *)instr,
	    M32_PLT_ENTSIZE) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2), EC_ADDR(pltaddr)));
		return (RD_ERR);
	}

	if (rtld_db_version >= RD_VERSION3) {
		rpi->pi_flags = 0;
		rpi->pi_baddr = 0;
	}

	if ((instr[0] != M_NOP) &&
	    ((instr[1] & (~(S_MASK(22)))) == M_BA_A)) {
		/*
		 * Unbound PLT
		 */
		if ((rerr = rd_binder_exit_addr(rap, MSG_ORIG(MSG_SYM_RTBIND),
		    &(rpi->pi_target))) != RD_OK) {
			return (rerr);
		}
		rpi->pi_skip_method = RD_RESOLVE_TARGET_STEP;
		rpi->pi_nstep = 1;
	} else if ((instr[2] & (~(S_MASK(13)))) == M_JMPL) {
		/*
		 * Resolved 32-bit PLT entry format (full-32):
		 *
		 * .PLT:
		 * 0	sethi	(.-PLT0), %g1
		 * 1	sethi	%hi(dest), %g1
		 * 2	jmpl	%g1 + lo(dest), %g0
		 * 3	nop
		 */
		rpi->pi_skip_method = RD_RESOLVE_STEP;
		rpi->pi_nstep = 4;
		rpi->pi_target = 0;
		if (rtld_db_version >= RD_VERSION3) {
			uint_t		hi_bits;
			uint_t		lo_bits;
			hi_bits = instr[1] & S_MASK(22); /* 31..10 */
			lo_bits = instr[2] & S_MASK(10); /* 09..00 */
			destaddr = (hi_bits << 10) | lo_bits;
			pltbound++;
		}
	} else  if ((instr[0] == M_NOP) &&
	    ((instr[1] & (~(S_MASK(22)))) == M_BA_A)) {
		/*
		 * Resolved 32-bit PLT entry format (b+-8mb):
		 * .PLT
		 * 0	nop
		 * 1	ba,a	<dest>
		 * 2	nop
		 * 3	nop
		 */
		rpi->pi_skip_method = RD_RESOLVE_STEP;
		rpi->pi_nstep = 2;
		rpi->pi_target = 0;
		if (rtld_db_version >= RD_VERSION3) {
			uint_t	d22;
			d22 = instr[1] & S_MASK(22);
			destaddr = ((int)pltaddr + 4) +
				(((int)d22 << 10) >> 8);
			pltbound++;
		}
	} else if ((instr[0] == M_NOP) &&
	    ((instr[1] & (~(S_MASK(19)))) == M_BA_A_PT)) {
		/*
		 * Resolved 32-bit PLT entry format (b+-2mb):
		 * .PLT
		 * 0	nop
		 * 1	ba,a,pt	%icc, <dest>
		 * 2	nop
		 * 3	nop
		 */
		rpi->pi_skip_method = RD_RESOLVE_STEP;
		rpi->pi_nstep = 2;
		rpi->pi_target = 0;
		if (rtld_db_version >= RD_VERSION3) {
			uint_t	d19;
			d19 = instr[1] & S_MASK(22);
			destaddr = ((int)pltaddr + 4) +
				(((int)d19 << 13) >> 11);
			pltbound++;
		}
	} else
		rpi->pi_skip_method = RD_RESOLVE_NONE;

	if ((rtld_db_version >= RD_VERSION3) && pltbound) {
		rpi->pi_flags |= RD_FLG_PI_PLTBOUND;
		rpi->pi_baddr = destaddr;
	}
	return (RD_OK);
}
