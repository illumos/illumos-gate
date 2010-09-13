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

#include	<proc_service.h>
#include	<link.h>
#include	<rtld_db.h>
#include	<_rtld_db.h>
#include	<msg.h>

/*
 * A un-initialized SPARCV9 PLT look like so:
 *
 * .PLT
 *	sethi	(. - .PLT0), %g1
 *	ba,a	%xcc, .PLT1
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *
 * To test to see if this is an uninitialized PLT we check
 * the second instruction and confirm that it's a branch.
 */
/* ARGSUSED 2 */
rd_err_e
plt64_resolution(rd_agent_t *rap, psaddr_t pc, lwpid_t lwpid,
	psaddr_t pltbase, rd_plt_info_t *rpi)
{
	instr_t		instr[8];
	rd_err_e	rerr;
	psaddr_t	destaddr = 0;
	psaddr_t	pltoff;
	int		pltbound = 0;

	if (rtld_db_version >= RD_VERSION3) {
		rpi->pi_flags = 0;
		rpi->pi_baddr = 0;
	}

	pltoff = pc - pltbase;

	if (pltoff >= (M64_PLT_NEARPLTS * M64_PLT_ENTSIZE)) {
		psaddr_t	pltptr, pltptrval;
		psaddr_t	pltaddr;
		psaddr_t	pltblockoff;

		/*
		 * Handle far PLT's
		 *
		 * .PLT#
		 * 0	mov	%o7, %g5
		 * 1	call	. + 8
		 * 2	nop
		 * 3	ldx	[%o7 + (.PLTP# - .PLT#+4)], %g1
		 * 4	jmpl	%o7 + %g1, %g1
		 * 5	mov	%g5, %o7
		 */

		pltblockoff = pltoff - (M64_PLT_NEARPLTS * M64_PLT_ENTSIZE);
		pltblockoff =
			((pltblockoff / M64_PLT_FBLOCKSZ) * M64_PLT_FBLOCKSZ) +
			(((pltblockoff % M64_PLT_FBLOCKSZ) / M64_PLT_FENTSIZE) *
			M64_PLT_FENTSIZE);


		pltaddr = pltbase + (M64_PLT_NEARPLTS * M64_PLT_ENTSIZE) +
			pltblockoff;

		if (ps_pread(rap->rd_psp, pltaddr, (char *)instr,
		    M64_PLT_FENTSIZE) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2),
				EC_ADDR(pltaddr)));
			return (RD_ERR);

		}

		if (instr[0] != M_MOVO7TOG5) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_BADFPLT),
				EC_ADDR(pltaddr), EC_ADDR(instr[0])));
			return (RD_ERR);
		}

		/*
		 * the offset is a positive displacement from the
		 * ldx [%o7 + #], %g1 instruction.  So - we don't
		 * need to worry about the sign bit :)
		 */
		pltptr = instr[3] & S_MASK(12);
		pltptr += pltaddr + 4;
		/*
		 * Load the pltptr to determine whether it is
		 * pointing to .PLT0 or to the final
		 * destination.
		 */
		if (ps_pread(rap->rd_psp, pltptr, &pltptrval,
		    sizeof (long long)) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2),
				EC_ADDR(pltptr)));
			return (RD_ERR);
		}
		pltptrval += pltaddr + 4;
		if (pltptrval == pltbase) {
			if ((rerr = rd_binder_exit_addr(rap,
			    MSG_ORIG(MSG_SYM_RTBIND),
			    &(rpi->pi_target))) != RD_OK) {
				return (rerr);
			}
			rpi->pi_skip_method = RD_RESOLVE_TARGET_STEP;
			rpi->pi_nstep = 1;
		} else {
			rpi->pi_skip_method = RD_RESOLVE_STEP;
			rpi->pi_nstep = 6;
			rpi->pi_target = 0;
			if (rtld_db_version >= RD_VERSION3) {
				destaddr = pltptrval;
				pltbound++;
			}
		}
	} else  {
		psaddr_t	pltaddr;

		pltaddr = pltbase +
			((pltoff / M64_PLT_ENTSIZE) * M64_PLT_ENTSIZE);

		if (ps_pread(rap->rd_psp, pltaddr, (char *)instr,
		    M64_PLT_ENTSIZE) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2),
				EC_ADDR(pltaddr)));
			return (RD_ERR);

		}
		/*
		 * ELF64 NEAR PLT's
		 */
		if ((instr[0] != M_NOP) &&
		    ((instr[1] & (~(S_MASK(19)))) == M_BA_A_XCC)) {
			/*
			 * Unbound PLT
			 */
			if ((rerr = rd_binder_exit_addr(rap,
			    MSG_ORIG(MSG_SYM_RTBIND),
			    &(rpi->pi_target))) != RD_OK) {
				return (rerr);
			}
			rpi->pi_skip_method = RD_RESOLVE_TARGET_STEP;
			rpi->pi_nstep = 1;
		} else  if ((instr[0] == M_NOP) &&
		    ((instr[1] & (~(S_MASK(22)))) == M_BA_A)) {
			/*
			 * Resolved 64-bit PLT entry format (b+-8mb):
			 * .PLT
			 * 0	nop
			 * 1	ba,a	<dest>
			 * 2	nop
			 * 3	nop
			 * 4	nop
			 * 5	nop
			 * 6	nop
			 * 7	nop
			 */
			rpi->pi_skip_method = RD_RESOLVE_STEP;
			rpi->pi_nstep = 2;
			rpi->pi_target = 0;
			if (rtld_db_version >= RD_VERSION3) {
				uint_t	d22;
				d22 = instr[1] & S_MASK(22);
				/* LINTED */
				destaddr = ((long)pltaddr + 4) +
					/* LINTED */
					(((int)d22 << 10) >> 8);
				pltbound++;
			}
		} else if ((instr[0] == M_NOP) &&
		    ((instr[1] & (~(S_MASK(19)))) == M_BA_A_PT)) {
			/*
			 * Resolved 64-bit PLT entry format (b+-2mb):
			 * .PLT
			 * 0	nop
			 * 1	ba,a,pt	%icc, <dest>
			 * 2	nop
			 * 3	nop
			 * 4	nop
			 * 5	nop
			 * 6	nop
			 * 7	nop
			 */
			rpi->pi_skip_method = RD_RESOLVE_STEP;
			rpi->pi_nstep = 2;
			rpi->pi_target = 0;
			if (rtld_db_version >= RD_VERSION3) {
				uint_t	d19;
				d19 = instr[1] & S_MASK(22);
				/* LINTED */
				destaddr = ((long)pltaddr + 4) +
					/* LINTED */
					(((int)d19 << 13) >> 11);
				pltbound++;
			}
		} else if ((instr[6] & (~(S_MASK(13)))) == M_JMPL_G5G0) {
			/*
			 * Resolved 64-bit PLT entry format (abs-64):
			 * .PLT
			 * 0	nop
			 * 1	sethi	%hh(dest), %g1
			 * 2	sethi	%lm(dest), %g5
			 * 3	or	%g1, %hm(dest), %g1
			 * 4	sllx	%g1, 32, %g1
			 * 5	or	%g1, %g5, %g5
			 * 6	jmpl	%g5 + %lo(dest), %g0
			 * 7	nop
			 */
			rpi->pi_skip_method = RD_RESOLVE_STEP;
			rpi->pi_nstep = 8;
			rpi->pi_target = 0;
			if (rtld_db_version >= RD_VERSION3) {
				uintptr_t	hh_bits;
				uintptr_t	hm_bits;
				uintptr_t	lm_bits;
				uintptr_t	lo_bits;
				hh_bits = instr[1] & S_MASK(22); /* 63..42 */
				hm_bits = instr[3] & S_MASK(10); /* 41..32 */
				lm_bits = instr[2] & S_MASK(22); /* 31..10 */
				lo_bits = instr[6] & S_MASK(10); /* 09..00 */
				destaddr = (hh_bits << 42) | (hm_bits << 32) |
					(lm_bits << 10) | lo_bits;
				pltbound++;
			}
		} else if (instr[3] == M_JMPL) {
			/*
			 * Resolved 64-bit PLT entry format (top-32):
			 *
			 * .PLT:
			 * 0	nop
			 * 1	sethi	%hi(~dest), %g5
			 * 2	xnor	%g5, %lo(~dest), %g1
			 * 3	jmpl	%g1, %g0
			 * 4	nop
			 * 5	nop
			 * 6	nop
			 * 7	nop
			 */
			rpi->pi_skip_method = RD_RESOLVE_STEP;
			rpi->pi_nstep = 5;
			rpi->pi_target = 0;
			if (rtld_db_version >= RD_VERSION3) {
				uintptr_t hi_bits;
				uintptr_t lo_bits;
				hi_bits = (instr[1] & S_MASK(22)) << 10;
				lo_bits = (instr[2] & S_MASK(10));
				destaddr = hi_bits ^ ~lo_bits;
				pltbound++;
			}
		} else if ((instr[2] & (~(S_MASK(13)))) == M_XNOR_G5G1) {
			/*
			 * Resolved 64-bit PLT entry format (top-44):
			 *
			 * .PLT:
			 * 0	nop
			 * 1	sethi	%h44(~dest), %g5
			 * 2	xnor	%g5, %m44(~dest), %g1
			 * 3	slxx	%g1, 12, %g1
			 * 4	jmpl %g1 + %l44(dest), %g0
			 * 5	nop
			 * 6	nop
			 * 7	nop
			 */
			rpi->pi_skip_method = RD_RESOLVE_STEP;
			rpi->pi_nstep = 6;
			rpi->pi_target = 0;
			if (rtld_db_version >= RD_VERSION3) {
				uintptr_t h44_bits;
				uintptr_t	m44_bits;
				uintptr_t	l44_bits;
				h44_bits = (((long)instr[1] & S_MASK(22))
					<< 10);
				m44_bits = (((long)instr[2] & S_MASK(13))
					<< 41) >> 41;
				l44_bits = (((long)instr[4] & S_MASK(13))
					<< 41) >> 41;
				destaddr = (~(h44_bits ^ m44_bits) << 12)
					+ l44_bits;
				pltbound++;
			}
		} else
			rpi->pi_skip_method = RD_RESOLVE_NONE;
	}

	if ((rtld_db_version >= RD_VERSION3) && pltbound) {
		rpi->pi_flags |= RD_FLG_PI_PLTBOUND;
		rpi->pi_baddr = destaddr;
	}

	return (RD_OK);
}
