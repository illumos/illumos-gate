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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* common code with bug fixes from original version in trap.c */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/vmsystm.h>
#include <sys/fpu/fpusystm.h>
#include <sys/fpu/fpu_simulator.h>
#include <sys/inline.h>
#include <sys/debug.h>
#include <sys/privregs.h>
#include <sys/machpcb.h>
#include <sys/simulate.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/stack.h>
#include <sys/watchpoint.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/mman.h>
#include <sys/asi.h>
#include <sys/copyops.h>
#include <vm/as.h>
#include <vm/page.h>
#include <sys/model.h>
#include <vm/seg_vn.h>
#include <sys/byteorder.h>
#include <sys/time.h>

#define	IS_IBIT_SET(x)	(x & 0x2000)
#define	IS_VIS1(op, op3)(op == 2 && op3 == 0x36)
#define	IS_FLOAT_QUAD_OP(op, op3)(op == 2 && (op3 == 0x34 ||	\
		op3 == 0x35))
#define	IS_PARTIAL_OR_SHORT_FLOAT_LD_ST(op, op3, asi)		\
		(op == 3 && (op3 == IOP_V8_LDDFA ||		\
		op3 == IOP_V8_STDFA) &&	asi > ASI_SNFL)

static int aligndebug = 0;

/*
 * For the sake of those who must be compatible with unaligned
 * architectures, users can link their programs to use a
 * corrective trap handler that will fix unaligned references
 * a special trap #6 (T_FIX_ALIGN) enables this 'feature'.
 * Returns 1 for success, 0 for failure.
 */

int
do_unaligned(struct regs *rp, caddr_t *badaddr)
{
	uint_t	inst, op3, asi = 0;
	uint_t	rd, rs1, rs2;
	int	sz, nf = 0, ltlend = 0;
	int	floatflg;
	int	fsrflg;
	int	immflg;
	int	lddstdflg;
	caddr_t	addr;
	uint64_t val;
	union {
		uint64_t	l[2];
		uint32_t	i[4];
		uint16_t	s[8];
		uint8_t		c[16];
	} data;

	ASSERT(USERMODE(rp->r_tstate));
	inst = fetch_user_instr((caddr_t)rp->r_pc);

	op3 = (inst >> 19) & 0x3f;
	rd = (inst >> 25) & 0x1f;
	rs1 = (inst >> 14) & 0x1f;
	rs2 = inst & 0x1f;
	floatflg = (inst >> 24) & 1;
	immflg = (inst >> 13) & 1;
	lddstdflg = fsrflg = 0;

	/* if not load or store do nothing */
	if ((inst >> 30) != 3)
		return (0);

	/* if ldstub or swap, do nothing */
	if ((inst & 0xc1680000) == 0xc0680000)
		return (0);

	/* if cas/casx, do nothing */
	if ((inst & 0xc1e00000) == 0xc1e00000)
		return (0);

	if (floatflg) {
		switch ((inst >> 19) & 3) {	/* map size bits to a number */
		case 0: sz = 4;
			break;			/* ldf{a}/stf{a} */
		case 1: fsrflg = 1;
			if (rd == 0)
				sz = 4;		/* ldfsr/stfsr */
			else  if (rd == 1)
				sz = 8;		/* ldxfsr/stxfsr */
			else
				return (SIMU_ILLEGAL);
			break;
		case 2: sz = 16;
			break;		/* ldqf{a}/stqf{a} */
		case 3: sz = 8;
			break;		/* lddf{a}/stdf{a} */
		}
		/*
		 * Fix to access extra double register encoding plus
		 * compensate to access the correct fpu_dreg.
		 */
		if ((sz > 4) && (fsrflg == 0)) {
			if ((rd & 1) == 1)
				rd = (rd & 0x1e) | 0x20;
			rd = rd >> 1;
			if ((sz == 16) && ((rd & 0x1) != 0))
				return (SIMU_ILLEGAL);
		}
	} else {
		int sz_bits = (inst >> 19) & 0xf;
		switch (sz_bits) {		/* map size bits to a number */
		case 0:				/* lduw{a} */
		case 4:				/* stw{a} */
		case 8:				/* ldsw{a} */
		case 0xf:			/* swap */
			sz = 4; break;
		case 1:				/* ldub{a} */
		case 5:				/* stb{a} */
		case 9:				/* ldsb{a} */
		case 0xd:			/* ldstub */
			sz = 1; break;
		case 2:				/* lduh{a} */
		case 6:				/* sth{a} */
		case 0xa:			/* ldsh{a} */
			sz = 2; break;
		case 3:				/* ldd{a} */
		case 7:				/* std{a} */
			lddstdflg = 1;
			sz = 8; break;
		case 0xb:			/* ldx{a} */
		case 0xe:			/* stx{a} */
			sz = 8; break;
		}
	}


	/* only support primary and secondary asi's */
	if ((op3 >> 4) & 1) {
		if (immflg) {
			asi = (uint_t)(rp->r_tstate >> TSTATE_ASI_SHIFT) &
			    TSTATE_ASI_MASK;
		} else {
			asi = (inst >> 5) & 0xff;
		}
		switch (asi) {
		case ASI_P:
		case ASI_S:
			break;
		case ASI_PNF:
		case ASI_SNF:
			nf = 1;
			break;
		case ASI_PL:
		case ASI_SL:
			ltlend = 1;
			break;
		case ASI_PNFL:
		case ASI_SNFL:
			ltlend = 1;
			nf = 1;
			break;
		default:
			return (0);
		}
		/*
		 * Non-faulting stores generate a data_access_exception trap,
		 * according to the Spitfire manual, which should be signaled
		 * as an illegal instruction trap, because it can't be fixed.
		 */
		if ((nf) && ((op3 == IOP_V8_STQFA) || (op3 == IOP_V8_STDFA)))
			return (SIMU_ILLEGAL);
	}

	if (aligndebug) {
		printf("unaligned access at %p, instruction: 0x%x\n",
		    (void *)rp->r_pc, inst);
		printf("type %s", (((inst >> 21) & 1) ? "st" : "ld"));
		if (((inst >> 21) & 1) == 0)
			printf(" %s", (((inst >> 22) & 1) ?
			    "signed" : "unsigned"));
		printf(" asi 0x%x size %d immflg %d\n", asi, sz, immflg);
		printf("rd = %d, op3 = 0x%x, rs1 = %d, rs2 = %d, imm13=0x%x\n",
		    rd, op3, rs1, rs2, (inst & 0x1fff));
	}

	(void) flush_user_windows_to_stack(NULL);
	if (getreg(rp, rs1, &val, badaddr))
		return (SIMU_FAULT);
	addr = (caddr_t)val;		/* convert to 32/64 bit address */
	if (aligndebug)
		printf("addr 1 = %p\n", (void *)addr);

	/* check immediate bit and use immediate field or reg (rs2) */
	if (immflg) {
		int imm;
		imm  = inst & 0x1fff;		/* mask out immediate field */
		imm <<= 19;			/* sign extend it */
		imm >>= 19;
		addr += imm;			/* compute address */
	} else {
		if (getreg(rp, rs2, &val, badaddr))
			return (SIMU_FAULT);
		addr += val;
	}

	/*
	 * If this is a 32-bit program, chop the address accordingly.  The
	 * intermediate uintptr_t casts prevent warnings under a certain
	 * compiler, and the temporary 32 bit storage is intended to force
	 * proper code generation and break up what would otherwise be a
	 * quadruple cast.
	 */
	if (curproc->p_model == DATAMODEL_ILP32) {
		caddr32_t addr32 = (caddr32_t)(uintptr_t)addr;
		addr = (caddr_t)(uintptr_t)addr32;
	}

	if (aligndebug)
		printf("addr 2 = %p\n", (void *)addr);

	if (addr >= curproc->p_as->a_userlimit) {
		*badaddr = addr;
		goto badret;
	}

	/* a single bit differentiates ld and st */
	if ((inst >> 21) & 1) {			/* store */
		if (floatflg) {
			klwp_id_t lwp = ttolwp(curthread);
			kfpu_t *fp = lwptofpu(lwp);
			/* Ensure fp has been enabled */
			if (fpu_exists) {
				if (!(_fp_read_fprs() & FPRS_FEF))
					fp_enable();
			} else {
				if (!fp->fpu_en)
					fp_enable();
			}
			/* if fpu_exists read fpu reg */
			if (fpu_exists) {
				if (fsrflg) {
					_fp_read_pfsr(&data.l[0]);
				} else {
					if (sz == 4) {
						data.i[0] = 0;
						_fp_read_pfreg(
						    (unsigned *)&data.i[1], rd);
					}
					if (sz >= 8)
						_fp_read_pdreg(
						    &data.l[0], rd);
					if (sz == 16)
						_fp_read_pdreg(
						    &data.l[1], rd+1);
				}
			} else {
				if (fsrflg) {
					/* Clear reserved bits, set version=7 */
					fp->fpu_fsr &= ~0x30301000;
					fp->fpu_fsr |= 0xE0000;
					data.l[0] = fp->fpu_fsr;
				} else {
					if (sz == 4) {
						data.i[0] = 0;
						data.i[1] =
						    (unsigned)fp->
						    fpu_fr.fpu_regs[rd];
					}
					if (sz >= 8)
						data.l[0] =
						    fp->fpu_fr.fpu_dregs[rd];
					if (sz == 16)
						data.l[1] =
						    fp->fpu_fr.fpu_dregs[rd+1];
				}
			}
		} else {
			if (lddstdflg) {		/* combine the data */
				if (getreg(rp, rd, &data.l[0], badaddr))
					return (SIMU_FAULT);
				if (getreg(rp, rd+1, &data.l[1], badaddr))
					return (SIMU_FAULT);
				if (ltlend) {
					/*
					 * For STD, each 32-bit word is byte-
					 * swapped individually.  For
					 * simplicity we don't want to do that
					 * below, so we swap the words now to
					 * get the desired result in the end.
					 */
					data.i[0] = data.i[3];
				} else {
					data.i[0] = data.i[1];
					data.i[1] = data.i[3];
				}
			} else {
				if (getreg(rp, rd, &data.l[0], badaddr))
					return (SIMU_FAULT);
			}
		}

		if (aligndebug) {
			if (sz == 16) {
				printf("data %x %x %x %x\n",
				    data.i[0], data.i[1], data.i[2], data.c[3]);
			} else {
				printf("data %x %x %x %x %x %x %x %x\n",
				    data.c[0], data.c[1], data.c[2], data.c[3],
				    data.c[4], data.c[5], data.c[6], data.c[7]);
			}
		}

		if (ltlend) {
			if (sz == 1) {
				if (xcopyout_little(&data.c[7], addr,
				    (size_t)sz) != 0)
					goto badret;
			} else if (sz == 2) {
				if (xcopyout_little(&data.s[3], addr,
				    (size_t)sz) != 0)
					goto badret;
			} else if (sz == 4) {
				if (xcopyout_little(&data.i[1], addr,
				    (size_t)sz) != 0)
					goto badret;
			} else {
				if (xcopyout_little(&data.l[0], addr,
				    (size_t)sz) != 0)
					goto badret;
			}
		} else {
			if (sz == 1) {
				if (copyout(&data.c[7], addr, (size_t)sz) == -1)
					goto badret;
			} else if (sz == 2) {
				if (copyout(&data.s[3], addr, (size_t)sz) == -1)
					goto badret;
			} else if (sz == 4) {
				if (copyout(&data.i[1], addr, (size_t)sz) == -1)
					goto badret;
			} else {
				if (copyout(&data.l[0], addr, (size_t)sz) == -1)
					goto badret;
			}
		}
	} else {				/* load */
		if (sz == 1) {
			if (ltlend) {
				if (xcopyin_little(addr, &data.c[7],
				    (size_t)sz) != 0) {
					if (nf)
						data.c[7] = 0;
					else
						goto badret;
				}
			} else {
				if (copyin(addr, &data.c[7],
				    (size_t)sz) == -1) {
					if (nf)
						data.c[7] = 0;
					else
						goto badret;
				}
			}
			/* if signed and the sign bit is set extend it */
			if (((inst >> 22) & 1) && ((data.c[7] >> 7) & 1)) {
				data.i[0] = (uint_t)-1;	/* extend sign bit */
				data.s[2] = (ushort_t)-1;
				data.c[6] = (uchar_t)-1;
			} else {
				data.i[0] = 0;	/* clear upper 32+24 bits */
				data.s[2] = 0;
				data.c[6] = 0;
			}
		} else if (sz == 2) {
			if (ltlend) {
				if (xcopyin_little(addr, &data.s[3],
				    (size_t)sz) != 0) {
					if (nf)
						data.s[3] = 0;
					else
						goto badret;
				}
			} else {
				if (copyin(addr, &data.s[3],
				    (size_t)sz) == -1) {
					if (nf)
						data.s[3] = 0;
					else
						goto badret;
				}
			}
			/* if signed and the sign bit is set extend it */
			if (((inst >> 22) & 1) && ((data.s[3] >> 15) & 1)) {
				data.i[0] = (uint_t)-1;	/* extend sign bit */
				data.s[2] = (ushort_t)-1;
			} else {
				data.i[0] = 0;	/* clear upper 32+16 bits */
				data.s[2] = 0;
			}
		} else if (sz == 4) {
			if (ltlend) {
				if (xcopyin_little(addr, &data.i[1],
				    (size_t)sz) != 0) {
					if (!nf)
						goto badret;
					data.i[1] = 0;
				}
			} else {
				if (copyin(addr, &data.i[1],
				    (size_t)sz) == -1) {
					if (!nf)
						goto badret;
					data.i[1] = 0;
				}
			}
			/* if signed and the sign bit is set extend it */
			if (((inst >> 22) & 1) && ((data.i[1] >> 31) & 1)) {
				data.i[0] = (uint_t)-1;	/* extend sign bit */
			} else {
				data.i[0] = 0;	/* clear upper 32 bits */
			}
		} else {
			if (ltlend) {
				if (xcopyin_little(addr, &data.l[0],
				    (size_t)sz) != 0) {
					if (!nf)
						goto badret;
					data.l[0] = 0;
				}
			} else {
				if (copyin(addr, &data.l[0],
				    (size_t)sz) == -1) {
					if (!nf)
						goto badret;
					data.l[0] = 0;
				}
			}
		}

		if (aligndebug) {
			if (sz == 16) {
				printf("data %x %x %x %x\n",
				    data.i[0], data.i[1], data.i[2], data.c[3]);
			} else {
				printf("data %x %x %x %x %x %x %x %x\n",
				    data.c[0], data.c[1], data.c[2], data.c[3],
				    data.c[4], data.c[5], data.c[6], data.c[7]);
			}
		}

		if (floatflg) {		/* if fpu_exists write fpu reg */
			klwp_id_t lwp = ttolwp(curthread);
			kfpu_t *fp = lwptofpu(lwp);
			/* Ensure fp has been enabled */
			if (fpu_exists) {
				if (!(_fp_read_fprs() & FPRS_FEF))
					fp_enable();
			} else {
				if (!fp->fpu_en)
					fp_enable();
			}
			/* if fpu_exists read fpu reg */
			if (fpu_exists) {
				if (fsrflg) {
					_fp_write_pfsr(&data.l[0]);
				} else {
					if (sz == 4)
						_fp_write_pfreg(
						    (unsigned *)&data.i[1], rd);
					if (sz >= 8)
						_fp_write_pdreg(
						    &data.l[0], rd);
					if (sz == 16)
						_fp_write_pdreg(
						    &data.l[1], rd+1);
				}
			} else {
				if (fsrflg) {
					fp->fpu_fsr = data.l[0];
				} else {
					if (sz == 4)
						fp->fpu_fr.fpu_regs[rd] =
						    (unsigned)data.i[1];
					if (sz >= 8)
						fp->fpu_fr.fpu_dregs[rd] =
						    data.l[0];
					if (sz == 16)
						fp->fpu_fr.fpu_dregs[rd+1] =
						    data.l[1];
				}
			}
		} else {
			if (lddstdflg) {		/* split the data */
				if (ltlend) {
					/*
					 * For LDD, each 32-bit word is byte-
					 * swapped individually.  We didn't
					 * do that above, but this will give
					 * us the desired result.
					 */
					data.i[3] = data.i[0];
				} else {
					data.i[3] = data.i[1];
					data.i[1] = data.i[0];
				}
				data.i[0] = 0;
				data.i[2] = 0;
				if (putreg(&data.l[0], rp, rd, badaddr) == -1)
					goto badret;
				if (putreg(&data.l[1], rp, rd+1, badaddr) == -1)
					goto badret;
			} else {
				if (putreg(&data.l[0], rp, rd, badaddr) == -1)
					goto badret;
			}
		}
	}
	return (SIMU_SUCCESS);
badret:
	return (SIMU_FAULT);
}


int
simulate_lddstd(struct regs *rp, caddr_t *badaddr)
{
	uint_t	inst, op3, asi = 0;
	uint_t	rd, rs1, rs2;
	int	nf = 0, ltlend = 0, usermode;
	int	immflg;
	uint64_t reven;
	uint64_t rodd;
	caddr_t	addr;
	uint64_t val;
	uint64_t data;

	usermode = USERMODE(rp->r_tstate);

	if (usermode)
		inst = fetch_user_instr((caddr_t)rp->r_pc);
	else
		inst = *(uint_t *)rp->r_pc;

	op3 = (inst >> 19) & 0x3f;
	rd = (inst >> 25) & 0x1f;
	rs1 = (inst >> 14) & 0x1f;
	rs2 = inst & 0x1f;
	immflg = (inst >> 13) & 1;

	if (USERMODE(rp->r_tstate))
		(void) flush_user_windows_to_stack(NULL);
	else
		flush_windows();

	if ((op3 >> 4) & 1) {		/* is this LDDA/STDA? */
		if (immflg) {
			asi = (uint_t)(rp->r_tstate >> TSTATE_ASI_SHIFT) &
			    TSTATE_ASI_MASK;
		} else {
			asi = (inst >> 5) & 0xff;
		}
		switch (asi) {
		case ASI_P:
		case ASI_S:
			break;
		case ASI_PNF:
		case ASI_SNF:
			nf = 1;
			break;
		case ASI_PL:
		case ASI_SL:
			ltlend = 1;
			break;
		case ASI_PNFL:
		case ASI_SNFL:
			ltlend = 1;
			nf = 1;
			break;
		case ASI_AIUP:
		case ASI_AIUS:
			usermode = 1;
			break;
		case ASI_AIUPL:
		case ASI_AIUSL:
			usermode = 1;
			ltlend = 1;
			break;
		default:
			return (SIMU_ILLEGAL);
		}
	}

	if (getreg(rp, rs1, &val, badaddr))
		return (SIMU_FAULT);
	addr = (caddr_t)val;		/* convert to 32/64 bit address */

	/* check immediate bit and use immediate field or reg (rs2) */
	if (immflg) {
		int imm;
		imm  = inst & 0x1fff;		/* mask out immediate field */
		imm <<= 19;			/* sign extend it */
		imm >>= 19;
		addr += imm;			/* compute address */
	} else {
		if (getreg(rp, rs2, &val, badaddr))
			return (SIMU_FAULT);
		addr += val;
	}

	/*
	 * T_UNIMP_LDD and T_UNIMP_STD are higher priority than
	 * T_ALIGNMENT.  So we have to make sure that the address is
	 * kosher before trying to use it, because the hardware hasn't
	 * checked it for us yet.
	 */
	if (((uintptr_t)addr & 0x7) != 0) {
		if (curproc->p_fixalignment)
			return (do_unaligned(rp, badaddr));
		else
			return (SIMU_UNALIGN);
	}

	/*
	 * If this is a 32-bit program, chop the address accordingly.  The
	 * intermediate uintptr_t casts prevent warnings under a certain
	 * compiler, and the temporary 32 bit storage is intended to force
	 * proper code generation and break up what would otherwise be a
	 * quadruple cast.
	 */
	if (curproc->p_model == DATAMODEL_ILP32 && usermode) {
		caddr32_t addr32 = (caddr32_t)(uintptr_t)addr;
		addr = (caddr_t)(uintptr_t)addr32;
	}

	if ((inst >> 21) & 1) {			/* store */
		if (getreg(rp, rd, &reven, badaddr))
			return (SIMU_FAULT);
		if (getreg(rp, rd+1, &rodd, badaddr))
			return (SIMU_FAULT);
		if (ltlend) {
			reven = BSWAP_32(reven);
			rodd  = BSWAP_32(rodd);
		}
		data = (reven << 32) | rodd;
		if (usermode) {
			if (suword64_nowatch(addr, data) == -1)
				return (SIMU_FAULT);
		} else {
			*(uint64_t *)addr = data;
		}
	} else {				/* load */
		if (usermode) {
			if (fuword64_nowatch(addr, &data)) {
				if (nf)
					data = 0;
				else
					return (SIMU_FAULT);
			}
		} else
			data = *(uint64_t *)addr;

		reven = (data >> 32);
		rodd  = (uint64_t)(uint32_t)data;
		if (ltlend) {
			reven = BSWAP_32(reven);
			rodd  = BSWAP_32(rodd);
		}

		if (putreg(&reven, rp, rd, badaddr) == -1)
			return (SIMU_FAULT);
		if (putreg(&rodd, rp, rd+1, badaddr) == -1)
			return (SIMU_FAULT);
	}
	return (SIMU_SUCCESS);
}


/*
 * simulate popc
 */
static int
simulate_popc(struct regs *rp, caddr_t *badaddr, uint_t inst)
{
	uint_t	rd, rs2, rs1;
	uint_t	immflg;
	uint64_t val, cnt = 0;

	rd = (inst >> 25) & 0x1f;
	rs1 = (inst >> 14) & 0x1f;
	rs2 = inst & 0x1f;
	immflg = (inst >> 13) & 1;

	if (rs1 > 0)
		return (SIMU_ILLEGAL);

	(void) flush_user_windows_to_stack(NULL);

	/* check immediate bit and use immediate field or reg (rs2) */
	if (immflg) {
		int64_t imm;
		imm  = inst & 0x1fff;		/* mask out immediate field */
		imm <<= 51;			/* sign extend it */
		imm >>= 51;
		if (imm != 0) {
			for (cnt = 0; imm != 0; imm &= imm-1)
				cnt++;
		}
	} else {
		if (getreg(rp, rs2, &val, badaddr))
			return (SIMU_FAULT);
		if (val != 0) {
			for (cnt = 0; val != 0; val &= val-1)
				cnt++;
		}
	}

	if (putreg(&cnt, rp, rd, badaddr) == -1)
		return (SIMU_FAULT);

	return (SIMU_SUCCESS);
}

/*
 * simulate mulscc
 */
static int
simulate_mulscc(struct regs *rp, caddr_t *badaddr, uint_t inst)
{
	uint32_t	s1, s2;
	uint32_t	c, d, v;
	uint_t		rd, rs1;
	int64_t		d64;
	uint64_t	ud64;
	uint64_t	drs1;

	(void) flush_user_windows_to_stack(NULL);

	if ((inst >> 13) & 1) {		/* immediate */
		d64 = inst & 0x1fff;
		d64 <<= 51;		/* sign extend it */
		d64 >>= 51;
	} else {
		uint_t		rs2;
		uint64_t	drs2;

		if (inst & 0x1fe0) {
			return (SIMU_ILLEGAL);
		}
		rs2 = inst & 0x1f;
		if (getreg(rp, rs2, &drs2, badaddr)) {
			return (SIMU_FAULT);
		}
		d64 = (int64_t)drs2;
	}

	rs1 = (inst >> 14) & 0x1f;
	if (getreg(rp, rs1, &drs1, badaddr)) {
		return (SIMU_FAULT);
	}
	/* icc.n xor icc.v */
	s1 = ((rp->r_tstate & TSTATE_IN) >> (TSTATE_CCR_SHIFT + 3)) ^
	    ((rp->r_tstate & TSTATE_IV) >> (TSTATE_CCR_SHIFT + 1));
	s1 = (s1 << 31) | (((uint32_t)drs1) >> 1);

	if (rp->r_y & 1) {
		s2 = (uint32_t)d64;
	} else {
		s2 = 0;
	}
	d = s1 + s2;

	ud64 = (uint64_t)d;

	/* set the icc flags */
	v = (s1 & s2 & ~d) | (~s1 & ~s2 & d);
	c = (s1 & s2) | (~d & (s1 | s2));
	rp->r_tstate &= ~TSTATE_ICC;
	rp->r_tstate |= (uint64_t)((c >> 31) & 1) << (TSTATE_CCR_SHIFT + 0);
	rp->r_tstate |= (uint64_t)((v >> 31) & 1) << (TSTATE_CCR_SHIFT + 1);
	rp->r_tstate |= (uint64_t)(d ? 0 : 1) << (TSTATE_CCR_SHIFT + 2);
	rp->r_tstate |= (uint64_t)((d >> 31) & 1) << (TSTATE_CCR_SHIFT + 3);

	if (rp->r_tstate & TSTATE_IC) {
		ud64 |= (1ULL << 32);
	}

	/* set the xcc flags */
	rp->r_tstate &= ~TSTATE_XCC;
	if (ud64 == 0) {
		rp->r_tstate |= TSTATE_XZ;
	}

	rd = (inst >> 25) & 0x1f;
	if (putreg(&ud64, rp, rd, badaddr)) {
		return (SIMU_FAULT);
	}

	d64 = (drs1 << 32) | (uint32_t)rp->r_y;
	d64 >>= 1;
	rp->r_y = (uint32_t)d64;

	return (SIMU_SUCCESS);
}

/*
 * simulate unimplemented instructions (popc, ldqf{a}, stqf{a})
 */
int
simulate_unimp(struct regs *rp, caddr_t *badaddr)
{
	uint_t	inst, optype, op3, asi;
	uint_t	rs1, rd;
	uint_t	ignor, i;
	machpcb_t *mpcb = lwptompcb(ttolwp(curthread));
	int	nomatch = 0;
	caddr_t	addr = (caddr_t)rp->r_pc;
	struct as *as;
	caddr_t	ka;
	pfn_t	pfnum;
	page_t *pp;
	proc_t *p = ttoproc(curthread);
	struct seg *mapseg;
	struct segvn_data *svd;

	ASSERT(USERMODE(rp->r_tstate));
	inst = fetch_user_instr(addr);
	if (inst == (uint_t)-1) {
		mpcb->mpcb_illexcaddr = addr;
		mpcb->mpcb_illexcinsn = (uint32_t)-1;
		return (SIMU_ILLEGAL);
	}

	/*
	 * When fixing dirty v8 instructions there's a race if two processors
	 * are executing the dirty executable at the same time.  If one
	 * cleans the instruction as the other is executing it the second
	 * processor will see a clean instruction when it comes through this
	 * code and will return SIMU_ILLEGAL.  To work around the race
	 * this code will keep track of the last illegal instruction seen
	 * by each lwp and will only take action if the illegal instruction
	 * is repeatable.
	 */
	if (addr != mpcb->mpcb_illexcaddr ||
	    inst != mpcb->mpcb_illexcinsn)
		nomatch = 1;
	mpcb->mpcb_illexcaddr = addr;
	mpcb->mpcb_illexcinsn = inst;

	/* instruction fields */
	i = (inst >> 13) & 0x1;
	rd = (inst >> 25) & 0x1f;
	optype = (inst >> 30) & 0x3;
	op3 = (inst >> 19) & 0x3f;
	ignor = (inst >> 5) & 0xff;
	if (IS_IBIT_SET(inst)) {
		asi = (uint32_t)((rp->r_tstate >> TSTATE_ASI_SHIFT) &
		    TSTATE_ASI_MASK);
	} else {
		asi = ignor;
	}

	if (IS_VIS1(optype, op3) ||
	    IS_PARTIAL_OR_SHORT_FLOAT_LD_ST(optype, op3, asi) ||
	    IS_FLOAT_QUAD_OP(optype, op3)) {
		klwp_t *lwp = ttolwp(curthread);
		kfpu_t *fp = lwptofpu(lwp);
		if (fpu_exists) {
			if (!(_fp_read_fprs() & FPRS_FEF))
				fp_enable();
			_fp_read_pfsr(&fp->fpu_fsr);
		} else {
			if (!fp->fpu_en)
				fp_enable();
		}
		fp_precise(rp);
		return (SIMU_RETRY);
	}

	if (optype == 2 && op3 == IOP_V8_POPC) {
		return (simulate_popc(rp, badaddr, inst));
	} else if (optype == 3 && op3 == IOP_V8_POPC) {
		return (SIMU_ILLEGAL);
	} else if (optype == OP_V8_ARITH && op3 == IOP_V8_MULScc) {
		return (simulate_mulscc(rp, badaddr, inst));
	}

	if (optype == OP_V8_LDSTR) {
		if (op3 == IOP_V8_LDQF || op3 == IOP_V8_LDQFA ||
		    op3 == IOP_V8_STQF || op3 == IOP_V8_STQFA)
			return (do_unaligned(rp, badaddr));
	}

	/* This is a new instruction so illexccnt should also be set. */
	if (nomatch) {
		mpcb->mpcb_illexccnt = 0;
		return (SIMU_RETRY);
	}

	/*
	 * In order to keep us from entering into an infinite loop while
	 * attempting to clean up faulty instructions, we will return
	 * SIMU_ILLEGAL once we've cleaned up the instruction as much
	 * as we can, and still end up here.
	 */
	if (mpcb->mpcb_illexccnt >= 3)
		return (SIMU_ILLEGAL);

	mpcb->mpcb_illexccnt += 1;

	/*
	 * The rest of the code handles v8 binaries with instructions
	 * that have dirty (non-zero) bits in reserved or 'ignored'
	 * fields; these will cause core dumps on v9 machines.
	 *
	 * We only clean dirty instructions in 32-bit programs (ie, v8)
	 * running on SPARCv9 processors.  True v9 programs are forced
	 * to use the instruction set as intended.
	 */
	if (lwp_getdatamodel(curthread->t_lwp) != DATAMODEL_ILP32)
		return (SIMU_ILLEGAL);
	switch (optype) {
	case OP_V8_BRANCH:
	case OP_V8_CALL:
		return (SIMU_ILLEGAL);	/* these don't have ignored fields */
		/*NOTREACHED*/
	case OP_V8_ARITH:
		switch (op3) {
		case IOP_V8_RETT:
			if (rd == 0 && !(i == 0 && ignor))
				return (SIMU_ILLEGAL);
			if (rd)
				inst &= ~(0x1f << 25);
			if (i == 0 && ignor)
				inst &= ~(0xff << 5);
			break;
		case IOP_V8_TCC:
			if (i == 0 && ignor != 0) {
				inst &= ~(0xff << 5);
			} else if (i == 1 && (((inst >> 7) & 0x3f) != 0)) {
				inst &= ~(0x3f << 7);
			} else {
				return (SIMU_ILLEGAL);
			}
			break;
		case IOP_V8_JMPL:
		case IOP_V8_RESTORE:
		case IOP_V8_SAVE:
			if ((op3 == IOP_V8_RETT && rd) ||
			    (i == 0 && ignor)) {
				inst &= ~(0xff << 5);
			} else {
				return (SIMU_ILLEGAL);
			}
			break;
		case IOP_V8_FCMP:
			if (rd == 0)
				return (SIMU_ILLEGAL);
			inst &= ~(0x1f << 25);
			break;
		case IOP_V8_RDASR:
			rs1 = ((inst >> 14) & 0x1f);
			if (rs1 == 1 || (rs1 >= 7 && rs1 <= 14)) {
				/*
				 * The instruction specifies an invalid
				 * state register - better bail out than
				 * "fix" it when we're not sure what was
				 * intended.
				 */
				return (SIMU_ILLEGAL);
			}
				/*
				 * Note: this case includes the 'stbar'
				 * instruction (rs1 == 15 && i == 0).
				 */
				if ((ignor = (inst & 0x3fff)) != 0)
					inst &= ~(0x3fff);
			break;
		case IOP_V8_SRA:
		case IOP_V8_SRL:
		case IOP_V8_SLL:
			if (ignor == 0)
				return (SIMU_ILLEGAL);
			inst &= ~(0xff << 5);
			break;
		case IOP_V8_ADD:
		case IOP_V8_AND:
		case IOP_V8_OR:
		case IOP_V8_XOR:
		case IOP_V8_SUB:
		case IOP_V8_ANDN:
		case IOP_V8_ORN:
		case IOP_V8_XNOR:
		case IOP_V8_ADDC:
		case IOP_V8_UMUL:
		case IOP_V8_SMUL:
		case IOP_V8_SUBC:
		case IOP_V8_UDIV:
		case IOP_V8_SDIV:
		case IOP_V8_ADDcc:
		case IOP_V8_ANDcc:
		case IOP_V8_ORcc:
		case IOP_V8_XORcc:
		case IOP_V8_SUBcc:
		case IOP_V8_ANDNcc:
		case IOP_V8_ORNcc:
		case IOP_V8_XNORcc:
		case IOP_V8_ADDCcc:
		case IOP_V8_UMULcc:
		case IOP_V8_SMULcc:
		case IOP_V8_SUBCcc:
		case IOP_V8_UDIVcc:
		case IOP_V8_SDIVcc:
		case IOP_V8_TADDcc:
		case IOP_V8_TSUBcc:
		case IOP_V8_TADDccTV:
		case IOP_V8_TSUBccTV:
		case IOP_V8_MULScc:
		case IOP_V8_WRASR:
		case IOP_V8_FLUSH:
			if (i != 0 || ignor == 0)
				return (SIMU_ILLEGAL);
			inst &= ~(0xff << 5);
			break;
		default:
			return (SIMU_ILLEGAL);
		}
		break;
	case OP_V8_LDSTR:
		switch (op3) {
		case IOP_V8_STFSR:
		case IOP_V8_LDFSR:
			if (rd == 0 && !(i == 0 && ignor))
				return (SIMU_ILLEGAL);
			if (rd)
				inst &= ~(0x1f << 25);
			if (i == 0 && ignor)
				inst &= ~(0xff << 5);
			break;
		default:
			if (optype == OP_V8_LDSTR && !IS_LDST_ALT(op3) &&
			    i == 0 && ignor)
				inst &= ~(0xff << 5);
			else
				return (SIMU_ILLEGAL);
			break;
		}
		break;
	default:
		return (SIMU_ILLEGAL);
	}

	as = p->p_as;

	AS_LOCK_ENTER(as, RW_READER);
	mapseg = as_findseg(as, (caddr_t)rp->r_pc, 0);
	ASSERT(mapseg != NULL);
	svd = (struct segvn_data *)mapseg->s_data;

	/*
	 * We only create COW page for MAP_PRIVATE mappings.
	 */
	SEGVN_LOCK_ENTER(as, &svd->lock, RW_READER);
	if ((svd->type & MAP_TYPE) & MAP_SHARED) {
		SEGVN_LOCK_EXIT(as, &svd->lock);
		AS_LOCK_EXIT(as);
		return (SIMU_ILLEGAL);
	}
	SEGVN_LOCK_EXIT(as, &svd->lock);
	AS_LOCK_EXIT(as);

	/*
	 * A "flush" instruction using the user PC's vaddr will not work
	 * here, at least on Spitfire. Instead we create a temporary kernel
	 * mapping to the user's text page, then modify and flush that.
	 * Break COW by locking user page.
	 */
	if (as_fault(as->a_hat, as, (caddr_t)(rp->r_pc & PAGEMASK), PAGESIZE,
	    F_SOFTLOCK, S_READ))
		return (SIMU_FAULT);

	AS_LOCK_ENTER(as, RW_READER);
	pfnum = hat_getpfnum(as->a_hat, (caddr_t)rp->r_pc);
	AS_LOCK_EXIT(as);
	if (pf_is_memory(pfnum)) {
		pp = page_numtopp_nolock(pfnum);
		ASSERT(pp == NULL || PAGE_LOCKED(pp));
	} else {
		(void) as_fault(as->a_hat, as, (caddr_t)(rp->r_pc & PAGEMASK),
		    PAGESIZE, F_SOFTUNLOCK, S_READ);
		return (SIMU_FAULT);
	}

	AS_LOCK_ENTER(as, RW_READER);
	ka = ppmapin(pp, PROT_READ|PROT_WRITE, (caddr_t)rp->r_pc);
	*(uint_t *)(ka + (uintptr_t)(rp->r_pc % PAGESIZE)) = inst;
	doflush(ka + (uintptr_t)(rp->r_pc % PAGESIZE));
	ppmapout(ka);
	AS_LOCK_EXIT(as);

	(void) as_fault(as->a_hat, as, (caddr_t)(rp->r_pc & PAGEMASK),
	    PAGESIZE, F_SOFTUNLOCK, S_READ);
	return (SIMU_RETRY);
}

/*
 * Simulate a "rd %tick" or "rd %stick" (%asr24) instruction.
 */
int
simulate_rdtick(struct regs *rp)
{
	uint_t	inst, op, op3, rd, rs1, i;
	caddr_t badaddr;

	inst = fetch_user_instr((caddr_t)rp->r_pc);
	op   = (inst >> 30) & 0x3;
	rd   = (inst >> 25) & 0x1F;
	op3  = (inst >> 19) & 0x3F;
	i    = (inst >> 13) & 0x1;

	/*
	 * Make sure this is either a %tick read (rs1 == 0x4) or
	 * a %stick read (rs1 == 0x18) instruction.
	 */
	if (op == 2 && op3 == 0x28 && i == 0) {
		rs1 = (inst >> 14) & 0x1F;

		if (rs1 == 0x4) {
			uint64_t tick;
			(void) flush_user_windows_to_stack(NULL);
			tick = gettick_counter();
			if (putreg(&tick, rp, rd, &badaddr) == 0)
				return (SIMU_SUCCESS);
		} else if (rs1 == 0x18) {
			uint64_t stick;
			(void) flush_user_windows_to_stack(NULL);
			stick = gethrtime_unscaled();
			if (putreg(&stick, rp, rd, &badaddr) == 0)
				return (SIMU_SUCCESS);
		}
	}

	return (SIMU_FAULT);
}

/*
 * Get the value of a register for instruction simulation
 * by using the regs or window structure pointers.
 * Return 0 for success, and -1 for failure.  If there is a failure,
 * save the faulting address using badaddr pointer.
 * We have 64 bit globals and outs, and 32 or 64 bit ins and locals.
 * Don't truncate globals/outs for 32 bit programs, for v8+ support.
 */
int
getreg(struct regs *rp, uint_t reg, uint64_t *val, caddr_t *badaddr)
{
	uint64_t *rgs, *sp;
	int rv = 0;

	rgs = (uint64_t *)&rp->r_ps;		/* globals and outs */
	sp = (uint64_t *)rp->r_sp;		/* ins and locals */
	if (reg == 0) {
		*val = 0;
	} else if (reg < 16) {
		*val = rgs[reg];
	} else if (IS_V9STACK(sp)) {
		uint64_t *rw = (uint64_t *)((uintptr_t)sp + V9BIAS64);
		uint64_t *addr = (uint64_t *)&rw[reg - 16];
		uint64_t res;

		if (USERMODE(rp->r_tstate)) {
			if (fuword64_nowatch(addr, &res) == -1) {
				*badaddr = (caddr_t)addr;
				rv = -1;
			}
		} else {
			res = *addr;
		}
		*val = res;
	} else {
		caddr32_t sp32 = (caddr32_t)(uintptr_t)sp;
		uint32_t *rw = (uint32_t *)(uintptr_t)sp32;
		uint32_t *addr = (uint32_t *)&rw[reg - 16];
		uint32_t res;

		if (USERMODE(rp->r_tstate)) {
			if (fuword32_nowatch(addr, &res) == -1) {
				*badaddr = (caddr_t)addr;
				rv = -1;
			}
		} else {
			res = *addr;
		}
		*val = (uint64_t)res;
	}
	return (rv);
}

/*
 * Set the value of a register after instruction simulation
 * by using the regs or window structure pointers.
 * Return 0 for succes -1 failure.
 * save the faulting address using badaddr pointer.
 * We have 64 bit globals and outs, and 32 or 64 bit ins and locals.
 * Don't truncate globals/outs for 32 bit programs, for v8+ support.
 */
int
putreg(uint64_t	*data, struct regs *rp, uint_t reg, caddr_t *badaddr)
{
	uint64_t *rgs, *sp;
	int rv = 0;

	rgs = (uint64_t *)&rp->r_ps;		/* globals and outs */
	sp = (uint64_t *)rp->r_sp;		/* ins and locals */
	if (reg == 0) {
		return (0);
	} else if (reg < 16) {
		rgs[reg] = *data;
	} else if (IS_V9STACK(sp)) {
		uint64_t *rw = (uint64_t *)((uintptr_t)sp + V9BIAS64);
		uint64_t *addr = (uint64_t *)&rw[reg - 16];
		uint64_t res;

		if (USERMODE(rp->r_tstate)) {
			struct machpcb *mpcb = lwptompcb(curthread->t_lwp);

			res = *data;
			if (suword64_nowatch(addr, res) != 0) {
				*badaddr = (caddr_t)addr;
				rv = -1;
			}
			/*
			 * We have changed a local or in register;
			 * nuke the watchpoint return windows.
			 */
			mpcb->mpcb_rsp[0] = NULL;
			mpcb->mpcb_rsp[1] = NULL;
		} else {
			res = *data;
			*addr = res;
		}
	} else {
		caddr32_t sp32 = (caddr32_t)(uintptr_t)sp;
		uint32_t *rw = (uint32_t *)(uintptr_t)sp32;
		uint32_t *addr = (uint32_t *)&rw[reg - 16];
		uint32_t res;

		if (USERMODE(rp->r_tstate)) {
			struct machpcb *mpcb = lwptompcb(curthread->t_lwp);

			res = (uint_t)*data;
			if (suword32_nowatch(addr, res) != 0) {
				*badaddr = (caddr_t)addr;
				rv = -1;
			}
			/*
			 * We have changed a local or in register;
			 * nuke the watchpoint return windows.
			 */
			mpcb->mpcb_rsp[0] = NULL;
			mpcb->mpcb_rsp[1] = NULL;

		} else {
			res = (uint_t)*data;
			*addr = res;
		}
	}
	return (rv);
}

/*
 * Calculate a memory reference address from instruction
 * operands, used to return the address of a fault, instead
 * of the instruction when an error occurs.  This is code that is
 * common with most of the routines that simulate instructions.
 */
int
calc_memaddr(struct regs *rp, caddr_t *badaddr)
{
	uint_t	inst;
	uint_t	rd, rs1, rs2;
	int	sz;
	int	immflg;
	int	floatflg;
	caddr_t  addr;
	uint64_t val;

	if (USERMODE(rp->r_tstate))
		inst = fetch_user_instr((caddr_t)rp->r_pc);
	else
		inst = *(uint_t *)rp->r_pc;

	rd = (inst >> 25) & 0x1f;
	rs1 = (inst >> 14) & 0x1f;
	rs2 = inst & 0x1f;
	floatflg = (inst >> 24) & 1;
	immflg = (inst >> 13) & 1;

	if (floatflg) {
		switch ((inst >> 19) & 3) {	/* map size bits to a number */
		case 0: sz = 4; break;		/* ldf/stf */
		case 1: return (0);		/* ld[x]fsr/st[x]fsr */
		case 2: sz = 16; break;		/* ldqf/stqf */
		case 3: sz = 8; break;		/* lddf/stdf */
		}
		/*
		 * Fix to access extra double register encoding plus
		 * compensate to access the correct fpu_dreg.
		 */
		if (sz > 4) {
			if ((rd & 1) == 1)
				rd = (rd & 0x1e) | 0x20;
			rd = rd >> 1;
		}
	} else {
		switch ((inst >> 19) & 0xf) {	/* map size bits to a number */
		case 0:				/* lduw */
		case 4:				/* stw */
		case 8:				/* ldsw */
		case 0xf:			/* swap */
			sz = 4; break;
		case 1:				/* ldub */
		case 5:				/* stb */
		case 9:				/* ldsb */
		case 0xd:			/* ldstub */
			sz = 1; break;
		case 2:				/* lduh */
		case 6:				/* sth */
		case 0xa:			/* ldsh */
			sz = 2; break;
		case 3:				/* ldd */
		case 7:				/* std */
		case 0xb:			/* ldx */
		case 0xe:			/* stx */
			sz = 8; break;
		}
	}

	if (USERMODE(rp->r_tstate))
		(void) flush_user_windows_to_stack(NULL);
	else
		flush_windows();

	if (getreg(rp, rs1, &val, badaddr))
		return (SIMU_FAULT);
	addr = (caddr_t)val;

	/* check immediate bit and use immediate field or reg (rs2) */
	if (immflg) {
		int imm;
		imm = inst & 0x1fff;		/* mask out immediate field */
		imm <<= 19;			/* sign extend it */
		imm >>= 19;
		addr += imm;			/* compute address */
	} else {
		if (getreg(rp, rs2, &val, badaddr))
			return (SIMU_FAULT);
		addr += val;
	}

	/*
	 * If this is a 32-bit program, chop the address accordingly.  The
	 * intermediate uintptr_t casts prevent warnings under a certain
	 * compiler, and the temporary 32 bit storage is intended to force
	 * proper code generation and break up what would otherwise be a
	 * quadruple cast.
	 */
	if (curproc->p_model == DATAMODEL_ILP32 && USERMODE(rp->r_tstate)) {
		caddr32_t addr32 = (caddr32_t)(uintptr_t)addr;
		addr = (caddr_t)(uintptr_t)addr32;
	}

	*badaddr = addr;
	return ((uintptr_t)addr & (sz - 1) ? SIMU_UNALIGN : SIMU_SUCCESS);
}

/*
 * Return the size of a load or store instruction (1, 2, 4, 8, 16, 64).
 * Also compute the precise address by instruction disassembly.
 * (v9 page faults only provide the page address via the hardware.)
 * Return 0 on failure (not a load or store instruction).
 */
int
instr_size(struct regs *rp, caddr_t *addrp, enum seg_rw rdwr)
{
	uint_t	inst, op3, asi;
	uint_t	rd, rs1, rs2;
	int	sz = 0;
	int	immflg;
	int	floatflg;
	caddr_t	addr;
	caddr_t badaddr;
	uint64_t val;

	if (rdwr == S_EXEC) {
		*addrp = (caddr_t)rp->r_pc;
		return (4);
	}

	/*
	 * Fetch the instruction from user-level.
	 * We would like to assert this:
	 *   ASSERT(USERMODE(rp->r_tstate));
	 * but we can't because we can reach this point from a
	 * register window underflow/overflow and the v9 wbuf
	 * traps call trap() with T_USER even though r_tstate
	 * indicates a system trap, not a user trap.
	 */
	inst = fetch_user_instr((caddr_t)rp->r_pc);

	op3 = (inst >> 19) & 0x3f;
	rd = (inst >> 25) & 0x1f;
	rs1 = (inst >> 14) & 0x1f;
	rs2 = inst & 0x1f;
	floatflg = (inst >> 24) & 1;
	immflg = (inst >> 13) & 1;

	/* if not load or store do nothing.  can't happen? */
	if ((inst >> 30) != 3)
		return (0);

	if (immflg)
		asi = (uint_t)((rp->r_tstate >> TSTATE_ASI_SHIFT) &
		    TSTATE_ASI_MASK);
	else
		asi = (inst >> 5) & 0xff;

	if (floatflg) {
		/* check for ld/st alternate and highest defined V9 asi */
		if ((op3 & 0x30) == 0x30 && asi > ASI_SNFL) {
			sz = extended_asi_size(asi);
		} else {
			switch (op3 & 3) {
			case 0:
				sz = 4;			/* ldf/stf/cas */
				break;
			case 1:
				if (rd == 0)
					sz = 4;		/* ldfsr/stfsr */
				else
					sz = 8;		/* ldxfsr/stxfsr */
				break;
			case 2:
				if (op3 == 0x3e)
					sz = 8;		/* casx */
				else
					sz = 16;	/* ldqf/stqf */
				break;
			case 3:
				sz = 8;			/* lddf/stdf */
				break;
			}
		}
	} else {
		switch (op3 & 0xf) {		/* map size bits to a number */
		case 0:				/* lduw */
		case 4:				/* stw */
		case 8:				/* ldsw */
		case 0xf:			/* swap */
			sz = 4; break;
		case 1:				/* ldub */
		case 5:				/* stb */
		case 9:				/* ldsb */
		case 0xd:			/* ldstub */
			sz = 1; break;
		case 2:				/* lduh */
		case 6:				/* sth */
		case 0xa:			/* ldsh */
			sz = 2; break;
		case 3:				/* ldd */
		case 7:				/* std */
		case 0xb:			/* ldx */
		case 0xe:			/* stx */
			sz = 8; break;
		}
	}

	if (sz == 0)	/* can't happen? */
		return (0);
	(void) flush_user_windows_to_stack(NULL);

	if (getreg(rp, rs1, &val, &badaddr))
		return (0);
	addr = (caddr_t)val;

	/* cas/casx don't use rs2 / simm13 to compute the address */
	if ((op3 & 0x3d) != 0x3c) {
		/* check immediate bit and use immediate field or reg (rs2) */
		if (immflg) {
			int imm;
			imm  = inst & 0x1fff;	/* mask out immediate field */
			imm <<= 19;		/* sign extend it */
			imm >>= 19;
			addr += imm;		/* compute address */
		} else {
			/*
			 * asi's in the 0xCx range are partial store
			 * instructions.  For these, rs2 is a mask, not part of
			 * the address.
			 */
			if (!(floatflg && (asi & 0xf0) == 0xc0)) {
				if (getreg(rp, rs2, &val, &badaddr))
					return (0);
				addr += val;
			}
		}
	}

	/*
	 * If this is a 32-bit program, chop the address accordingly.  The
	 * intermediate uintptr_t casts prevent warnings under a certain
	 * compiler, and the temporary 32 bit storage is intended to force
	 * proper code generation and break up what would otherwise be a
	 * quadruple cast.
	 */
	if (curproc->p_model == DATAMODEL_ILP32) {
		caddr32_t addr32 = (caddr32_t)(uintptr_t)addr;
		addr = (caddr_t)(uintptr_t)addr32;
	}

	*addrp = addr;
	ASSERT(sz != 0);
	return (sz);
}

/*
 * Fetch an instruction from user-level.
 * Deal with watchpoints, if they are in effect.
 */
int32_t
fetch_user_instr(caddr_t vaddr)
{
	proc_t *p = curproc;
	int32_t instr;

	/*
	 * If this is a 32-bit program, chop the address accordingly.  The
	 * intermediate uintptr_t casts prevent warnings under a certain
	 * compiler, and the temporary 32 bit storage is intended to force
	 * proper code generation and break up what would otherwise be a
	 * quadruple cast.
	 */
	if (p->p_model == DATAMODEL_ILP32) {
		caddr32_t vaddr32 = (caddr32_t)(uintptr_t)vaddr;
		vaddr = (caddr_t)(uintptr_t)vaddr32;
	}

	if (fuword32_nowatch(vaddr, (uint32_t *)&instr) == -1)
		instr = -1;

	return (instr);
}
