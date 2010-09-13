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
 * Copyright (c) 1996-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SCAT_CONST_H
#define	_SCAT_CONST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains definitions fundamental to the Starcat architecture;
 * how many exps, how many of each asic type, etc.
 */

/*
 * POST DEVELOPERS:
 * This file is copied to the OS workspace, and thus must abide by the OS
 * coding standards.  This file must always pass cstyle and hdrchk.
 */

#ifdef __cplusplus
extern "C" {
#endif


#define	SSC_COUNT		(2)
#define	SSC_MAX			(SSC_COUNT - 1)
#define	IS_VALID_SSC(ssc)	((ssc) >= 0 && (ssc) < SSC_COUNT)

#define	EXP_COUNT		(18)
#define	EXP_MAX			(EXP_COUNT - 1)
#define	IS_VALID_EXP(exp)	((exp) >= 0 && (exp) < EXP_COUNT)

#define	EXB_COUNT		EXP_COUNT
#define	EXB_MAX			EXP_MAX
#define	IS_VALID_EXB(exb)	IS_VALID_EXP(exb)

#ifdef No_More_No_More
	/* Support this for awhile until we purge everywhere: */
#define	NODE_COUNT		EXP_COUNT
#define	NODE_MAX		EXP_MAX
#define	IS_VALID_NODE(node)	IS_VALID_EXP(node)
#endif	/* No_More_No_More */

	/* Slots are L1 boards within an expander */
#define	SLOT_COUNT		(2)
#define	SLOT_MAX		(SLOT_COUNT - 1)
#define	IS_VALID_SLOT(slot)	((slot) >= 0 && (slot) < SLOT_COUNT)


#ifdef REFERENCE
	/* XXX: temporary definitions till Dan decides what he wants */
#define	L1_COUNT		(SLOT_COUNT * EXP_COUNT)
#define	L1_MAX			(L1_COUNT - 1)
#define	IS_VALID_L1_BOARD(brd)	((brd) >= 0 && (brd) < L1_COUNT)

#define	S0_PROC_COUNT		(4)	/* max procs on slot 0 L1 board */
#define	S1_PROC_COUNT		(2)	/* max procs on slot 1 L1 board */

#define	SPM_COUNT		(S0_PROC_COUNT + S1_PROC_COUNT)

#define	PROC_COUNT		((S0_PROC_COUNT * EXP_COUNT) + \
				    (S1_PROC_COUNT * EXP_COUNT))
#define	PROC_MAX		(PROC_COUNT - 1)
#define	IS_VALID_PROC(proc)	((proc) >= 0 && (proc) < PROC_COUNT)

#define	EXP2PROC(exp, spm)		((exp) * (spm))
#define	EXPSLTBBC2SRAM(exp, slt, bbc)	((exp * 3) + (slt * 2) + (bbc))

#define	PROC2EXP(proc)	((proc) / 6)
#define	PROC2SPM(proc)	((proc) % 6)
#define	PROC2CPU(proc)	(PROC2SPM(proc) & 0x3)
#define	PROC2SLT(proc)	(PROC2SPM(proc) >> 2)
#define	PROC2BBC(proc)	(((PROC2CPU(proc)) & 0x2) >> 1)
#define	PROC2PRT(proc)	((proc) & 0x1)
#define	EXPSLT(proc)	PROC2EXP(proc), PROC2SLT(proc)
#define	EXPSLTCPU(proc)	PROC2EXP(proc), PROC2SLT(proc), PROC2CPU(proc)
#endif /* REFERENCE */


	/*
	 * PFP = Packed flat port.
	 * For cases where one might need to maintain information
	 * (pcd arrays), or write loops, over all 18 X 6 = 108 ports.
	 * It is expected that this flat view of the ports is not made
	 * visible to the user, they should see only the ordered triple
	 * <exp>.<slot>.<lport> or the 10-bit Safari PortId.
	 * PWE = Port Within Expander. [0-5]. Comes along with the
	 * PFP model, should also not be externally visible.
	 */
#define	PORT_PER_EXP		6
#define	PWE_COUNT		PORT_PER_EXP
#define	PWE_MAX			(PWE_COUNT - 1)
#define	IS_VALID_PWE(pwe)	((pwe) >= 0 && (pwe) < PWE_COUNT)

#define	PFP_COUNT		(EXP_COUNT * PORT_PER_EXP)
#define	PFP_MAX			(PFP_COUNT - 1)
#define	IS_VALID_PFP(pfp)	((pfp) >= 0 && (pfp) < PFP_COUNT)

#define	PFP2EXP(pfp)		((pfp) / 6)
#define	PFP2PWE(pfp)		((pfp) % 6)
#define	PWE2SLOT(pwe)		((pwe) >> 2)
#define	PWE2LPORT(pwe)		((pwe) & 0x3)
#define	PFP2SLOT(pfp)		(PWE2SLOT(PFP2PWE(pfp)))
#define	PFP2LPORT(pfp)		(PWE2LPORT(PFP2PWE(pfp)))
#define	PFP2BBC(pfp)		(((PFP2PWE(pfp)) >> 1) & 1)
#define	PFP2BBCPORT(pfp)	((pfp) & 1)

#define	SL2PWE(slot, lport)	(((slot) << 2) + (lport))
#define	EPWE2PFP(exp, pwe)	(((exp) * 6) + (pwe))
#define	ESL2PFP(exp, slot, lport) (EPWE2PFP((exp), SL2PWE((slot), (lport))))

#define	S0_LPORT_COUNT		4	/* Ports on slot 0 L1 board */
#define	S0_LPORT_MAX		(S0_LPORT_COUNT - 1)
#define	IS_VALID_S0LPORT(lport)	((lport) >= 0 && (lport) < S0_LPORT_COUNT)
#define	S1_LPORT_COUNT		2	/* Ports on slot 1 L1 board */
#define	S1_LPORT_MAX		(S1_LPORT_COUNT - 1)
#define	IS_VALID_S1LPORT(lport)	((lport) >= 0 && (lport) < S1_LPORT_COUNT)
#define	LPORT_COUNT(slot)	((slot) ? S1_LPORT_COUNT : S0_LPORT_COUNT)
#define	LPORT_MAX(slot)		(LPORT_COUNT(slot) - 1)
#define	IS_VALID_LPORT(slot, lport) \
	((lport) >= 0 && (lport) < LPORT_COUNT(slot))
#define	XC_IOBUS_PER_PORT	2
#define	XC_IOCARD_PER_PORT	1
#define	IS_VALID_IOBUS(bus)	((bus) >= 0 && (bus) < XC_IOBUS_PER_PORT)
#define	IS_VALID_IOCARD(card)	((card) >= 0 && (card) < XC_IOCARD_PER_PORT)

	/* BBC in these macros is local to a slot, either 0 or 1: */
#define	S0_BBC_COUNT		2	/* BBCs on slot 0 L1 board */
#define	S0_BBC_MAX		(S0_BBC_COUNT - 1)
#define	IS_VALID_S0BBC(bbc)	((bbc) >= 0 && (bbc) < S0_BBC_COUNT)
#define	S1_BBC_COUNT		1	/* BBCs on slot 1 L1 board */
#define	S1_BBC_MAX		(S1_BBC_COUNT - 1)
#define	IS_VALID_S1BBC(bbc)	((bbc) >= 0 && (bbc) < S1_BBC_COUNT)
#define	BBC_COUNT(slot)	((slot) ? S1_BBC_COUNT : S0_BBC_COUNT)
#define	BBC_MAX(slot)		(BBC_COUNT(slot) - 1)
#define	IS_VALID_BBC(slot, bbc) \
	((bbc) >= 0 && (bbc) < BBC_COUNT(slot))

#define	LPORT2BBC(lport)	((lport) >> 1)
#define	PWE2BBC(pwe)		(((pwe) >> 1) & 1)


	/* These are for use as printf() arguments for "%2d.%d", etc.: */
#define	EXPSLOT(pfp)		PFP2EXP(pfp), PFP2SLOT(pfp)
#define	EXPSLOTLPORT(pfp)	PFP2EXP(pfp), PFP2SLOT(pfp), PFP2LPORT(pfp)


	/* Build a 5-bit Safari Agent ID: */
#define	SAFAGENT(slot, lport, is_ioport) \
	(((slot) ? ((is_ioport) ? 0x1C : 8) : 0) + (lport))

	/* Build a 10-bit Safari ID: */
#define	SAFARI_ID(exp, slot, lport, is_ioport) \
	(SAFAGENT(slot, lport, is_ioport) | ((exp) << 5))

	/* Given a Safari Agent ID, extract the expander number */
#define	GET_EXP(aid)		((aid & 0x3E0ull) >> 5)

	/* Cacheable memory per (CPU) port */
#define	DIMMS_PER_PORT		8
#define	IS_VALID_DIMM(dimm)	\
	(((dimm) >= 0) && (dimm < (DIMMS_PER_PORT)))
#define	PMBANKS_PER_PORT	2
#define	LMBANKS_PER_PMBANK	2
#define	IS_VALID_PMBANK(pmbank)	\
	(((pmbank) >= 0) && (pmbank < PMBANKS_PER_PORT))
#define	IS_VALID_LMBANK(lmbank)	\
	(((lmbank) >= 0) && (lmbank < PMBANKS_PER_PORT))

	/* Ecache per (CPU) port */
#define	ECDIMMS_PER_PORT	2
#define	IS_VALID_ECACHE(ecache)	\
	(((ecache) >= 0) && (ecache < ECDIMMS_PER_PORT))

	/* SCM asics per CSB: */
#define	SCM_COUNT		(2)
#define	SCM_MAX			(SCM_COUNT - 1)
#define	IS_VALID_SCM(scm)	((scm) >= 0 && (scm) < SCM_COUNT)

	/* Master ports in an SCM: */
#define	SCM_MPORT_COUNT			10

	/* SDI asics per EXB: */
#define	SDI_COUNT		(6)
#define	SDI_MAX			(SDI_COUNT - 1)
#define	IS_VALID_SDI(sdi)	((sdi) >= 0 && (sdi) < SDI_COUNT)

	/* Half-centerplanes, CSBs, etc. */
#define	CP_COUNT		(2)
#define	CP_MAX			(CP_COUNT - 1)
#define	IS_VALID_CP(cp)		((cp) >= 0 && (cp) < CP_COUNT)

	/* DMX asics on the half-centerplane: */
#define	DMX_COUNT		(6)
#define	DMX_MAX			(DMX_COUNT - 1)
#define	IS_VALID_DMX(dmx)	((dmx) >= 0 && (dmx) < DMX_COUNT)

	/* AMX asics on the half-centerplane: */
#define	AMX_COUNT		(2)
#define	AMX_MAX			(AMX_COUNT - 1)
#define	IS_VALID_AMX(amx)	((amx) >= 0 && (amx) < AMX_COUNT)

	/* Number of CPUs per SBBC on the various boards: */
#define	CPU_COUNT		(2)

	/* Number of WCI per WIB: */
#define	S0_WCI_COUNT		(2)
#define	S0_WCI_MIN		(2)
#define	S0_WCI_MAX		(S0_WCI_MIN + S0_WCI_COUNT - 1)
#define	S0_IS_VALID_WCI(wci)	((wci) >= S0_WCI_MIN && (wci) <= S0_WCI_MAX)
#define	S1_WCI_COUNT		(1)
#define	S1_WCI_MIN		(1)
#define	S1_WCI_MAX		(S1_WCI_MIN + S1_WCI_COUNT - 1)
#define	WCI_COUNT(slot)		((slot) ? S1_WCI_COUNT : S0_WCI_COUNT)
#define	WCI_MIN(slot)		((slot) ? S1_WCI_MIN : S0_WCI_MIN)
#define	WCI_MAX(slot)		((slot) ? S1_WCI_MAX : S0_WCI_MAX)
#define	S1_IS_VALID_WCI(wci)	((wci) >= S1_WCI_MIN && (wci) <= S1_WCI_MAX)
#define	IS_VALID_WCI(slot, wci)	((slot) ? S1_IS_VALID_WCI((wci)) : \
				    S0_IS_VALID_WCI((wci)))

	/* Safari reset number (within sbbc) given slot & lport */
#define	WCI_RST_NUM(slot, lport) \
	((slot) ? 1 : ((lport) & 1 ? 1 : 0))

	/* Number of non WCI safari devices per WIB */
#define	S0_WIB_PROC_COUNT	(2)	/* max procs on slot 0 WIB */
#define	S1_WIB_SCHIZO_COUNT	(1)	/* max schizos on slot 1 WIB */

	/* Number of Schizo per PCI I/O board: */
#define	SCHIZO_COUNT		(2)

	/*
	 * CPU and Maxcat L1 boards have 4 DXs, I/O boards have 2.
	 * But it's useful to have this for array dimensions, etc.
	 */
#define	DX_COUNT_MAX		(4)
#define	IS_VALID_CPU_DX(dx)	((dx) >= 0 && (dx) < DX_COUNT_MAX)

	/*
	 * DCDS asics for half of a CPU board. The DCDS is a data slice,
	 * 8 are required for a full Safari data path.
	 */
#define	DCDS_COUNT		(8)
#define	DCDS_MAX		(DCDS_COUNT - 1)
#define	IS_VALID_DCDS(dcds)	((dcds) >= 0 && (dcds) < DCDS_COUNT)


	/*
	 * Address, Data, or Response Bus.
	 * For all three, 0 or 1 is a valid value.
	 */
#define	BUS_COUNT		(CP_COUNT)
#define	BUS_MAX			(BUS_COUNT - 1)
#define	IS_VALID_BUS(bus)	((bus) >= 0 && (bus) < BUS_COUNT)

	/*
	 * Address, Data, or Response Bus configuration.
	 * For all three, 1. 2. or 3 is a valid value.
	 */
#define	BCONF_MIN		0x1
#define	BCONF_MAX		0x3
#define	BCONF_COUNT		3
#define	IS_VALID_BCONF(bconf)	((bconf) >= BCONF_MIN && (bconf) <= BCONF_MAX)

	/*
	 * This might seem a little obscure to be here, but it's needed
	 * for some array sizes and function prototypes:
	 */
#define	AXQ_NASM_SIZE				256


#ifdef __cplusplus
}
#endif

#endif	/* !_SCAT_CONST_H */
